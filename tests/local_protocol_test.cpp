#include "gatehold/controller/local_protocol.hpp"
#include "gatehold/firewall/activation_service.hpp"
#include "gatehold/firewall/activation_transaction_store.hpp"
#include "gatehold/firewall/native_validator.hpp"
#include "gatehold/firewall/pfctl_loader.hpp"
#include "gatehold/firewall/revision_store.hpp"
#include "gatehold/logging/operation_journal.hpp"
#include "temporary_directory.hpp"
#include "test_support.hpp"

#include <sys/socket.h>
#include <unistd.h>

#include <array>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <functional>
#include <limits>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

namespace controller = sasd::gatehold::controller;
namespace firewall = sasd::gatehold::firewall;
namespace logging = sasd::gatehold::logging;

namespace {

void create_private_directory(const std::filesystem::path& path) {
    std::filesystem::create_directory(path);
    std::filesystem::permissions(
        path,
        std::filesystem::perms::owner_all,
        std::filesystem::perm_options::replace);
}

void write_private_file(
    const std::filesystem::path& path,
    const std::string& content) {
    {
        std::ofstream output{path, std::ios::binary};
        output << content;
    }
    std::filesystem::permissions(
        path,
        std::filesystem::perms::owner_read | std::filesystem::perms::owner_write,
        std::filesystem::perm_options::replace);
}

std::string read_file(const std::filesystem::path& path) {
    std::ifstream input{path, std::ios::binary};
    return {std::istreambuf_iterator<char>{input},
            std::istreambuf_iterator<char>{}};
}

class SocketPair final {
public:
    SocketPair() {
        if (::socketpair(AF_UNIX, SOCK_STREAM, 0, descriptors_.data()) != 0) {
            descriptors_ = {-1, -1};
        }
    }

    ~SocketPair() {
        close_client();
        if (descriptors_[1] >= 0) {
            ::close(descriptors_[1]);
        }
    }

    SocketPair(const SocketPair&) = delete;
    SocketPair& operator=(const SocketPair&) = delete;

    [[nodiscard]] bool valid() const noexcept {
        return descriptors_[0] >= 0 && descriptors_[1] >= 0;
    }

    [[nodiscard]] int client() const noexcept {
        return descriptors_[0];
    }

    [[nodiscard]] int server() const noexcept {
        return descriptors_[1];
    }

    void close_client() noexcept {
        if (descriptors_[0] >= 0) {
            ::close(descriptors_[0]);
            descriptors_[0] = -1;
        }
    }

private:
    std::array<int, 2> descriptors_{-1, -1};
};

std::string frame(std::string_view payload) {
    const auto size = static_cast<std::uint32_t>(payload.size());
    std::string framed;
    framed.reserve(payload.size() + 4U);
    framed.push_back(static_cast<char>((size >> 24U) & 0xffU));
    framed.push_back(static_cast<char>((size >> 16U) & 0xffU));
    framed.push_back(static_cast<char>((size >> 8U) & 0xffU));
    framed.push_back(static_cast<char>(size & 0xffU));
    framed.append(payload);
    return framed;
}

bool send_all(int socket, std::string_view bytes) {
    std::size_t offset = 0;
    while (offset < bytes.size()) {
        const auto sent =
            ::send(socket, bytes.data() + offset, bytes.size() - offset, 0);
        if (sent <= 0) {
            return false;
        }
        offset += static_cast<std::size_t>(sent);
    }
    return true;
}

std::optional<std::string> receive_frame(int socket) {
    std::array<unsigned char, 4> header{};
    std::size_t offset = 0;
    while (offset < header.size()) {
        const auto received =
            ::recv(socket, header.data() + offset, header.size() - offset, 0);
        if (received <= 0) {
            return std::nullopt;
        }
        offset += static_cast<std::size_t>(received);
    }
    const std::uint32_t size =
        (static_cast<std::uint32_t>(header[0]) << 24U) |
        (static_cast<std::uint32_t>(header[1]) << 16U) |
        (static_cast<std::uint32_t>(header[2]) << 8U) |
        static_cast<std::uint32_t>(header[3]);
    if (size == 0U || size > controller::ControllerProtocolSession::maximum_payload_size) {
        return std::nullopt;
    }
    std::string payload(size, '\0');
    offset = 0;
    while (offset < payload.size()) {
        const auto received =
            ::recv(socket, payload.data() + offset, payload.size() - offset, 0);
        if (received <= 0) {
            return std::nullopt;
        }
        offset += static_cast<std::size_t>(received);
    }
    return payload;
}

std::string status_request(std::string request_id = "status-request") {
    return "gatehold-controller-v1\nrequest_id=" + request_id +
           "\noperation=status\n";
}

std::string activation_request(
    std::uint64_t revision,
    std::string request_id,
    std::string operation_id,
    std::string authorization_reference = "protocol-approval") {
    return "gatehold-controller-v1\nrequest_id=" + request_id +
           "\noperation=activate\noperation_id=" + operation_id +
           "\nrevision=" + std::to_string(revision) +
           "\nauthorization_reference=" + authorization_reference +
           "\nprobe_timeout_ms=1000\nconfirmation_timeout_ms=5000\n";
}

class CapturingAuthorizer final : public firewall::ActivationAuthorizer {
public:
    [[nodiscard]] firewall::AuthorizationResult authorize(
        const std::string&,
        std::uint64_t,
        const std::string& authorization_reference) const override {
        const std::scoped_lock lock{mutex_};
        last_reference_ = authorization_reference;
        return {
            .status = firewall::AuthorizationStatus::authorized,
            .decision_id = "protocol-decision",
            .message = "authorized"};
    }

    [[nodiscard]] std::string last_reference() const {
        const std::scoped_lock lock{mutex_};
        return last_reference_;
    }

private:
    mutable std::mutex mutex_;
    mutable std::string last_reference_;
};

class ConfirmGate final : public firewall::ConfirmationGate {
public:
    [[nodiscard]] firewall::ConfirmationResult await_confirmation(
        const std::string&,
        std::uint64_t,
        std::chrono::milliseconds) const override {
        return {
            .status = firewall::ConfirmationStatus::confirmed,
            .confirmation_id = "protocol-confirmation",
            .message = "confirmed"};
    }
};

class HealthyProbe final : public firewall::HealthProbe {
public:
    [[nodiscard]] std::string id() const override {
        return "protocol-management-path";
    }

    [[nodiscard]] firewall::HealthProbeResult run(
        std::chrono::milliseconds) const override {
        return {
            .status = firewall::HealthProbeStatus::healthy,
            .message = "healthy"};
    }
};

std::vector<std::reference_wrapper<const firewall::HealthProbe>> probes(
    const firewall::HealthProbe& probe) {
    return {std::cref(probe)};
}

struct ExchangeResult {
    controller::ProtocolSessionResult session;
    std::optional<std::string> response;
};

ExchangeResult run_exchange(
    const controller::ControllerProtocolSession& session,
    std::string_view payload,
    std::chrono::milliseconds timeout = std::chrono::milliseconds{1000},
    bool fragmented = false) {
    SocketPair sockets;
    controller::ProtocolSessionResult session_result;
    std::thread server{[&] {
        session_result = session.serve(sockets.server(), timeout);
    }};
    const auto request_frame = frame(payload);
    if (fragmented) {
        for (const char byte : request_frame) {
            const std::string_view part{&byte, 1U};
            if (!send_all(sockets.client(), part)) {
                break;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds{1});
        }
    } else {
        static_cast<void>(send_all(sockets.client(), request_frame));
    }
    auto response = receive_frame(sockets.client());
    server.join();
    return {.session = std::move(session_result), .response = std::move(response)};
}

}  // namespace

int main(int argc, char* argv[]) {
    gatehold::test::Context test;
    test.check(argc == 2, "test receives the fake pfctl executable path");
    if (argc != 2) {
        return test.result();
    }

    const gatehold::test::TemporaryDirectory temporary{
        "gatehold-local-protocol-test"};
    const auto revision_root = temporary.path() / "revisions";
    const auto candidate_root = temporary.path() / "candidates";
    const auto transaction_root = temporary.path() / "transactions";
    const auto journal_root = temporary.path() / "journal";
    create_private_directory(revision_root);
    create_private_directory(candidate_root);
    create_private_directory(transaction_root);
    create_private_directory(journal_root);

    const auto fake_pfctl =
        std::filesystem::absolute(std::filesystem::path{argv[1]});
    const auto trace = temporary.path() / "loads.trace";
    ::setenv("GATEHOLD_FAKE_PFCTL_TRACE", trace.c_str(), 1);
    const firewall::RevisionStore revisions{revision_root};
    const firewall::ActivationTransactionStore transactions{transaction_root};
    for (const auto& [revision, content] :
         std::vector<std::pair<std::uint64_t, std::string>>{
             {1, "block all\n"},
             {2, "block all\npass out all\n"},
             {3, "block log all\n"}}) {
        const auto candidate =
            candidate_root / (std::to_string(revision) + ".pf.conf");
        write_private_file(candidate, content);
        test.check(revisions.store(revision, candidate).ok(), "revision is stored");
    }
    test.check(
        revisions.mark_last_known_good(1).ok(),
        "initial protocol rollback revision is marked");

    const firewall::PfctlValidator validator{
        fake_pfctl, std::chrono::milliseconds{1000}};
    const firewall::PfctlLoader loader{
        fake_pfctl, std::chrono::milliseconds{1000}};
    const logging::OperationJournal journal{journal_root};
    const CapturingAuthorizer authorizer;
    const ConfirmGate confirmation;
    const HealthyProbe healthy_probe;
    const auto timestamp = [] { return "2026-09-18T17:00:00Z"; };
    const firewall::PfActivationService activation_service{
        revisions,
        transactions,
        validator,
        loader,
        journal,
        authorizer,
        confirmation,
        probes(healthy_probe),
        timestamp};
    controller::PrivilegedPfController pf_controller{
        activation_service, journal, timestamp};
    test.check(
        pf_controller.start().accepts_activations(),
        "protocol controller completes startup recovery");

    SocketPair credential_sockets;
    test.check(credential_sockets.valid(), "credential socket pair is created");
    const auto credentials =
        controller::PeerCredentialReader{}.read(credential_sockets.server());
    test.check(
        credentials.ok() && credentials.user_id == ::geteuid() &&
            credentials.group_id == ::getegid(),
        "peer credentials resolve the connected effective UID and GID");
    test.check(
        !controller::PeerCredentialReader{}.read(-1).ok(),
        "invalid descriptor cannot produce peer credentials");

    const controller::PeerCredentialPolicy allowed_peer{::geteuid(), ::getegid()};
    const controller::ControllerProtocolSession protocol{
        pf_controller, journal, allowed_peer, timestamp};

    const auto status = run_exchange(
        protocol,
        status_request(),
        std::chrono::milliseconds{1000},
        true);
    test.check(
        status.session.ok() && status.response.has_value() &&
            status.response->find("result=completed\n") != std::string::npos &&
            status.response->find("controller_state=ready\n") !=
                std::string::npos &&
            status.response->find("event_id=GH-IPC-0002\n") !=
                std::string::npos,
        "fragmented status request returns bounded ready response");
    test.check(
        status.session.peer_user_id == std::optional<uid_t>{::geteuid()} &&
            status.session.peer_group_id == std::optional<gid_t>{::getegid()},
        "completed session reports verified peer identity");

    const auto activation = run_exchange(
        protocol,
        activation_request(2, "request-activate-2", "activate-via-protocol"));
    test.check(
        activation.session.ok() && activation.response.has_value() &&
            activation.response->find("result=completed\n") !=
                std::string::npos &&
            activation.response->find("activation_status=committed\n") !=
                std::string::npos,
        "authorized protocol request dispatches committed activation");
    test.check(
        authorizer.last_reference() == "protocol-approval",
        "authorization reference crosses protocol only to trusted authorizer");
    test.check(
        revisions.last_known_good().revision == std::optional<std::uint64_t>{2},
        "protocol activation advances last known good after confirmation");
    const auto journal_text = read_file(journal.journal_path());
    test.check(
        journal_text.find("protocol-approval") == std::string::npos &&
            journal_text.find("GH-IPC-0001") != std::string::npos &&
            journal_text.find("GH-IPC-0003") != std::string::npos,
        "protocol audit records authentication and dispatch without approval data");

    const uid_t denied_user =
        ::geteuid() == std::numeric_limits<uid_t>::max() ? 0 : ::geteuid() + 1U;
    const controller::ControllerProtocolSession denied_protocol{
        pf_controller,
        journal,
        controller::PeerCredentialPolicy{denied_user},
        timestamp};
    const auto denied =
        run_exchange(denied_protocol, status_request("denied-peer"));
    test.check(
        denied.session.status ==
                controller::ProtocolSessionStatus::peer_rejected &&
            denied.session.event_id == "GH-IPC-1001" &&
            denied.response.has_value() &&
            denied.response->find("event_id=GH-IPC-1001\n") !=
                std::string::npos,
        "UID policy rejects an otherwise valid local peer before request parsing");

    const auto unsupported = run_exchange(
        protocol,
        "gatehold-controller-v2\nrequest_id=wrong-version\noperation=status\n");
    test.check(
        unsupported.session.status ==
                controller::ProtocolSessionStatus::invalid_request &&
            unsupported.session.event_id == "GH-IPC-1003",
        "unsupported protocol version is rejected");
    const auto malformed = run_exchange(
        protocol,
        "gatehold-controller-v1\nrequest_id=bad request\noperation=status\n");
    test.check(
        malformed.session.status ==
                controller::ProtocolSessionStatus::invalid_request &&
            malformed.session.event_id == "GH-IPC-1002",
        "unsafe request identifier is rejected");

    SocketPair oversized_sockets;
    controller::ProtocolSessionResult oversized_result;
    std::thread oversized_server{[&] {
        oversized_result = protocol.serve(
            oversized_sockets.server(), std::chrono::milliseconds{1000});
    }};
    const std::array<unsigned char, 4> oversized_header{0, 0, 16, 1};
    static_cast<void>(::send(
        oversized_sockets.client(),
        oversized_header.data(),
        oversized_header.size(),
        0));
    const auto oversized_response = receive_frame(oversized_sockets.client());
    oversized_server.join();
    test.check(
        oversized_result.status ==
                controller::ProtocolSessionStatus::invalid_request &&
            oversized_response.has_value() &&
            oversized_response->find("GH-IPC-1002") != std::string::npos,
        "payload larger than four KiB is rejected before allocation");

    SocketPair truncated_sockets;
    controller::ProtocolSessionResult truncated_result;
    std::thread truncated_server{[&] {
        truncated_result = protocol.serve(
            truncated_sockets.server(), std::chrono::milliseconds{1000});
    }};
    const std::array<unsigned char, 4> truncated_header{0, 0, 0, 20};
    static_cast<void>(::send(
        truncated_sockets.client(),
        truncated_header.data(),
        truncated_header.size(),
        0));
    static_cast<void>(::send(truncated_sockets.client(), "short", 5, 0));
    static_cast<void>(::shutdown(truncated_sockets.client(), SHUT_WR));
    const auto truncated_response = receive_frame(truncated_sockets.client());
    truncated_server.join();
    test.check(
        truncated_result.status ==
                controller::ProtocolSessionStatus::invalid_request &&
            truncated_result.event_id == "GH-IPC-1002" &&
            truncated_response.has_value(),
        "truncated payload is rejected while preserving the response channel");

    SocketPair timeout_sockets;
    controller::ProtocolSessionResult timeout_result;
    std::thread timeout_server{[&] {
        timeout_result = protocol.serve(
            timeout_sockets.server(), std::chrono::milliseconds{50});
    }};
    const auto timeout_response = receive_frame(timeout_sockets.client());
    timeout_server.join();
    test.check(
        timeout_result.status == controller::ProtocolSessionStatus::timed_out &&
            timeout_response.has_value() &&
            timeout_response->find("GH-IPC-2002") != std::string::npos,
        "silent peer expires at the bounded input deadline");

    const auto unsafe_journal_root = temporary.path() / "unsafe-journal";
    std::filesystem::create_directory(unsafe_journal_root);
    std::filesystem::permissions(
        unsafe_journal_root,
        std::filesystem::perms::all,
        std::filesystem::perm_options::replace);
    const logging::OperationJournal unsafe_journal{unsafe_journal_root};
    const controller::ControllerProtocolSession unaudited_protocol{
        pf_controller, unsafe_journal, allowed_peer, timestamp};
    const auto unaudited = run_exchange(
        unaudited_protocol,
        activation_request(3, "unaudited-request", "unaudited-activation"));
    test.check(
        unaudited.session.status ==
                controller::ProtocolSessionStatus::audit_failed &&
            unaudited.response.has_value() &&
            unaudited.response->find("GH-IPC-2004") != std::string::npos &&
            revisions.last_known_good().revision ==
                std::optional<std::uint64_t>{2},
        "audit failure rejects protocol request before activation dispatch");

    controller::PrivilegedPfController unstarted_controller{
        activation_service, journal, timestamp};
    const controller::ControllerProtocolSession unstarted_protocol{
        unstarted_controller, journal, allowed_peer, timestamp};
    const auto unstarted = run_exchange(
        unstarted_protocol,
        activation_request(3, "unstarted-request", "unstarted-activation"));
    test.check(
        unstarted.session.ok() && unstarted.response.has_value() &&
            unstarted.response->find("result=rejected\n") !=
                std::string::npos &&
            unstarted.response->find("activation_status=not_dispatched\n") !=
                std::string::npos &&
            revisions.last_known_good().revision ==
                std::optional<std::uint64_t>{2},
        "protocol cannot bypass controller startup recovery gate");

    SocketPair lost_response_sockets;
    controller::ProtocolSessionResult lost_response_result;
    std::thread lost_response_server{[&] {
        lost_response_result = protocol.serve(
            lost_response_sockets.server(), std::chrono::milliseconds{1000});
    }};
    const auto lost_request = frame(activation_request(
        3, "lost-response-request", "lost-response-activation"));
    test.check(
        send_all(lost_response_sockets.client(), lost_request),
        "response-loss activation request is transferred completely");
    lost_response_sockets.close_client();
    lost_response_server.join();
    test.check(
        lost_response_result.status ==
                controller::ProtocolSessionStatus::io_error &&
            lost_response_result.event_id == "GH-IPC-2003" &&
            revisions.last_known_good().revision ==
                std::optional<std::uint64_t>{3},
        "lost response is reported without undoing a durably committed activation");

    return test.result();
}
