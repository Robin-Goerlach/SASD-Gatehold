#include "gatehold/controller/local_listener.hpp"
#include "gatehold/controller/local_protocol.hpp"
#include "gatehold/controller/privileged_pf_controller.hpp"
#include "gatehold/firewall/activation_service.hpp"
#include "gatehold/firewall/activation_transaction_store.hpp"
#include "gatehold/firewall/native_validator.hpp"
#include "gatehold/firewall/pfctl_loader.hpp"
#include "gatehold/firewall/revision_store.hpp"
#include "gatehold/logging/operation_journal.hpp"
#include "temporary_directory.hpp"
#include "test_support.hpp"

#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

#include <array>
#include <cerrno>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iostream>
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

void create_directory(
    const std::filesystem::path& path,
    std::filesystem::perms permissions) {
    std::filesystem::create_directory(path);
    std::filesystem::permissions(
        path, permissions, std::filesystem::perm_options::replace);
}

void write_private_file(
    const std::filesystem::path& path,
    std::string_view content) {
    {
        std::ofstream output{path, std::ios::binary};
        output << content;
    }
    std::filesystem::permissions(
        path,
        std::filesystem::perms::owner_read |
            std::filesystem::perms::owner_write,
        std::filesystem::perm_options::replace);
}

std::string read_file(const std::filesystem::path& path) {
    std::ifstream input{path, std::ios::binary};
    return {std::istreambuf_iterator<char>{input},
            std::istreambuf_iterator<char>{}};
}

class DenyingAuthorizer final : public firewall::ActivationAuthorizer {
public:
    [[nodiscard]] firewall::AuthorizationResult authorize(
        const std::string&,
        std::uint64_t,
        const std::string&) const override {
        return {
            .status = firewall::AuthorizationStatus::denied,
            .decision_id = "listener-test-denial",
            .message = "denied"};
    }
};

class RejectingConfirmation final : public firewall::ConfirmationGate {
public:
    [[nodiscard]] firewall::ConfirmationResult await_confirmation(
        const std::string&,
        std::uint64_t,
        std::chrono::milliseconds) const override {
        return {
            .status = firewall::ConfirmationStatus::rejected,
            .confirmation_id = "listener-test-rejection",
            .message = "rejected"};
    }
};

class UnhealthyProbe final : public firewall::HealthProbe {
public:
    [[nodiscard]] std::string id() const override {
        return "listener-test-probe";
    }

    [[nodiscard]] firewall::HealthProbeResult run(
        std::chrono::milliseconds) const override {
        return {
            .status = firewall::HealthProbeStatus::unhealthy,
            .message = "unhealthy"};
    }
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

bool send_all(int descriptor, std::string_view bytes) {
    std::size_t offset = 0;
    while (offset < bytes.size()) {
        const auto sent = ::send(
            descriptor, bytes.data() + offset, bytes.size() - offset, 0);
        if (sent <= 0) {
            return false;
        }
        offset += static_cast<std::size_t>(sent);
    }
    return true;
}

std::optional<std::string> receive_frame(int descriptor) {
    std::array<unsigned char, 4> header{};
    std::size_t offset = 0;
    while (offset < header.size()) {
        const auto received = ::recv(
            descriptor,
            header.data() + offset,
            header.size() - offset,
            0);
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
    if (size == 0U ||
        size > controller::ControllerProtocolSession::maximum_payload_size) {
        return std::nullopt;
    }
    std::string payload(size, '\0');
    offset = 0;
    while (offset < payload.size()) {
        const auto received = ::recv(
            descriptor,
            payload.data() + offset,
            payload.size() - offset,
            0);
        if (received <= 0) {
            return std::nullopt;
        }
        offset += static_cast<std::size_t>(received);
    }
    return payload;
}

class ClientSocket final {
public:
    explicit ClientSocket(const std::filesystem::path& socket_path) {
        descriptor_ = ::socket(AF_UNIX, SOCK_STREAM, 0);
        if (descriptor_ < 0) {
            return;
        }
        sockaddr_un address{};
#if defined(__OpenBSD__)
        address.sun_len = static_cast<decltype(address.sun_len)>(
            offsetof(sockaddr_un, sun_path) +
            socket_path.native().size() + 1U);
#endif
        address.sun_family = AF_UNIX;
        const auto path = socket_path.native();
        if (path.size() >= sizeof(address.sun_path)) {
            ::close(descriptor_);
            descriptor_ = -1;
            return;
        }
        std::copy(path.begin(), path.end(), address.sun_path);
        address.sun_path[path.size()] = '\0';
        const auto size = static_cast<socklen_t>(
            offsetof(sockaddr_un, sun_path) + path.size() + 1U);
        if (::connect(
                descriptor_,
                reinterpret_cast<const sockaddr*>(&address),
                size) != 0) {
            ::close(descriptor_);
            descriptor_ = -1;
        }
    }

    ~ClientSocket() {
        if (descriptor_ >= 0) {
            ::close(descriptor_);
        }
    }

    ClientSocket(const ClientSocket&) = delete;
    ClientSocket& operator=(const ClientSocket&) = delete;

    [[nodiscard]] int get() const noexcept {
        return descriptor_;
    }

private:
    int descriptor_{-1};
};

bool wait_until_serving(const controller::LocalControllerListener& listener) {
    for (int attempt = 0; attempt < 200; ++attempt) {
        if (listener.has_active_admission()) {
            return true;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds{1});
    }
    return false;
}

}  // namespace

int main() {
    gatehold::test::Context test;
    const gatehold::test::TemporaryDirectory temporary{
        "gatehold-local-listener-test"};
    const auto journal_root = temporary.path() / "journal";
    const auto socket_root = temporary.path() / "run";
    const auto revision_root = temporary.path() / "revisions";
    const auto transaction_root = temporary.path() / "transactions";
    create_directory(journal_root, std::filesystem::perms::owner_all);
    create_directory(socket_root, std::filesystem::perms::owner_all);
    create_directory(revision_root, std::filesystem::perms::owner_all);
    create_directory(transaction_root, std::filesystem::perms::owner_all);

    const logging::OperationJournal journal{journal_root};
    const firewall::RevisionStore revisions{revision_root};
    const firewall::ActivationTransactionStore transactions{transaction_root};
    const firewall::PfctlValidator validator;
    const firewall::PfctlLoader loader;
    const DenyingAuthorizer authorizer;
    const RejectingConfirmation confirmation;
    const UnhealthyProbe probe;
    const std::vector<std::reference_wrapper<const firewall::HealthProbe>> probes{
        std::cref(probe)};
    const auto timestamp = [] { return "2026-09-19T09:00:00Z"; };
    const firewall::PfActivationService activation_service{
        revisions,
        transactions,
        validator,
        loader,
        journal,
        authorizer,
        confirmation,
        probes,
        timestamp};
    controller::PrivilegedPfController pf_controller{
        activation_service, journal, timestamp};
    const controller::ControllerProtocolSession protocol{
        pf_controller,
        journal,
        controller::PeerCredentialPolicy{::geteuid(), ::getegid()},
        timestamp};

    controller::LocalControllerListener relative_listener{
        protocol,
        journal,
        {.socket_path = "gatehold.sock"},
        timestamp};
    test.check(
        relative_listener.start().status ==
            controller::LocalListenerStatus::invalid_configuration,
        "relative listener path is rejected");

    const auto unsafe_root = temporary.path() / "unsafe-run";
    create_directory(unsafe_root, std::filesystem::perms::all);
    controller::LocalControllerListener unsafe_listener{
        protocol,
        journal,
        {.socket_path = unsafe_root / "gatehold.sock"},
        timestamp};
    test.check(
        unsafe_listener.start().status ==
            controller::LocalListenerStatus::unsafe_directory,
        "group or world writable listener parent is rejected");

    const auto canonical_root = temporary.path() / "canonical-run";
    create_directory(canonical_root, std::filesystem::perms::owner_all);
    const auto alias_root = temporary.path() / "run-alias";
    std::filesystem::create_directory_symlink(canonical_root, alias_root);
    controller::LocalControllerListener aliased_listener{
        protocol,
        journal,
        {.socket_path = alias_root / "gatehold.sock"},
        timestamp};
    test.check(
        aliased_listener.start().status ==
            controller::LocalListenerStatus::unsafe_directory,
        "listener rejects a socket path below a symlinked directory");

    const auto occupied_path = socket_root / "occupied.sock";
    write_private_file(occupied_path, "do-not-replace");
    controller::LocalControllerListener occupied_listener{
        protocol,
        journal,
        {.socket_path = occupied_path},
        timestamp};
    test.check(
        occupied_listener.start().status ==
                controller::LocalListenerStatus::address_in_use &&
            read_file(occupied_path) == "do-not-replace",
        "listener refuses and preserves an existing filesystem entry");

    controller::LocalControllerListener unsafe_mode_listener{
        protocol,
        journal,
        {.socket_path = socket_root / "unsafe-mode.sock",
         .socket_mode = 0666},
        timestamp};
    test.check(
        unsafe_mode_listener.start().status ==
            controller::LocalListenerStatus::invalid_configuration,
        "listener rejects a world-accessible socket mode");

    controller::LocalControllerListener missing_group_listener{
        protocol,
        journal,
        {.socket_path = socket_root / "missing-group.sock",
         .socket_mode = 0660},
        timestamp};
    test.check(
        missing_group_listener.start().status ==
            controller::LocalListenerStatus::invalid_configuration,
        "group-accessible mode requires an explicit target group");

    controller::LocalControllerListener unexpected_group_listener{
        protocol,
        journal,
        {.socket_path = socket_root / "unexpected-group.sock",
         .socket_mode = 0600,
         .socket_group_id = ::getegid()},
        timestamp};
    test.check(
        unexpected_group_listener.start().status ==
            controller::LocalListenerStatus::invalid_configuration,
        "private mode rejects an inconsistent target group");

    controller::LocalControllerListener unsafe_rate_limit_listener{
        protocol,
        journal,
        {.socket_path = socket_root / "unsafe-rate-limit.sock",
         .admission_rate_limit =
             {.maximum_admissions = 0U,
              .window = std::chrono::milliseconds{1000}}},
        timestamp};
    test.check(
        unsafe_rate_limit_listener.start().status ==
            controller::LocalListenerStatus::invalid_configuration,
        "listener rejects an unsafe admission rate limit before binding");

    const auto unsafe_journal_root = temporary.path() / "unsafe-journal";
    create_directory(unsafe_journal_root, std::filesystem::perms::all);
    const logging::OperationJournal unsafe_journal{unsafe_journal_root};
    const auto unaudited_path = socket_root / "unaudited.sock";
    controller::LocalControllerListener unaudited_listener{
        protocol,
        unsafe_journal,
        {.socket_path = unaudited_path},
        timestamp};
    test.check(
        unaudited_listener.start().status ==
                controller::LocalListenerStatus::audit_failed &&
            !std::filesystem::exists(unaudited_path),
        "audit failure prevents listener socket creation");

    const int capability_probe = ::socket(AF_UNIX, SOCK_STREAM, 0);
    if (capability_probe < 0) {
        test.check(
            errno == EPERM,
            "filesystem socket capability probe only permits policy denial");
        if (errno == EPERM) {
            std::cout
                << "SKIPPED: runtime policy denies creation of AF_UNIX sockets\n";
        }
        return test.result();
    }
    ::close(capability_probe);

    const auto socket_path = socket_root / "gatehold.sock";
    controller::LocalControllerListener listener{
        protocol,
        journal,
        {.socket_path = socket_path, .socket_mode = 0600, .listen_backlog = 4},
        timestamp};
    const auto started = listener.start();
    struct stat socket_status {};
    const bool socket_is_private =
        ::lstat(socket_path.c_str(), &socket_status) == 0 &&
        S_ISSOCK(socket_status.st_mode) &&
        (socket_status.st_mode & 0777) == 0600;
    test.check(
        started.ok() && listener.is_listening() && socket_is_private,
        "listener creates a private filesystem socket");
    test.check(
        listener.start().status == controller::LocalListenerStatus::listening,
        "listener start is idempotent");

    controller::LocalControllerListener competing_listener{
        protocol,
        journal,
        {.socket_path = socket_path},
        timestamp};
    test.check(
        competing_listener.start().status ==
                controller::LocalListenerStatus::address_in_use &&
            std::filesystem::exists(socket_path),
        "second listener cannot replace the active socket");

    const auto idle = listener.serve_one(
        std::chrono::milliseconds{25}, std::chrono::milliseconds{1000});
    test.check(
        idle.status == controller::LocalListenerStatus::accept_timed_out &&
            listener.is_listening(),
        "idle accept deadline is bounded without stopping the listener");
    test.check(
        listener
                .serve_one(
                    std::chrono::milliseconds{0},
                    std::chrono::milliseconds{1000})
                .status ==
            controller::LocalListenerStatus::invalid_configuration,
        "listener rejects an invalid accept deadline");

    controller::LocalListenerResult served;
    std::thread server{[&] {
        served = listener.serve_one(
            std::chrono::milliseconds{1000},
            std::chrono::milliseconds{1000});
    }};
    const bool admission_active = wait_until_serving(listener);
    test.check(
        admission_active,
        "listener exposes active admission state for supervision");
    if (!admission_active) {
        server.join();
        static_cast<void>(listener.stop());
        return test.result();
    }
    const auto concurrent = listener.serve_one(
        std::chrono::milliseconds{1000}, std::chrono::milliseconds{1000});
    test.check(
        concurrent.status == controller::LocalListenerStatus::busy,
        "listener rejects concurrent admission beyond its one-session bound");
    test.check(
        listener.stop().status == controller::LocalListenerStatus::busy,
        "listener cannot be stopped while admission owns the descriptor");

    ClientSocket client{socket_path};
    const std::string request = frame(
        "gatehold-controller-v1\nrequest_id=listener-status\noperation=status\n");
    test.check(
        client.get() >= 0 && send_all(client.get(), request),
        "client connects and transfers a framed status request");
    const auto response = receive_frame(client.get());
    server.join();
    test.check(
        served.status == controller::LocalListenerStatus::session_completed &&
            served.session.has_value() && served.session->ok() &&
            response.has_value() &&
            response->find("request_id=listener-status\n") !=
                std::string::npos &&
            response->find("controller_state=created\n") !=
                std::string::npos,
        "listener dispatches one authenticated connection into the protocol");

    const auto stopped = listener.stop();
    test.check(
        stopped.ok() && !listener.is_listening() &&
            !std::filesystem::exists(socket_path),
        "clean stop removes the listener-owned socket path");
    test.check(
        listener.stop().status == controller::LocalListenerStatus::stopped,
        "listener stop is idempotent");

    const auto journal_text = read_file(journal.journal_path());
    test.check(
        journal_text.find("GH-LSN-0001") != std::string::npos &&
            journal_text.find("GH-LSN-0002") != std::string::npos &&
            journal_text.find("GH-LSN-0003") != std::string::npos &&
            journal_text.find("GH-LSN-1004") != std::string::npos &&
            journal_text.find(socket_path.string()) == std::string::npos,
        "listener lifecycle and admission are audited without filesystem paths");

    const auto replaced_path = socket_root / "replaced.sock";
    controller::LocalControllerListener replaced_listener{
        protocol,
        journal,
        {.socket_path = replaced_path},
        timestamp};
    test.check(
        replaced_listener.start().ok(),
        "replacement-safety listener starts");
    test.check(
        ::unlink(replaced_path.c_str()) == 0,
        "test removes the listener directory entry");
    write_private_file(replaced_path, "replacement-must-survive");
    test.check(
        replaced_listener.stop().status ==
                controller::LocalListenerStatus::cleanup_failed &&
            read_file(replaced_path) == "replacement-must-survive",
        "shutdown never unlinks a substituted filesystem entry");

    const auto destructor_path = socket_root / "destructor.sock";
    {
        controller::LocalControllerListener destructor_listener{
            protocol,
            journal,
            {.socket_path = destructor_path,
             .socket_mode = 0660,
             .socket_group_id = ::getegid()},
            timestamp};
        test.check(
            destructor_listener.start().ok(),
            "destructor cleanup listener starts");
        struct stat group_socket {};
        test.check(
            ::lstat(destructor_path.c_str(), &group_socket) == 0 &&
                (group_socket.st_mode & 0777) == 0660 &&
                group_socket.st_gid == ::getegid(),
            "listener applies and verifies the delegated group socket policy");
    }
    test.check(
        !std::filesystem::exists(destructor_path),
        "listener destructor removes only its owned socket path");
    test.check(
        read_file(journal.journal_path())
                .find("\"socket_group_delegated\":\"true\"") !=
            std::string::npos,
        "listener readiness audits group delegation without exposing its GID");

    return test.result();
}
