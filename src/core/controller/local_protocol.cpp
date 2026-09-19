#if defined(__linux__) && !defined(_GNU_SOURCE)
#define _GNU_SOURCE
#endif

#include "gatehold/controller/local_protocol.hpp"

#include "gatehold/logging/event.hpp"

#include <fcntl.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <array>
#include <charconv>
#include <chrono>
#include <cstdint>
#include <ctime>
#include <iomanip>
#include <limits>
#include <optional>
#include <sstream>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace sasd::gatehold::controller {
namespace {

constexpr std::chrono::milliseconds minimum_probe_timeout{100};
constexpr std::chrono::milliseconds maximum_probe_timeout{60000};
constexpr std::chrono::milliseconds minimum_confirmation_timeout{1000};
constexpr std::chrono::milliseconds maximum_confirmation_timeout{600000};

enum class IoStatus { completed, timed_out, closed, invalid_size, failed };

struct FrameResult {
    IoStatus status{IoStatus::failed};
    std::string payload;
};

enum class RequestOperation { status, activate };

struct ParsedRequest {
    RequestOperation operation{RequestOperation::status};
    std::string request_id;
    std::optional<firewall::ActivationRequest> activation;
};

struct ParseResult {
    bool valid{false};
    std::string event_id{"GH-IPC-1002"};
    std::string message{"Controller protocol request is malformed."};
    std::optional<ParsedRequest> request;
};

std::string system_utc_timestamp() {
    const auto now = std::chrono::system_clock::now();
    const std::time_t time = std::chrono::system_clock::to_time_t(now);
    struct tm utc_time {};
    if (::gmtime_r(&time, &utc_time) == nullptr) {
        return "1970-01-01T00:00:00Z";
    }

    std::ostringstream output;
    output << std::put_time(&utc_time, "%Y-%m-%dT%H:%M:%SZ");
    return output.str();
}

bool valid_identifier(std::string_view value) noexcept {
    if (value.empty() || value.size() > 128U) {
        return false;
    }
    for (const char character : value) {
        const bool alpha_numeric =
            (character >= 'a' && character <= 'z') ||
            (character >= 'A' && character <= 'Z') ||
            (character >= '0' && character <= '9');
        if (!alpha_numeric && character != '-' && character != '_' &&
            character != '.' && character != ':') {
            return false;
        }
    }
    return true;
}

template <typename Integer>
std::optional<Integer> parse_unsigned(std::string_view value) noexcept {
    if (value.empty() || value.front() == '+' || value.front() == '-') {
        return std::nullopt;
    }
    Integer parsed{};
    const auto conversion =
        std::from_chars(value.data(), value.data() + value.size(), parsed);
    if (conversion.ec != std::errc{} ||
        conversion.ptr != value.data() + value.size()) {
        return std::nullopt;
    }
    return parsed;
}

std::optional<std::string_view> field_value(
    std::string_view line,
    std::string_view key) noexcept {
    if (!line.starts_with(key) || line.size() <= key.size() ||
        line[key.size()] != '=') {
        return std::nullopt;
    }
    return line.substr(key.size() + 1U);
}

std::optional<std::vector<std::string_view>> split_lines(
    const std::string& payload) {
    if (payload.empty() || payload.back() != '\n') {
        return std::nullopt;
    }

    std::vector<std::string_view> lines;
    std::size_t offset = 0;
    while (offset < payload.size()) {
        const auto end = payload.find('\n', offset);
        if (end == std::string::npos) {
            return std::nullopt;
        }
        const std::string_view line{payload.data() + offset, end - offset};
        if (line.empty() || line.find('\r') != std::string_view::npos ||
            line.find('\0') != std::string_view::npos) {
            return std::nullopt;
        }
        lines.push_back(line);
        offset = end + 1U;
    }
    return lines;
}

ParseResult parse_request(const std::string& payload) {
    const auto lines = split_lines(payload);
    if (!lines.has_value() || lines->size() < 3U) {
        return {};
    }
    if ((*lines)[0] != "gatehold-controller-v1") {
        return {
            .valid = false,
            .event_id = "GH-IPC-1003",
            .message = "Controller protocol version is unsupported.",
            .request = std::nullopt};
    }

    const auto request_id = field_value((*lines)[1], "request_id");
    const auto operation = field_value((*lines)[2], "operation");
    if (!request_id.has_value() || !valid_identifier(*request_id) ||
        !operation.has_value()) {
        return {};
    }

    if (*operation == "status") {
        if (lines->size() != 3U) {
            return {};
        }
        return {
            .valid = true,
            .event_id = "GH-IPC-0002",
            .message = "Controller status request parsed.",
            .request = ParsedRequest{
                .operation = RequestOperation::status,
                .request_id = std::string{*request_id},
                .activation = std::nullopt}};
    }

    if (*operation != "activate") {
        return {
            .valid = false,
            .event_id = "GH-IPC-1003",
            .message = "Controller protocol operation is unsupported.",
            .request = std::nullopt};
    }
    if (lines->size() != 8U) {
        return {};
    }

    const auto operation_id = field_value((*lines)[3], "operation_id");
    const auto revision = field_value((*lines)[4], "revision");
    const auto authorization_reference =
        field_value((*lines)[5], "authorization_reference");
    const auto probe_timeout =
        field_value((*lines)[6], "probe_timeout_ms");
    const auto confirmation_timeout =
        field_value((*lines)[7], "confirmation_timeout_ms");
    if (!operation_id.has_value() || !valid_identifier(*operation_id) ||
        !revision.has_value() || !authorization_reference.has_value() ||
        !valid_identifier(*authorization_reference) ||
        !probe_timeout.has_value() || !confirmation_timeout.has_value()) {
        return {};
    }

    const auto parsed_revision = parse_unsigned<std::uint64_t>(*revision);
    const auto parsed_probe_timeout =
        parse_unsigned<std::uint64_t>(*probe_timeout);
    const auto parsed_confirmation_timeout =
        parse_unsigned<std::uint64_t>(*confirmation_timeout);
    if (!parsed_revision.has_value() || *parsed_revision == 0 ||
        !parsed_probe_timeout.has_value() ||
        *parsed_probe_timeout <
            static_cast<std::uint64_t>(minimum_probe_timeout.count()) ||
        *parsed_probe_timeout >
            static_cast<std::uint64_t>(maximum_probe_timeout.count()) ||
        !parsed_confirmation_timeout.has_value() ||
        *parsed_confirmation_timeout <
            static_cast<std::uint64_t>(minimum_confirmation_timeout.count()) ||
        *parsed_confirmation_timeout > static_cast<std::uint64_t>(
            maximum_confirmation_timeout.count())) {
        return {};
    }

    return {
        .valid = true,
        .event_id = "GH-IPC-0003",
        .message = "Controller activation request parsed.",
        .request = ParsedRequest{
            .operation = RequestOperation::activate,
            .request_id = std::string{*request_id},
            .activation = firewall::ActivationRequest{
                .operation_id = std::string{*operation_id},
                .revision = *parsed_revision,
                .authorization_reference =
                    std::string{*authorization_reference},
                .probe_timeout = std::chrono::milliseconds{
                    *parsed_probe_timeout},
                .confirmation_timeout = std::chrono::milliseconds{
                    *parsed_confirmation_timeout}}}};
}

bool configure_socket(int socket) noexcept {
    const int status_flags = ::fcntl(socket, F_GETFL, 0);
    if (status_flags < 0 ||
        ::fcntl(socket, F_SETFL, status_flags | O_NONBLOCK) != 0) {
        return false;
    }
    const int descriptor_flags = ::fcntl(socket, F_GETFD, 0);
    if (descriptor_flags < 0 ||
        ::fcntl(socket, F_SETFD, descriptor_flags | FD_CLOEXEC) != 0) {
        return false;
    }
#if defined(SO_NOSIGPIPE)
    const int enabled = 1;
    if (::setsockopt(
            socket,
            SOL_SOCKET,
            SO_NOSIGPIPE,
            &enabled,
            static_cast<socklen_t>(sizeof(enabled))) != 0) {
        return false;
    }
#endif
    return true;
}

int remaining_timeout(
    std::chrono::steady_clock::time_point deadline) noexcept {
    const auto now = std::chrono::steady_clock::now();
    if (now >= deadline) {
        return 0;
    }
    auto remaining =
        std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now);
    if (remaining < deadline - now) {
        remaining += std::chrono::milliseconds{1};
    }
    return static_cast<int>(remaining.count());
}

IoStatus wait_for(
    int socket,
    short events,
    std::chrono::steady_clock::time_point deadline) noexcept {
    for (;;) {
        const int timeout = remaining_timeout(deadline);
        if (timeout == 0) {
            return IoStatus::timed_out;
        }
        struct pollfd descriptor {
            .fd = socket, .events = events, .revents = 0
        };
        const int polled = ::poll(&descriptor, 1, timeout);
        if (polled == 0) {
            return IoStatus::timed_out;
        }
        if (polled < 0) {
            if (errno == EINTR) {
                continue;
            }
            return IoStatus::failed;
        }
        if ((descriptor.revents & POLLNVAL) != 0) {
            return IoStatus::failed;
        }
        return IoStatus::completed;
    }
}

IoStatus read_exact(
    int socket,
    unsigned char* destination,
    std::size_t size,
    std::chrono::steady_clock::time_point deadline) noexcept {
    std::size_t offset = 0;
    while (offset < size) {
        const auto waited = wait_for(socket, POLLIN, deadline);
        if (waited != IoStatus::completed) {
            return waited;
        }
        const auto received = ::recv(
            socket, destination + offset, size - offset, 0);
        if (received > 0) {
            offset += static_cast<std::size_t>(received);
            continue;
        }
        if (received == 0) {
            return IoStatus::closed;
        }
        if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) {
            continue;
        }
        return IoStatus::failed;
    }
    return IoStatus::completed;
}

FrameResult read_frame(
    int socket,
    std::chrono::milliseconds timeout) {
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    std::array<unsigned char, 4> header{};
    const auto header_status =
        read_exact(socket, header.data(), header.size(), deadline);
    if (header_status != IoStatus::completed) {
        return {.status = header_status, .payload = {}};
    }

    const std::uint32_t payload_size =
        (static_cast<std::uint32_t>(header[0]) << 24U) |
        (static_cast<std::uint32_t>(header[1]) << 16U) |
        (static_cast<std::uint32_t>(header[2]) << 8U) |
        static_cast<std::uint32_t>(header[3]);
    if (payload_size == 0U ||
        payload_size > ControllerProtocolSession::maximum_payload_size) {
        return {.status = IoStatus::invalid_size, .payload = {}};
    }

    std::string payload(payload_size, '\0');
    const auto payload_status = read_exact(
        socket,
        reinterpret_cast<unsigned char*>(payload.data()),
        payload.size(),
        deadline);
    return {
        .status = payload_status,
        .payload = payload_status == IoStatus::completed ? std::move(payload)
                                                        : std::string{}};
}

IoStatus write_exact(
    int socket,
    const unsigned char* source,
    std::size_t size,
    std::chrono::steady_clock::time_point deadline) noexcept {
    std::size_t offset = 0;
    while (offset < size) {
        const auto waited = wait_for(socket, POLLOUT, deadline);
        if (waited != IoStatus::completed) {
            return waited;
        }
#if defined(MSG_NOSIGNAL)
        constexpr int send_flags = MSG_NOSIGNAL;
#else
        constexpr int send_flags = 0;
#endif
        const auto sent =
            ::send(socket, source + offset, size - offset, send_flags);
        if (sent > 0) {
            offset += static_cast<std::size_t>(sent);
            continue;
        }
        if (sent < 0 &&
            (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)) {
            continue;
        }
        return IoStatus::failed;
    }
    return IoStatus::completed;
}

IoStatus write_frame(
    int socket,
    std::string_view payload,
    std::chrono::milliseconds timeout) noexcept {
    if (payload.empty() ||
        payload.size() > ControllerProtocolSession::maximum_payload_size) {
        return IoStatus::invalid_size;
    }
    const auto payload_size = static_cast<std::uint32_t>(payload.size());
    const std::array<unsigned char, 4> header{
        static_cast<unsigned char>((payload_size >> 24U) & 0xffU),
        static_cast<unsigned char>((payload_size >> 16U) & 0xffU),
        static_cast<unsigned char>((payload_size >> 8U) & 0xffU),
        static_cast<unsigned char>(payload_size & 0xffU)};
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    const auto header_status =
        write_exact(socket, header.data(), header.size(), deadline);
    if (header_status != IoStatus::completed) {
        return header_status;
    }
    return write_exact(
        socket,
        reinterpret_cast<const unsigned char*>(payload.data()),
        payload.size(),
        deadline);
}

logging::Event protocol_event(
    std::string timestamp,
    logging::Severity severity,
    std::string event_id,
    std::string operation_id,
    std::string outcome,
    std::string message,
    const std::optional<PeerCredentialResult>& credentials = std::nullopt) {
    logging::Event event{
        .timestamp = std::move(timestamp),
        .severity = severity,
        .event_id = std::move(event_id),
        .component = "controller-local-protocol",
        .operation_id = std::move(operation_id),
        .action = "controller.protocol",
        .outcome = std::move(outcome),
        .message = std::move(message),
        .attributes = {}};
    if (credentials.has_value() && credentials->ok()) {
        event.attributes.emplace(
            "peer_uid", std::to_string(credentials->user_id));
        event.attributes.emplace(
            "peer_gid", std::to_string(credentials->group_id));
    }
    return event;
}

std::string activation_status(firewall::ActivationStatus status) {
    using Status = firewall::ActivationStatus;
    switch (status) {
        case Status::committed:
            return "committed";
        case Status::invalid_request:
            return "invalid_request";
        case Status::authorization_denied:
            return "authorization_denied";
        case Status::authorization_error:
            return "authorization_error";
        case Status::last_known_good_unavailable:
            return "last_known_good_unavailable";
        case Status::target_unavailable:
            return "target_unavailable";
        case Status::native_revalidation_failed:
            return "native_revalidation_failed";
        case Status::activation_failed:
            return "activation_failed";
        case Status::verification_failed_rolled_back:
            return "verification_failed_rolled_back";
        case Status::confirmation_failed_rolled_back:
            return "confirmation_failed_rolled_back";
        case Status::commit_failed_rolled_back:
            return "commit_failed_rolled_back";
        case Status::transaction_conflict:
            return "transaction_conflict";
        case Status::transaction_store_failed:
            return "transaction_store_failed";
        case Status::committed_with_warning:
            return "committed_with_warning";
        case Status::committed_cleanup_pending:
            return "committed_cleanup_pending";
        case Status::audit_failed:
            return "audit_failed";
        case Status::audit_failed_rolled_back:
            return "audit_failed_rolled_back";
        case Status::rollback_failed:
            return "rollback_failed";
    }
    return "unknown";
}

std::string response_payload(
    std::string_view request_id,
    std::string_view result,
    ControllerState state,
    std::string_view event_id,
    std::string_view message,
    std::optional<std::string_view> activation = std::nullopt) {
    std::string response;
    response.reserve(512U);
    response += "gatehold-controller-v1\nrequest_id=";
    response += request_id;
    response += "\nresult=";
    response += result;
    response += "\ncontroller_state=";
    response += to_string(state);
    response += "\nevent_id=";
    response += event_id;
    response += "\nmessage=";
    response += message;
    response += '\n';
    if (activation.has_value()) {
        response += "activation_status=";
        response += *activation;
        response += '\n';
    }
    return response;
}

ProtocolSessionResult session_result(
    ProtocolSessionStatus status,
    std::string event_id,
    std::string message,
    const std::optional<PeerCredentialResult>& credentials) {
    ProtocolSessionResult result{
        .status = status,
        .event_id = std::move(event_id),
        .message = std::move(message),
        .peer_user_id = std::nullopt,
        .peer_group_id = std::nullopt};
    if (credentials.has_value() && credentials->ok()) {
        result.peer_user_id = credentials->user_id;
        result.peer_group_id = credentials->group_id;
    }
    return result;
}

}  // namespace

bool PeerCredentialResult::ok() const noexcept {
    return status == PeerCredentialStatus::available;
}

PeerCredentialResult PeerCredentialReader::read(int connected_socket) const {
#if defined(__OpenBSD__)
    uid_t user_id = 0;
    gid_t group_id = 0;
    if (::getpeereid(connected_socket, &user_id, &group_id) == 0) {
        return {
            .status = PeerCredentialStatus::available,
            .user_id = user_id,
            .group_id = group_id,
            .event_id = "GH-IPC-0001",
            .message = "Unix peer credentials were verified."};
    }
#elif defined(__linux__)
    struct ucred credentials {};
    socklen_t length = static_cast<socklen_t>(sizeof(credentials));
    if (::getsockopt(
            connected_socket,
            SOL_SOCKET,
            SO_PEERCRED,
            &credentials,
            &length) == 0 &&
        length == sizeof(credentials)) {
        return {
            .status = PeerCredentialStatus::available,
            .user_id = credentials.uid,
            .group_id = credentials.gid,
            .event_id = "GH-IPC-0001",
            .message = "Unix peer credentials were verified."};
    }
#else
    static_cast<void>(connected_socket);
#endif
    return {
        .status = PeerCredentialStatus::unavailable,
        .user_id = 0,
        .group_id = 0,
        .event_id = "GH-IPC-2001",
        .message = "Unix peer credentials could not be verified."};
}

PeerCredentialPolicy::PeerCredentialPolicy(
    uid_t allowed_user_id,
    std::optional<gid_t> allowed_group_id)
    : allowed_user_id_{allowed_user_id},
      allowed_group_id_{allowed_group_id} {}

bool PeerCredentialPolicy::allows(
    const PeerCredentialResult& credentials) const noexcept {
    return credentials.ok() && credentials.user_id == allowed_user_id_ &&
           (!allowed_group_id_.has_value() ||
            credentials.group_id == *allowed_group_id_);
}

bool ProtocolSessionResult::ok() const noexcept {
    return status == ProtocolSessionStatus::completed;
}

ControllerProtocolSession::ControllerProtocolSession(
    PrivilegedPfController& controller,
    const logging::OperationJournal& journal,
    PeerCredentialPolicy peer_policy,
    TimestampSource timestamp_source)
    : controller_{controller},
      journal_{journal},
      peer_policy_{std::move(peer_policy)},
      timestamp_source_{std::move(timestamp_source)} {
    if (!timestamp_source_) {
        timestamp_source_ = system_utc_timestamp;
    }
}

ProtocolSessionResult ControllerProtocolSession::serve(
    int connected_socket,
    std::chrono::milliseconds io_timeout) const {
    const auto append = [this](logging::Event event) {
        return journal_.append(event).ok();
    };
    const auto write_response = [connected_socket, io_timeout](
                                    const std::string& response) {
        return write_frame(connected_socket, response, io_timeout) ==
               IoStatus::completed;
    };
    const auto io_failure = [](const std::optional<PeerCredentialResult>& peer) {
        return session_result(
            ProtocolSessionStatus::io_error,
            "GH-IPC-2003",
            "Controller protocol response could not be transferred.",
            peer);
    };

    if (connected_socket < 0 ||
        io_timeout <= std::chrono::milliseconds::zero() ||
        io_timeout > maximum_io_timeout ||
        !configure_socket(connected_socket)) {
        return session_result(
            ProtocolSessionStatus::io_error,
            "GH-IPC-2003",
            "Controller protocol socket or timeout is invalid.",
            std::nullopt);
    }

    const auto credentials = credential_reader_.read(connected_socket);
    const std::optional<PeerCredentialResult> peer{credentials};
    if (!credentials.ok()) {
        static_cast<void>(append(protocol_event(
            timestamp_source_(),
            logging::Severity::error,
            credentials.event_id,
            "controller-protocol",
            "failed",
            credentials.message)));
        const auto response = response_payload(
            "protocol-request",
            "rejected",
            controller_.state(),
            credentials.event_id,
            "Peer credentials could not be verified.");
        if (!write_response(response)) {
            return io_failure(peer);
        }
        return session_result(
            ProtocolSessionStatus::peer_rejected,
            credentials.event_id,
            credentials.message,
            peer);
    }

    if (!peer_policy_.allows(credentials)) {
        static_cast<void>(append(protocol_event(
            timestamp_source_(),
            logging::Severity::warning,
            "GH-IPC-1001",
            "controller-protocol",
            "rejected",
            "Unix peer is not allowed to use the controller protocol.",
            peer)));
        const auto response = response_payload(
            "protocol-request",
            "rejected",
            controller_.state(),
            "GH-IPC-1001",
            "Peer is not authorized for the controller protocol.");
        if (!write_response(response)) {
            return io_failure(peer);
        }
        return session_result(
            ProtocolSessionStatus::peer_rejected,
            "GH-IPC-1001",
            "Unix peer is not allowed to use the controller protocol.",
            peer);
    }

    if (!append(protocol_event(
            timestamp_source_(),
            logging::Severity::info,
            "GH-IPC-0001",
            "controller-protocol",
            "authenticated",
            "Unix peer credentials were accepted.",
            peer))) {
        const auto response = response_payload(
            "protocol-request",
            "error",
            controller_.state(),
            "GH-IPC-2004",
            "Controller protocol audit is unavailable.");
        if (!write_response(response)) {
            return io_failure(peer);
        }
        return session_result(
            ProtocolSessionStatus::audit_failed,
            "GH-IPC-2004",
            "Peer authentication could not be audited.",
            peer);
    }

    const auto frame = read_frame(connected_socket, io_timeout);
    if (frame.status != IoStatus::completed) {
        const bool timed_out = frame.status == IoStatus::timed_out;
        const bool invalid_frame =
            frame.status == IoStatus::invalid_size ||
            frame.status == IoStatus::closed;
        const std::string event_id =
            timed_out ? "GH-IPC-2002"
                      : invalid_frame ? "GH-IPC-1002" : "GH-IPC-2003";
        const auto protocol_status =
            timed_out ? ProtocolSessionStatus::timed_out
                      : invalid_frame ? ProtocolSessionStatus::invalid_request
                                      : ProtocolSessionStatus::io_error;
        static_cast<void>(append(protocol_event(
            timestamp_source_(),
            timed_out ? logging::Severity::warning : logging::Severity::error,
            event_id,
            "controller-protocol",
            timed_out ? "timed_out" : "rejected",
            timed_out ? "Controller protocol request timed out."
                      : "Controller protocol frame could not be read.",
            peer)));
        const auto response = response_payload(
            "protocol-request",
            "rejected",
            controller_.state(),
            event_id,
            timed_out ? "Controller protocol request timed out."
                      : "Controller protocol frame is invalid.");
        if (!write_response(response)) {
            return io_failure(peer);
        }
        return session_result(
            protocol_status,
            event_id,
            timed_out ? "Controller protocol request timed out."
                      : "Controller protocol frame is invalid.",
            peer);
    }

    const auto parsed = parse_request(frame.payload);
    if (!parsed.valid || !parsed.request.has_value()) {
        static_cast<void>(append(protocol_event(
            timestamp_source_(),
            logging::Severity::warning,
            parsed.event_id,
            "controller-protocol",
            "rejected",
            parsed.message,
            peer)));
        const auto response = response_payload(
            "protocol-request",
            "rejected",
            controller_.state(),
            parsed.event_id,
            parsed.message);
        if (!write_response(response)) {
            return io_failure(peer);
        }
        return session_result(
            ProtocolSessionStatus::invalid_request,
            parsed.event_id,
            parsed.message,
            peer);
    }

    const ParsedRequest& request = *parsed.request;
    auto intent = protocol_event(
        timestamp_source_(),
        logging::Severity::info,
        request.operation == RequestOperation::status ? "GH-IPC-0002"
                                                      : "GH-IPC-0003",
        request.request_id,
        "dispatching",
        request.operation == RequestOperation::status
            ? "Controller status request is being dispatched."
            : "Controller activation request is being dispatched.",
        peer);
    intent.attributes.emplace(
        "operation",
        request.operation == RequestOperation::status ? "status" : "activate");
    if (request.activation.has_value()) {
        intent.attributes.emplace(
            "revision", std::to_string(request.activation->revision));
    }
    if (!append(std::move(intent))) {
        const auto response = response_payload(
            request.request_id,
            "error",
            controller_.state(),
            "GH-IPC-2004",
            "Controller request dispatch could not be audited.");
        if (!write_response(response)) {
            return io_failure(peer);
        }
        return session_result(
            ProtocolSessionStatus::audit_failed,
            "GH-IPC-2004",
            "Controller request dispatch could not be audited.",
            peer);
    }

    if (request.operation == RequestOperation::status) {
        const auto response = response_payload(
            request.request_id,
            "completed",
            controller_.state(),
            "GH-IPC-0002",
            "Controller status returned.");
        if (!write_response(response)) {
            static_cast<void>(append(protocol_event(
                timestamp_source_(),
                logging::Severity::error,
                "GH-IPC-2003",
                request.request_id,
                "failed",
                "Controller status response could not be transferred.",
                peer)));
            return io_failure(peer);
        }
        return session_result(
            ProtocolSessionStatus::completed,
            "GH-IPC-0002",
            "Controller status request completed.",
            peer);
    }

    const auto activation = controller_.activate(*request.activation);
    const std::string operation_status =
        activation.activation.has_value()
            ? activation_status(activation.activation->status)
            : "not_dispatched";
    const auto response = response_payload(
        request.request_id,
        activation.status == ControllerDispatchStatus::completed ? "completed"
                                                                 : "rejected",
        activation.state,
        activation.event_id,
        activation.status == ControllerDispatchStatus::completed
            ? "Activation request completed."
            : "Activation request was not dispatched.",
        operation_status);
    if (!write_response(response)) {
        static_cast<void>(append(protocol_event(
            timestamp_source_(),
            logging::Severity::error,
            "GH-IPC-2003",
            request.request_id,
            "failed",
            "Controller activation response could not be transferred.",
            peer)));
        return io_failure(peer);
    }
    return session_result(
        ProtocolSessionStatus::completed,
        activation.event_id,
        "Controller activation request completed.",
        peer);
}

}  // namespace sasd::gatehold::controller
