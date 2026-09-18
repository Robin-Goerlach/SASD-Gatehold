#include "gatehold/firewall/health_probes.hpp"

#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cerrno>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <optional>
#include <string>
#include <utility>

namespace sasd::gatehold::firewall {
namespace {

class SocketDescriptor final {
public:
    explicit SocketDescriptor(int descriptor) noexcept
        : descriptor_{descriptor} {}

    ~SocketDescriptor() {
        if (descriptor_ >= 0) {
            ::close(descriptor_);
        }
    }

    SocketDescriptor(const SocketDescriptor&) = delete;
    SocketDescriptor& operator=(const SocketDescriptor&) = delete;

    [[nodiscard]] int get() const noexcept {
        return descriptor_;
    }

private:
    int descriptor_{-1};
};

struct NumericEndpoint {
    sockaddr_storage address{};
    socklen_t length{0};
    int family{AF_UNSPEC};
};

bool valid_timeout(
    std::chrono::milliseconds timeout,
    std::chrono::milliseconds maximum) noexcept {
    return timeout > std::chrono::milliseconds::zero() && timeout <= maximum;
}

std::optional<NumericEndpoint> parse_numeric_endpoint(
    const std::string& address,
    std::uint16_t port) noexcept {
    if (port == 0) {
        return std::nullopt;
    }

    sockaddr_in ipv4{};
    if (::inet_pton(AF_INET, address.c_str(), &ipv4.sin_addr) == 1) {
        const std::uint32_t host_address = ntohl(ipv4.sin_addr.s_addr);
        const bool unspecified = host_address == INADDR_ANY;
        const bool broadcast = host_address == INADDR_BROADCAST;
        const bool multicast =
            (host_address & 0xf0000000U) == 0xe0000000U;
        if (unspecified || broadcast || multicast) {
            return std::nullopt;
        }

        ipv4.sin_family = AF_INET;
        ipv4.sin_port = htons(port);
        NumericEndpoint endpoint;
        std::memcpy(&endpoint.address, &ipv4, sizeof(ipv4));
        endpoint.length = static_cast<socklen_t>(sizeof(ipv4));
        endpoint.family = AF_INET;
        return endpoint;
    }

    sockaddr_in6 ipv6{};
    if (::inet_pton(AF_INET6, address.c_str(), &ipv6.sin6_addr) == 1) {
        if (IN6_IS_ADDR_UNSPECIFIED(&ipv6.sin6_addr) ||
            IN6_IS_ADDR_MULTICAST(&ipv6.sin6_addr) ||
            IN6_IS_ADDR_LINKLOCAL(&ipv6.sin6_addr) ||
            IN6_IS_ADDR_V4MAPPED(&ipv6.sin6_addr)) {
            return std::nullopt;
        }

        ipv6.sin6_family = AF_INET6;
        ipv6.sin6_port = htons(port);
        NumericEndpoint endpoint;
        std::memcpy(&endpoint.address, &ipv6, sizeof(ipv6));
        endpoint.length = static_cast<socklen_t>(sizeof(ipv6));
        endpoint.family = AF_INET6;
        return endpoint;
    }

    return std::nullopt;
}

bool set_nonblocking_close_on_exec(int descriptor) noexcept {
    const int status_flags = ::fcntl(descriptor, F_GETFL, 0);
    if (status_flags < 0 ||
        ::fcntl(descriptor, F_SETFL, status_flags | O_NONBLOCK) != 0) {
        return false;
    }

    const int descriptor_flags = ::fcntl(descriptor, F_GETFD, 0);
    return descriptor_flags >= 0 &&
           ::fcntl(descriptor, F_SETFD, descriptor_flags | FD_CLOEXEC) == 0;
}

HealthProbeResult connection_error(int error) {
    if (error == ETIMEDOUT) {
        return {
            .status = HealthProbeStatus::timed_out,
            .message = "TCP management connection timed out."};
    }
    return {
        .status = HealthProbeStatus::unhealthy,
        .message = "TCP management endpoint did not accept a connection."};
}

}  // namespace

PfctlInfoProbe::PfctlInfoProbe(std::filesystem::path executable)
    : executable_{std::move(executable)} {}

std::string PfctlInfoProbe::id() const {
    return "pf-control-plane";
}

HealthProbeResult PfctlInfoProbe::run(
    std::chrono::milliseconds timeout) const {
    if (!valid_timeout(timeout, maximum_timeout)) {
        return {
            .status = HealthProbeStatus::execution_error,
            .message = "PF information probe timeout is outside safe bounds."};
    }

    const auto process =
        process_runner_.run(executable_, {"-s", "info"}, timeout);
    if (!process.launched || process.exit_code == 126 ||
        process.exit_code == 127 || !process.error_message.empty()) {
        return {
            .status = HealthProbeStatus::execution_error,
            .message = "PF information probe could not execute pfctl safely."};
    }
    if (process.timed_out) {
        return {
            .status = HealthProbeStatus::timed_out,
            .message = "PF information probe exceeded its time limit."};
    }
    if (process.output_truncated) {
        return {
            .status = HealthProbeStatus::execution_error,
            .message = "PF information probe exceeded its output limit."};
    }
    if (process.exit_code != 0) {
        return {
            .status = HealthProbeStatus::unhealthy,
            .message = "PF information could not be retrieved after activation."};
    }

    return {
        .status = HealthProbeStatus::healthy,
        .message = "PF control plane responded after activation."};
}

TcpConnectProbe::TcpConnectProbe(
    std::string identifier,
    std::string numeric_address,
    std::uint16_t port)
    : identifier_{std::move(identifier)},
      numeric_address_{std::move(numeric_address)},
      port_{port} {}

std::string TcpConnectProbe::id() const {
    return identifier_;
}

HealthProbeResult TcpConnectProbe::run(
    std::chrono::milliseconds timeout) const {
    if (!valid_timeout(timeout, maximum_timeout)) {
        return {
            .status = HealthProbeStatus::execution_error,
            .message =
                "TCP management probe timeout is outside safe bounds."};
    }

    const auto endpoint = parse_numeric_endpoint(numeric_address_, port_);
    if (!endpoint.has_value()) {
        return {
            .status = HealthProbeStatus::execution_error,
            .message =
                "TCP management probe requires a safe numeric endpoint."};
    }

    SocketDescriptor socket{::socket(endpoint->family, SOCK_STREAM, 0)};
    if (socket.get() < 0 || !set_nonblocking_close_on_exec(socket.get())) {
        return {
            .status = HealthProbeStatus::execution_error,
            .message = "TCP management probe could not create a safe socket."};
    }

    const int connection = ::connect(
        socket.get(),
        reinterpret_cast<const sockaddr*>(&endpoint->address),
        endpoint->length);
    if (connection == 0 || (connection < 0 && errno == EISCONN)) {
        return {
            .status = HealthProbeStatus::healthy,
            .message = "TCP management endpoint accepted a connection."};
    }
    if (connection < 0 && errno != EINPROGRESS && errno != EINTR) {
        return connection_error(errno);
    }

    const auto deadline = std::chrono::steady_clock::now() + timeout;
    for (;;) {
        const auto now = std::chrono::steady_clock::now();
        if (now >= deadline) {
            return {
                .status = HealthProbeStatus::timed_out,
                .message = "TCP management connection timed out."};
        }
        auto remaining =
            std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now);
        if (remaining < deadline - now) {
            remaining += std::chrono::milliseconds{1};
        }

        struct pollfd descriptor {
            .fd = socket.get(), .events = POLLOUT, .revents = 0
        };
        const int polled =
            ::poll(&descriptor, 1, static_cast<int>(remaining.count()));
        if (polled == 0) {
            return {
                .status = HealthProbeStatus::timed_out,
                .message = "TCP management connection timed out."};
        }
        if (polled < 0) {
            if (errno == EINTR) {
                continue;
            }
            return {
                .status = HealthProbeStatus::execution_error,
                .message = "TCP management probe could not wait for connection."};
        }
        if ((descriptor.revents & POLLNVAL) != 0) {
            return {
                .status = HealthProbeStatus::execution_error,
                .message = "TCP management probe socket became invalid."};
        }

        int socket_error = 0;
        socklen_t error_length = sizeof(socket_error);
        if (::getsockopt(
                socket.get(),
                SOL_SOCKET,
                SO_ERROR,
                &socket_error,
                &error_length) != 0) {
            return {
                .status = HealthProbeStatus::execution_error,
                .message =
                    "TCP management probe could not inspect connection state."};
        }
        if (socket_error != 0) {
            return connection_error(socket_error);
        }
        return {
            .status = HealthProbeStatus::healthy,
            .message = "TCP management endpoint accepted a connection."};
    }
}

}  // namespace sasd::gatehold::firewall
