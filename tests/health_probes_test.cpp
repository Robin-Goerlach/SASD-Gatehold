#include "gatehold/firewall/health_probes.hpp"
#include "test_support.hpp"

#include <arpa/inet.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <array>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <string>
#include <thread>

namespace firewall = sasd::gatehold::firewall;

namespace {

class ListeningSocket final {
public:
    ListeningSocket() {
        descriptor_ = ::socket(AF_INET, SOCK_STREAM, 0);
        if (descriptor_ < 0) {
            return;
        }

        const int enabled = 1;
        static_cast<void>(::setsockopt(
            descriptor_, SOL_SOCKET, SO_REUSEADDR, &enabled, sizeof(enabled)));

        sockaddr_in address{};
        address.sin_family = AF_INET;
        address.sin_port = 0;
        address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        if (::bind(
                descriptor_,
                reinterpret_cast<const sockaddr*>(&address),
                sizeof(address)) != 0 ||
            ::listen(descriptor_, 8) != 0) {
            ::close(descriptor_);
            descriptor_ = -1;
            return;
        }

        socklen_t length = sizeof(address);
        if (::getsockname(
                descriptor_,
                reinterpret_cast<sockaddr*>(&address),
                &length) != 0) {
            ::close(descriptor_);
            descriptor_ = -1;
            return;
        }
        port_ = ntohs(address.sin_port);
    }

    ~ListeningSocket() {
        if (descriptor_ >= 0) {
            ::close(descriptor_);
        }
    }

    ListeningSocket(const ListeningSocket&) = delete;
    ListeningSocket& operator=(const ListeningSocket&) = delete;

    [[nodiscard]] bool valid() const noexcept {
        return descriptor_ >= 0 && port_ != 0;
    }

    [[nodiscard]] std::uint16_t port() const noexcept {
        return port_;
    }

    [[nodiscard]] int accept_connections(int expected) const {
        int accepted = 0;
        while (accepted < expected) {
            struct pollfd descriptor {
                .fd = descriptor_, .events = POLLIN, .revents = 0
            };
            if (::poll(&descriptor, 1, 2000) <= 0) {
                break;
            }
            const int connection = ::accept(descriptor_, nullptr, nullptr);
            if (connection < 0) {
                break;
            }
            ::close(connection);
            ++accepted;
        }
        return accepted;
    }

private:
    int descriptor_{-1};
    std::uint16_t port_{0};
};

std::uint16_t unused_loopback_port() {
    const int descriptor = ::socket(AF_INET, SOCK_STREAM, 0);
    if (descriptor < 0) {
        return 0;
    }
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_port = 0;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (::bind(
            descriptor,
            reinterpret_cast<const sockaddr*>(&address),
            sizeof(address)) != 0) {
        ::close(descriptor);
        return 0;
    }
    socklen_t length = sizeof(address);
    if (::getsockname(
            descriptor,
            reinterpret_cast<sockaddr*>(&address),
            &length) != 0) {
        ::close(descriptor);
        return 0;
    }
    const auto port = ntohs(address.sin_port);
    ::close(descriptor);
    return port;
}

}  // namespace

int main(int argc, char* argv[]) {
    gatehold::test::Context test;
    test.check(argc == 2, "test receives the fake pfctl executable path");
    if (argc != 2) {
        return test.result();
    }

    const auto fake_pfctl =
        std::filesystem::absolute(std::filesystem::path{argv[1]});
    const firewall::PfctlInfoProbe pf_probe{fake_pfctl};
    test.check(
        pf_probe.id() == "pf-control-plane",
        "PF information probe exposes a stable safe identifier");

    ::unsetenv("GATEHOLD_FAKE_PFCTL_INFO_MODE");
    test.check(
        pf_probe.run(std::chrono::milliseconds{1000}).status ==
            firewall::HealthProbeStatus::healthy,
        "successful pfctl information query is healthy");

    ::setenv("GATEHOLD_FAKE_PFCTL_INFO_MODE", "unhealthy", 1);
    test.check(
        pf_probe.run(std::chrono::milliseconds{1000}).status ==
            firewall::HealthProbeStatus::unhealthy,
        "non-zero pfctl information result is unhealthy");

    ::setenv("GATEHOLD_FAKE_PFCTL_INFO_MODE", "timeout", 1);
    test.check(
        pf_probe.run(std::chrono::milliseconds{50}).status ==
            firewall::HealthProbeStatus::timed_out,
        "hung pfctl information query is killed at its deadline");

    ::setenv("GATEHOLD_FAKE_PFCTL_INFO_MODE", "flood", 1);
    test.check(
        pf_probe.run(std::chrono::milliseconds{1000}).status ==
            firewall::HealthProbeStatus::execution_error,
        "excessive pfctl information output is rejected");
    ::unsetenv("GATEHOLD_FAKE_PFCTL_INFO_MODE");

    test.check(
        firewall::PfctlInfoProbe{"relative/pfctl"}
                .run(std::chrono::milliseconds{1000})
                .status == firewall::HealthProbeStatus::execution_error,
        "relative pfctl path cannot be executed");
    test.check(
        pf_probe.run(std::chrono::milliseconds{0}).status ==
                firewall::HealthProbeStatus::execution_error &&
            pf_probe.run(std::chrono::milliseconds{60001}).status ==
                firewall::HealthProbeStatus::execution_error,
        "PF probe rejects non-positive and excessive deadlines");

    ListeningSocket listener;
    test.check(listener.valid(), "loopback management listener is available");
    std::atomic<int> accepted{0};
    std::thread accepting{[&] {
        accepted.store(listener.accept_connections(1));
    }};
    const firewall::TcpConnectProbe management_probe{
        "management-api", "127.0.0.1", listener.port()};
    const auto connected = management_probe.run(std::chrono::milliseconds{1000});
    accepting.join();
    test.check(
        connected.status == firewall::HealthProbeStatus::healthy &&
            accepted.load() == 1,
        "TCP probe verifies a reachable numeric management endpoint");
    test.check(
        connected.message.find("127.0.0.1") == std::string::npos,
        "TCP result message does not disclose the configured address");

    const auto unused_port = unused_loopback_port();
    test.check(unused_port != 0, "unused loopback port is available");
    const firewall::TcpConnectProbe refused_probe{
        "closed-management-api", "127.0.0.1", unused_port};
    test.check(
        refused_probe.run(std::chrono::milliseconds{1000}).status ==
            firewall::HealthProbeStatus::unhealthy,
        "refused management connection is unhealthy");

    test.check(
        firewall::TcpConnectProbe{"dns-name", "localhost", 443}
                .run(std::chrono::milliseconds{1000})
                .status == firewall::HealthProbeStatus::execution_error,
        "TCP probe refuses DNS names");
    test.check(
        firewall::TcpConnectProbe{"wildcard", "0.0.0.0", 443}
                    .run(std::chrono::milliseconds{1000})
                    .status == firewall::HealthProbeStatus::execution_error &&
            firewall::TcpConnectProbe{"multicast", "224.0.0.1", 443}
                    .run(std::chrono::milliseconds{1000})
                    .status == firewall::HealthProbeStatus::execution_error &&
            firewall::TcpConnectProbe{"mapped", "::ffff:127.0.0.1", 443}
                    .run(std::chrono::milliseconds{1000})
                    .status == firewall::HealthProbeStatus::execution_error &&
            firewall::TcpConnectProbe{"zero-port", "127.0.0.1", 0}
                    .run(std::chrono::milliseconds{1000})
                    .status == firewall::HealthProbeStatus::execution_error,
        "TCP probe refuses wildcard, multicast, mapped, and zero-port endpoints");
    test.check(
        management_probe.run(std::chrono::milliseconds{0}).status ==
                firewall::HealthProbeStatus::execution_error &&
            management_probe.run(std::chrono::milliseconds{60001}).status ==
                firewall::HealthProbeStatus::execution_error,
        "TCP probe rejects non-positive and excessive deadlines");

    ListeningSocket concurrent_listener;
    test.check(
        concurrent_listener.valid(),
        "concurrent management listener is available");
    const firewall::TcpConnectProbe concurrent_probe{
        "concurrent-management-api", "127.0.0.1", concurrent_listener.port()};
    std::atomic<int> concurrently_accepted{0};
    std::thread concurrent_acceptor{[&] {
        concurrently_accepted.store(concurrent_listener.accept_connections(4));
    }};
    std::array<firewall::HealthProbeResult, 4> results;
    std::array<std::thread, 4> workers{
        std::thread{[&] {
            results[0] = concurrent_probe.run(std::chrono::milliseconds{1000});
        }},
        std::thread{[&] {
            results[1] = concurrent_probe.run(std::chrono::milliseconds{1000});
        }},
        std::thread{[&] {
            results[2] = concurrent_probe.run(std::chrono::milliseconds{1000});
        }},
        std::thread{[&] {
            results[3] = concurrent_probe.run(std::chrono::milliseconds{1000});
        }}};
    for (auto& worker : workers) {
        worker.join();
    }
    concurrent_acceptor.join();
    bool all_healthy = concurrently_accepted.load() == 4;
    for (const auto& result : results) {
        all_healthy = all_healthy && result.ok();
    }
    test.check(
        all_healthy,
        "immutable TCP probe safely supports concurrent checks");

    return test.result();
}
