#pragma once

#include "gatehold/firewall/activation_service.hpp"
#include "gatehold/system/posix_process_runner.hpp"

#include <chrono>
#include <cstdint>
#include <filesystem>
#include <string>

namespace sasd::gatehold::firewall {

class PfctlInfoProbe final : public HealthProbe {
public:
    static constexpr std::chrono::milliseconds maximum_timeout{60000};

    explicit PfctlInfoProbe(
        std::filesystem::path executable = "/sbin/pfctl");

    [[nodiscard]] std::string id() const override;
    [[nodiscard]] HealthProbeResult run(
        std::chrono::milliseconds timeout) const override;

private:
    std::filesystem::path executable_;
    system::PosixProcessRunner process_runner_;
};

class TcpConnectProbe final : public HealthProbe {
public:
    static constexpr std::chrono::milliseconds maximum_timeout{60000};

    TcpConnectProbe(
        std::string identifier,
        std::string numeric_address,
        std::uint16_t port);

    [[nodiscard]] std::string id() const override;
    [[nodiscard]] HealthProbeResult run(
        std::chrono::milliseconds timeout) const override;

private:
    std::string identifier_;
    std::string numeric_address_;
    std::uint16_t port_{0};
};

}  // namespace sasd::gatehold::firewall
