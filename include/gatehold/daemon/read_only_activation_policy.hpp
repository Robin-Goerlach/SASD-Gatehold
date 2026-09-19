#pragma once

#include "gatehold/firewall/activation_service.hpp"

#include <chrono>
#include <cstdint>
#include <string>

namespace sasd::gatehold::daemon {

class ReadOnlyActivationAuthorizer final
    : public firewall::ActivationAuthorizer {
public:
    [[nodiscard]] firewall::AuthorizationResult authorize(
        const std::string& operation_id,
        std::uint64_t revision,
        const std::string& authorization_reference) const override;
};

class UnavailableConfirmationGate final : public firewall::ConfirmationGate {
public:
    [[nodiscard]] firewall::ConfirmationResult await_confirmation(
        const std::string& operation_id,
        std::uint64_t revision,
        std::chrono::milliseconds timeout) const override;
};

class FailClosedActivationHealthProbe final : public firewall::HealthProbe {
public:
    [[nodiscard]] std::string id() const override;
    [[nodiscard]] firewall::HealthProbeResult run(
        std::chrono::milliseconds timeout) const override;
};

}  // namespace sasd::gatehold::daemon
