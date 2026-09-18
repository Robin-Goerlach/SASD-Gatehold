#pragma once

#include "gatehold/firewall/activation_service.hpp"
#include "gatehold/logging/operation_journal.hpp"

#include <functional>
#include <mutex>
#include <optional>
#include <string>

namespace sasd::gatehold::controller {

enum class ControllerState { created, starting, ready, read_only, blocked };

[[nodiscard]] std::string to_string(ControllerState state);

enum class ControllerStartupStatus { ready, read_only, blocked };

struct ControllerStartupResult {
    ControllerStartupStatus status{ControllerStartupStatus::blocked};
    ControllerState state{ControllerState::blocked};
    std::string event_id;
    std::string message;
    std::optional<firewall::ActivationRecoveryResult> recovery;

    [[nodiscard]] bool accepts_activations() const noexcept;
};

enum class ControllerDispatchStatus { completed, controller_not_ready };

struct ControllerActivationResult {
    ControllerDispatchStatus status{
        ControllerDispatchStatus::controller_not_ready};
    ControllerState state{ControllerState::created};
    std::string event_id;
    std::string message;
    std::optional<firewall::ActivationResult> activation;

    [[nodiscard]] bool ok() const noexcept;
};

class PrivilegedPfController {
public:
    using TimestampSource = std::function<std::string()>;

    PrivilegedPfController(
        const firewall::PfActivationService& activation_service,
        const logging::OperationJournal& journal,
        TimestampSource timestamp_source = {});

    [[nodiscard]] ControllerStartupResult start();
    [[nodiscard]] ControllerActivationResult activate(
        const firewall::ActivationRequest& request);
    [[nodiscard]] ControllerState state() const;

private:
    const firewall::PfActivationService& activation_service_;
    const logging::OperationJournal& journal_;
    TimestampSource timestamp_source_;
    mutable std::mutex lifecycle_mutex_;
    ControllerState state_{ControllerState::created};
};

}  // namespace sasd::gatehold::controller
