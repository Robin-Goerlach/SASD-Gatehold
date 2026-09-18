#include "gatehold/controller/privileged_pf_controller.hpp"

#include "gatehold/logging/event.hpp"

#include <chrono>
#include <ctime>
#include <iomanip>
#include <sstream>
#include <utility>

namespace sasd::gatehold::controller {
namespace {

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

logging::Event controller_event(
    std::string timestamp,
    logging::Severity severity,
    std::string event_id,
    std::string operation_id,
    std::string action,
    std::string outcome,
    std::string message,
    ControllerState state) {
    return {
        .timestamp = std::move(timestamp),
        .severity = severity,
        .event_id = std::move(event_id),
        .component = "privileged-pf-controller",
        .operation_id = std::move(operation_id),
        .action = std::move(action),
        .outcome = std::move(outcome),
        .message = std::move(message),
        .attributes = {{"controller_state", to_string(state)}}};
}

bool requires_read_only(firewall::ActivationStatus status) noexcept {
    switch (status) {
        case firewall::ActivationStatus::transaction_conflict:
        case firewall::ActivationStatus::transaction_store_failed:
        case firewall::ActivationStatus::committed_with_warning:
        case firewall::ActivationStatus::committed_cleanup_pending:
        case firewall::ActivationStatus::audit_failed:
        case firewall::ActivationStatus::audit_failed_rolled_back:
            return true;
        case firewall::ActivationStatus::committed:
        case firewall::ActivationStatus::invalid_request:
        case firewall::ActivationStatus::authorization_denied:
        case firewall::ActivationStatus::authorization_error:
        case firewall::ActivationStatus::last_known_good_unavailable:
        case firewall::ActivationStatus::target_unavailable:
        case firewall::ActivationStatus::native_revalidation_failed:
        case firewall::ActivationStatus::activation_failed:
        case firewall::ActivationStatus::verification_failed_rolled_back:
        case firewall::ActivationStatus::confirmation_failed_rolled_back:
        case firewall::ActivationStatus::commit_failed_rolled_back:
        case firewall::ActivationStatus::rollback_failed:
            return false;
    }
    return true;
}

ControllerStartupStatus startup_status(ControllerState state) noexcept {
    switch (state) {
        case ControllerState::ready:
            return ControllerStartupStatus::ready;
        case ControllerState::read_only:
            return ControllerStartupStatus::read_only;
        case ControllerState::created:
        case ControllerState::starting:
        case ControllerState::blocked:
            return ControllerStartupStatus::blocked;
    }
    return ControllerStartupStatus::blocked;
}

}  // namespace

std::string to_string(ControllerState state) {
    switch (state) {
        case ControllerState::created:
            return "created";
        case ControllerState::starting:
            return "starting";
        case ControllerState::ready:
            return "ready";
        case ControllerState::read_only:
            return "read_only";
        case ControllerState::blocked:
            return "blocked";
    }
    return "blocked";
}

bool ControllerStartupResult::accepts_activations() const noexcept {
    return status == ControllerStartupStatus::ready &&
           state == ControllerState::ready;
}

bool ControllerActivationResult::ok() const noexcept {
    return status == ControllerDispatchStatus::completed &&
           activation.has_value() && activation->ok();
}

PrivilegedPfController::PrivilegedPfController(
    const firewall::PfActivationService& activation_service,
    const logging::OperationJournal& journal,
    TimestampSource timestamp_source)
    : activation_service_{activation_service},
      journal_{journal},
      timestamp_source_{std::move(timestamp_source)} {
    if (!timestamp_source_) {
        timestamp_source_ = system_utc_timestamp;
    }
}

ControllerStartupResult PrivilegedPfController::start() {
    const std::scoped_lock lifecycle_lock{lifecycle_mutex_};

    if (state_ != ControllerState::created) {
        return {
            .status = startup_status(state_),
            .state = state_,
            .event_id = "GH-CTL-1002",
            .message = "Controller startup has already completed or is blocked.",
            .recovery = std::nullopt};
    }

    state_ = ControllerState::starting;
    const bool startup_audited = journal_
                                     .append(controller_event(
                                         timestamp_source_(),
                                         logging::Severity::info,
                                         "GH-CTL-0001",
                                         "controller-startup",
                                         "controller.start",
                                         "started",
                                         "Controller startup recovery began.",
                                         state_))
                                     .ok();

    auto recovery = activation_service_.recover_pending();
    if (!recovery.ok()) {
        state_ = ControllerState::blocked;
        static_cast<void>(journal_.append(controller_event(
            timestamp_source_(),
            logging::Severity::critical,
            "GH-CTL-2001",
            "controller-startup",
            "controller.start",
            "blocked",
            "Controller blocked because pending activation recovery failed.",
            state_)));
        return {
            .status = ControllerStartupStatus::blocked,
            .state = state_,
            .event_id = "GH-CTL-2001",
            .message =
                "Controller blocked because pending activation recovery failed.",
            .recovery = std::move(recovery)};
    }

    if (!startup_audited ||
        recovery.status ==
            firewall::ActivationRecoveryStatus::audit_failed_recovered) {
        state_ = ControllerState::read_only;
        static_cast<void>(journal_.append(controller_event(
            timestamp_source_(),
            logging::Severity::error,
            "GH-CTL-2002",
            "controller-startup",
            "controller.start",
            "read_only",
            "Recovery completed, but audit durability is unavailable.",
            state_)));
        return {
            .status = ControllerStartupStatus::read_only,
            .state = state_,
            .event_id = "GH-CTL-2002",
            .message =
                "Recovery completed, but audit durability is unavailable.",
            .recovery = std::move(recovery)};
    }

    state_ = ControllerState::ready;
    const auto ready_audit = journal_.append(controller_event(
        timestamp_source_(),
        logging::Severity::info,
        "GH-CTL-0002",
        "controller-startup",
        "controller.start",
        "ready",
        "Controller recovery completed and activation dispatch is enabled.",
        state_));
    if (!ready_audit.ok()) {
        state_ = ControllerState::read_only;
        return {
            .status = ControllerStartupStatus::read_only,
            .state = state_,
            .event_id = "GH-CTL-2002",
            .message =
                "Recovery completed, but readiness could not be audited durably.",
            .recovery = std::move(recovery)};
    }

    return {
        .status = ControllerStartupStatus::ready,
        .state = state_,
        .event_id = "GH-CTL-0002",
        .message = "Controller is ready to dispatch activation requests.",
        .recovery = std::move(recovery)};
}

ControllerActivationResult PrivilegedPfController::activate(
    const firewall::ActivationRequest& request) {
    const std::scoped_lock lifecycle_lock{lifecycle_mutex_};

    if (state_ != ControllerState::ready) {
        static_cast<void>(journal_.append(controller_event(
            timestamp_source_(),
            logging::Severity::warning,
            "GH-CTL-1001",
            "controller-dispatch",
            "controller.activate",
            "rejected",
            "Activation dispatch rejected because the controller is not ready.",
            state_)));
        return {
            .status = ControllerDispatchStatus::controller_not_ready,
            .state = state_,
            .event_id = "GH-CTL-1001",
            .message =
                "Activation dispatch rejected because the controller is not ready.",
            .activation = std::nullopt};
    }

    auto activation = activation_service_.activate(request);
    std::string event_id = activation.event_id;
    std::string message = activation.message;

    if (activation.status == firewall::ActivationStatus::rollback_failed) {
        state_ = ControllerState::blocked;
        event_id = "GH-CTL-2003";
        message =
            "Controller blocked after a critical activation rollback failure.";
        static_cast<void>(journal_.append(controller_event(
            timestamp_source_(),
            logging::Severity::critical,
            event_id,
            request.operation_id,
            "controller.activate",
            "blocked",
            message,
            state_)));
    } else if (requires_read_only(activation.status)) {
        state_ = ControllerState::read_only;
        event_id = "GH-CTL-2004";
        message =
            "Controller entered read-only mode after activation safety state degraded.";
        static_cast<void>(journal_.append(controller_event(
            timestamp_source_(),
            logging::Severity::error,
            event_id,
            request.operation_id,
            "controller.activate",
            "read_only",
            message,
            state_)));
    }

    return {
        .status = ControllerDispatchStatus::completed,
        .state = state_,
        .event_id = std::move(event_id),
        .message = std::move(message),
        .activation = std::move(activation)};
}

ControllerState PrivilegedPfController::state() const {
    const std::scoped_lock lifecycle_lock{lifecycle_mutex_};
    return state_;
}

}  // namespace sasd::gatehold::controller
