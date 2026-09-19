#include "gatehold/controller/controller_service.hpp"

#include "gatehold/logging/event.hpp"

#include <chrono>
#include <ctime>
#include <iomanip>
#include <limits>
#include <sstream>
#include <string>
#include <utility>

namespace sasd::gatehold::controller {
namespace {

class RunningClaim final {
public:
    explicit RunningClaim(std::atomic_flag& flag) noexcept
        : flag_{flag}, acquired_{!flag_.test_and_set()} {}

    ~RunningClaim() {
        if (acquired_) {
            flag_.clear();
        }
    }

    RunningClaim(const RunningClaim&) = delete;
    RunningClaim& operator=(const RunningClaim&) = delete;

    [[nodiscard]] bool acquired() const noexcept {
        return acquired_;
    }

private:
    std::atomic_flag& flag_;
    bool acquired_{false};
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

logging::Event service_event(
    std::string timestamp,
    logging::Severity severity,
    std::string event_id,
    std::string outcome,
    std::string message,
    ControllerState state) {
    return {
        .timestamp = std::move(timestamp),
        .severity = severity,
        .event_id = std::move(event_id),
        .component = "controller-service",
        .operation_id = "controller-service",
        .action = "controller.service",
        .outcome = std::move(outcome),
        .message = std::move(message),
        .attributes = {{"controller_state", to_string(state)}}};
}

ControllerServiceResult service_result(
    ControllerServiceStatus status,
    std::string event_id,
    std::string message,
    ControllerState state) {
    return {
        .status = status,
        .event_id = std::move(event_id),
        .message = std::move(message),
        .controller_state = state,
        .sessions_handled = 0,
        .protocol_failures = 0,
        .accept_timeouts = 0,
        .rate_limited_connections = 0,
        .listener_errors = 0,
        .controller_startup = std::nullopt,
        .listener_startup = std::nullopt,
        .listener_shutdown = std::nullopt};
}

bool valid_config(const ControllerServiceConfig& config) noexcept {
    return config.accept_poll_interval >=
               ControllerService::minimum_accept_poll_interval &&
           config.accept_poll_interval <=
               ControllerService::maximum_accept_poll_interval &&
           config.session_io_timeout > std::chrono::milliseconds::zero() &&
           config.session_io_timeout <=
               ControllerProtocolSession::maximum_io_timeout &&
           config.maximum_consecutive_listener_errors > 0U &&
           config.maximum_consecutive_listener_errors <=
               ControllerService::maximum_listener_error_limit;
}

void increment_saturated(std::size_t& value) noexcept {
    if (value < std::numeric_limits<std::size_t>::max()) {
        ++value;
    }
}

}  // namespace

bool ControllerServiceResult::ok() const noexcept {
    return status == ControllerServiceStatus::stopped;
}

ControllerService::ControllerService(
    PrivilegedPfController& controller,
    ControllerConnectionAcceptor& listener,
    const logging::OperationJournal& journal,
    ControllerServiceConfig config,
    TimestampSource timestamp_source)
    : controller_{controller},
      listener_{listener},
      journal_{journal},
      config_{config},
      timestamp_source_{std::move(timestamp_source)} {
    if (!timestamp_source_) {
        timestamp_source_ = system_utc_timestamp;
    }
}

ControllerServiceResult ControllerService::run(std::stop_token stop_token) {
    RunningClaim claim{running_};
    if (!claim.acquired()) {
        return service_result(
            ControllerServiceStatus::already_running,
            "GH-SVC-1002",
            "Controller service already has an active run loop.",
            controller_.state());
    }

    const bool configuration_valid = valid_config(config_);
    const bool startup_audited = journal_
                                     .append(service_event(
                                         timestamp_source_(),
                                         logging::Severity::info,
                                         "GH-SVC-0001",
                                         "starting",
                                         "Controller service recovery and startup began.",
                                         controller_.state()))
                                     .ok();

    if (!configuration_valid) {
        static_cast<void>(journal_.append(service_event(
            timestamp_source_(),
            logging::Severity::warning,
            "GH-SVC-1001",
            "rejected",
            "Controller service configuration is outside safe bounds.",
            controller_.state())));
    }

    auto startup = controller_.start();
    auto output = service_result(
        ControllerServiceStatus::stopped,
        "GH-SVC-0003",
        "Controller service stopped cleanly.",
        startup.state);
    output.controller_startup = startup;

    if (!configuration_valid) {
        output.status = ControllerServiceStatus::invalid_configuration;
        output.event_id = "GH-SVC-1001";
        output.message =
            "Controller recovery completed, but service configuration is invalid.";
        return output;
    }

    if (!startup_audited) {
        output.status = ControllerServiceStatus::audit_failed;
        output.event_id = "GH-SVC-2001";
        output.message =
            "Controller recovery completed, but service startup audit failed.";
        return output;
    }

    if (stop_token.stop_requested()) {
        const auto stopped_event = service_event(
            timestamp_source_(),
            logging::Severity::info,
            "GH-SVC-0003",
            "stopped",
            "Controller service stop was already requested after recovery.",
            startup.state);
        if (!journal_.append(stopped_event).ok()) {
            output.status = ControllerServiceStatus::audit_failed;
            output.event_id = "GH-SVC-2005";
            output.message = "Controller service stop could not be audited.";
        }
        return output;
    }

    auto listener_startup = listener_.start();
    output.listener_startup = listener_startup;
    if (!listener_startup.ok()) {
        auto failed = service_event(
            timestamp_source_(),
            logging::Severity::error,
            "GH-SVC-2002",
            "failed",
            "Controller service listener failed to start.",
            startup.state);
        failed.attributes.emplace(
            "listener_event_id", listener_startup.event_id);
        static_cast<void>(journal_.append(std::move(failed)));
        output.status = ControllerServiceStatus::listener_start_failed;
        output.event_id = "GH-SVC-2002";
        output.message = "Controller service listener failed to start.";
        return output;
    }

    auto running_event = service_event(
        timestamp_source_(),
        logging::Severity::info,
        "GH-SVC-0002",
        "running",
        "Controller service admission loop is active.",
        startup.state);
    running_event.attributes.emplace(
        "maximum_consecutive_listener_errors",
        std::to_string(config_.maximum_consecutive_listener_errors));
    if (!journal_.append(std::move(running_event)).ok()) {
        output.listener_shutdown = listener_.stop();
        if (!output.listener_shutdown->ok()) {
            output.status = ControllerServiceStatus::shutdown_failed;
            output.event_id = "GH-SVC-2004";
            output.message =
                "Service readiness audit failed and listener shutdown was incomplete.";
        } else {
            output.status = ControllerServiceStatus::audit_failed;
            output.event_id = "GH-SVC-2005";
            output.message =
                "Controller service readiness could not be audited.";
        }
        return output;
    }

    std::size_t consecutive_errors = 0;
    bool rate_limit_audited = false;
    while (!stop_token.stop_requested()) {
        auto admission = listener_.serve_one(
            config_.accept_poll_interval, config_.session_io_timeout);
        switch (admission.status) {
            case LocalListenerStatus::session_completed:
                increment_saturated(output.sessions_handled);
                if (!admission.session.has_value() ||
                    !admission.session->ok()) {
                    increment_saturated(output.protocol_failures);
                }
                consecutive_errors = 0;
                break;
            case LocalListenerStatus::accept_timed_out:
                increment_saturated(output.accept_timeouts);
                consecutive_errors = 0;
                break;
            case LocalListenerStatus::rate_limited:
                increment_saturated(output.rate_limited_connections);
                consecutive_errors = 0;
                if (!rate_limit_audited) {
                    auto limited = service_event(
                        timestamp_source_(),
                        logging::Severity::warning,
                        "GH-SVC-1003",
                        "limited",
                        "Controller connection admission rate limit activated.",
                        controller_.state());
                    if (!journal_.append(std::move(limited)).ok()) {
                        output.status = ControllerServiceStatus::audit_failed;
                        output.event_id = "GH-SVC-2005";
                        output.message =
                            "Connection rate limiting could not be audited.";
                    }
                    rate_limit_audited = true;
                }
                break;
            default:
                increment_saturated(output.listener_errors);
                ++consecutive_errors;
                break;
        }

        if (consecutive_errors >=
            config_.maximum_consecutive_listener_errors) {
            auto failed = service_event(
                timestamp_source_(),
                logging::Severity::critical,
                "GH-SVC-2003",
                "failed",
                "Controller service stopped after repeated listener failures.",
                controller_.state());
            failed.attributes.emplace(
                "consecutive_listener_errors",
                std::to_string(consecutive_errors));
            static_cast<void>(journal_.append(std::move(failed)));
            output.status = ControllerServiceStatus::listener_failed;
            output.event_id = "GH-SVC-2003";
            output.message =
                "Controller service stopped after repeated listener failures.";
            break;
        }
        if (output.status == ControllerServiceStatus::audit_failed) {
            break;
        }
    }

    auto listener_shutdown = listener_.stop();
    output.listener_shutdown = listener_shutdown;
    output.controller_state = controller_.state();
    if (!listener_shutdown.ok()) {
        output.status = ControllerServiceStatus::shutdown_failed;
        output.event_id = "GH-SVC-2004";
        output.message = "Controller service listener did not stop cleanly.";
        return output;
    }

    auto stopped = service_event(
        timestamp_source_(),
        output.status == ControllerServiceStatus::stopped
            ? logging::Severity::info
            : logging::Severity::error,
        "GH-SVC-0003",
        "stopped",
        "Controller service listener is closed.",
        output.controller_state);
    stopped.attributes.emplace(
        "sessions_handled", std::to_string(output.sessions_handled));
    stopped.attributes.emplace(
        "protocol_failures", std::to_string(output.protocol_failures));
    stopped.attributes.emplace(
        "listener_errors", std::to_string(output.listener_errors));
    stopped.attributes.emplace(
        "rate_limited_connections",
        std::to_string(output.rate_limited_connections));
    if (!journal_.append(std::move(stopped)).ok()) {
        output.status = ControllerServiceStatus::audit_failed;
        output.event_id = "GH-SVC-2005";
        output.message = "Controller service shutdown could not be audited.";
    }
    return output;
}

bool ControllerService::is_running() const noexcept {
    return running_.test();
}

}  // namespace sasd::gatehold::controller
