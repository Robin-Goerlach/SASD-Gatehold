#pragma once

#include "gatehold/controller/local_listener.hpp"
#include "gatehold/controller/privileged_pf_controller.hpp"
#include "gatehold/logging/operation_journal.hpp"

#include <atomic>
#include <chrono>
#include <cstddef>
#include <functional>
#include <optional>
#include <stop_token>
#include <string>

namespace sasd::gatehold::controller {

struct ControllerServiceConfig {
    std::chrono::milliseconds accept_poll_interval{250};
    std::chrono::milliseconds session_io_timeout{5000};
    std::size_t maximum_consecutive_listener_errors{3};
};

enum class ControllerServiceStatus {
    stopped,
    already_running,
    invalid_configuration,
    audit_failed,
    listener_start_failed,
    listener_failed,
    shutdown_failed
};

struct ControllerServiceResult {
    ControllerServiceStatus status{ControllerServiceStatus::listener_failed};
    std::string event_id;
    std::string message;
    ControllerState controller_state{ControllerState::created};
    std::size_t sessions_handled{0};
    std::size_t protocol_failures{0};
    std::size_t accept_timeouts{0};
    std::size_t listener_errors{0};
    std::optional<ControllerStartupResult> controller_startup;
    std::optional<LocalListenerResult> listener_startup;
    std::optional<LocalListenerResult> listener_shutdown;

    [[nodiscard]] bool ok() const noexcept;
};

class ControllerService final {
public:
    using TimestampSource = std::function<std::string()>;

    static constexpr std::chrono::milliseconds minimum_accept_poll_interval{10};
    static constexpr std::chrono::milliseconds maximum_accept_poll_interval{
        1000};
    static constexpr std::size_t maximum_listener_error_limit = 100U;

    ControllerService(
        PrivilegedPfController& controller,
        ControllerConnectionAcceptor& listener,
        const logging::OperationJournal& journal,
        ControllerServiceConfig config = {},
        TimestampSource timestamp_source = {});

    [[nodiscard]] ControllerServiceResult run(std::stop_token stop_token);
    [[nodiscard]] bool is_running() const noexcept;

private:
    PrivilegedPfController& controller_;
    ControllerConnectionAcceptor& listener_;
    const logging::OperationJournal& journal_;
    ControllerServiceConfig config_;
    TimestampSource timestamp_source_;
    std::atomic_flag running_ = ATOMIC_FLAG_INIT;
};

}  // namespace sasd::gatehold::controller
