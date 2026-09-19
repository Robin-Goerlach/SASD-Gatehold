#include "gatehold/system/posix_signal_stop_bridge.hpp"

#include "gatehold/logging/event.hpp"

#include <chrono>
#include <ctime>
#include <iomanip>
#include <sstream>
#include <utility>

namespace sasd::gatehold::system {
namespace {

std::atomic_flag global_bridge_active = ATOMIC_FLAG_INIT;

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

logging::Event signal_event(
    std::string timestamp,
    logging::Severity severity,
    std::string event_id,
    std::string outcome,
    std::string message) {
    return {
        .timestamp = std::move(timestamp),
        .severity = severity,
        .event_id = std::move(event_id),
        .component = "posix-signal-stop-bridge",
        .operation_id = "process-lifetime",
        .action = "process.signal-stop",
        .outcome = std::move(outcome),
        .message = std::move(message),
        .attributes = {}};
}

bool append_bridge_event(
    const logging::OperationJournal& journal,
    const PosixSignalStopBridge::TimestampSource& timestamp_source,
    logging::Severity severity,
    std::string event_id,
    std::string outcome,
    std::string message) noexcept {
    try {
        return journal
            .append(signal_event(
                timestamp_source(),
                severity,
                std::move(event_id),
                std::move(outcome),
                std::move(message)))
            .ok();
    } catch (...) {
        return false;
    }
}

SignalStopBridgeResult bridge_result(
    SignalStopBridgeStatus status,
    std::string event_id,
    std::string message) {
    return {
        .status = status,
        .event_id = std::move(event_id),
        .message = std::move(message)};
}

sigset_t termination_signal_set() noexcept {
    sigset_t signals{};
    ::sigemptyset(&signals);
    ::sigaddset(&signals, SIGINT);
    ::sigaddset(&signals, SIGTERM);
    return signals;
}

std::string signal_name(int signal_number) {
    if (signal_number == SIGINT) {
        return "SIGINT";
    }
    if (signal_number == SIGTERM) {
        return "SIGTERM";
    }
    return "UNKNOWN";
}

}  // namespace

bool SignalStopBridgeResult::ok() const noexcept {
    return status == SignalStopBridgeStatus::started ||
           status == SignalStopBridgeStatus::stopped;
}

PosixSignalStopBridge::PosixSignalStopBridge(
    const logging::OperationJournal& journal,
    TimestampSource timestamp_source)
    : journal_{journal}, timestamp_source_{std::move(timestamp_source)} {
    if (!timestamp_source_) {
        timestamp_source_ = system_utc_timestamp;
    }
}

PosixSignalStopBridge::~PosixSignalStopBridge() {
    std::scoped_lock lock{state_mutex_};
    if (state_ != State::active) {
        return;
    }

    if (::pthread_equal(owner_thread_, ::pthread_self()) != 0) {
        stop_worker_without_restoring_mask();
        static_cast<void>(::pthread_sigmask(SIG_SETMASK, &previous_mask_, nullptr));
    } else {
        stop_worker_without_restoring_mask();
    }
    state_ = State::stopped;
    if (owns_global_claim_) {
        global_bridge_active.clear();
        owns_global_claim_ = false;
    }
}

SignalStopBridgeResult PosixSignalStopBridge::start() {
    std::scoped_lock lock{state_mutex_};
    if (state_ == State::active) {
        return bridge_result(
            SignalStopBridgeStatus::already_started,
            "GH-SIG-1001",
            "Signal stop bridge is already active.");
    }
    if (state_ == State::stopped) {
        return bridge_result(
            SignalStopBridgeStatus::already_stopped,
            "GH-SIG-1002",
            "Signal stop bridge is one-shot and has already stopped.");
    }
    if (global_bridge_active.test_and_set()) {
        return bridge_result(
            SignalStopBridgeStatus::globally_active,
            "GH-SIG-1003",
            "Another signal stop bridge is already active in this process.");
    }
    owns_global_claim_ = true;

    const bool startup_audited = append_bridge_event(
        journal_,
        timestamp_source_,
        logging::Severity::info,
        "GH-SIG-0001",
        "starting",
        "Synchronous SIGINT and SIGTERM monitoring is starting.");
    if (!startup_audited) {
        global_bridge_active.clear();
        owns_global_claim_ = false;
        return bridge_result(
            SignalStopBridgeStatus::audit_failed,
            "GH-SIG-2001",
            "Signal monitoring did not start because startup audit failed.");
    }

    const auto signals = termination_signal_set();
    const int mask_error =
        ::pthread_sigmask(SIG_BLOCK, &signals, &previous_mask_);
    if (mask_error != 0) {
        static_cast<void>(append_bridge_event(
            journal_,
            timestamp_source_,
            logging::Severity::error,
            "GH-SIG-2002",
            "failed",
            "SIGINT and SIGTERM could not be blocked."));
        global_bridge_active.clear();
        owns_global_claim_ = false;
        return bridge_result(
            SignalStopBridgeStatus::mask_failed,
            "GH-SIG-2002",
            "SIGINT and SIGTERM could not be blocked.");
    }

    owner_thread_ = ::pthread_self();
    try {
        worker_ = std::jthread{
            [this](std::stop_token worker_stop) noexcept {
                wait_for_signals(worker_stop);
            }};
    } catch (...) {
        const int restore_error =
            ::pthread_sigmask(SIG_SETMASK, &previous_mask_, nullptr);
        static_cast<void>(append_bridge_event(
            journal_,
            timestamp_source_,
            logging::Severity::error,
            "GH-SIG-2003",
            "failed",
            "Signal-waiting thread could not be started."));
        global_bridge_active.clear();
        owns_global_claim_ = false;
        if (restore_error != 0) {
            return bridge_result(
                SignalStopBridgeStatus::mask_restore_failed,
                "GH-SIG-2006",
                "The signal-waiting thread failed and the prior signal mask "
                "could not be restored.");
        }
        return bridge_result(
            SignalStopBridgeStatus::thread_start_failed,
            "GH-SIG-2003",
            "Signal-waiting thread could not be started.");
    }

    state_ = State::active;
    return bridge_result(
        SignalStopBridgeStatus::started,
        "GH-SIG-0001",
        "Synchronous SIGINT and SIGTERM monitoring started.");
}

SignalStopBridgeResult PosixSignalStopBridge::stop() {
    std::scoped_lock lock{state_mutex_};
    if (state_ == State::idle) {
        return bridge_result(
            SignalStopBridgeStatus::not_started,
            "GH-SIG-1004",
            "Signal stop bridge has not started.");
    }
    if (state_ == State::stopped) {
        return bridge_result(
            SignalStopBridgeStatus::already_stopped,
            "GH-SIG-1002",
            "Signal stop bridge has already stopped.");
    }
    if (::pthread_equal(owner_thread_, ::pthread_self()) == 0) {
        static_cast<void>(append_bridge_event(
            journal_,
            timestamp_source_,
            logging::Severity::warning,
            "GH-SIG-1005",
            "rejected",
            "Signal bridge cleanup was requested from the wrong thread."));
        return bridge_result(
            SignalStopBridgeStatus::wrong_thread,
            "GH-SIG-1005",
            "Signal stop bridge must be stopped by its starting thread.");
    }

    worker_.request_stop();
    const int wake_error = ::pthread_kill(worker_.native_handle(), SIGTERM);
    if (worker_.joinable()) {
        worker_.join();
    }

    const int restore_error =
        ::pthread_sigmask(SIG_SETMASK, &previous_mask_, nullptr);
    state_ = State::stopped;
    if (owns_global_claim_) {
        global_bridge_active.clear();
        owns_global_claim_ = false;
    }

    if (wake_error != 0) {
        static_cast<void>(append_bridge_event(
            journal_,
            timestamp_source_,
            logging::Severity::error,
            "GH-SIG-2005",
            "failed",
            "Signal-waiting thread could not be woken for shutdown."));
        return bridge_result(
            SignalStopBridgeStatus::wake_failed,
            "GH-SIG-2005",
            "Signal-waiting thread could not be woken for shutdown.");
    }
    if (restore_error != 0) {
        static_cast<void>(append_bridge_event(
            journal_,
            timestamp_source_,
            logging::Severity::error,
            "GH-SIG-2006",
            "failed",
            "The starting thread signal mask could not be restored."));
        return bridge_result(
            SignalStopBridgeStatus::mask_restore_failed,
            "GH-SIG-2006",
            "The starting thread signal mask could not be restored.");
    }

    if (wait_error_.load() != 0) {
        return bridge_result(
            SignalStopBridgeStatus::wait_failed,
            "GH-SIG-2004",
            "Synchronous signal waiting failed.");
    }

    const bool stopped_audited = append_bridge_event(
        journal_,
        timestamp_source_,
        logging::Severity::info,
        "GH-SIG-0003",
        "stopped",
        "Synchronous SIGINT and SIGTERM monitoring stopped.");
    if (!stopped_audited) {
        return bridge_result(
            SignalStopBridgeStatus::audit_failed,
            "GH-SIG-2007",
            "Signal monitoring stopped, but shutdown audit failed.");
    }

    return bridge_result(
        SignalStopBridgeStatus::stopped,
        "GH-SIG-0003",
        "Synchronous SIGINT and SIGTERM monitoring stopped.");
}

std::stop_token PosixSignalStopBridge::stop_token() const noexcept {
    return service_stop_source_.get_token();
}

bool PosixSignalStopBridge::is_active() const noexcept {
    const std::scoped_lock lock{state_mutex_};
    return state_ == State::active;
}

int PosixSignalStopBridge::received_signal() const noexcept {
    return received_signal_.load();
}

bool PosixSignalStopBridge::signal_event_audited() const noexcept {
    return signal_event_audited_.load();
}

void PosixSignalStopBridge::wait_for_signals(
    std::stop_token worker_stop) noexcept {
    const auto signals = termination_signal_set();
    for (;;) {
        int signal_number = 0;
        const int wait_error = ::sigwait(&signals, &signal_number);
        if (wait_error != 0) {
            wait_error_.store(wait_error);
            static_cast<void>(service_stop_source_.request_stop());
            try {
                signal_event_audited_.store(
                    journal_
                        .append(signal_event(
                            timestamp_source_(),
                            logging::Severity::error,
                            "GH-SIG-2004",
                            "failed",
                            "Synchronous signal waiting failed."))
                        .ok());
            } catch (...) {
                signal_event_audited_.store(false);
            }
            return;
        }
        if (worker_stop.stop_requested()) {
            return;
        }

        int expected = 0;
        if (received_signal_.compare_exchange_strong(expected, signal_number)) {
            static_cast<void>(service_stop_source_.request_stop());
            try {
                auto received = signal_event(
                    timestamp_source_(),
                    logging::Severity::info,
                    "GH-SIG-0002",
                    "stop-requested",
                    "A termination signal requested cooperative service stop.");
                received.attributes.emplace(
                    "signal", signal_name(signal_number));
                signal_event_audited_.store(journal_.append(received).ok());
            } catch (...) {
                signal_event_audited_.store(false);
            }
        }
    }
}

void PosixSignalStopBridge::stop_worker_without_restoring_mask() noexcept {
    if (!worker_.joinable()) {
        return;
    }
    worker_.request_stop();
    static_cast<void>(::pthread_kill(worker_.native_handle(), SIGTERM));
    worker_.join();
}

}  // namespace sasd::gatehold::system
