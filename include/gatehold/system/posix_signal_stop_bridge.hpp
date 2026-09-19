#pragma once

#include "gatehold/logging/operation_journal.hpp"

#include <pthread.h>
#include <signal.h>

#include <atomic>
#include <functional>
#include <mutex>
#include <stop_token>
#include <string>
#include <thread>

namespace sasd::gatehold::system {

enum class SignalStopBridgeStatus {
    started,
    stopped,
    already_started,
    already_stopped,
    globally_active,
    not_started,
    wrong_thread,
    audit_failed,
    mask_failed,
    thread_start_failed,
    wait_failed,
    wake_failed,
    mask_restore_failed
};

struct SignalStopBridgeResult {
    SignalStopBridgeStatus status{SignalStopBridgeStatus::not_started};
    std::string event_id;
    std::string message;

    [[nodiscard]] bool ok() const noexcept;
};

class PosixSignalStopBridge final {
public:
    using TimestampSource = std::function<std::string()>;

    explicit PosixSignalStopBridge(
        const logging::OperationJournal& journal,
        TimestampSource timestamp_source = {});
    ~PosixSignalStopBridge();

    PosixSignalStopBridge(const PosixSignalStopBridge&) = delete;
    PosixSignalStopBridge& operator=(const PosixSignalStopBridge&) = delete;
    PosixSignalStopBridge(PosixSignalStopBridge&&) = delete;
    PosixSignalStopBridge& operator=(PosixSignalStopBridge&&) = delete;

    // The instance must be started, stopped, and destroyed on the same thread.
    // Start it before creating threads that must inherit the blocked signals.
    [[nodiscard]] SignalStopBridgeResult start();
    [[nodiscard]] SignalStopBridgeResult stop();
    [[nodiscard]] std::stop_token stop_token() const noexcept;
    [[nodiscard]] bool is_active() const noexcept;
    [[nodiscard]] int received_signal() const noexcept;
    [[nodiscard]] bool signal_event_audited() const noexcept;

private:
    enum class State { idle, active, stopped };

    void wait_for_signals(std::stop_token worker_stop) noexcept;
    void stop_worker_without_restoring_mask() noexcept;

    const logging::OperationJournal& journal_;
    TimestampSource timestamp_source_;
    mutable std::mutex state_mutex_;
    State state_{State::idle};
    sigset_t previous_mask_{};
    pthread_t owner_thread_{};
    std::jthread worker_;
    std::stop_source service_stop_source_;
    std::atomic<int> received_signal_{0};
    std::atomic<int> wait_error_{0};
    std::atomic<bool> signal_event_audited_{true};
    bool owns_global_claim_{false};
};

}  // namespace sasd::gatehold::system
