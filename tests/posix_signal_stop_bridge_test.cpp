#include "gatehold/logging/operation_journal.hpp"
#include "gatehold/system/posix_signal_stop_bridge.hpp"
#include "temporary_directory.hpp"
#include "test_support.hpp"

#include <pthread.h>
#include <signal.h>
#include <unistd.h>

#include <chrono>
#include <filesystem>
#include <fstream>
#include <stdexcept>
#include <string>
#include <thread>

namespace logging = sasd::gatehold::logging;
namespace system_api = sasd::gatehold::system;

namespace {

void create_private_directory(const std::filesystem::path& path) {
    std::filesystem::create_directory(path);
    std::filesystem::permissions(
        path,
        std::filesystem::perms::owner_all,
        std::filesystem::perm_options::replace);
}

std::string read_file(const std::filesystem::path& path) {
    std::ifstream input{path, std::ios::binary};
    return {std::istreambuf_iterator<char>{input},
            std::istreambuf_iterator<char>{}};
}

bool wait_for_stop(std::stop_token token) {
    for (int attempt = 0; attempt < 1000; ++attempt) {
        if (token.stop_requested()) {
            return true;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds{1});
    }
    return false;
}

bool same_membership(
    const sigset_t& left,
    const sigset_t& right,
    int signal_number) {
    return ::sigismember(&left, signal_number) ==
           ::sigismember(&right, signal_number);
}

}  // namespace

int main() {
    gatehold::test::Context test;
    const gatehold::test::TemporaryDirectory temporary{
        "gatehold-signal-stop-bridge-test"};
    const auto journal_root = temporary.path() / "journal";
    create_private_directory(journal_root);

    const logging::OperationJournal journal{journal_root};
    const auto timestamp = [] { return "2026-09-19T13:00:00Z"; };

    sigset_t original_mask{};
    test.check(
        ::pthread_sigmask(SIG_SETMASK, nullptr, &original_mask) == 0,
        "original signal mask can be inspected");

    const logging::OperationJournal unavailable_journal{
        temporary.path() / "missing-journal-root"};
    system_api::PosixSignalStopBridge unaudited_bridge{
        unavailable_journal, timestamp};
    const auto unaudited_start = unaudited_bridge.start();
    sigset_t mask_after_audit_failure{};
    test.check(
        unaudited_start.status ==
                system_api::SignalStopBridgeStatus::audit_failed &&
            ::pthread_sigmask(
                SIG_SETMASK, nullptr, &mask_after_audit_failure) == 0 &&
            same_membership(
                mask_after_audit_failure, original_mask, SIGINT) &&
            same_membership(
                mask_after_audit_failure, original_mask, SIGTERM),
        "startup audit failure leaves signal ownership and masks unchanged");

    system_api::PosixSignalStopBridge throwing_timestamp_bridge{
        journal,
        []() -> std::string {
            throw std::runtime_error{"timestamp unavailable"};
        }};
    test.check(
        throwing_timestamp_bridge.start().status ==
            system_api::SignalStopBridgeStatus::audit_failed,
        "timestamp failure cannot leak exclusive signal ownership");

    system_api::PosixSignalStopBridge bridge{journal, timestamp};
    const auto idle_stop = bridge.stop();
    test.check(
        !idle_stop.ok() && idle_stop.status ==
                               system_api::SignalStopBridgeStatus::not_started,
        "stopping an idle signal bridge is rejected");

    const auto started = bridge.start();
    test.check(
        started.ok() && bridge.is_active() &&
            !bridge.stop_token().stop_requested(),
        "signal bridge starts with an unrequested stop token");

    sigset_t active_mask{};
    test.check(
        ::pthread_sigmask(SIG_SETMASK, nullptr, &active_mask) == 0 &&
            ::sigismember(&active_mask, SIGINT) == 1 &&
            ::sigismember(&active_mask, SIGTERM) == 1,
        "starting thread blocks both managed termination signals");

    system_api::PosixSignalStopBridge competing{journal, timestamp};
    const auto competing_start = competing.start();
    test.check(
        competing_start.status ==
            system_api::SignalStopBridgeStatus::globally_active,
        "only one signal bridge can own process signal consumption");

    system_api::SignalStopBridgeResult foreign_stop;
    std::thread foreign_thread{[&bridge, &foreign_stop] {
        foreign_stop = bridge.stop();
    }};
    foreign_thread.join();
    test.check(
        foreign_stop.status == system_api::SignalStopBridgeStatus::wrong_thread &&
            bridge.is_active(),
        "a different thread cannot restore the starting thread mask");

    test.check(
        ::kill(::getpid(), SIGTERM) == 0,
        "SIGTERM can be delivered to the blocked process signal set");
    test.check(
        wait_for_stop(bridge.stop_token()) &&
            bridge.received_signal() == SIGTERM &&
            bridge.signal_event_audited(),
        "SIGTERM becomes an audited cooperative stop request");

    const auto stopped = bridge.stop();
    test.check(
        stopped.ok() && !bridge.is_active(),
        "owner thread stops and joins signal monitoring");

    sigset_t restored_mask{};
    test.check(
        ::pthread_sigmask(SIG_SETMASK, nullptr, &restored_mask) == 0 &&
            same_membership(restored_mask, original_mask, SIGINT) &&
            same_membership(restored_mask, original_mask, SIGTERM),
        "signal bridge restores the original managed-signal mask");
    test.check(
        bridge.start().status ==
            system_api::SignalStopBridgeStatus::already_stopped &&
            bridge.stop().status ==
                system_api::SignalStopBridgeStatus::already_stopped,
        "signal bridge lifecycle is deliberately one-shot");

    system_api::PosixSignalStopBridge interrupt_bridge{journal, timestamp};
    test.check(interrupt_bridge.start().ok(), "a new bridge can start after cleanup");
    test.check(
        ::kill(::getpid(), SIGINT) == 0 &&
            wait_for_stop(interrupt_bridge.stop_token()) &&
            interrupt_bridge.received_signal() == SIGINT,
        "SIGINT also becomes a cooperative stop request");
    test.check(
        interrupt_bridge.stop().ok(),
        "SIGINT bridge restores its owner mask and stops");

    const auto journal_text = read_file(journal.journal_path());
    test.check(
        journal_text.find("GH-SIG-0001") != std::string::npos &&
            journal_text.find("GH-SIG-0002") != std::string::npos &&
            journal_text.find("GH-SIG-0003") != std::string::npos &&
            journal_text.find("SIGTERM") != std::string::npos &&
            journal_text.find("SIGINT") != std::string::npos,
        "signal lifecycle and allowlisted signal names are journaled");

    return test.result();
}
