#include "gatehold/controller/controller_service.hpp"
#include "gatehold/controller/local_listener.hpp"
#include "gatehold/controller/privileged_pf_controller.hpp"
#include "gatehold/firewall/activation_service.hpp"
#include "gatehold/firewall/activation_transaction_store.hpp"
#include "gatehold/firewall/native_validator.hpp"
#include "gatehold/firewall/pfctl_loader.hpp"
#include "gatehold/firewall/revision_store.hpp"
#include "gatehold/logging/operation_journal.hpp"
#include "temporary_directory.hpp"
#include "test_support.hpp"

#include <unistd.h>

#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <functional>
#include <mutex>
#include <optional>
#include <stop_token>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

namespace controller = sasd::gatehold::controller;
namespace firewall = sasd::gatehold::firewall;
namespace logging = sasd::gatehold::logging;

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

std::size_t count_occurrences(
    std::string_view text,
    std::string_view needle) {
    std::size_t count = 0;
    std::size_t offset = 0;
    while ((offset = text.find(needle, offset)) != std::string_view::npos) {
        ++count;
        offset += needle.size();
    }
    return count;
}

class DenyingAuthorizer final : public firewall::ActivationAuthorizer {
public:
    [[nodiscard]] firewall::AuthorizationResult authorize(
        const std::string&,
        std::uint64_t,
        const std::string&) const override {
        return {
            .status = firewall::AuthorizationStatus::denied,
            .decision_id = "service-test-denial",
            .message = "denied"};
    }
};

class RejectingConfirmation final : public firewall::ConfirmationGate {
public:
    [[nodiscard]] firewall::ConfirmationResult await_confirmation(
        const std::string&,
        std::uint64_t,
        std::chrono::milliseconds) const override {
        return {
            .status = firewall::ConfirmationStatus::rejected,
            .confirmation_id = "service-test-rejection",
            .message = "rejected"};
    }
};

class UnhealthyProbe final : public firewall::HealthProbe {
public:
    [[nodiscard]] std::string id() const override {
        return "service-test-probe";
    }

    [[nodiscard]] firewall::HealthProbeResult run(
        std::chrono::milliseconds) const override {
        return {
            .status = firewall::HealthProbeStatus::unhealthy,
            .message = "unhealthy"};
    }
};

controller::ProtocolSessionResult protocol_result(
    controller::ProtocolSessionStatus status,
    std::string event_id) {
    return {
        .status = status,
        .event_id = std::move(event_id),
        .message = "scripted protocol result",
        .peer_user_id = ::geteuid(),
        .peer_group_id = ::getegid()};
}

controller::LocalListenerResult listener_result(
    controller::LocalListenerStatus status,
    std::string event_id,
    std::optional<controller::ProtocolSessionResult> session = std::nullopt) {
    return {
        .status = status,
        .event_id = std::move(event_id),
        .message = "scripted listener result",
        .session = std::move(session)};
}

class ScriptedAcceptor final : public controller::ControllerConnectionAcceptor {
public:
    [[nodiscard]] controller::LocalListenerResult start() override {
        ++start_calls;
        if (on_start) {
            on_start();
        }
        return start_result;
    }

    [[nodiscard]] controller::LocalListenerResult serve_one(
        std::chrono::milliseconds accept_timeout,
        std::chrono::milliseconds session_timeout) override {
        const auto call = ++serve_calls;
        last_accept_timeout_ms.store(accept_timeout.count());
        last_session_timeout_ms.store(session_timeout.count());
        if (serve_delay > std::chrono::milliseconds::zero()) {
            std::this_thread::sleep_for(serve_delay);
        }
        if (on_serve) {
            on_serve();
        }

        controller::LocalListenerResult selected = listener_result(
            controller::LocalListenerStatus::accept_timed_out,
            "GH-LSN-1005");
        {
            const std::scoped_lock lock{script_mutex_};
            if (next_result_ < admissions.size()) {
                selected = admissions[next_result_];
                ++next_result_;
            }
        }
        if (stop_source != nullptr && request_stop_after_call != 0U &&
            call >= request_stop_after_call) {
            static_cast<void>(stop_source->request_stop());
        }
        return selected;
    }

    [[nodiscard]] controller::LocalListenerResult stop() override {
        ++stop_calls;
        return stop_result;
    }

    controller::LocalListenerResult start_result = listener_result(
        controller::LocalListenerStatus::listening, "GH-LSN-0002");
    controller::LocalListenerResult stop_result = listener_result(
        controller::LocalListenerStatus::stopped, "GH-LSN-0003");
    std::vector<controller::LocalListenerResult> admissions;
    std::stop_source* stop_source{nullptr};
    std::size_t request_stop_after_call{0};
    std::chrono::milliseconds serve_delay{0};
    std::function<void()> on_start;
    std::function<void()> on_serve;
    std::atomic<std::size_t> start_calls{0};
    std::atomic<std::size_t> serve_calls{0};
    std::atomic<std::size_t> stop_calls{0};
    std::atomic<std::int64_t> last_accept_timeout_ms{0};
    std::atomic<std::int64_t> last_session_timeout_ms{0};

private:
    std::mutex script_mutex_;
    std::size_t next_result_{0};
};

bool wait_until_running(const controller::ControllerService& service) {
    for (int attempt = 0; attempt < 500; ++attempt) {
        if (service.is_running()) {
            return true;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds{1});
    }
    return false;
}

}  // namespace

int main() {
    gatehold::test::Context test;
    const gatehold::test::TemporaryDirectory temporary{
        "gatehold-controller-service-test"};
    const auto journal_root = temporary.path() / "journal";
    const auto revision_root = temporary.path() / "revisions";
    const auto transaction_root = temporary.path() / "transactions";
    create_private_directory(journal_root);
    create_private_directory(revision_root);
    create_private_directory(transaction_root);

    const logging::OperationJournal journal{journal_root};
    const firewall::RevisionStore revisions{revision_root};
    const firewall::ActivationTransactionStore transactions{transaction_root};
    const firewall::PfctlValidator validator;
    const firewall::PfctlLoader loader;
    const DenyingAuthorizer authorizer;
    const RejectingConfirmation confirmation;
    const UnhealthyProbe probe;
    const std::vector<std::reference_wrapper<const firewall::HealthProbe>> probes{
        std::cref(probe)};
    const auto timestamp = [] { return "2026-09-19T12:00:00Z"; };
    const firewall::PfActivationService activation_service{
        revisions,
        transactions,
        validator,
        loader,
        journal,
        authorizer,
        confirmation,
        probes,
        timestamp};

    controller::PrivilegedPfController invalid_controller{
        activation_service, journal, timestamp};
    ScriptedAcceptor invalid_acceptor;
    controller::ControllerService invalid_service{
        invalid_controller,
        invalid_acceptor,
        journal,
        {.accept_poll_interval = std::chrono::milliseconds{1}},
        timestamp};
    const auto invalid = invalid_service.run(std::stop_token{});
    test.check(
        invalid.status ==
                controller::ControllerServiceStatus::invalid_configuration &&
            invalid.controller_startup.has_value() &&
            invalid_controller.state() == controller::ControllerState::ready &&
            invalid_acceptor.start_calls.load() == 0U,
        "invalid service configuration still recovers without listener exposure");

    controller::PrivilegedPfController prestopped_controller{
        activation_service, journal, timestamp};
    ScriptedAcceptor prestopped_acceptor;
    std::stop_source prestopped_source;
    static_cast<void>(prestopped_source.request_stop());
    controller::ControllerService prestopped_service{
        prestopped_controller,
        prestopped_acceptor,
        journal,
        {},
        timestamp};
    const auto prestopped = prestopped_service.run(prestopped_source.get_token());
    test.check(
        prestopped.ok() && prestopped.controller_startup.has_value() &&
            prestopped.controller_state == controller::ControllerState::ready &&
            prestopped_acceptor.start_calls.load() == 0U,
        "pre-requested stop still performs recovery without exposing listener");

    controller::PrivilegedPfController normal_controller{
        activation_service, journal, timestamp};
    ScriptedAcceptor normal_acceptor;
    std::stop_source normal_stop;
    normal_acceptor.stop_source = &normal_stop;
    normal_acceptor.request_stop_after_call = 6U;
    normal_acceptor.admissions = {
        listener_result(
            controller::LocalListenerStatus::accept_timed_out,
            "GH-LSN-1005"),
        listener_result(
            controller::LocalListenerStatus::session_completed,
            "GH-IPC-0002",
            protocol_result(
                controller::ProtocolSessionStatus::completed,
                "GH-IPC-0002")),
        listener_result(
            controller::LocalListenerStatus::session_completed,
            "GH-IPC-1001",
            protocol_result(
                controller::ProtocolSessionStatus::peer_rejected,
                "GH-IPC-1001")),
        listener_result(
            controller::LocalListenerStatus::accept_timed_out,
            "GH-LSN-1005"),
        listener_result(
            controller::LocalListenerStatus::rate_limited,
            "GH-LSN-1006"),
        listener_result(
            controller::LocalListenerStatus::rate_limited,
            "GH-LSN-1006")};
    controller::ControllerService normal_service{
        normal_controller,
        normal_acceptor,
        journal,
        {.accept_poll_interval = std::chrono::milliseconds{20},
         .session_io_timeout = std::chrono::milliseconds{750},
         .maximum_consecutive_listener_errors = 3U},
        timestamp};
    const auto normal = normal_service.run(normal_stop.get_token());
    test.check(
        normal.ok() && normal.sessions_handled == 2U &&
            normal.protocol_failures == 1U && normal.accept_timeouts == 2U &&
            normal.rate_limited_connections == 2U &&
            normal.listener_errors == 0U &&
            normal_acceptor.start_calls.load() == 1U &&
            normal_acceptor.stop_calls.load() == 1U,
        "service handles success, peer rejection, idle polls, and clean stop");
    test.check(
        normal_acceptor.last_accept_timeout_ms.load() == 20 &&
            normal_acceptor.last_session_timeout_ms.load() == 750,
        "service passes configured bounded deadlines to listener");
    const auto normal_journal = read_file(journal.journal_path());
    test.check(
        count_occurrences(normal_journal, "GH-SVC-1003") == 1U &&
            normal_journal.find("\"rate_limited_connections\":\"2\"") !=
                std::string::npos,
        "rate-limit activation is audited once and summarized at shutdown");

    controller::PrivilegedPfController error_controller{
        activation_service, journal, timestamp};
    ScriptedAcceptor error_acceptor;
    error_acceptor.admissions = {
        listener_result(
            controller::LocalListenerStatus::io_error, "GH-LSN-2003"),
        listener_result(
            controller::LocalListenerStatus::accept_timed_out,
            "GH-LSN-1005"),
        listener_result(
            controller::LocalListenerStatus::busy, "GH-LSN-1004"),
        listener_result(
            controller::LocalListenerStatus::not_listening,
            "GH-LSN-1001")};
    controller::ControllerService error_service{
        error_controller,
        error_acceptor,
        journal,
        {.accept_poll_interval = std::chrono::milliseconds{20},
         .session_io_timeout = std::chrono::milliseconds{500},
         .maximum_consecutive_listener_errors = 2U},
        timestamp};
    const auto errors = error_service.run(std::stop_token{});
    test.check(
        errors.status == controller::ControllerServiceStatus::listener_failed &&
            errors.event_id == "GH-SVC-2003" &&
            errors.listener_errors == 3U && errors.accept_timeouts == 1U &&
            error_acceptor.serve_calls.load() == 4U &&
            error_acceptor.stop_calls.load() == 1U,
        "idle success resets error streak before bounded terminal failure");

    controller::PrivilegedPfController failed_start_controller{
        activation_service, journal, timestamp};
    ScriptedAcceptor failed_start_acceptor;
    failed_start_acceptor.start_result = listener_result(
        controller::LocalListenerStatus::address_in_use, "GH-LSN-1003");
    controller::ControllerService failed_start_service{
        failed_start_controller,
        failed_start_acceptor,
        journal,
        {},
        timestamp};
    const auto failed_start =
        failed_start_service.run(std::stop_token{});
    test.check(
        failed_start.status ==
                controller::ControllerServiceStatus::listener_start_failed &&
            failed_start.controller_state == controller::ControllerState::ready &&
            failed_start_acceptor.stop_calls.load() == 0U,
        "listener startup failure occurs only after mandatory recovery");

    controller::PrivilegedPfController failed_stop_controller{
        activation_service, journal, timestamp};
    ScriptedAcceptor failed_stop_acceptor;
    std::stop_source failed_stop_source;
    failed_stop_acceptor.stop_source = &failed_stop_source;
    failed_stop_acceptor.request_stop_after_call = 1U;
    failed_stop_acceptor.stop_result = listener_result(
        controller::LocalListenerStatus::cleanup_failed, "GH-LSN-2004");
    controller::ControllerService failed_stop_service{
        failed_stop_controller,
        failed_stop_acceptor,
        journal,
        {},
        timestamp};
    const auto failed_stop =
        failed_stop_service.run(failed_stop_source.get_token());
    test.check(
        failed_stop.status ==
                controller::ControllerServiceStatus::shutdown_failed &&
            failed_stop.event_id == "GH-SVC-2004",
        "listener cleanup failure remains a terminal service failure");

    const auto transition_journal_root =
        temporary.path() / "transition-journal";
    create_private_directory(transition_journal_root);
    const logging::OperationJournal transition_journal{
        transition_journal_root};
    controller::PrivilegedPfController transition_controller{
        activation_service, journal, timestamp};
    ScriptedAcceptor transition_acceptor;
    transition_acceptor.on_start = [&] {
        std::filesystem::permissions(
            transition_journal_root,
            std::filesystem::perms::all,
            std::filesystem::perm_options::replace);
    };
    transition_acceptor.stop_result = listener_result(
        controller::LocalListenerStatus::cleanup_failed, "GH-LSN-2004");
    controller::ControllerService transition_service{
        transition_controller,
        transition_acceptor,
        transition_journal,
        {},
        timestamp};
    const auto transition = transition_service.run(std::stop_token{});
    test.check(
        transition.status ==
                controller::ControllerServiceStatus::shutdown_failed &&
            transition.event_id == "GH-SVC-2004" &&
            transition_acceptor.serve_calls.load() == 0U &&
            transition_acceptor.stop_calls.load() == 1U,
        "readiness audit failure never admits and preserves shutdown failure");

    const auto rate_audit_root = temporary.path() / "rate-audit-journal";
    create_private_directory(rate_audit_root);
    const logging::OperationJournal rate_audit_journal{rate_audit_root};
    controller::PrivilegedPfController rate_audit_controller{
        activation_service, journal, timestamp};
    ScriptedAcceptor rate_audit_acceptor;
    rate_audit_acceptor.admissions = {listener_result(
        controller::LocalListenerStatus::rate_limited, "GH-LSN-1006")};
    rate_audit_acceptor.on_serve = [&] {
        std::filesystem::permissions(
            rate_audit_root,
            std::filesystem::perms::all,
            std::filesystem::perm_options::replace);
    };
    controller::ControllerService rate_audit_service{
        rate_audit_controller,
        rate_audit_acceptor,
        rate_audit_journal,
        {},
        timestamp};
    const auto rate_audit = rate_audit_service.run(std::stop_token{});
    test.check(
        rate_audit.status == controller::ControllerServiceStatus::audit_failed &&
            rate_audit.event_id == "GH-SVC-2005" &&
            rate_audit.rate_limited_connections == 1U &&
            rate_audit_acceptor.serve_calls.load() == 1U &&
            rate_audit_acceptor.stop_calls.load() == 1U,
        "unaudited rate-limit activation stops further admission");
    std::filesystem::permissions(
        rate_audit_root,
        std::filesystem::perms::owner_all,
        std::filesystem::perm_options::replace);

    const auto unsafe_journal_root = temporary.path() / "unsafe-journal";
    std::filesystem::create_directory(unsafe_journal_root);
    std::filesystem::permissions(
        unsafe_journal_root,
        std::filesystem::perms::all,
        std::filesystem::perm_options::replace);
    const logging::OperationJournal unsafe_journal{unsafe_journal_root};
    controller::PrivilegedPfController unaudited_controller{
        activation_service, journal, timestamp};
    ScriptedAcceptor unaudited_acceptor;
    controller::ControllerService unaudited_service{
        unaudited_controller,
        unaudited_acceptor,
        unsafe_journal,
        {},
        timestamp};
    const auto unaudited = unaudited_service.run(std::stop_token{});
    test.check(
        unaudited.status == controller::ControllerServiceStatus::audit_failed &&
            unaudited.controller_state == controller::ControllerState::ready &&
            unaudited_acceptor.start_calls.load() == 0U,
        "service audit failure still runs recovery but never opens listener");

    controller::PrivilegedPfController concurrent_controller{
        activation_service, journal, timestamp};
    ScriptedAcceptor concurrent_acceptor;
    concurrent_acceptor.serve_delay = std::chrono::milliseconds{20};
    std::stop_source concurrent_stop;
    controller::ControllerService concurrent_service{
        concurrent_controller,
        concurrent_acceptor,
        journal,
        {.accept_poll_interval = std::chrono::milliseconds{20}},
        timestamp};
    controller::ControllerServiceResult concurrent_result;
    std::thread running{[&] {
        concurrent_result = concurrent_service.run(concurrent_stop.get_token());
    }};
    const bool became_running = wait_until_running(concurrent_service);
    test.check(became_running, "service exposes active run-loop state");
    const auto duplicate = concurrent_service.run(std::stop_token{});
    test.check(
        duplicate.status ==
            controller::ControllerServiceStatus::already_running,
        "second concurrent service loop is rejected");
    static_cast<void>(concurrent_stop.request_stop());
    running.join();
    test.check(
        concurrent_result.ok() && concurrent_acceptor.stop_calls.load() == 1U,
        "active service observes stop token and closes listener");

    const auto journal_text = read_file(journal.journal_path());
    test.check(
        journal_text.find("GH-SVC-0001") != std::string::npos &&
            journal_text.find("GH-SVC-0002") != std::string::npos &&
            journal_text.find("GH-SVC-0003") != std::string::npos &&
            journal_text.find("GH-SVC-2002") != std::string::npos &&
            journal_text.find("GH-SVC-2003") != std::string::npos &&
            journal_text.find("listener_event_id") != std::string::npos,
        "service lifecycle and terminal failures use stable audit events");

    return test.result();
}
