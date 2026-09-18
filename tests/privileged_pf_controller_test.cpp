#include "gatehold/controller/privileged_pf_controller.hpp"
#include "gatehold/firewall/activation_transaction_store.hpp"
#include "gatehold/firewall/native_validator.hpp"
#include "gatehold/firewall/pfctl_loader.hpp"
#include "gatehold/firewall/revision_store.hpp"
#include "gatehold/logging/operation_journal.hpp"
#include "temporary_directory.hpp"
#include "test_support.hpp"

#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <functional>
#include <string>
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

void write_private_file(
    const std::filesystem::path& path,
    const std::string& content) {
    {
        std::ofstream output{path, std::ios::binary};
        output << content;
    }
    std::filesystem::permissions(
        path,
        std::filesystem::perms::owner_read | std::filesystem::perms::owner_write,
        std::filesystem::perm_options::replace);
}

std::string read_file(const std::filesystem::path& path) {
    std::ifstream input{path, std::ios::binary};
    return {std::istreambuf_iterator<char>{input},
            std::istreambuf_iterator<char>{}};
}

void clear_file(const std::filesystem::path& path) {
    std::ofstream output{path, std::ios::trunc};
}

class AllowAuthorizer final : public firewall::ActivationAuthorizer {
public:
    [[nodiscard]] firewall::AuthorizationResult authorize(
        const std::string&,
        std::uint64_t,
        const std::string&) const override {
        return {
            .status = firewall::AuthorizationStatus::authorized,
            .decision_id = "controller-test-decision",
            .message = "authorized"};
    }
};

class ConfirmGate final : public firewall::ConfirmationGate {
public:
    [[nodiscard]] firewall::ConfirmationResult await_confirmation(
        const std::string&,
        std::uint64_t,
        std::chrono::milliseconds) const override {
        return {
            .status = firewall::ConfirmationStatus::confirmed,
            .confirmation_id = "controller-test-confirmation",
            .message = "confirmed"};
    }
};

class FixedProbe final : public firewall::HealthProbe {
public:
    explicit FixedProbe(firewall::HealthProbeStatus status) : status_{status} {}

    [[nodiscard]] std::string id() const override {
        return "controller-management-path";
    }

    [[nodiscard]] firewall::HealthProbeResult run(
        std::chrono::milliseconds) const override {
        return {
            .status = status_,
            .message = status_ == firewall::HealthProbeStatus::healthy
                           ? "healthy"
                           : "unhealthy"};
    }

private:
    firewall::HealthProbeStatus status_;
};

std::vector<std::reference_wrapper<const firewall::HealthProbe>> probes(
    const firewall::HealthProbe& probe) {
    return {std::cref(probe)};
}

firewall::ActivationRequest request(
    std::uint64_t revision,
    std::string operation_id = "controller-activation") {
    return {
        .operation_id = std::move(operation_id),
        .revision = revision,
        .authorization_reference = "controller-approval",
        .probe_timeout = std::chrono::seconds{1},
        .confirmation_timeout = std::chrono::seconds{5}};
}

}  // namespace

int main(int argc, char* argv[]) {
    gatehold::test::Context test;
    test.check(argc == 2, "test receives the fake pfctl executable path");
    if (argc != 2) {
        return test.result();
    }

    const gatehold::test::TemporaryDirectory temporary{
        "gatehold-controller-test"};
    const auto fake_pfctl =
        std::filesystem::absolute(std::filesystem::path{argv[1]});
    const auto trace = temporary.path() / "loads.trace";
    ::setenv("GATEHOLD_FAKE_PFCTL_TRACE", trace.c_str(), 1);
    const firewall::PfctlValidator validator{
        fake_pfctl, std::chrono::milliseconds{1000}};
    const firewall::PfctlLoader loader{
        fake_pfctl, std::chrono::milliseconds{1000}};
    const AllowAuthorizer authorizer;
    const ConfirmGate confirmation;
    const FixedProbe healthy{firewall::HealthProbeStatus::healthy};
    const FixedProbe unhealthy{firewall::HealthProbeStatus::unhealthy};
    const auto timestamp = [] { return "2026-09-18T15:00:00Z"; };

    const auto revision_root = temporary.path() / "revisions";
    const auto candidate_root = temporary.path() / "candidates";
    const auto transaction_root = temporary.path() / "transactions";
    const auto journal_root = temporary.path() / "journal";
    create_private_directory(revision_root);
    create_private_directory(candidate_root);
    create_private_directory(transaction_root);
    create_private_directory(journal_root);
    const firewall::RevisionStore revisions{revision_root};
    const firewall::ActivationTransactionStore transactions{transaction_root};
    const logging::OperationJournal journal{journal_root};
    const auto first = candidate_root / "1.pf.conf";
    const auto second = candidate_root / "2.pf.conf";
    write_private_file(first, "block all\n");
    write_private_file(second, "block all\npass out all\n");
    test.check(
        revisions.store(1, first).ok() && revisions.store(2, second).ok() &&
            revisions.mark_last_known_good(1).ok(),
        "normal controller fixture is prepared");
    const firewall::PfActivationService service{
        revisions,
        transactions,
        validator,
        loader,
        journal,
        authorizer,
        confirmation,
        probes(healthy),
        timestamp};
    controller::PrivilegedPfController pf_controller{service, journal, timestamp};

    clear_file(trace);
    const auto before_start = pf_controller.activate(request(2, "before-start"));
    test.check(
        before_start.status ==
                controller::ControllerDispatchStatus::controller_not_ready &&
            before_start.event_id == "GH-CTL-1001",
        "activation is rejected before startup recovery");
    test.check(
        read_file(trace).empty(),
        "pre-start rejection never reaches the native PF loader");

    const auto started = pf_controller.start();
    test.check(
        started.accepts_activations() &&
            started.recovery.has_value() &&
            started.recovery->status ==
                firewall::ActivationRecoveryStatus::no_pending &&
            pf_controller.state() == controller::ControllerState::ready,
        "controller becomes ready only after recovery reports no pending state");
    const auto repeated_start = pf_controller.start();
    test.check(
        repeated_start.status == controller::ControllerStartupStatus::ready &&
            !repeated_start.recovery.has_value(),
        "repeated startup is idempotent and does not rerun recovery");
    const auto successful = pf_controller.activate(request(2, "after-start"));
    test.check(
        successful.ok() &&
            successful.state == controller::ControllerState::ready,
        "ready controller dispatches a successful activation");
    const auto startup_journal = read_file(journal.journal_path());
    test.check(
        startup_journal.find("GH-CTL-0001") != std::string::npos &&
            startup_journal.find("GH-CTL-0002") != std::string::npos,
        "startup intent and readiness have stable audit events");

    const auto ordered_revision_root = temporary.path() / "ordered-revisions";
    const auto ordered_candidate_root = temporary.path() / "ordered-candidates";
    const auto ordered_transaction_root =
        temporary.path() / "ordered-transactions";
    const auto ordered_journal_root = temporary.path() / "ordered-journal";
    create_private_directory(ordered_revision_root);
    create_private_directory(ordered_candidate_root);
    create_private_directory(ordered_transaction_root);
    create_private_directory(ordered_journal_root);
    const firewall::RevisionStore ordered_revisions{ordered_revision_root};
    const firewall::ActivationTransactionStore ordered_transactions{
        ordered_transaction_root};
    const logging::OperationJournal ordered_journal{ordered_journal_root};
    const auto rollback_candidate = ordered_candidate_root / "30.pf.conf";
    const auto target_candidate = ordered_candidate_root / "31.pf.conf";
    write_private_file(rollback_candidate, "block all\nFAKE_LOAD_SLEEP\n");
    write_private_file(target_candidate, "block all\npass out all\n");
    test.check(
        ordered_revisions.store(30, rollback_candidate).ok() &&
            ordered_revisions.store(31, target_candidate).ok() &&
            ordered_revisions.mark_last_known_good(30).ok() &&
            ordered_transactions
                .begin({
                    .operation_id = "interrupted-activation",
                    .target_revision = 31,
                    .rollback_revision = 30,
                    .phase = firewall::ActivationPhase::prepared_for_load})
                .ok() &&
            ordered_transactions
                .advance(
                    "interrupted-activation",
                    firewall::ActivationPhase::target_loaded)
                .ok(),
        "ordered startup fixture contains an interrupted activation");
    const firewall::PfActivationService ordered_service{
        ordered_revisions,
        ordered_transactions,
        validator,
        loader,
        ordered_journal,
        authorizer,
        confirmation,
        probes(healthy),
        timestamp};
    controller::PrivilegedPfController ordered_controller{
        ordered_service, ordered_journal, timestamp};
    clear_file(trace);
    controller::ControllerStartupResult ordered_start;
    controller::ControllerActivationResult ordered_activation;
    std::thread startup_thread{[&] { ordered_start = ordered_controller.start(); }};
    std::this_thread::sleep_for(std::chrono::milliseconds{40});
    std::thread activation_thread{[&] {
        ordered_activation = ordered_controller.activate(
            request(31, "after-concurrent-recovery"));
    }};
    startup_thread.join();
    activation_thread.join();
    test.check(
        ordered_start.accepts_activations() && ordered_activation.ok(),
        "request waiting during startup is dispatched only after recovery");
    const auto ordered_trace = read_file(trace);
    const auto rollback_position =
        ordered_trace.find("00000000000000000030.pf.conf");
    const auto target_position =
        ordered_trace.find("00000000000000000031.pf.conf");
    test.check(
        rollback_position != std::string::npos &&
            target_position != std::string::npos &&
            rollback_position < target_position,
        "startup rollback reaches PF before the queued target activation");

    const auto unsafe_journal_root = temporary.path() / "unsafe-journal";
    const auto safe_revision_root = temporary.path() / "safe-revisions";
    const auto safe_transaction_root = temporary.path() / "safe-transactions";
    std::filesystem::create_directory(unsafe_journal_root);
    std::filesystem::permissions(
        unsafe_journal_root,
        std::filesystem::perms::all,
        std::filesystem::perm_options::replace);
    create_private_directory(safe_revision_root);
    create_private_directory(safe_transaction_root);
    const firewall::RevisionStore safe_revisions{safe_revision_root};
    const firewall::ActivationTransactionStore safe_transactions{
        safe_transaction_root};
    const logging::OperationJournal unsafe_journal{unsafe_journal_root};
    const firewall::PfActivationService unaudited_service{
        safe_revisions,
        safe_transactions,
        validator,
        loader,
        unsafe_journal,
        authorizer,
        confirmation,
        probes(healthy),
        timestamp};
    controller::PrivilegedPfController unaudited_controller{
        unaudited_service, unsafe_journal, timestamp};
    const auto unaudited_start = unaudited_controller.start();
    clear_file(trace);
    const auto unaudited_dispatch =
        unaudited_controller.activate(request(2, "unaudited-dispatch"));
    test.check(
        unaudited_start.status ==
                controller::ControllerStartupStatus::read_only &&
            unaudited_controller.state() ==
                controller::ControllerState::read_only &&
            unaudited_dispatch.status ==
                controller::ControllerDispatchStatus::controller_not_ready,
        "audit-unavailable startup completes recovery in read-only mode");
    test.check(
        read_file(trace).empty(),
        "read-only controller never dispatches to PF service");

    const auto corrupt_transaction_root =
        temporary.path() / "corrupt-transactions";
    const auto corrupt_journal_root = temporary.path() / "corrupt-journal";
    const auto corrupt_revision_root = temporary.path() / "corrupt-revisions";
    create_private_directory(corrupt_transaction_root);
    create_private_directory(corrupt_journal_root);
    create_private_directory(corrupt_revision_root);
    const firewall::ActivationTransactionStore corrupt_transactions{
        corrupt_transaction_root};
    write_private_file(
        corrupt_transactions.transaction_path(),
        "gatehold-activation-v1\ncorrupted\n");
    const firewall::RevisionStore corrupt_revisions{corrupt_revision_root};
    const logging::OperationJournal corrupt_journal{corrupt_journal_root};
    const firewall::PfActivationService corrupt_service{
        corrupt_revisions,
        corrupt_transactions,
        validator,
        loader,
        corrupt_journal,
        authorizer,
        confirmation,
        probes(healthy),
        timestamp};
    controller::PrivilegedPfController corrupt_controller{
        corrupt_service, corrupt_journal, timestamp};
    clear_file(trace);
    const auto corrupt_start = corrupt_controller.start();
    test.check(
        corrupt_start.status == controller::ControllerStartupStatus::blocked &&
            corrupt_start.event_id == "GH-CTL-2001" &&
            corrupt_start.recovery.has_value() &&
            corrupt_start.recovery->status ==
                firewall::ActivationRecoveryStatus::failed,
        "corrupt pending state blocks controller startup without guessing");
    test.check(
        read_file(trace).empty(),
        "failed recovery never performs a guessed PF operation");

    const auto degraded_revision_root =
        temporary.path() / "degraded-revisions";
    const auto degraded_candidate_root =
        temporary.path() / "degraded-candidates";
    const auto degraded_transaction_root =
        temporary.path() / "degraded-transactions";
    const auto degraded_journal_root = temporary.path() / "degraded-journal";
    create_private_directory(degraded_revision_root);
    create_private_directory(degraded_candidate_root);
    create_private_directory(degraded_transaction_root);
    create_private_directory(degraded_journal_root);
    const firewall::RevisionStore degraded_revisions{degraded_revision_root};
    const firewall::ActivationTransactionStore degraded_transactions{
        degraded_transaction_root};
    const logging::OperationJournal degraded_journal{degraded_journal_root};
    const auto degraded_previous = degraded_candidate_root / "40.pf.conf";
    const auto degraded_target = degraded_candidate_root / "41.pf.conf";
    write_private_file(degraded_previous, "block all\n");
    write_private_file(degraded_target, "block all\npass out all\n");
    test.check(
        degraded_revisions.store(40, degraded_previous).ok() &&
            degraded_revisions.store(41, degraded_target).ok() &&
            degraded_revisions.mark_last_known_good(40).ok(),
        "degraded-audit fixture is prepared");
    const firewall::PfActivationService degraded_service{
        degraded_revisions,
        degraded_transactions,
        validator,
        loader,
        degraded_journal,
        authorizer,
        confirmation,
        probes(healthy),
        timestamp};
    controller::PrivilegedPfController degraded_controller{
        degraded_service, degraded_journal, timestamp};
    test.check(
        degraded_controller.start().accepts_activations(),
        "degraded-audit controller starts while journal is healthy");
    std::filesystem::permissions(
        degraded_journal_root,
        std::filesystem::perms::all,
        std::filesystem::perm_options::replace);
    clear_file(trace);
    const auto degraded_activation = degraded_controller.activate(
        request(41, "audit-degraded-activation"));
    test.check(
        degraded_activation.activation.has_value() &&
            degraded_activation.activation->status ==
                firewall::ActivationStatus::audit_failed &&
            degraded_activation.state == controller::ControllerState::read_only,
        "activation audit failure permanently degrades controller to read-only");
    const auto rejected_after_degradation = degraded_controller.activate(
        request(41, "after-audit-degradation"));
    test.check(
        rejected_after_degradation.status ==
            controller::ControllerDispatchStatus::controller_not_ready,
        "read-only degradation rejects subsequent activation requests");
    test.check(
        read_file(trace).empty(),
        "audit failure and subsequent rejection occur before PF mutation");

    const auto broken_revision_root = temporary.path() / "broken-revisions";
    const auto broken_candidate_root = temporary.path() / "broken-candidates";
    const auto broken_transaction_root =
        temporary.path() / "broken-transactions";
    const auto broken_journal_root = temporary.path() / "broken-journal";
    create_private_directory(broken_revision_root);
    create_private_directory(broken_candidate_root);
    create_private_directory(broken_transaction_root);
    create_private_directory(broken_journal_root);
    const firewall::RevisionStore broken_revisions{broken_revision_root};
    const firewall::ActivationTransactionStore broken_transactions{
        broken_transaction_root};
    const logging::OperationJournal broken_journal{broken_journal_root};
    const auto broken_previous = broken_candidate_root / "50.pf.conf";
    const auto broken_target = broken_candidate_root / "51.pf.conf";
    write_private_file(broken_previous, "FAKE_LOAD_FAIL\n");
    write_private_file(broken_target, "block all\n");
    test.check(
        broken_revisions.store(50, broken_previous).ok() &&
            broken_revisions.store(51, broken_target).ok() &&
            broken_revisions.mark_last_known_good(50).ok(),
        "rollback-failure controller fixture is prepared");
    const firewall::PfActivationService broken_service{
        broken_revisions,
        broken_transactions,
        validator,
        loader,
        broken_journal,
        authorizer,
        confirmation,
        probes(unhealthy),
        timestamp};
    controller::PrivilegedPfController broken_controller{
        broken_service, broken_journal, timestamp};
    test.check(
        broken_controller.start().accepts_activations(),
        "rollback-failure controller starts from clean durable state");
    const auto broken_activation = broken_controller.activate(
        request(51, "rollback-failure-activation"));
    test.check(
        broken_activation.activation.has_value() &&
            broken_activation.activation->status ==
                firewall::ActivationStatus::rollback_failed &&
            broken_activation.state == controller::ControllerState::blocked &&
            broken_activation.event_id == "GH-CTL-2003",
        "failed rollback permanently blocks controller activation dispatch");
    test.check(
        broken_controller.activate(request(51, "after-critical-failure")).status ==
            controller::ControllerDispatchStatus::controller_not_ready,
        "blocked controller rejects every later activation request");

    return test.result();
}
