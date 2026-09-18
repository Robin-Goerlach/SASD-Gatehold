#include "gatehold/firewall/activation_service.hpp"
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
#include <atomic>
#include <array>
#include <string>
#include <thread>
#include <utility>
#include <vector>

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

class FixedAuthorizer final : public firewall::ActivationAuthorizer {
public:
    explicit FixedAuthorizer(firewall::AuthorizationStatus status)
        : status_{status} {}

    [[nodiscard]] firewall::AuthorizationResult authorize(
        const std::string&,
        std::uint64_t,
        const std::string&) const override {
        return {
            .status = status_,
            .decision_id = status_ == firewall::AuthorizationStatus::authorized
                               ? "decision-42"
                               : "",
            .message = status_ == firewall::AuthorizationStatus::authorized
                           ? "authorized"
                           : "denied"};
    }

private:
    firewall::AuthorizationStatus status_;
};

class FixedConfirmationGate final : public firewall::ConfirmationGate {
public:
    explicit FixedConfirmationGate(firewall::ConfirmationStatus status)
        : status_{status} {}

    [[nodiscard]] firewall::ConfirmationResult await_confirmation(
        const std::string&,
        std::uint64_t,
        std::chrono::milliseconds) const override {
        return {
            .status = status_,
            .confirmation_id = status_ == firewall::ConfirmationStatus::confirmed
                                   ? "confirmation-42"
                                   : "",
            .message = status_ == firewall::ConfirmationStatus::confirmed
                           ? "confirmed"
                           : "not confirmed"};
    }

private:
    firewall::ConfirmationStatus status_;
};

class ConcurrencyTrackingAuthorizer final
    : public firewall::ActivationAuthorizer {
public:
    [[nodiscard]] firewall::AuthorizationResult authorize(
        const std::string&,
        std::uint64_t,
        const std::string&) const override {
        const int active = active_calls_.fetch_add(1) + 1;
        int observed = maximum_calls_.load();
        while (active > observed &&
               !maximum_calls_.compare_exchange_weak(observed, active)) {
        }
        std::this_thread::sleep_for(std::chrono::milliseconds{40});
        active_calls_.fetch_sub(1);
        return {
            .status = firewall::AuthorizationStatus::authorized,
            .decision_id = "concurrency-decision",
            .message = "authorized"};
    }

    [[nodiscard]] int maximum_calls() const noexcept {
        return maximum_calls_.load();
    }

private:
    mutable std::atomic<int> active_calls_{0};
    mutable std::atomic<int> maximum_calls_{0};
};

class CallbackProbe final : public firewall::HealthProbe {
public:
    using Callback = std::function<firewall::HealthProbeResult()>;

    CallbackProbe(std::string identifier, Callback callback)
        : identifier_{std::move(identifier)}, callback_{std::move(callback)} {}

    [[nodiscard]] std::string id() const override {
        return identifier_;
    }

    [[nodiscard]] firewall::HealthProbeResult run(
        std::chrono::milliseconds) const override {
        return callback_();
    }

private:
    std::string identifier_;
    Callback callback_;
};

std::vector<std::reference_wrapper<const firewall::HealthProbe>> probes(
    const firewall::HealthProbe& probe) {
    return {std::cref(probe)};
}

firewall::ActivationRequest request(std::uint64_t revision) {
    return {
        .operation_id = "activate-revision-" + std::to_string(revision),
        .revision = revision,
        .authorization_reference = "approval-reference-42",
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

    const gatehold::test::TemporaryDirectory temporary{"gatehold-activate-test"};
    const auto revision_root = temporary.path() / "revisions";
    const auto candidate_root = temporary.path() / "candidates";
    const auto journal_root = temporary.path() / "journal";
    create_private_directory(revision_root);
    create_private_directory(candidate_root);
    create_private_directory(journal_root);

    const auto fake_pfctl =
        std::filesystem::absolute(std::filesystem::path{argv[1]});
    const auto trace = temporary.path() / "loads.trace";
    ::setenv("GATEHOLD_FAKE_PFCTL_TRACE", trace.c_str(), 1);

    const firewall::RevisionStore revisions{revision_root};
    const std::vector<std::pair<std::uint64_t, std::string>> revision_contents{
        {1, "block all\n"},
        {2, "block all\npass out all\n"},
        {3, "FAKE_LOAD_FAIL\n"},
        {4, "FAKE_REJECT\n"},
        {5, "block log all\n"}};
    for (const auto& [revision, content] : revision_contents) {
        const auto candidate =
            candidate_root / (std::to_string(revision) + ".pf.conf");
        write_private_file(candidate, content);
        test.check(
            revisions.store(revision, candidate).ok(),
            "test revision is stored");
    }
    test.check(
        revisions.mark_last_known_good(1).ok(),
        "initial rollback revision is marked");

    const firewall::PfctlValidator validator{
        fake_pfctl, std::chrono::milliseconds{1000}};
    const firewall::PfctlLoader loader{
        fake_pfctl, std::chrono::milliseconds{1000}};
    const logging::OperationJournal journal{journal_root};
    const FixedAuthorizer authorized{firewall::AuthorizationStatus::authorized};
    const FixedAuthorizer denied{firewall::AuthorizationStatus::denied};
    const FixedConfirmationGate confirmed{
        firewall::ConfirmationStatus::confirmed};
    const FixedConfirmationGate timed_out{
        firewall::ConfirmationStatus::timed_out};
    const CallbackProbe healthy_probe{
        "management-path",
        [] {
            return firewall::HealthProbeResult{
                .status = firewall::HealthProbeStatus::healthy,
                .message = "management path reachable"};
        }};
    const CallbackProbe unhealthy_probe{
        "management-path",
        [] {
            return firewall::HealthProbeResult{
                .status = firewall::HealthProbeStatus::unhealthy,
                .message = "management path unreachable"};
        }};

    const firewall::PfActivationService denied_service{
        revisions,
        validator,
        loader,
        journal,
        denied,
        confirmed,
        probes(healthy_probe),
        [] { return "2026-09-18T13:30:00Z"; }};
    clear_file(trace);
    const auto denied_result = denied_service.activate(request(2));
    test.check(
        denied_result.status == firewall::ActivationStatus::authorization_denied,
        "denied authorization prevents activation");
    test.check(read_file(trace).empty(), "denied request never invokes PF load");
    test.check(
        revisions.last_known_good().revision == std::optional<std::uint64_t>{1},
        "denied request leaves last known good unchanged");

    const firewall::PfActivationService successful_service{
        revisions,
        validator,
        loader,
        journal,
        authorized,
        confirmed,
        probes(healthy_probe),
        [] { return "2026-09-18T13:31:00Z"; }};
    clear_file(trace);
    const auto committed = successful_service.activate(request(2));
    test.check(committed.ok(), "healthy confirmed activation commits");
    test.check(
        committed.event_id == "GH-ACT-0007",
        "committed activation has stable final event ID");
    test.check(
        revisions.last_known_good().revision == std::optional<std::uint64_t>{2},
        "confirmed revision becomes last known good");
    test.check(
        read_file(trace).find("00000000000000000002.pf.conf") !=
            std::string::npos,
        "target revision is loaded through native adapter");
    test.check(
        read_file(journal.journal_path()).find("approval-reference-42") ==
            std::string::npos,
        "authorization reference is not copied into the journal");

    const firewall::PfActivationService unhealthy_service{
        revisions,
        validator,
        loader,
        journal,
        authorized,
        confirmed,
        probes(unhealthy_probe),
        [] { return "2026-09-18T13:32:00Z"; }};
    clear_file(trace);
    const auto unhealthy = unhealthy_service.activate(request(5));
    test.check(
        unhealthy.status ==
            firewall::ActivationStatus::verification_failed_rolled_back,
        "failed health probe rolls activation back");
    test.check(unhealthy.rollback_performed, "probe failure performs rollback");
    const auto unhealthy_trace = read_file(trace);
    test.check(
        unhealthy_trace.find("00000000000000000005.pf.conf") !=
                std::string::npos &&
            unhealthy_trace.find("00000000000000000002.pf.conf") !=
                std::string::npos,
        "probe failure loads target then prior last known good");
    test.check(
        revisions.last_known_good().revision == std::optional<std::uint64_t>{2},
        "probe failure preserves prior last known good");

    const firewall::PfActivationService timeout_service{
        revisions,
        validator,
        loader,
        journal,
        authorized,
        timed_out,
        probes(healthy_probe),
        [] { return "2026-09-18T13:33:00Z"; }};
    clear_file(trace);
    const auto confirmation_timeout = timeout_service.activate(request(5));
    test.check(
        confirmation_timeout.status ==
            firewall::ActivationStatus::confirmation_failed_rolled_back,
        "confirmation timeout rolls activation back");
    test.check(
        confirmation_timeout.confirmation->status ==
            firewall::ConfirmationStatus::timed_out,
        "confirmation timeout remains distinguishable");

    clear_file(trace);
    const auto invalid_native = successful_service.activate(request(4));
    test.check(
        invalid_native.status ==
            firewall::ActivationStatus::native_revalidation_failed,
        "revision is revalidated immediately before activation");
    test.check(
        read_file(trace).empty(),
        "failed native revalidation prevents PF mutation");

    clear_file(trace);
    const auto load_failed = successful_service.activate(request(3));
    test.check(
        load_failed.status == firewall::ActivationStatus::activation_failed,
        "native load failure is reported");
    test.check(
        load_failed.rollback_performed,
        "ambiguous native load failure still restores last known good");
    test.check(
        read_file(trace).find("00000000000000000002.pf.conf") !=
            std::string::npos,
        "load failure invokes last-known-good rollback");

    const auto empty_revision_root = temporary.path() / "empty-revisions";
    const auto empty_journal_root = temporary.path() / "empty-journal";
    create_private_directory(empty_revision_root);
    create_private_directory(empty_journal_root);
    const firewall::RevisionStore empty_revisions{empty_revision_root};
    const logging::OperationJournal empty_journal{empty_journal_root};
    const firewall::PfActivationService no_rollback_service{
        empty_revisions,
        validator,
        loader,
        empty_journal,
        authorized,
        confirmed,
        probes(healthy_probe)};
    test.check(
        no_rollback_service.activate(request(2)).status ==
            firewall::ActivationStatus::last_known_good_unavailable,
        "activation is impossible without a rollback revision");

    const auto unsafe_journal_root = temporary.path() / "unsafe-journal";
    std::filesystem::create_directory(unsafe_journal_root);
    std::filesystem::permissions(
        unsafe_journal_root,
        std::filesystem::perms::all,
        std::filesystem::perm_options::replace);
    const logging::OperationJournal unsafe_journal{unsafe_journal_root};
    const firewall::PfActivationService fail_closed_service{
        revisions,
        validator,
        loader,
        unsafe_journal,
        authorized,
        confirmed,
        probes(healthy_probe)};
    clear_file(trace);
    test.check(
        fail_closed_service.activate(request(5)).status ==
            firewall::ActivationStatus::audit_failed,
        "audit failure before mutation fails closed");
    test.check(
        read_file(trace).empty(),
        "pre-activation audit failure never loads PF");

    const auto late_journal_root = temporary.path() / "late-journal";
    create_private_directory(late_journal_root);
    const logging::OperationJournal late_journal{late_journal_root};
    const CallbackProbe audit_breaking_probe{
        "audit-breaker",
        [&late_journal_root] {
            std::filesystem::permissions(
                late_journal_root,
                std::filesystem::perms::all,
                std::filesystem::perm_options::replace);
            return firewall::HealthProbeResult{
                .status = firewall::HealthProbeStatus::healthy,
                .message = "probe completed"};
        }};
    const firewall::PfActivationService late_audit_service{
        revisions,
        validator,
        loader,
        late_journal,
        authorized,
        confirmed,
        probes(audit_breaking_probe)};
    clear_file(trace);
    const auto late_audit = late_audit_service.activate(request(5));
    test.check(
        late_audit.status ==
            firewall::ActivationStatus::audit_failed_rolled_back,
        "audit failure after mutation triggers rollback");
    test.check(
        late_audit.rollback_performed,
        "late audit failure restores PF despite unavailable journal");
    test.check(
        revisions.last_known_good().revision == std::optional<std::uint64_t>{2},
        "late audit failure preserves last known good");

    const auto broken_revision_root = temporary.path() / "broken-revisions";
    const auto broken_candidate_root = temporary.path() / "broken-candidates";
    const auto broken_journal_root = temporary.path() / "broken-journal";
    create_private_directory(broken_revision_root);
    create_private_directory(broken_candidate_root);
    create_private_directory(broken_journal_root);
    const firewall::RevisionStore broken_revisions{broken_revision_root};
    const auto broken_previous = broken_candidate_root / "10.pf.conf";
    const auto good_target = broken_candidate_root / "11.pf.conf";
    write_private_file(broken_previous, "FAKE_LOAD_FAIL\n");
    write_private_file(good_target, "block all\n");
    test.check(
        broken_revisions.store(10, broken_previous).ok() &&
            broken_revisions.store(11, good_target).ok() &&
            broken_revisions.mark_last_known_good(10).ok(),
        "rollback-failure fixture is prepared");
    const logging::OperationJournal broken_journal{broken_journal_root};
    const firewall::PfActivationService broken_rollback_service{
        broken_revisions,
        validator,
        loader,
        broken_journal,
        authorized,
        confirmed,
        probes(unhealthy_probe)};
    test.check(
        broken_rollback_service.activate(request(11)).status ==
            firewall::ActivationStatus::rollback_failed,
        "failed rollback is escalated as critical terminal state");

    const ConcurrencyTrackingAuthorizer concurrency_authorizer;
    const auto concurrency_journal_root = temporary.path() / "concurrency-journal";
    create_private_directory(concurrency_journal_root);
    const logging::OperationJournal concurrency_journal{concurrency_journal_root};
    const firewall::PfActivationService serialized_service{
        revisions,
        validator,
        loader,
        concurrency_journal,
        concurrency_authorizer,
        confirmed,
        probes(healthy_probe)};
    std::array<firewall::ActivationResult, 2> concurrent_results;
    std::array<std::thread, 2> activation_threads{
        std::thread{[&] { concurrent_results[0] = serialized_service.activate(request(5)); }},
        std::thread{[&] { concurrent_results[1] = serialized_service.activate(request(5)); }}};
    for (auto& thread : activation_threads) {
        thread.join();
    }
    test.check(
        concurrency_authorizer.maximum_calls() == 1,
        "one activation-service instance serializes concurrent requests");
    const int committed_count =
        (concurrent_results[0].ok() ? 1 : 0) +
        (concurrent_results[1].ok() ? 1 : 0);
    test.check(
        committed_count == 1,
        "exactly one concurrent request commits the target revision");

    const firewall::PfActivationService no_probe_service{
        revisions,
        validator,
        loader,
        journal,
        authorized,
        confirmed,
        {}};
    test.check(
        no_probe_service.activate(request(5)).status ==
            firewall::ActivationStatus::invalid_request,
        "activation without health probes is rejected");

    ::unsetenv("GATEHOLD_FAKE_PFCTL_TRACE");
    return test.result();
}
