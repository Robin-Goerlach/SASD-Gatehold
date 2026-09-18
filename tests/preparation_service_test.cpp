#include "gatehold/firewall/candidate_store.hpp"
#include "gatehold/firewall/preparation_service.hpp"
#include "gatehold/logging/operation_journal.hpp"
#include "temporary_directory.hpp"
#include "test_support.hpp"

#include <chrono>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <string>
#include <utility>

namespace firewall = sasd::gatehold::firewall;
namespace logging = sasd::gatehold::logging;

namespace {

firewall::RuleSet valid_ruleset(std::string description = "Allow HTTPS") {
    firewall::Rule rule{
        .id = "allow-lan-https",
        .description = std::move(description),
        .action = firewall::Action::pass,
        .direction = firewall::Direction::inbound,
        .address_family = firewall::AddressFamily::inet,
        .interface = "em1",
        .protocol = firewall::Protocol::tcp,
        .source = firewall::Endpoint{.network = "192.0.2.0/24"},
        .destination = firewall::Endpoint{.network = "any", .port = 443},
        .log = true,
        .quick = true,
        .enabled = true};
    return {.revision = 42, .rules = {std::move(rule)}};
}

std::string read_file(const std::filesystem::path& path) {
    std::ifstream input{path};
    return {
        std::istreambuf_iterator<char>{input},
        std::istreambuf_iterator<char>{}};
}

void create_private_directory(const std::filesystem::path& path) {
    std::filesystem::create_directory(path);
    std::filesystem::permissions(
        path,
        std::filesystem::perms::owner_all,
        std::filesystem::perm_options::replace);
}

}  // namespace

int main(int argc, char* argv[]) {
    gatehold::test::Context test;
    test.check(argc == 2, "test receives the fake pfctl executable path");
    if (argc != 2) {
        return test.result();
    }

    const gatehold::test::TemporaryDirectory temporary{"gatehold-prepare-test"};
    const auto staging_root = temporary.path() / "staging";
    const auto journal_root = temporary.path() / "journal";
    create_private_directory(staging_root);
    create_private_directory(journal_root);

    const firewall::CandidateStore store{staging_root};
    const firewall::PfctlValidator validator{
        std::filesystem::absolute(std::filesystem::path{argv[1]}),
        std::chrono::milliseconds{1000}};
    const logging::OperationJournal journal{journal_root};
    const firewall::PfPreparationService service{
        store,
        validator,
        journal,
        [] { return "2026-09-18T12:00:00Z"; }};

    const firewall::PreparationRequest valid_request{
        .operation_id = "op-prepare-valid", .rule_set = valid_ruleset()};
    const auto prepared = service.prepare(valid_request);
    test.check(prepared.ok(), "valid ruleset reaches prepared state");
    test.check(
        prepared.journaled_events.size() == 7U,
        "successful preparation journals all seven transitions");
    test.check(
        std::filesystem::is_regular_file(prepared.candidate_path),
        "prepared candidate remains available for review");
    test.check(
        prepared.event_id == "GH-OP-0005",
        "prepared operation has a stable final event ID");

    const auto journal_text = read_file(journal.journal_path());
    test.check(
        journal_text.find("GH-OP-0001") != std::string::npos &&
            journal_text.find("GH-OP-0005") != std::string::npos,
        "journal records operation start and prepared completion");
    test.check(
        journal_text.find("fake pfctl") == std::string::npos,
        "native diagnostic output is excluded from audit journal");

    auto invalid_rules = valid_ruleset();
    invalid_rules.rules.front().interface = "em0\npass all";
    const auto invalid = service.prepare(
        {.operation_id = "op-invalid-model", .rule_set = std::move(invalid_rules)});
    test.check(
        invalid.status == firewall::PreparationStatus::invalid_model,
        "invalid model is rejected before staging");
    test.check(
        !std::filesystem::exists(staging_root / "op-invalid-model.pf.conf"),
        "invalid model creates no candidate file");
    test.check(
        invalid.journaled_events.size() == 2U,
        "model rejection is journaled after operation start");

    const auto rejected = service.prepare(
        {.operation_id = "op-native-reject",
         .rule_set = valid_ruleset("FAKE_REJECT")});
    test.check(
        rejected.status == firewall::PreparationStatus::native_rejected,
        "native syntax rejection stops preparation");
    test.check(
        rejected.event_id == "GH-PF-1002",
        "native rejection retains its stable event ID");

    const auto timeout_stage = temporary.path() / "timeout-stage";
    create_private_directory(timeout_stage);
    const firewall::CandidateStore timeout_store{timeout_stage};
    const firewall::PfctlValidator timeout_validator{
        std::filesystem::absolute(std::filesystem::path{argv[1]}),
        std::chrono::milliseconds{30}};
    const firewall::PfPreparationService timeout_service{
        timeout_store,
        timeout_validator,
        journal,
        [] { return "2026-09-18T12:00:00Z"; }};
    const auto timed_out = timeout_service.prepare(
        {.operation_id = "op-native-timeout",
         .rule_set = valid_ruleset("FAKE_SLEEP")});
    test.check(
        timed_out.status == firewall::PreparationStatus::native_timed_out,
        "native validation timeout stops preparation");
    test.check(
        timed_out.event_id == "GH-PF-2002",
        "native timeout retains its stable event ID");

    const auto duplicate = service.prepare(valid_request);
    test.check(
        duplicate.status == firewall::PreparationStatus::staging_failed,
        "write-once operation ID prevents duplicate preparation");
    test.check(
        duplicate.event_id == "GH-STAGE-1004",
        "duplicate candidate has a stable staging error ID");

    const auto missing_stage = temporary.path() / "missing-stage";
    create_private_directory(missing_stage);
    const firewall::CandidateStore missing_store{missing_stage};
    const firewall::PfctlValidator missing_validator{
        temporary.path() / "missing-pfctl", std::chrono::milliseconds{100}};
    const firewall::PfPreparationService missing_service{
        missing_store,
        missing_validator,
        journal,
        [] { return "2026-09-18T12:00:00Z"; }};
    const auto execution_error = missing_service.prepare(
        {.operation_id = "op-missing-pfctl", .rule_set = valid_ruleset()});
    test.check(
        execution_error.status ==
            firewall::PreparationStatus::native_execution_error,
        "missing pfctl stops preparation as execution error");

    const auto unsafe_journal_root = temporary.path() / "unsafe-journal";
    std::filesystem::create_directory(unsafe_journal_root);
    std::filesystem::permissions(
        unsafe_journal_root,
        std::filesystem::perms::all,
        std::filesystem::perm_options::replace);
    const auto fail_closed_stage = temporary.path() / "fail-closed-stage";
    create_private_directory(fail_closed_stage);
    const firewall::CandidateStore fail_closed_store{fail_closed_stage};
    const logging::OperationJournal unsafe_journal{unsafe_journal_root};
    const firewall::PfPreparationService fail_closed_service{
        fail_closed_store,
        validator,
        unsafe_journal,
        [] { return "2026-09-18T12:00:00Z"; }};
    const auto audit_failed = fail_closed_service.prepare(
        {.operation_id = "op-audit-failed", .rule_set = valid_ruleset()});
    test.check(
        audit_failed.status == firewall::PreparationStatus::audit_failed,
        "unsafe audit journal fails the operation closed");
    test.check(
        !std::filesystem::exists(
            fail_closed_stage / "op-audit-failed.pf.conf"),
        "audit failure occurs before candidate staging");

    return test.result();
}
