#include "gatehold/daemon/read_only_activation_policy.hpp"
#include "gatehold/firewall/activation_service.hpp"
#include "gatehold/firewall/activation_transaction_store.hpp"
#include "gatehold/firewall/native_validator.hpp"
#include "gatehold/firewall/pfctl_loader.hpp"
#include "gatehold/firewall/revision_store.hpp"
#include "gatehold/logging/operation_journal.hpp"
#include "temporary_directory.hpp"
#include "test_support.hpp"

#include <chrono>
#include <filesystem>
#include <fstream>
#include <functional>
#include <string>
#include <vector>

namespace daemon_api = sasd::gatehold::daemon;
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

}  // namespace

int main() {
    gatehold::test::Context test;
    const daemon_api::ReadOnlyActivationAuthorizer authorizer;
    const auto authorization = authorizer.authorize(
        "operation-17", 17, "highly-sensitive-approval-reference");
    test.check(
        authorization.status == firewall::AuthorizationStatus::denied &&
            authorization.decision_id.empty(),
        "bootstrap authorizer always denies without inventing a decision");

    const daemon_api::UnavailableConfirmationGate confirmation;
    test.check(
        confirmation
                .await_confirmation(
                    "operation-17", 17, std::chrono::seconds{10})
                .status == firewall::ConfirmationStatus::unavailable,
        "bootstrap confirmation provider cannot confirm activation");

    const daemon_api::FailClosedActivationHealthProbe probe;
    test.check(
        probe.id() == "read-only-daemon" &&
            probe.run(std::chrono::seconds{1}).status ==
                firewall::HealthProbeStatus::execution_error,
        "bootstrap health probe cannot report false health");

    const gatehold::test::TemporaryDirectory temporary{
        "gatehold-read-only-policy-test"};
    const auto journal_root = temporary.path() / "journal";
    const auto revision_root = temporary.path() / "revisions";
    const auto transaction_root = temporary.path() / "transactions";
    create_private_directory(journal_root);
    create_private_directory(revision_root);
    create_private_directory(transaction_root);

    const logging::OperationJournal journal{journal_root};
    const firewall::RevisionStore revisions{revision_root};
    const firewall::ActivationTransactionStore transactions{transaction_root};
    const firewall::PfctlValidator validator{
        "/definitely/not/a/pfctl-binary"};
    const firewall::PfctlLoader loader{
        "/definitely/not/a/pfctl-binary"};
    const std::vector<std::reference_wrapper<const firewall::HealthProbe>> probes{
        std::cref(probe)};
    const auto timestamp = [] { return "2026-09-19T16:00:00Z"; };
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

    const auto result = activation_service.activate({
        .operation_id = "operation-17",
        .revision = 17,
        .authorization_reference = "highly-sensitive-approval-reference",
        .probe_timeout = std::chrono::seconds{1},
        .confirmation_timeout = std::chrono::seconds{10}});
    test.check(
        result.status == firewall::ActivationStatus::authorization_denied &&
            result.authorization.has_value() &&
            !result.native_validation.has_value() &&
            !result.activation.has_value() &&
            !result.transaction.has_value() &&
            !result.rollback_performed,
        "valid activation is denied before validation, mutation, or transaction");
    test.check(
        !std::filesystem::exists(transactions.transaction_path()),
        "denied bootstrap activation leaves no pending transaction");

    const auto journal_text = read_file(journal.journal_path());
    test.check(
        journal_text.find("GH-AUTH-1001") != std::string::npos &&
            journal_text.find("highly-sensitive-approval-reference") ==
                std::string::npos &&
            journal_text.find("/definitely/not/a/pfctl-binary") ==
                std::string::npos,
        "denial is audited without authorization references or executable paths");

    return test.result();
}
