#include "gatehold/firewall/activation_transaction_store.hpp"
#include "temporary_directory.hpp"
#include "test_support.hpp"

#include <atomic>
#include <filesystem>
#include <fstream>
#include <string>
#include <thread>
#include <vector>

namespace firewall = sasd::gatehold::firewall;

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

firewall::PendingActivation transaction(
    std::string operation_id = "activation-42") {
    return {
        .operation_id = std::move(operation_id),
        .target_revision = 42,
        .rollback_revision = 41,
        .phase = firewall::ActivationPhase::prepared_for_load};
}

}  // namespace

int main() {
    gatehold::test::Context test;
    const gatehold::test::TemporaryDirectory temporary{"gatehold-txn-test"};
    const auto root = temporary.path() / "transactions";
    create_private_directory(root);

    const firewall::ActivationTransactionStore store{root};
    auto invalid = transaction();
    invalid.target_revision = 0;
    test.check(
        store.begin(invalid).status ==
            firewall::ActivationTransactionStatus::invalid_record,
        "zero target revision is rejected");

    const auto created = store.begin(transaction());
    test.check(created.ok(), "pending transaction is created durably");
    test.check(
        created.event_id == "GH-TXN-0001",
        "transaction creation has stable event ID");
    const auto permissions =
        std::filesystem::status(store.transaction_path()).permissions();
    test.check(
        (permissions &
         (std::filesystem::perms::group_all |
          std::filesystem::perms::others_all)) ==
            std::filesystem::perms::none,
        "pending transaction is private");
    test.check(
        store.begin(transaction("other-operation")).status ==
            firewall::ActivationTransactionStatus::conflict,
        "existing transaction provides a system-wide conflict guard");

    const auto loaded = store.load();
    test.check(
        loaded.status == firewall::ActivationTransactionStatus::loaded &&
            loaded.transaction->operation_id == "activation-42" &&
            loaded.transaction->target_revision == 42 &&
            loaded.transaction->rollback_revision == 41,
        "pending transaction round-trips exactly");
    test.check(
        store.advance("other-operation", firewall::ActivationPhase::target_loaded)
                .status ==
            firewall::ActivationTransactionStatus::invalid_transition,
        "another operation cannot advance pending state");
    test.check(
        store.advance("activation-42", firewall::ActivationPhase::verified)
                .status ==
            firewall::ActivationTransactionStatus::invalid_transition,
        "transaction phases cannot be skipped");

    const std::vector<firewall::ActivationPhase> phases{
        firewall::ActivationPhase::target_loaded,
        firewall::ActivationPhase::verified,
        firewall::ActivationPhase::awaiting_confirmation,
        firewall::ActivationPhase::committing,
        firewall::ActivationPhase::committed};
    for (const auto phase : phases) {
        const auto advanced = store.advance("activation-42", phase);
        test.check(advanced.ok(), "transaction advances one durable phase");
        test.check(
            advanced.transaction->phase == phase,
            "advanced phase is returned accurately");
    }
    test.check(
        store.clear("other-operation").status ==
            firewall::ActivationTransactionStatus::conflict,
        "another operation cannot clear pending state");
    test.check(store.clear("activation-42").ok(), "owner operation clears state");
    test.check(
        store.load().status == firewall::ActivationTransactionStatus::no_pending,
        "cleared transaction is absent");

    write_private_file(store.transaction_path(), "malformed\n");
    test.check(
        store.load().status ==
            firewall::ActivationTransactionStatus::invalid_record,
        "malformed transaction is rejected without guessing");
    std::filesystem::remove(store.transaction_path());

    const auto symlink_target = temporary.path() / "external-transaction";
    write_private_file(symlink_target, "untouched\n");
    std::filesystem::create_symlink(symlink_target, store.transaction_path());
    test.check(
        store.load().status == firewall::ActivationTransactionStatus::unsafe_file,
        "symlink transaction is rejected");
    std::filesystem::remove(store.transaction_path());

    const auto concurrent_root = temporary.path() / "concurrent-transactions";
    create_private_directory(concurrent_root);
    const firewall::ActivationTransactionStore concurrent_store{concurrent_root};
    std::atomic<int> created_count{0};
    std::atomic<int> conflict_count{0};
    std::vector<std::thread> threads;
    for (int index = 0; index < 6; ++index) {
        threads.emplace_back([&, index] {
            const auto result = concurrent_store.begin(
                transaction("concurrent-" + std::to_string(index)));
            if (result.status == firewall::ActivationTransactionStatus::created) {
                ++created_count;
            } else if (
                result.status == firewall::ActivationTransactionStatus::conflict) {
                ++conflict_count;
            }
        });
    }
    for (auto& thread : threads) {
        thread.join();
    }
    test.check(created_count.load() == 1, "exactly one concurrent begin wins");
    test.check(
        conflict_count.load() == 5,
        "all other concurrent begins observe the durable lock");

    const auto unsafe_root = temporary.path() / "unsafe-transactions";
    std::filesystem::create_directory(unsafe_root);
    std::filesystem::permissions(
        unsafe_root,
        std::filesystem::perms::all,
        std::filesystem::perm_options::replace);
    test.check(
        firewall::ActivationTransactionStore{unsafe_root}
                .begin(transaction())
                .status == firewall::ActivationTransactionStatus::unsafe_root,
        "group/world-writable transaction root is rejected");

    return test.result();
}
