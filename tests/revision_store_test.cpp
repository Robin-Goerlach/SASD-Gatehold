#include "gatehold/firewall/revision_store.hpp"
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

}  // namespace

int main() {
    gatehold::test::Context test;
    const gatehold::test::TemporaryDirectory temporary{"gatehold-revision-test"};
    const auto root = temporary.path() / "revisions";
    const auto candidates = temporary.path() / "candidates";
    create_private_directory(root);
    create_private_directory(candidates);

    const firewall::RevisionStore store{root};
    const auto candidate_one = candidates / "one.pf.conf";
    const std::string content_one = "block log all\n";
    write_private_file(candidate_one, content_one);

    test.check(
        store.store(0, candidate_one).status ==
            firewall::RevisionStatus::invalid_revision,
        "revision zero is rejected");

    const auto stored_one = store.store(1, candidate_one);
    test.check(stored_one.ok(), "first revision is stored");
    test.check(
        stored_one.revision_path.filename() == "00000000000000000001.pf.conf",
        "revision filename is deterministic and fixed width");
    test.check(store.load(1).content == content_one, "stored revision is readable");

    const auto duplicate = store.store(1, candidate_one);
    test.check(
        duplicate.status == firewall::RevisionStatus::already_exists,
        "existing revision cannot be overwritten");
    test.check(
        store.load(1).content == content_one,
        "duplicate attempt leaves original revision unchanged");
    test.check(
        store.load(99).status == firewall::RevisionStatus::not_found,
        "missing revision is reported explicitly");

    const auto linked_source = candidates / "linked.pf.conf";
    std::filesystem::create_symlink(candidate_one, linked_source);
    test.check(
        store.store(2, linked_source).status ==
            firewall::RevisionStatus::unsafe_source,
        "symlink candidate is rejected");

    const auto public_source = candidates / "public.pf.conf";
    write_private_file(public_source, "block all\n");
    std::filesystem::permissions(
        public_source,
        std::filesystem::perms::group_read,
        std::filesystem::perm_options::add);
    test.check(
        store.store(2, public_source).status ==
            firewall::RevisionStatus::unsafe_source,
        "group-readable candidate is rejected");

    const auto oversized = candidates / "oversized.pf.conf";
    write_private_file(oversized, "x");
    std::filesystem::resize_file(
        oversized, firewall::RevisionStore::maximum_revision_size + 1U);
    test.check(
        store.store(2, oversized).status == firewall::RevisionStatus::too_large,
        "oversized candidate is rejected");

    const auto candidate_two = candidates / "two.pf.conf";
    const std::string content_two = "block all\npass on em1\n";
    write_private_file(candidate_two, content_two);
    test.check(store.store(2, candidate_two).ok(), "second revision is stored");

    const auto mark_one = store.mark_last_known_good(1);
    test.check(mark_one.ok(), "first revision can be marked last known good");
    const auto marker_permissions =
        std::filesystem::status(root / "last-known-good").permissions();
    test.check(
        (marker_permissions &
         (std::filesystem::perms::group_all | std::filesystem::perms::others_all)) ==
            std::filesystem::perms::none,
        "last-known-good marker is private");
    test.check(
        store.last_known_good().revision == std::optional<std::uint64_t>{1},
        "last-known-good marker resolves to first revision");

    const auto mark_two = store.mark_last_known_good(2);
    test.check(mark_two.ok(), "last-known-good marker can advance atomically");
    test.check(
        store.last_known_good().revision == std::optional<std::uint64_t>{2},
        "last-known-good marker resolves to second revision");
    test.check(
        store.load(1).content == content_one,
        "advancing marker does not modify prior immutable revision");
    test.check(
        store.mark_last_known_good(99).status == firewall::RevisionStatus::not_found,
        "missing revision cannot become last known good");

    write_private_file(root / "last-known-good", "not-a-revision\n");
    test.check(
        store.last_known_good().status == firewall::RevisionStatus::corrupt_pointer,
        "malformed last-known-good marker is rejected");

    const auto external_target = temporary.path() / "external-target";
    write_private_file(external_target, "untouched\n");
    std::filesystem::remove(root / "last-known-good");
    std::filesystem::create_symlink(external_target, root / "last-known-good");
    test.check(
        store.last_known_good().status == firewall::RevisionStatus::corrupt_pointer,
        "symlink last-known-good marker is rejected");
    test.check(
        store.mark_last_known_good(1).ok(),
        "atomic marker update replaces a hostile symlink itself");
    std::ifstream external_input{external_target};
    std::string external_content;
    std::getline(external_input, external_content);
    test.check(
        external_content == "untouched",
        "hostile symlink target is never modified");

    const auto candidate_three = candidates / "three.pf.conf";
    write_private_file(candidate_three, "block in all\n");
    std::atomic<int> stored_count{0};
    std::atomic<int> duplicate_count{0};
    std::vector<std::thread> threads;
    for (int index = 0; index < 4; ++index) {
        threads.emplace_back([&]() {
            const auto result = store.store(3, candidate_three);
            if (result.ok()) {
                ++stored_count;
            } else if (result.status == firewall::RevisionStatus::already_exists) {
                ++duplicate_count;
            }
        });
    }
    for (auto& thread : threads) {
        thread.join();
    }
    test.check(stored_count.load() == 1, "exactly one concurrent immutable store wins");
    test.check(
        duplicate_count.load() == 3,
        "all other concurrent stores observe existing revision");

    const auto unsafe_root = temporary.path() / "unsafe-revisions";
    std::filesystem::create_directory(unsafe_root);
    std::filesystem::permissions(
        unsafe_root,
        std::filesystem::perms::all,
        std::filesystem::perm_options::replace);
    test.check(
        firewall::RevisionStore{unsafe_root}.store(1, candidate_one).status ==
            firewall::RevisionStatus::unsafe_root,
        "group/world-writable revision root is rejected");

    return test.result();
}
