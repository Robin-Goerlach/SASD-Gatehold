#include "gatehold/logging/event.hpp"
#include "gatehold/logging/operation_journal.hpp"
#include "temporary_directory.hpp"
#include "test_support.hpp"

#include <atomic>
#include <filesystem>
#include <fstream>
#include <string>
#include <thread>
#include <utility>
#include <vector>

namespace logging = sasd::gatehold::logging;

namespace {

logging::Event event_for(std::string operation_id, int sequence) {
    return {
        .timestamp = "2026-09-18T12:00:00Z",
        .severity = logging::Severity::info,
        .event_id = "GH-TEST-0001",
        .component = "operation-journal-test",
        .operation_id = std::move(operation_id),
        .action = "test.append",
        .outcome = "succeeded",
        .message = "Concurrent journal test event.",
        .attributes = {
            {"api_token", "must-not-leak"},
            {"sequence", std::to_string(sequence)}}};
}

std::vector<std::string> read_lines(const std::filesystem::path& path) {
    std::ifstream input{path};
    std::vector<std::string> lines;
    for (std::string line; std::getline(input, line);) {
        lines.push_back(std::move(line));
    }
    return lines;
}

}  // namespace

int main() {
    gatehold::test::Context test;
    const gatehold::test::TemporaryDirectory temporary{"gatehold-journal-test"};
    test.check(!temporary.path().empty(), "temporary directory was created");
    if (temporary.path().empty()) {
        return test.result();
    }

    const auto root = temporary.path() / "journal";
    std::filesystem::create_directory(root);
    std::filesystem::permissions(
        root,
        std::filesystem::perms::owner_all,
        std::filesystem::perm_options::replace);
    const logging::OperationJournal journal{root};

    logging::Event invalid_event;
    test.check(
        journal.append(invalid_event).status == logging::JournalStatus::invalid_event,
        "event without required fields is rejected");

    auto large_event = event_for("large-event", 0);
    large_event.message.assign(logging::OperationJournal::maximum_entry_size, 'x');
    test.check(
        journal.append(large_event).status == logging::JournalStatus::invalid_event,
        "oversized journal entry is rejected");

    test.check(journal.append(event_for("initial", 0)).ok(), "valid event is appended");

    constexpr int thread_count = 4;
    constexpr int events_per_thread = 20;
    std::atomic<int> append_failures{0};
    std::vector<std::thread> threads;
    for (int thread_index = 0; thread_index < thread_count; ++thread_index) {
        threads.emplace_back([&journal, &append_failures, thread_index]() {
            for (int index = 0; index < events_per_thread; ++index) {
                const auto operation = "thread-" + std::to_string(thread_index);
                if (!journal.append(event_for(operation, index)).ok()) {
                    ++append_failures;
                }
            }
        });
    }
    for (auto& thread : threads) {
        thread.join();
    }
    test.check(append_failures.load() == 0, "concurrent appends all succeed");

    const auto lines = read_lines(journal.journal_path());
    test.check(
        lines.size() == 1U +
                            static_cast<std::size_t>(thread_count * events_per_thread),
        "journal contains one complete line per append");
    for (const auto& line : lines) {
        test.check(
            line.starts_with('{') && line.ends_with('}'),
            "each journal line is a complete JSON object");
        test.check(
            line.find("must-not-leak") == std::string::npos,
            "sensitive attribute is redacted before persistence");
    }

    const auto permissions = std::filesystem::status(journal.journal_path()).permissions();
    test.check(
        (permissions &
         (std::filesystem::perms::group_all | std::filesystem::perms::others_all)) ==
            std::filesystem::perms::none,
        "journal is inaccessible to group and others");

    const auto unsafe_root = temporary.path() / "unsafe-root";
    std::filesystem::create_directory(unsafe_root);
    std::filesystem::permissions(
        unsafe_root,
        std::filesystem::perms::all,
        std::filesystem::perm_options::replace);
    test.check(
        logging::OperationJournal{unsafe_root}.append(event_for("unsafe", 1)).status ==
            logging::JournalStatus::unsafe_root,
        "group/world-writable audit root is rejected");

    const auto symlink_root = temporary.path() / "journal-link";
    std::filesystem::create_directory_symlink(root, symlink_root);
    test.check(
        logging::OperationJournal{symlink_root}.append(event_for("link", 1)).status ==
            logging::JournalStatus::unsafe_root,
        "symlink audit root is rejected");

    const auto attack_root = temporary.path() / "attack-root";
    std::filesystem::create_directory(attack_root);
    std::filesystem::permissions(
        attack_root,
        std::filesystem::perms::owner_all,
        std::filesystem::perm_options::replace);
    const auto target = temporary.path() / "do-not-touch";
    {
        std::ofstream output{target};
        output << "unchanged\n";
    }
    std::filesystem::create_symlink(target, attack_root / "operations.jsonl");
    test.check(
        logging::OperationJournal{attack_root}.append(event_for("link-file", 1)).status ==
            logging::JournalStatus::unsafe_journal,
        "symlink journal file is rejected");
    test.check(
        read_lines(target) == std::vector<std::string>{"unchanged"},
        "symlink target remains unchanged");

    const auto full_root = temporary.path() / "full-root";
    std::filesystem::create_directory(full_root);
    std::filesystem::permissions(
        full_root,
        std::filesystem::perms::owner_all,
        std::filesystem::perm_options::replace);
    const logging::OperationJournal full_journal{full_root};
    {
        std::ofstream output{full_journal.journal_path()};
    }
    std::filesystem::permissions(
        full_journal.journal_path(),
        std::filesystem::perms::owner_read | std::filesystem::perms::owner_write,
        std::filesystem::perm_options::replace);
    std::filesystem::resize_file(
        full_journal.journal_path(),
        logging::OperationJournal::maximum_journal_size);
    test.check(
        full_journal.append(event_for("capacity", 1)).status ==
            logging::JournalStatus::capacity_exceeded,
        "journal refuses growth beyond its hard size limit");

    return test.result();
}
