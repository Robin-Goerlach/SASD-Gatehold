#include "gatehold/logging/operation_journal.hpp"

#include "gatehold/logging/json_event_formatter.hpp"

#include <fcntl.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cerrno>
#include <cstdint>
#include <cstring>
#include <string>
#include <string_view>
#include <utility>

namespace sasd::gatehold::logging {
namespace {

constexpr std::string_view journal_filename = "operations.jsonl";

JournalResult failure(
    JournalStatus status,
    std::string event_id,
    std::string message) {
    return {
        .status = status,
        .event_id = std::move(event_id),
        .message = std::move(message)};
}

bool write_all(int descriptor, std::string_view content) noexcept {
    std::size_t offset = 0;
    while (offset < content.size()) {
        const auto written = ::write(
            descriptor,
            content.data() + offset,
            content.size() - offset);
        if (written < 0) {
            if (errno == EINTR) {
                continue;
            }
            return false;
        }
        if (written == 0) {
            errno = EIO;
            return false;
        }
        offset += static_cast<std::size_t>(written);
    }
    return true;
}

bool has_required_fields(const Event& event) noexcept {
    return !event.timestamp.empty() && !event.event_id.empty() &&
           !event.component.empty() && !event.operation_id.empty() &&
           !event.action.empty() && !event.outcome.empty();
}

}  // namespace

bool JournalResult::ok() const noexcept {
    return status == JournalStatus::appended;
}

OperationJournal::OperationJournal(std::filesystem::path root_directory)
    : root_directory_{std::move(root_directory)} {}

std::filesystem::path OperationJournal::journal_path() const {
    return root_directory_ / journal_filename;
}

JournalResult OperationJournal::append(const Event& event) const {
    if (!has_required_fields(event)) {
        return failure(
            JournalStatus::invalid_event,
            "GH-AUDIT-1001",
            "Audit event is missing one or more required fields.");
    }

    std::string serialized = JsonEventFormatter{}.format(event);
    if (serialized.size() + 1U > maximum_entry_size) {
        return failure(
            JournalStatus::invalid_event,
            "GH-AUDIT-1002",
            "Serialized audit event exceeds the maximum entry size.");
    }
    serialized.push_back('\n');

    if (!root_directory_.is_absolute()) {
        return failure(
            JournalStatus::unsafe_root,
            "GH-AUDIT-1003",
            "Audit root must be an absolute path.");
    }

    struct stat root_status {};
    if (::lstat(root_directory_.c_str(), &root_status) != 0 ||
        !S_ISDIR(root_status.st_mode) || root_status.st_uid != ::geteuid() ||
        (root_status.st_mode & (S_IWGRP | S_IWOTH)) != 0) {
        return failure(
            JournalStatus::unsafe_root,
            "GH-AUDIT-1003",
            "Audit root must be a non-symlink directory owned by the current user and not group/world writable.");
    }

    const int directory_descriptor = ::open(
        root_directory_.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (directory_descriptor < 0) {
        return failure(
            JournalStatus::unsafe_root,
            "GH-AUDIT-1003",
            "Audit root could not be opened safely.");
    }

    const int journal_descriptor = ::openat(
        directory_descriptor,
        journal_filename.data(),
        O_WRONLY | O_APPEND | O_CREAT | O_CLOEXEC | O_NOFOLLOW,
        S_IRUSR | S_IWUSR);
    if (journal_descriptor < 0) {
        const int open_error = errno;
        ::close(directory_descriptor);
        return failure(
            JournalStatus::unsafe_journal,
            "GH-AUDIT-1004",
            std::string{"Audit journal could not be opened safely: "} +
                std::strerror(open_error));
    }

    struct stat journal_status {};
    if (::fstat(journal_descriptor, &journal_status) != 0 ||
        !S_ISREG(journal_status.st_mode) ||
        journal_status.st_uid != ::geteuid() ||
        (journal_status.st_mode & (S_IRWXG | S_IRWXO)) != 0) {
        ::close(journal_descriptor);
        ::close(directory_descriptor);
        return failure(
            JournalStatus::unsafe_journal,
            "GH-AUDIT-1004",
            "Audit journal must be a private regular file owned by the current user.");
    }

    bool successful = ::flock(journal_descriptor, LOCK_EX) == 0;
    if (successful) {
        struct stat locked_status {};
        successful = ::fstat(journal_descriptor, &locked_status) == 0;
        if (successful) {
            const auto current_size = locked_status.st_size < 0
                                          ? maximum_journal_size
                                          : static_cast<std::uintmax_t>(
                                                locked_status.st_size);
            if (current_size + serialized.size() > maximum_journal_size) {
                ::flock(journal_descriptor, LOCK_UN);
                ::close(journal_descriptor);
                ::close(directory_descriptor);
                return failure(
                    JournalStatus::capacity_exceeded,
                    "GH-AUDIT-1005",
                    "Audit journal reached its size limit and must be rotated.");
            }
        }
    }
    if (successful) {
        successful = write_all(journal_descriptor, serialized);
    }
    if (successful) {
        successful = ::fsync(journal_descriptor) == 0;
    }
    const int append_error = successful ? 0 : errno;
    ::flock(journal_descriptor, LOCK_UN);
    if (::close(journal_descriptor) != 0 && successful) {
        successful = false;
    }
    if (successful && ::fsync(directory_descriptor) != 0) {
        successful = false;
    }
    ::close(directory_descriptor);

    if (!successful) {
        return failure(
            JournalStatus::io_error,
            "GH-AUDIT-2001",
            std::string{"Could not append and synchronize audit event: "} +
                std::strerror(append_error == 0 ? EIO : append_error));
    }

    return {
        .status = JournalStatus::appended,
        .event_id = "GH-AUDIT-0001",
        .message = "Audit event appended successfully."};
}

}  // namespace sasd::gatehold::logging
