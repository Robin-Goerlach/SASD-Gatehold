#include "gatehold/firewall/revision_store.hpp"

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <atomic>
#include <cerrno>
#include <charconv>
#include <cstring>
#include <iomanip>
#include <sstream>
#include <string>
#include <string_view>
#include <utility>

namespace sasd::gatehold::firewall {
namespace {

constexpr std::string_view last_known_good_filename = "last-known-good";
std::atomic<std::uint64_t> temporary_sequence{0};

std::string revision_filename(std::uint64_t revision) {
    std::ostringstream output;
    output << std::setfill('0') << std::setw(20) << revision << ".pf.conf";
    return output.str();
}

RevisionWriteResult write_failure(
    RevisionStatus status,
    std::string event_id,
    std::string message) {
    return {
        .status = status,
        .event_id = std::move(event_id),
        .message = std::move(message),
        .revision_path = {}};
}

RevisionReadResult read_failure(
    RevisionStatus status,
    std::string event_id,
    std::string message) {
    return {
        .status = status,
        .event_id = std::move(event_id),
        .message = std::move(message),
        .content = {}};
}

LastKnownGoodResult pointer_failure(
    RevisionStatus status,
    std::string event_id,
    std::string message) {
    return {
        .status = status,
        .event_id = std::move(event_id),
        .message = std::move(message),
        .revision = std::nullopt};
}

bool safe_root(const std::filesystem::path& root) noexcept {
    struct stat status {};
    return root.is_absolute() && ::lstat(root.c_str(), &status) == 0 &&
           S_ISDIR(status.st_mode) && status.st_uid == ::geteuid() &&
           (status.st_mode & (S_IWGRP | S_IWOTH)) == 0;
}

int open_root(const std::filesystem::path& root) noexcept {
    return ::open(root.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
}

bool private_regular_file(const struct stat& status) noexcept {
    return S_ISREG(status.st_mode) && status.st_uid == ::geteuid() &&
           (status.st_mode & (S_IRWXG | S_IRWXO)) == 0;
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

bool read_all(int descriptor, std::size_t size, std::string& output) {
    output.clear();
    output.reserve(size);
    std::string buffer(4096U, '\0');
    while (output.size() < size) {
        const auto remaining = size - output.size();
        const auto count = ::read(
            descriptor,
            buffer.data(),
            std::min(remaining, buffer.size()));
        if (count < 0) {
            if (errno == EINTR) {
                continue;
            }
            return false;
        }
        if (count == 0) {
            errno = EIO;
            return false;
        }
        output.append(buffer.data(), static_cast<std::size_t>(count));
    }
    return true;
}

}  // namespace

bool RevisionWriteResult::ok() const noexcept {
    return status == RevisionStatus::stored;
}

bool RevisionReadResult::ok() const noexcept {
    return status == RevisionStatus::loaded;
}

bool LastKnownGoodResult::ok() const noexcept {
    return status == RevisionStatus::marked_last_known_good ||
           status == RevisionStatus::last_known_good_found;
}

RevisionStore::RevisionStore(std::filesystem::path root_directory)
    : root_directory_{std::move(root_directory)} {}

std::filesystem::path RevisionStore::revision_path(
    std::uint64_t revision) const {
    return root_directory_ / revision_filename(revision);
}

RevisionWriteResult RevisionStore::store(
    std::uint64_t revision,
    const std::filesystem::path& validated_candidate) const {
    if (revision == 0) {
        return write_failure(
            RevisionStatus::invalid_revision,
            "GH-REV-1001",
            "Revision number must be greater than zero.");
    }
    if (!safe_root(root_directory_)) {
        return write_failure(
            RevisionStatus::unsafe_root,
            "GH-REV-1002",
            "Revision root is not a safe owner-controlled directory.");
    }

    const int source_descriptor = ::open(
        validated_candidate.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (source_descriptor < 0) {
        return write_failure(
            RevisionStatus::unsafe_source,
            "GH-REV-1003",
            "Validated candidate could not be opened safely.");
    }

    struct stat source_status {};
    if (::fstat(source_descriptor, &source_status) != 0 ||
        !private_regular_file(source_status)) {
        ::close(source_descriptor);
        return write_failure(
            RevisionStatus::unsafe_source,
            "GH-REV-1003",
            "Validated candidate must be a private regular file owned by the current user.");
    }
    if (source_status.st_size < 0 ||
        static_cast<std::uintmax_t>(source_status.st_size) > maximum_revision_size) {
        ::close(source_descriptor);
        return write_failure(
            RevisionStatus::too_large,
            "GH-REV-1004",
            "Validated candidate exceeds the revision size limit.");
    }

    std::string content;
    const auto content_size = static_cast<std::size_t>(source_status.st_size);
    if (!read_all(source_descriptor, content_size, content)) {
        const int read_error = errno;
        ::close(source_descriptor);
        return write_failure(
            RevisionStatus::io_error,
            "GH-REV-2001",
            std::string{"Could not read validated candidate: "} +
                std::strerror(read_error));
    }
    ::close(source_descriptor);

    const int directory_descriptor = open_root(root_directory_);
    if (directory_descriptor < 0) {
        return write_failure(
            RevisionStatus::unsafe_root,
            "GH-REV-1002",
            "Revision root could not be opened safely.");
    }

    const std::string filename = revision_filename(revision);
    const int revision_descriptor = ::openat(
        directory_descriptor,
        filename.c_str(),
        O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
        S_IRUSR);
    if (revision_descriptor < 0) {
        const int open_error = errno;
        ::close(directory_descriptor);
        if (open_error == EEXIST) {
            return write_failure(
                RevisionStatus::already_exists,
                "GH-REV-1005",
                "Revision already exists and is immutable.");
        }
        return write_failure(
            RevisionStatus::io_error,
            "GH-REV-2002",
            std::string{"Could not create revision: "} + std::strerror(open_error));
    }

    bool successful = write_all(revision_descriptor, content);
    if (successful && ::fsync(revision_descriptor) != 0) {
        successful = false;
    }
    if (::close(revision_descriptor) != 0) {
        successful = false;
    }
    if (successful && ::fsync(directory_descriptor) != 0) {
        successful = false;
    }
    if (!successful) {
        const int write_error = errno;
        ::unlinkat(directory_descriptor, filename.c_str(), 0);
        ::close(directory_descriptor);
        return write_failure(
            RevisionStatus::io_error,
            "GH-REV-2003",
            std::string{"Could not persist revision: "} +
                std::strerror(write_error));
    }
    ::close(directory_descriptor);

    return {
        .status = RevisionStatus::stored,
        .event_id = "GH-REV-0001",
        .message = "Validated PF revision stored immutably.",
        .revision_path = revision_path(revision)};
}

RevisionReadResult RevisionStore::load(std::uint64_t revision) const {
    if (revision == 0) {
        return read_failure(
            RevisionStatus::invalid_revision,
            "GH-REV-1001",
            "Revision number must be greater than zero.");
    }
    if (!safe_root(root_directory_)) {
        return read_failure(
            RevisionStatus::unsafe_root,
            "GH-REV-1002",
            "Revision root is not a safe owner-controlled directory.");
    }

    const int directory_descriptor = open_root(root_directory_);
    if (directory_descriptor < 0) {
        return read_failure(
            RevisionStatus::unsafe_root,
            "GH-REV-1002",
            "Revision root could not be opened safely.");
    }
    const std::string filename = revision_filename(revision);
    const int descriptor =
        ::openat(directory_descriptor, filename.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (descriptor < 0) {
        const int open_error = errno;
        ::close(directory_descriptor);
        return read_failure(
            open_error == ENOENT ? RevisionStatus::not_found
                                 : RevisionStatus::io_error,
            open_error == ENOENT ? "GH-REV-1006" : "GH-REV-2004",
            open_error == ENOENT
                ? "Revision was not found."
                : std::string{"Could not open revision: "} +
                      std::strerror(open_error));
    }

    struct stat status {};
    if (::fstat(descriptor, &status) != 0 || !private_regular_file(status)) {
        ::close(descriptor);
        ::close(directory_descriptor);
        return read_failure(
            RevisionStatus::unsafe_source,
            "GH-REV-1007",
            "Revision file failed type, ownership, or permission checks.");
    }
    if (status.st_size < 0 ||
        static_cast<std::uintmax_t>(status.st_size) > maximum_revision_size) {
        ::close(descriptor);
        ::close(directory_descriptor);
        return read_failure(
            RevisionStatus::too_large,
            "GH-REV-1004",
            "Stored revision exceeds the revision size limit.");
    }

    std::string content;
    const auto size = static_cast<std::size_t>(status.st_size);
    const bool successful = read_all(descriptor, size, content);
    const int read_error = successful ? 0 : errno;
    ::close(descriptor);
    ::close(directory_descriptor);
    if (!successful) {
        return read_failure(
            RevisionStatus::io_error,
            "GH-REV-2005",
            std::string{"Could not read revision: "} +
                std::strerror(read_error));
    }

    return {
        .status = RevisionStatus::loaded,
        .event_id = "GH-REV-0002",
        .message = "PF revision loaded successfully.",
        .content = std::move(content)};
}

LastKnownGoodResult RevisionStore::mark_last_known_good(
    std::uint64_t revision) const {
    const auto existing = load(revision);
    if (!existing.ok()) {
        return pointer_failure(
            existing.status,
            existing.event_id,
            "Cannot mark a revision that is unavailable or unsafe.");
    }

    const int directory_descriptor = open_root(root_directory_);
    if (directory_descriptor < 0) {
        return pointer_failure(
            RevisionStatus::unsafe_root,
            "GH-REV-1002",
            "Revision root could not be opened safely.");
    }

    const auto sequence = temporary_sequence.fetch_add(1U);
    const std::string temporary_name =
        ".last-known-good." + std::to_string(revision) + "." +
        std::to_string(::getpid()) + "." + std::to_string(sequence) + ".tmp";
    const int descriptor = ::openat(
        directory_descriptor,
        temporary_name.c_str(),
        O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
        S_IRUSR | S_IWUSR);
    if (descriptor < 0) {
        const int open_error = errno;
        ::close(directory_descriptor);
        return pointer_failure(
            RevisionStatus::io_error,
            "GH-REV-2006",
            std::string{"Could not create last-known-good marker: "} +
                std::strerror(open_error));
    }

    const std::string content = std::to_string(revision) + "\n";
    bool successful = write_all(descriptor, content);
    if (successful && ::fsync(descriptor) != 0) {
        successful = false;
    }
    if (::close(descriptor) != 0) {
        successful = false;
    }
    if (successful &&
        ::renameat(
            directory_descriptor,
            temporary_name.c_str(),
            directory_descriptor,
            last_known_good_filename.data()) != 0) {
        successful = false;
    }
    if (successful && ::fsync(directory_descriptor) != 0) {
        successful = false;
    }
    if (!successful) {
        const int write_error = errno;
        ::unlinkat(directory_descriptor, temporary_name.c_str(), 0);
        ::close(directory_descriptor);
        return pointer_failure(
            RevisionStatus::io_error,
            "GH-REV-2007",
            std::string{"Could not atomically update last-known-good marker: "} +
                std::strerror(write_error));
    }
    ::close(directory_descriptor);

    return {
        .status = RevisionStatus::marked_last_known_good,
        .event_id = "GH-REV-0003",
        .message = "Revision marked as last known good.",
        .revision = revision};
}

LastKnownGoodResult RevisionStore::last_known_good() const {
    if (!safe_root(root_directory_)) {
        return pointer_failure(
            RevisionStatus::unsafe_root,
            "GH-REV-1002",
            "Revision root is not a safe owner-controlled directory.");
    }

    const int directory_descriptor = open_root(root_directory_);
    if (directory_descriptor < 0) {
        return pointer_failure(
            RevisionStatus::unsafe_root,
            "GH-REV-1002",
            "Revision root could not be opened safely.");
    }
    const int descriptor = ::openat(
        directory_descriptor,
        last_known_good_filename.data(),
        O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (descriptor < 0) {
        const int open_error = errno;
        ::close(directory_descriptor);
        return pointer_failure(
            open_error == ENOENT ? RevisionStatus::not_found
                                 : RevisionStatus::corrupt_pointer,
            open_error == ENOENT ? "GH-REV-1008" : "GH-REV-1009",
            open_error == ENOENT
                ? "No last-known-good revision is recorded."
                : "Last-known-good marker could not be opened safely.");
    }

    struct stat status {};
    if (::fstat(descriptor, &status) != 0 || !private_regular_file(status) ||
        status.st_size < 2 || status.st_size > 32) {
        ::close(descriptor);
        ::close(directory_descriptor);
        return pointer_failure(
            RevisionStatus::corrupt_pointer,
            "GH-REV-1009",
            "Last-known-good marker failed validation.");
    }

    std::string content;
    const bool read_successful = read_all(
        descriptor, static_cast<std::size_t>(status.st_size), content);
    ::close(descriptor);
    ::close(directory_descriptor);
    if (!read_successful || content.empty() || content.back() != '\n') {
        return pointer_failure(
            RevisionStatus::corrupt_pointer,
            "GH-REV-1009",
            "Last-known-good marker is incomplete or malformed.");
    }

    content.pop_back();
    std::uint64_t revision = 0;
    const auto [end, error] = std::from_chars(
        content.data(), content.data() + content.size(), revision);
    if (error != std::errc{} || end != content.data() + content.size() ||
        revision == 0 || !load(revision).ok()) {
        return pointer_failure(
            RevisionStatus::corrupt_pointer,
            "GH-REV-1009",
            "Last-known-good marker references an invalid or unavailable revision.");
    }

    return {
        .status = RevisionStatus::last_known_good_found,
        .event_id = "GH-REV-0004",
        .message = "Last-known-good revision loaded successfully.",
        .revision = revision};
}

}  // namespace sasd::gatehold::firewall
