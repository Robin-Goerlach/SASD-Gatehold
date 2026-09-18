#include "gatehold/firewall/candidate_store.hpp"

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>
#include <string>
#include <utility>

namespace sasd::gatehold::firewall {
namespace {

bool is_ascii_alphanumeric(char value) noexcept {
    return (value >= '0' && value <= '9') ||
           (value >= 'A' && value <= 'Z') ||
           (value >= 'a' && value <= 'z');
}

bool is_valid_operation_id(std::string_view value) noexcept {
    if (value.empty() || value.size() > 64U ||
        !is_ascii_alphanumeric(value.front())) {
        return false;
    }

    for (const char character : value) {
        if (!is_ascii_alphanumeric(character) && character != '-' &&
            character != '_' && character != '.') {
            return false;
        }
    }
    return true;
}

StageResult failure(
    StageStatus status,
    std::string event_id,
    std::string message) {
    return {
        .status = status,
        .candidate_path = {},
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

}  // namespace

bool StageResult::ok() const noexcept {
    return status == StageStatus::staged;
}

CandidateStore::CandidateStore(std::filesystem::path root_directory)
    : root_directory_{std::move(root_directory)} {}

const std::filesystem::path& CandidateStore::root_directory() const noexcept {
    return root_directory_;
}

StageResult CandidateStore::stage(
    std::string_view operation_id,
    std::string_view candidate) const {
    if (!is_valid_operation_id(operation_id)) {
        return failure(
            StageStatus::invalid_operation_id,
            "GH-STAGE-1001",
            "Operation ID contains unsupported characters or has an invalid length.");
    }

    if (candidate.size() > maximum_candidate_size ||
        candidate.find('\0') != std::string_view::npos) {
        return failure(
            StageStatus::invalid_content,
            "GH-STAGE-1002",
            "Candidate is too large or contains a NUL byte.");
    }

    if (!root_directory_.is_absolute()) {
        return failure(
            StageStatus::unsafe_root,
            "GH-STAGE-1003",
            "Staging root must be an absolute path.");
    }

    struct stat root_status {};
    if (::lstat(root_directory_.c_str(), &root_status) != 0 ||
        !S_ISDIR(root_status.st_mode) || root_status.st_uid != ::geteuid() ||
        (root_status.st_mode & (S_IWGRP | S_IWOTH)) != 0) {
        return failure(
            StageStatus::unsafe_root,
            "GH-STAGE-1003",
            "Staging root must be a non-symlink directory owned by the current user and not group/world writable.");
    }

    const int directory_descriptor = ::open(
        root_directory_.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (directory_descriptor < 0) {
        return failure(
            StageStatus::unsafe_root,
            "GH-STAGE-1003",
            "Staging root could not be opened safely.");
    }

    const std::string filename = std::string{operation_id} + ".pf.conf";
    const int candidate_descriptor = ::openat(
        directory_descriptor,
        filename.c_str(),
        O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
        S_IRUSR | S_IWUSR);

    if (candidate_descriptor < 0) {
        const int open_error = errno;
        ::close(directory_descriptor);
        if (open_error == EEXIST) {
            return failure(
                StageStatus::already_exists,
                "GH-STAGE-1004",
                "A candidate already exists for this operation ID.");
        }
        return failure(
            StageStatus::io_error,
            "GH-STAGE-2001",
            std::string{"Could not create candidate: "} + std::strerror(open_error));
    }

    bool successful = write_all(candidate_descriptor, candidate);
    if (successful && ::fsync(candidate_descriptor) != 0) {
        successful = false;
    }
    if (::close(candidate_descriptor) != 0) {
        successful = false;
    }
    if (successful && ::fsync(directory_descriptor) != 0) {
        successful = false;
    }

    if (!successful) {
        const int write_error = errno;
        ::unlinkat(directory_descriptor, filename.c_str(), 0);
        ::close(directory_descriptor);
        return failure(
            StageStatus::io_error,
            "GH-STAGE-2002",
            std::string{"Could not persist candidate: "} + std::strerror(write_error));
    }

    ::close(directory_descriptor);
    return {
        .status = StageStatus::staged,
        .candidate_path = root_directory_ / filename,
        .event_id = "GH-STAGE-0001",
        .message = "PF candidate staged successfully."};
}

}  // namespace sasd::gatehold::firewall
