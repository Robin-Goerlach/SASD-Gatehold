#include "gatehold/daemon/process_lock.hpp"

#include <fcntl.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cerrno>
#include <string_view>
#include <utility>

namespace sasd::gatehold::daemon {
namespace {

constexpr std::string_view lock_filename = ".gateholdd.lock";

DaemonProcessLockResult failure(
    DaemonProcessLockStatus status,
    std::string event_id,
    std::string message) {
    return {
        .status = status,
        .lock = std::nullopt,
        .event_id = std::move(event_id),
        .message = std::move(message)};
}

bool safe_directory(const struct stat& status, uid_t user_id) noexcept {
    return S_ISDIR(status.st_mode) && status.st_uid == user_id &&
           (status.st_mode & (S_IWGRP | S_IWOTH)) == 0;
}

bool safe_lock_file(const struct stat& status, uid_t user_id) noexcept {
    return S_ISREG(status.st_mode) && status.st_uid == user_id &&
           status.st_nlink == 1 &&
           (status.st_mode & (S_IRWXU | S_IRWXG | S_IRWXO)) ==
               (S_IRUSR | S_IWUSR);
}

void close_descriptor(int& descriptor) noexcept {
    if (descriptor >= 0) {
        static_cast<void>(::close(descriptor));
        descriptor = -1;
    }
}

}  // namespace

DaemonProcessLock::DaemonProcessLock(int descriptor) noexcept
    : descriptor_{descriptor} {}

DaemonProcessLock::~DaemonProcessLock() {
    close_descriptor(descriptor_);
}

DaemonProcessLock::DaemonProcessLock(DaemonProcessLock&& other) noexcept
    : descriptor_{std::exchange(other.descriptor_, -1)} {}

DaemonProcessLock& DaemonProcessLock::operator=(
    DaemonProcessLock&& other) noexcept {
    if (this != &other) {
        close_descriptor(descriptor_);
        descriptor_ = std::exchange(other.descriptor_, -1);
    }
    return *this;
}

bool DaemonProcessLock::owns_lock() const noexcept {
    return descriptor_ >= 0;
}

DaemonProcessLockResult DaemonProcessLock::acquire(
    const std::filesystem::path& transaction_root,
    uid_t effective_user_id) {
    const int directory_descriptor = ::open(
        transaction_root.c_str(),
        O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (directory_descriptor < 0) {
        return failure(
            DaemonProcessLockStatus::io_error,
            "GH-DMN-2003",
            "Daemon process-lock directory could not be opened safely.");
    }

    struct stat directory_status {};
    if (::fstat(directory_descriptor, &directory_status) != 0 ||
        !safe_directory(directory_status, effective_user_id)) {
        static_cast<void>(::close(directory_descriptor));
        return failure(
            DaemonProcessLockStatus::unsafe_lock_file,
            "GH-DMN-1006",
            "Daemon process-lock directory is unsafe.");
    }

    struct stat existing_status {};
    const int existing_result = ::fstatat(
        directory_descriptor,
        lock_filename.data(),
        &existing_status,
        AT_SYMLINK_NOFOLLOW);
    if (existing_result == 0 &&
        !safe_lock_file(existing_status, effective_user_id)) {
        static_cast<void>(::close(directory_descriptor));
        return failure(
            DaemonProcessLockStatus::unsafe_lock_file,
            "GH-DMN-1006",
            "Daemon process-lock entry is unsafe.");
    }
    if (existing_result != 0 && errno != ENOENT) {
        static_cast<void>(::close(directory_descriptor));
        return failure(
            DaemonProcessLockStatus::io_error,
            "GH-DMN-2003",
            "Daemon process-lock entry could not be inspected.");
    }

    int lock_descriptor = ::openat(
        directory_descriptor,
        lock_filename.data(),
        O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW,
        S_IRUSR | S_IWUSR);
    if (lock_descriptor < 0) {
        const bool unsafe_entry = errno == ELOOP || errno == EISDIR;
        static_cast<void>(::close(directory_descriptor));
        return failure(
            unsafe_entry ? DaemonProcessLockStatus::unsafe_lock_file
                         : DaemonProcessLockStatus::io_error,
            unsafe_entry ? "GH-DMN-1006" : "GH-DMN-2003",
            unsafe_entry ? "Daemon process-lock entry is unsafe."
                         : "Daemon process lock could not be opened.");
    }

    struct stat opened_status {};
    if (::fstat(lock_descriptor, &opened_status) != 0 ||
        !safe_lock_file(opened_status, effective_user_id)) {
        static_cast<void>(::close(lock_descriptor));
        static_cast<void>(::close(directory_descriptor));
        return failure(
            DaemonProcessLockStatus::unsafe_lock_file,
            "GH-DMN-1006",
            "Daemon process-lock entry is unsafe.");
    }

    if (::flock(lock_descriptor, LOCK_EX | LOCK_NB) != 0) {
        const bool contended = errno == EWOULDBLOCK || errno == EAGAIN;
        static_cast<void>(::close(lock_descriptor));
        static_cast<void>(::close(directory_descriptor));
        return failure(
            contended ? DaemonProcessLockStatus::already_running
                      : DaemonProcessLockStatus::io_error,
            contended ? "GH-DMN-1005" : "GH-DMN-2003",
            contended ? "Another daemon instance owns the process lock."
                      : "Daemon process lock could not be acquired.");
    }

    struct stat named_status {};
    const bool stable = ::fstatat(
                            directory_descriptor,
                            lock_filename.data(),
                            &named_status,
                            AT_SYMLINK_NOFOLLOW) == 0 &&
                        safe_lock_file(named_status, effective_user_id) &&
                        named_status.st_dev == opened_status.st_dev &&
                        named_status.st_ino == opened_status.st_ino;
    const int directory_close_status = ::close(directory_descriptor);
    if (!stable || directory_close_status != 0) {
        static_cast<void>(::flock(lock_descriptor, LOCK_UN));
        static_cast<void>(::close(lock_descriptor));
        return failure(
            DaemonProcessLockStatus::io_error,
            "GH-DMN-2003",
            "Daemon process-lock identity changed during acquisition.");
    }

    return {
        .status = DaemonProcessLockStatus::acquired,
        .lock = DaemonProcessLock{lock_descriptor},
        .event_id = "GH-DMN-0004",
        .message = "Daemon process exclusivity lock acquired."};
}

bool DaemonProcessLockResult::ok() const noexcept {
    return status == DaemonProcessLockStatus::acquired && lock.has_value() &&
           lock->owns_lock();
}

}  // namespace sasd::gatehold::daemon
