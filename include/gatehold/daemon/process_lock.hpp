#pragma once

#include <sys/types.h>

#include <filesystem>
#include <optional>
#include <string>

namespace sasd::gatehold::daemon {

enum class DaemonProcessLockStatus {
    acquired,
    already_running,
    unsafe_lock_file,
    io_error
};

struct DaemonProcessLockResult;

class DaemonProcessLock {
public:
    ~DaemonProcessLock();

    DaemonProcessLock(const DaemonProcessLock&) = delete;
    DaemonProcessLock& operator=(const DaemonProcessLock&) = delete;
    DaemonProcessLock(DaemonProcessLock&& other) noexcept;
    DaemonProcessLock& operator=(DaemonProcessLock&& other) noexcept;

    [[nodiscard]] static DaemonProcessLockResult acquire(
        const std::filesystem::path& transaction_root,
        uid_t effective_user_id);
    [[nodiscard]] bool owns_lock() const noexcept;

private:
    explicit DaemonProcessLock(int descriptor) noexcept;

    int descriptor_{-1};
};

struct DaemonProcessLockResult {
    DaemonProcessLockStatus status{DaemonProcessLockStatus::io_error};
    std::optional<DaemonProcessLock> lock;
    std::string event_id;
    std::string message;

    [[nodiscard]] bool ok() const noexcept;
};

}  // namespace sasd::gatehold::daemon
