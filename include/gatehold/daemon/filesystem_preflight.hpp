#pragma once

#include "gatehold/daemon/config.hpp"

#include <sys/types.h>

#include <string>

namespace sasd::gatehold::daemon {

enum class DaemonDirectoryRole {
    none,
    journal,
    revisions,
    transactions,
    socket_parent
};

[[nodiscard]] std::string to_string(DaemonDirectoryRole role);

enum class DaemonFilesystemStatus {
    ready,
    unsafe_directory,
    socket_path_occupied,
    io_error
};

struct DaemonFilesystemResult {
    DaemonFilesystemStatus status{DaemonFilesystemStatus::io_error};
    DaemonDirectoryRole failed_role{DaemonDirectoryRole::none};
    bool journal_root_ready{false};
    std::string event_id;
    std::string message;

    [[nodiscard]] bool ok() const noexcept;
};

[[nodiscard]] DaemonFilesystemResult preflight_daemon_filesystem(
    const DaemonConfig& config,
    mode_t socket_mode,
    uid_t effective_user_id);

}  // namespace sasd::gatehold::daemon
