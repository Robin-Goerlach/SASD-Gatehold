#include "gatehold/daemon/filesystem_preflight.hpp"

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <array>
#include <cerrno>
#include <filesystem>
#include <string>
#include <utility>

namespace sasd::gatehold::daemon {
namespace {

struct DirectoryExpectation {
    DaemonDirectoryRole role{DaemonDirectoryRole::none};
    const std::filesystem::path* path{nullptr};
    bool socket_parent{false};
};

DaemonFilesystemResult failure(
    DaemonFilesystemStatus status,
    DaemonDirectoryRole role,
    bool journal_root_ready,
    std::string event_id,
    std::string message) {
    return {
        .status = status,
        .failed_role = role,
        .journal_root_ready = journal_root_ready,
        .event_id = std::move(event_id),
        .message = std::move(message)};
}

DaemonFilesystemResult check_directory(
    const DirectoryExpectation& expected,
    bool journal_root_ready,
    mode_t socket_mode,
    const DaemonConfig& config,
    uid_t effective_user_id) {
    if (expected.path == nullptr) {
        return failure(
            DaemonFilesystemStatus::io_error,
            expected.role,
            journal_root_ready,
            "GH-DMN-2002",
            "Daemon filesystem preflight received an invalid directory role.");
    }

    std::error_code canonical_error;
    const auto canonical_path =
        std::filesystem::canonical(*expected.path, canonical_error);
    struct stat before {};
    if (canonical_error || canonical_path != *expected.path ||
        ::lstat(expected.path->c_str(), &before) != 0 ||
        !S_ISDIR(before.st_mode)) {
        return failure(
            DaemonFilesystemStatus::unsafe_directory,
            expected.role,
            journal_root_ready,
            "GH-DMN-1003",
            "Daemon directory is missing, aliased, or not a directory.");
    }

    const bool unsafe_storage_permissions =
        (before.st_mode & (S_IWGRP | S_IWOTH)) != 0;
    const bool unsafe_socket_permissions =
        expected.socket_parent &&
        ((before.st_mode & S_IWGRP) != 0 ||
         (before.st_mode & S_IRWXO) != 0);
    if (before.st_uid != effective_user_id || unsafe_storage_permissions ||
        unsafe_socket_permissions) {
        return failure(
            DaemonFilesystemStatus::unsafe_directory,
            expected.role,
            journal_root_ready,
            "GH-DMN-1003",
            "Daemon directory ownership or permissions are unsafe.");
    }

    if (expected.socket_parent && socket_mode == 0660 &&
        (!config.allowed_group_id.has_value() ||
         before.st_gid != *config.allowed_group_id ||
         (before.st_mode & S_IXGRP) == 0)) {
        return failure(
            DaemonFilesystemStatus::unsafe_directory,
            expected.role,
            journal_root_ready,
            "GH-DMN-1003",
            "Controller socket directory does not permit the configured group.");
    }

    const int descriptor = ::open(
        expected.path->c_str(),
        O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (descriptor < 0) {
        return failure(
            DaemonFilesystemStatus::io_error,
            expected.role,
            journal_root_ready,
            "GH-DMN-2002",
            "Daemon directory could not be opened without following links.");
    }

    struct stat opened {};
    const bool stable = ::fstat(descriptor, &opened) == 0 &&
                        opened.st_dev == before.st_dev &&
                        opened.st_ino == before.st_ino;
    const int close_status = ::close(descriptor);
    if (!stable || close_status != 0) {
        return failure(
            DaemonFilesystemStatus::io_error,
            expected.role,
            journal_root_ready,
            "GH-DMN-2002",
            "Daemon directory identity changed during preflight.");
    }

    return {
        .status = DaemonFilesystemStatus::ready,
        .failed_role = DaemonDirectoryRole::none,
        .journal_root_ready = journal_root_ready,
        .event_id = "GH-DMN-0003",
        .message = "Daemon directory passed filesystem preflight."};
}

}  // namespace

std::string to_string(DaemonDirectoryRole role) {
    switch (role) {
        case DaemonDirectoryRole::none:
            return "none";
        case DaemonDirectoryRole::journal:
            return "journal";
        case DaemonDirectoryRole::revisions:
            return "revisions";
        case DaemonDirectoryRole::transactions:
            return "transactions";
        case DaemonDirectoryRole::socket_parent:
            return "socket-parent";
    }
    return "unknown";
}

bool DaemonFilesystemResult::ok() const noexcept {
    return status == DaemonFilesystemStatus::ready;
}

DaemonFilesystemResult preflight_daemon_filesystem(
    const DaemonConfig& config,
    mode_t socket_mode,
    uid_t effective_user_id) {
    const auto socket_parent = config.socket_path.parent_path();
    const std::array expectations{
        DirectoryExpectation{
            .role = DaemonDirectoryRole::journal,
            .path = &config.journal_root,
            .socket_parent = false},
        DirectoryExpectation{
            .role = DaemonDirectoryRole::revisions,
            .path = &config.revision_root,
            .socket_parent = false},
        DirectoryExpectation{
            .role = DaemonDirectoryRole::transactions,
            .path = &config.transaction_root,
            .socket_parent = false},
        DirectoryExpectation{
            .role = DaemonDirectoryRole::socket_parent,
            .path = &socket_parent,
            .socket_parent = true}};

    bool journal_root_ready = false;
    for (const auto& expected : expectations) {
        auto checked = check_directory(
            expected,
            journal_root_ready,
            socket_mode,
            config,
            effective_user_id);
        if (!checked.ok()) {
            return checked;
        }
        if (expected.role == DaemonDirectoryRole::journal) {
            journal_root_ready = true;
        }
    }

    struct stat existing {};
    if (::lstat(config.socket_path.c_str(), &existing) == 0) {
        return failure(
            DaemonFilesystemStatus::socket_path_occupied,
            DaemonDirectoryRole::socket_parent,
            true,
            "GH-DMN-1004",
            "Controller socket path is already occupied.");
    }
    if (errno != ENOENT) {
        return failure(
            DaemonFilesystemStatus::io_error,
            DaemonDirectoryRole::socket_parent,
            true,
            "GH-DMN-2002",
            "Controller socket path availability could not be verified.");
    }

    return {
        .status = DaemonFilesystemStatus::ready,
        .failed_role = DaemonDirectoryRole::none,
        .journal_root_ready = true,
        .event_id = "GH-DMN-0003",
        .message = "All daemon directories passed filesystem preflight."};
}

}  // namespace sasd::gatehold::daemon
