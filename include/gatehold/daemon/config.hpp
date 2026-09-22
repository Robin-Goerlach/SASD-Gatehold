#pragma once

#include <sys/types.h>

#include <filesystem>
#include <optional>
#include <span>
#include <string>
#include <string_view>

namespace sasd::gatehold::daemon {

enum class DaemonCommand { help, version, serve_read_only };

struct DaemonConfig {
    std::filesystem::path journal_root;
    std::filesystem::path revision_root;
    std::filesystem::path transaction_root;
    std::filesystem::path socket_path;
    uid_t allowed_user_id{0};
    std::optional<gid_t> allowed_group_id;
};

enum class DaemonConfigStatus { parsed, help_requested, version_requested, invalid };

struct DaemonConfigResult {
    DaemonConfigStatus status{DaemonConfigStatus::invalid};
    DaemonCommand command{DaemonCommand::help};
    std::optional<DaemonConfig> config;
    std::string event_id;
    std::string message;

    [[nodiscard]] bool ok() const noexcept;
};

struct DaemonIdentityResult {
    bool valid{false};
    mode_t socket_mode{0600};
    std::optional<gid_t> socket_group_id{};
    std::string event_id;
    std::string message;
};

[[nodiscard]] DaemonConfigResult parse_daemon_arguments(
    std::span<const std::string_view> arguments);
[[nodiscard]] DaemonIdentityResult validate_daemon_identity(
    const DaemonConfig& config,
    uid_t effective_user_id,
    gid_t effective_group_id);

}  // namespace sasd::gatehold::daemon
