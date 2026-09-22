#include "gatehold/daemon/config.hpp"

#include <sys/un.h>

#include <array>
#include <charconv>
#include <cstdint>
#include <limits>
#include <optional>
#include <string_view>
#include <utility>

namespace sasd::gatehold::daemon {
namespace {

DaemonConfigResult invalid(std::string message) {
    return {
        .status = DaemonConfigStatus::invalid,
        .command = DaemonCommand::help,
        .config = std::nullopt,
        .event_id = "GH-DMN-1001",
        .message = std::move(message)};
}

bool safe_absolute_path(const std::filesystem::path& path) {
    const auto native = path.native();
    return path.is_absolute() && path != path.root_path() &&
           path.lexically_normal() == path &&
           native.find('\0') == std::string::npos;
}

bool is_same_or_ancestor(
    const std::filesystem::path& possible_ancestor,
    const std::filesystem::path& path) {
    auto ancestor_part = possible_ancestor.begin();
    auto path_part = path.begin();
    for (; ancestor_part != possible_ancestor.end();
         ++ancestor_part, ++path_part) {
        if (path_part == path.end() || *ancestor_part != *path_part) {
            return false;
        }
    }
    return true;
}

bool paths_overlap(
    const std::filesystem::path& left,
    const std::filesystem::path& right) {
    return is_same_or_ancestor(left, right) || is_same_or_ancestor(right, left);
}

template <typename Id>
std::optional<Id> parse_id(std::string_view value) {
    std::uintmax_t parsed = 0;
    const auto conversion =
        std::from_chars(value.data(), value.data() + value.size(), parsed);
    if (value.empty() || value.front() == '+' || value.front() == '-' ||
        conversion.ec != std::errc{} ||
        conversion.ptr != value.data() + value.size() ||
        parsed > static_cast<std::uintmax_t>(
                     std::numeric_limits<Id>::max())) {
        return std::nullopt;
    }
    return static_cast<Id>(parsed);
}

struct ParsedOptions {
    std::optional<std::filesystem::path> journal_root;
    std::optional<std::filesystem::path> revision_root;
    std::optional<std::filesystem::path> transaction_root;
    std::optional<std::filesystem::path> socket_path;
    std::optional<uid_t> allowed_user_id;
    std::optional<gid_t> allowed_group_id;
    bool allowed_group_seen{false};
};

template <typename Value>
bool assign_once(std::optional<Value>& destination, Value value) {
    if (destination.has_value()) {
        return false;
    }
    destination = std::move(value);
    return true;
}

}  // namespace

bool DaemonConfigResult::ok() const noexcept {
    return status == DaemonConfigStatus::parsed;
}

DaemonConfigResult parse_daemon_arguments(
    std::span<const std::string_view> arguments) {
    if (arguments.size() == 1U &&
        (arguments[0] == "--help" || arguments[0] == "-h")) {
        return {
            .status = DaemonConfigStatus::help_requested,
            .command = DaemonCommand::help,
            .config = std::nullopt,
            .event_id = "GH-DMN-0001",
            .message = "Daemon help requested."};
    }
    if (arguments.size() == 1U &&
        (arguments[0] == "--version" || arguments[0] == "-V")) {
        return {
            .status = DaemonConfigStatus::version_requested,
            .command = DaemonCommand::version,
            .config = std::nullopt,
            .event_id = "GH-DMN-0001",
            .message = "Daemon version requested."};
    }
    if (arguments.empty() || arguments[0] != "serve-read-only") {
        return invalid("Expected the explicit serve-read-only command.");
    }

    ParsedOptions options;
    for (std::size_t index = 1U; index < arguments.size();) {
        const auto option = arguments[index];
        if (index + 1U >= arguments.size()) {
            return invalid("A daemon option is missing its value.");
        }
        const auto value = arguments[index + 1U];
        if (value.empty()) {
            return invalid("Daemon option values must not be empty.");
        }

        bool assigned = false;
        if (option == "--journal-root") {
            assigned = assign_once(
                options.journal_root, std::filesystem::path{value});
        } else if (option == "--revision-root") {
            assigned = assign_once(
                options.revision_root, std::filesystem::path{value});
        } else if (option == "--transaction-root") {
            assigned = assign_once(
                options.transaction_root, std::filesystem::path{value});
        } else if (option == "--socket-path") {
            assigned = assign_once(
                options.socket_path, std::filesystem::path{value});
        } else if (option == "--allowed-uid") {
            const auto parsed = parse_id<uid_t>(value);
            if (!parsed.has_value()) {
                return invalid("Allowed UID must be an unsigned numeric identifier.");
            }
            assigned = assign_once(options.allowed_user_id, *parsed);
        } else if (option == "--allowed-gid") {
            if (options.allowed_group_seen) {
                return invalid("Each daemon option may be specified only once.");
            }
            options.allowed_group_seen = true;
            const auto parsed = parse_id<gid_t>(value);
            if (!parsed.has_value()) {
                return invalid("Allowed GID must be an unsigned numeric identifier.");
            }
            options.allowed_group_id = *parsed;
            assigned = true;
        } else {
            return invalid("Unknown daemon option.");
        }
        if (!assigned) {
            return invalid("Each daemon option may be specified only once.");
        }
        index += 2U;
    }

    if (!options.journal_root.has_value() ||
        !options.revision_root.has_value() ||
        !options.transaction_root.has_value() ||
        !options.socket_path.has_value() ||
        !options.allowed_user_id.has_value()) {
        return invalid("Required daemon options are missing.");
    }

    const std::array roots{
        *options.journal_root,
        *options.revision_root,
        *options.transaction_root};
    for (const auto& root : roots) {
        if (!safe_absolute_path(root)) {
            return invalid(
                "Daemon storage roots must be normalized absolute non-root paths.");
        }
    }
    if (paths_overlap(roots[0], roots[1]) ||
        paths_overlap(roots[0], roots[2]) ||
        paths_overlap(roots[1], roots[2])) {
        return invalid("Daemon storage roots must not overlap.");
    }

    const auto& socket_path = *options.socket_path;
    if (!safe_absolute_path(socket_path) ||
        socket_path.filename().empty() ||
        socket_path.native().size() >= sizeof(sockaddr_un::sun_path)) {
        return invalid("Controller socket path is outside safe bounds.");
    }
    const auto socket_parent = socket_path.parent_path();
    for (const auto& root : roots) {
        if (paths_overlap(socket_parent, root)) {
            return invalid(
                "Controller socket directory must be separate from storage roots.");
        }
    }

    return {
        .status = DaemonConfigStatus::parsed,
        .command = DaemonCommand::serve_read_only,
        .config = DaemonConfig{
            .journal_root = std::move(*options.journal_root),
            .revision_root = std::move(*options.revision_root),
            .transaction_root = std::move(*options.transaction_root),
            .socket_path = std::move(*options.socket_path),
            .allowed_user_id = *options.allowed_user_id,
            .allowed_group_id = options.allowed_group_id},
        .event_id = "GH-DMN-0001",
        .message = "Read-only daemon arguments parsed."};
}

DaemonIdentityResult validate_daemon_identity(
    const DaemonConfig& config,
    uid_t effective_user_id,
    gid_t effective_group_id) {
    if (!config.allowed_group_id.has_value()) {
        if (config.allowed_user_id != effective_user_id) {
            return {
                .valid = false,
                .socket_mode = 0600,
                .socket_group_id = std::nullopt,
                .event_id = "GH-DMN-1002",
                .message =
                    "Mode 0600 requires the allowed UID to equal the daemon UID."};
        }
        return {
            .valid = true,
            .socket_mode = 0600,
            .socket_group_id = std::nullopt,
            .event_id = "GH-DMN-0001",
            .message = "Daemon UID can access the private controller socket."};
    }

    if (*config.allowed_group_id != effective_group_id &&
        effective_user_id != 0U) {
        return {
            .valid = false,
            .socket_mode = 0600,
            .socket_group_id = std::nullopt,
            .event_id = "GH-DMN-1002",
            .message =
                "Only root may delegate the controller socket to another GID."};
    }
    return {
        .valid = true,
        .socket_mode = 0660,
        .socket_group_id = config.allowed_group_id,
        .event_id = "GH-DMN-0001",
        .message = "Configured API group can access the controller socket."};
}

}  // namespace sasd::gatehold::daemon
