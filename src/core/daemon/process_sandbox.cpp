#include "gatehold/daemon/process_sandbox.hpp"

#include <cstddef>
#include <set>
#include <string_view>
#include <utility>

#include <unistd.h>

namespace sasd::gatehold::daemon {
namespace {

constexpr std::string_view daemon_promises =
    "stdio rpath wpath cpath fattr flock unix proc exec";

DaemonSandboxResult result(
    DaemonSandboxStatus status,
    std::string event_id,
    std::string message) {
    return {
        .status = status,
        .event_id = std::move(event_id),
        .message = std::move(message)};
}

bool valid_path(const std::filesystem::path& path) {
    return path.is_absolute() && path != path.root_path() &&
           path.lexically_normal() == path &&
           path.native().find('\0') == std::string::npos;
}

bool valid_permissions(std::string_view permissions) {
    if (permissions.empty() || permissions.size() > 4U) {
        return false;
    }
    std::set<char> seen;
    for (const char permission : permissions) {
        if ((permission != 'r' && permission != 'w' && permission != 'x' &&
             permission != 'c') ||
            !seen.insert(permission).second) {
            return false;
        }
    }
    return true;
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
    return is_same_or_ancestor(left, right) ||
           is_same_or_ancestor(right, left);
}

bool valid_policy(const DaemonSandboxPolicy& policy) {
    if (policy.promises != daemon_promises ||
        policy.unveil_rules.size() != 6U) {
        return false;
    }
    const auto& rules = policy.unveil_rules;
    if (rules[0].permissions != "rwc" || rules[1].permissions != "r" ||
        rules[2].permissions != "rwc" || rules[3].permissions != "rwc" ||
        rules[4] != UnveilRule{"/sbin/pfctl", "x"} ||
        rules[5] != UnveilRule{"/dev/pf", "rw"}) {
        return false;
    }
    std::set<std::filesystem::path> paths;
    for (const auto& rule : policy.unveil_rules) {
        if (!valid_path(rule.path) || !valid_permissions(rule.permissions) ||
            !paths.insert(rule.path).second) {
            return false;
        }
    }
    for (std::size_t left = 0; left < 4U; ++left) {
        for (std::size_t right = left + 1U; right < 4U; ++right) {
            if (paths_overlap(rules[left].path, rules[right].path)) {
                return false;
            }
        }
    }
    return true;
}

}  // namespace

bool DaemonSandboxResult::can_continue() const noexcept {
    return status == DaemonSandboxStatus::applied ||
           status == DaemonSandboxStatus::unsupported;
}

bool DaemonSandboxResult::enforced() const noexcept {
    return status == DaemonSandboxStatus::applied;
}

bool NativeSandboxSystem::supported() const noexcept {
#if defined(__OpenBSD__)
    return true;
#else
    return false;
#endif
}

int NativeSandboxSystem::unveil(
    const char* path,
    const char* permissions) noexcept {
#if defined(__OpenBSD__)
    return ::unveil(path, permissions);
#else
    static_cast<void>(path);
    static_cast<void>(permissions);
    return -1;
#endif
}

int NativeSandboxSystem::pledge(
    const char* promises,
    const char* exec_promises) noexcept {
#if defined(__OpenBSD__)
    return ::pledge(promises, exec_promises);
#else
    static_cast<void>(promises);
    static_cast<void>(exec_promises);
    return -1;
#endif
}

DaemonSandboxPolicy make_read_only_daemon_sandbox_policy(
    const DaemonConfig& config) {
    return {
        .unveil_rules =
            {{config.journal_root, "rwc"},
             {config.revision_root, "r"},
             {config.transaction_root, "rwc"},
             {config.socket_path.parent_path(), "rwc"},
             {"/sbin/pfctl", "x"},
             {"/dev/pf", "rw"}},
        .promises = std::string{daemon_promises}};
}

DaemonSandboxResult apply_daemon_sandbox(
    const DaemonSandboxPolicy& policy,
    SandboxSystem& system) {
    if (!valid_policy(policy)) {
        return result(
            DaemonSandboxStatus::invalid_policy,
            "GH-SBX-1002",
            "Daemon sandbox policy is outside safe bounds.");
    }
    if (!system.supported()) {
        return result(
            DaemonSandboxStatus::unsupported,
            "GH-SBX-1001",
            "Daemon process sandbox is unavailable on this platform.");
    }

    for (const auto& rule : policy.unveil_rules) {
        if (system.unveil(
                rule.path.c_str(), rule.permissions.c_str()) != 0) {
            return result(
                DaemonSandboxStatus::unveil_failed,
                "GH-SBX-2001",
                "Daemon filesystem sandbox could not be applied.");
        }
    }
    if (system.unveil(nullptr, nullptr) != 0) {
        return result(
            DaemonSandboxStatus::unveil_lock_failed,
            "GH-SBX-2002",
            "Daemon filesystem sandbox could not be locked.");
    }
    if (system.pledge(policy.promises.c_str(), nullptr) != 0) {
        return result(
            DaemonSandboxStatus::pledge_failed,
            "GH-SBX-2003",
            "Daemon system-call sandbox could not be applied.");
    }
    return result(
        DaemonSandboxStatus::applied,
        "GH-SBX-0001",
        "Daemon process sandbox applied and locked.");
}

}  // namespace sasd::gatehold::daemon
