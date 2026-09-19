#pragma once

#include "gatehold/daemon/config.hpp"

#include <filesystem>
#include <string>
#include <vector>

namespace sasd::gatehold::daemon {

struct UnveilRule {
    std::filesystem::path path;
    std::string permissions;

    friend bool operator==(const UnveilRule&, const UnveilRule&) = default;
};

struct DaemonSandboxPolicy {
    std::vector<UnveilRule> unveil_rules;
    std::string promises;
};

enum class DaemonSandboxStatus {
    applied,
    unsupported,
    invalid_policy,
    unveil_failed,
    unveil_lock_failed,
    pledge_failed
};

struct DaemonSandboxResult {
    DaemonSandboxStatus status{DaemonSandboxStatus::invalid_policy};
    std::string event_id;
    std::string message;

    [[nodiscard]] bool can_continue() const noexcept;
    [[nodiscard]] bool enforced() const noexcept;
};

class SandboxSystem {
public:
    virtual ~SandboxSystem() = default;

    [[nodiscard]] virtual bool supported() const noexcept = 0;
    virtual int unveil(const char* path, const char* permissions) noexcept = 0;
    virtual int pledge(
        const char* promises,
        const char* exec_promises) noexcept = 0;
};

class NativeSandboxSystem final : public SandboxSystem {
public:
    [[nodiscard]] bool supported() const noexcept override;
    int unveil(const char* path, const char* permissions) noexcept override;
    int pledge(
        const char* promises,
        const char* exec_promises) noexcept override;
};

[[nodiscard]] DaemonSandboxPolicy make_read_only_daemon_sandbox_policy(
    const DaemonConfig& config);
[[nodiscard]] DaemonSandboxResult apply_daemon_sandbox(
    const DaemonSandboxPolicy& policy,
    SandboxSystem& system);

}  // namespace sasd::gatehold::daemon
