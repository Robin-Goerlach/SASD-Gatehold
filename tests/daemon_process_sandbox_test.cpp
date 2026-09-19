#include "gatehold/daemon/process_sandbox.hpp"

#include <cstdlib>
#include <iostream>
#include <limits>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace daemon_api = sasd::gatehold::daemon;

namespace {

struct RecordedCall {
    std::string operation;
    std::optional<std::string> first;
    std::optional<std::string> second;
};

class FakeSandboxSystem final : public daemon_api::SandboxSystem {
public:
    bool available{true};
    std::size_t failing_unveil_call{std::numeric_limits<std::size_t>::max()};
    bool fail_pledge{false};
    std::vector<RecordedCall> calls;

    [[nodiscard]] bool supported() const noexcept override {
        return available;
    }

    int unveil(const char* path, const char* permissions) noexcept override {
        calls.push_back({
            .operation = "unveil",
            .first = path == nullptr
                         ? std::nullopt
                         : std::optional<std::string>{path},
            .second = permissions == nullptr
                          ? std::nullopt
                          : std::optional<std::string>{permissions}});
        const auto call_index = unveil_calls_++;
        return call_index == failing_unveil_call ? -1 : 0;
    }

    int pledge(
        const char* promises,
        const char* exec_promises) noexcept override {
        calls.push_back({
            .operation = "pledge",
            .first = promises == nullptr
                         ? std::nullopt
                         : std::optional<std::string>{promises},
            .second = exec_promises == nullptr
                          ? std::nullopt
                          : std::optional<std::string>{exec_promises}});
        return fail_pledge ? -1 : 0;
    }

private:
    std::size_t unveil_calls_{0};
};

[[noreturn]] void fail(const std::string& message) {
    std::cerr << message << '\n';
    std::exit(1);
}

void require(bool condition, const std::string& message) {
    if (!condition) {
        fail(message);
    }
}

daemon_api::DaemonConfig config() {
    return {
        .journal_root = "/var/gatehold/audit",
        .revision_root = "/var/gatehold/revisions",
        .transaction_root = "/var/gatehold/transactions",
        .socket_path = "/var/run/gatehold/controller.sock",
        .allowed_user_id = 77,
        .allowed_group_id = std::nullopt};
}

void policy_is_minimal_and_role_specific() {
    const auto policy =
        daemon_api::make_read_only_daemon_sandbox_policy(config());
    const std::vector<daemon_api::UnveilRule> expected{
        {"/var/gatehold/audit", "rwc"},
        {"/var/gatehold/revisions", "r"},
        {"/var/gatehold/transactions", "rwc"},
        {"/var/run/gatehold", "rwc"},
        {"/sbin/pfctl", "x"},
        {"/dev/pf", "rw"}};
    require(policy.unveil_rules == expected, "Sandbox unveil rules changed.");
    require(
        policy.promises ==
            "stdio rpath wpath cpath fattr flock unix proc exec",
        "Sandbox pledge promises changed.");
}

void supported_platform_applies_and_locks_in_order() {
    const auto policy =
        daemon_api::make_read_only_daemon_sandbox_policy(config());
    FakeSandboxSystem system;
    const auto result = daemon_api::apply_daemon_sandbox(policy, system);

    require(result.enforced(), "Supported sandbox was not enforced.");
    require(result.can_continue(), "Applied sandbox rejected startup.");
    require(result.event_id == "GH-SBX-0001", "Applied event ID changed.");
    require(system.calls.size() == 8U, "Sandbox call count changed.");
    for (std::size_t index = 0; index < policy.unveil_rules.size(); ++index) {
        const auto& call = system.calls[index];
        require(call.operation == "unveil", "Unveil ordering changed.");
        require(
            call.first == policy.unveil_rules[index].path.string(),
            "Unveil path ordering changed.");
        require(
            call.second == policy.unveil_rules[index].permissions,
            "Unveil permission ordering changed.");
    }
    require(
        system.calls[6].operation == "unveil" &&
            !system.calls[6].first.has_value() &&
            !system.calls[6].second.has_value(),
        "Unveil policy was not locked before pledge.");
    require(
        system.calls[7].operation == "pledge" &&
            system.calls[7].first == policy.promises &&
            !system.calls[7].second.has_value(),
        "Parent pledge or child promise boundary changed.");
}

void unsupported_platform_is_explicit_and_side_effect_free() {
    const auto policy =
        daemon_api::make_read_only_daemon_sandbox_policy(config());
    FakeSandboxSystem system;
    system.available = false;
    const auto result = daemon_api::apply_daemon_sandbox(policy, system);

    require(result.can_continue(), "Portable platform should remain testable.");
    require(!result.enforced(), "Unsupported sandbox reported enforcement.");
    require(
        result.status == daemon_api::DaemonSandboxStatus::unsupported &&
            result.event_id == "GH-SBX-1001",
        "Unsupported sandbox result changed.");
    require(system.calls.empty(), "Unsupported sandbox made system calls.");
}

void partial_unveil_failures_stop_closed_without_path_disclosure() {
    const auto policy =
        daemon_api::make_read_only_daemon_sandbox_policy(config());
    for (std::size_t failing_call = 0;
         failing_call < policy.unveil_rules.size();
         ++failing_call) {
        FakeSandboxSystem system;
        system.failing_unveil_call = failing_call;
        const auto result = daemon_api::apply_daemon_sandbox(policy, system);
        require(!result.can_continue(), "Partial unveil failure was accepted.");
        require(
            result.status == daemon_api::DaemonSandboxStatus::unveil_failed &&
                result.event_id == "GH-SBX-2001",
            "Unveil failure classification changed.");
        require(
            system.calls.size() == failing_call + 1U,
            "Sandbox continued after unveil failure.");
        require(
            result.message.find("/var/gatehold") == std::string::npos,
            "Sandbox failure disclosed a configured path.");
    }
}

void lock_and_pledge_failures_stop_closed() {
    const auto policy =
        daemon_api::make_read_only_daemon_sandbox_policy(config());
    FakeSandboxSystem lock_failure;
    lock_failure.failing_unveil_call = policy.unveil_rules.size();
    const auto lock_result =
        daemon_api::apply_daemon_sandbox(policy, lock_failure);
    require(
        !lock_result.can_continue() &&
            lock_result.status ==
                daemon_api::DaemonSandboxStatus::unveil_lock_failed &&
            lock_result.event_id == "GH-SBX-2002" &&
            lock_failure.calls.size() == 7U,
        "Unveil lock failure did not stop before pledge.");

    FakeSandboxSystem pledge_failure;
    pledge_failure.fail_pledge = true;
    const auto pledge_result =
        daemon_api::apply_daemon_sandbox(policy, pledge_failure);
    require(
        !pledge_result.can_continue() &&
            pledge_result.status ==
                daemon_api::DaemonSandboxStatus::pledge_failed &&
            pledge_result.event_id == "GH-SBX-2003" &&
            pledge_failure.calls.size() == 8U,
        "Pledge failure did not stop startup.");
}

void invalid_policy_is_rejected_before_platform_calls() {
    auto policy = daemon_api::make_read_only_daemon_sandbox_policy(config());
    policy.unveil_rules[1].permissions = "rw";
    FakeSandboxSystem system;
    const auto result = daemon_api::apply_daemon_sandbox(policy, system);
    require(
        !result.can_continue() &&
            result.status == daemon_api::DaemonSandboxStatus::invalid_policy &&
            result.event_id == "GH-SBX-1002",
        "Invalid sandbox policy was not rejected.");
    require(system.calls.empty(), "Invalid policy made platform calls.");

    policy = daemon_api::make_read_only_daemon_sandbox_policy(config());
    policy.unveil_rules[3].path = policy.unveil_rules[0].path / "socket";
    FakeSandboxSystem overlap_system;
    const auto overlap_result =
        daemon_api::apply_daemon_sandbox(policy, overlap_system);
    require(
        !overlap_result.can_continue() && overlap_system.calls.empty(),
        "Overlapping sandbox trust roots were not rejected.");
}

}  // namespace

int main() {
    policy_is_minimal_and_role_specific();
    supported_platform_applies_and_locks_in_order();
    unsupported_platform_is_explicit_and_side_effect_free();
    partial_unveil_failures_stop_closed_without_path_disclosure();
    lock_and_pledge_failures_stop_closed();
    invalid_policy_is_rejected_before_platform_calls();
    return 0;
}
