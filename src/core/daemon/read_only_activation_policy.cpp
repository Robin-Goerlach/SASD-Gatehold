#include "gatehold/daemon/read_only_activation_policy.hpp"

namespace sasd::gatehold::daemon {

firewall::AuthorizationResult ReadOnlyActivationAuthorizer::authorize(
    const std::string&,
    std::uint64_t,
    const std::string&) const {
    return {
        .status = firewall::AuthorizationStatus::denied,
        .decision_id = {},
        .message = "This bootstrap daemon does not authorize PF activation."};
}

firewall::ConfirmationResult
UnavailableConfirmationGate::await_confirmation(
    const std::string&,
    std::uint64_t,
    std::chrono::milliseconds) const {
    return {
        .status = firewall::ConfirmationStatus::unavailable,
        .confirmation_id = {},
        .message = "This bootstrap daemon has no confirmation provider."};
}

std::string FailClosedActivationHealthProbe::id() const {
    return "read-only-daemon";
}

firewall::HealthProbeResult FailClosedActivationHealthProbe::run(
    std::chrono::milliseconds) const {
    return {
        .status = firewall::HealthProbeStatus::execution_error,
        .message = "This bootstrap daemon has no activation health probe."};
}

}  // namespace sasd::gatehold::daemon
