#pragma once

#include "gatehold/firewall/activation_transaction_store.hpp"
#include "gatehold/firewall/native_validator.hpp"
#include "gatehold/firewall/pfctl_loader.hpp"
#include "gatehold/firewall/revision_store.hpp"
#include "gatehold/logging/event.hpp"
#include "gatehold/logging/operation_journal.hpp"

#include <chrono>
#include <cstdint>
#include <functional>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

namespace sasd::gatehold::firewall {

enum class AuthorizationStatus { authorized, denied, unavailable };

struct AuthorizationResult {
    AuthorizationStatus status{AuthorizationStatus::unavailable};
    std::string decision_id;
    std::string message;

    [[nodiscard]] bool ok() const noexcept;
};

class ActivationAuthorizer {
public:
    virtual ~ActivationAuthorizer() = default;

    [[nodiscard]] virtual AuthorizationResult authorize(
        const std::string& operation_id,
        std::uint64_t revision,
        const std::string& authorization_reference) const = 0;
};

enum class HealthProbeStatus { healthy, unhealthy, timed_out, execution_error };

struct HealthProbeResult {
    HealthProbeStatus status{HealthProbeStatus::execution_error};
    std::string message;

    [[nodiscard]] bool ok() const noexcept;
};

class HealthProbe {
public:
    virtual ~HealthProbe() = default;

    [[nodiscard]] virtual std::string id() const = 0;
    [[nodiscard]] virtual HealthProbeResult run(
        std::chrono::milliseconds timeout) const = 0;
};

enum class ConfirmationStatus { confirmed, rejected, timed_out, unavailable };

struct ConfirmationResult {
    ConfirmationStatus status{ConfirmationStatus::unavailable};
    std::string confirmation_id;
    std::string message;

    [[nodiscard]] bool ok() const noexcept;
};

class ConfirmationGate {
public:
    virtual ~ConfirmationGate() = default;

    [[nodiscard]] virtual ConfirmationResult await_confirmation(
        const std::string& operation_id,
        std::uint64_t revision,
        std::chrono::milliseconds timeout) const = 0;
};

enum class ActivationStatus {
    committed,
    invalid_request,
    authorization_denied,
    authorization_error,
    last_known_good_unavailable,
    target_unavailable,
    native_revalidation_failed,
    activation_failed,
    verification_failed_rolled_back,
    confirmation_failed_rolled_back,
    commit_failed_rolled_back,
    transaction_conflict,
    transaction_store_failed,
    committed_with_warning,
    committed_cleanup_pending,
    audit_failed,
    audit_failed_rolled_back,
    rollback_failed
};

struct ActivationRequest {
    std::string operation_id;
    std::uint64_t revision{0};
    std::string authorization_reference;
    std::chrono::milliseconds probe_timeout{5000};
    std::chrono::milliseconds confirmation_timeout{60000};
};

struct ActivationResult {
    ActivationStatus status{ActivationStatus::invalid_request};
    std::string event_id;
    std::string message;
    std::optional<std::uint64_t> rollback_revision;
    std::optional<AuthorizationResult> authorization;
    std::optional<NativeValidationResult> native_validation;
    std::optional<PfctlLoadResult> activation;
    std::optional<PfctlLoadResult> rollback;
    std::vector<HealthProbeResult> probe_results;
    std::optional<ConfirmationResult> confirmation;
    std::optional<ActivationTransactionResult> transaction;
    bool rollback_performed{false};
    std::vector<logging::Event> journaled_events;

    [[nodiscard]] bool ok() const noexcept;
};

enum class ActivationRecoveryStatus {
    no_pending,
    rolled_back,
    committed_cleaned,
    audit_failed_recovered,
    failed
};

struct ActivationRecoveryResult {
    ActivationRecoveryStatus status{ActivationRecoveryStatus::failed};
    std::string event_id;
    std::string message;
    std::optional<PendingActivation> transaction;
    std::optional<NativeValidationResult> native_validation;
    std::optional<PfctlLoadResult> rollback;
    std::vector<logging::Event> journaled_events;

    [[nodiscard]] bool ok() const noexcept;
};

class PfActivationService {
public:
    using TimestampSource = std::function<std::string()>;

    PfActivationService(
        const RevisionStore& revision_store,
        const ActivationTransactionStore& transaction_store,
        const PfctlValidator& validator,
        const PfctlLoader& loader,
        const logging::OperationJournal& journal,
        const ActivationAuthorizer& authorizer,
        const ConfirmationGate& confirmation_gate,
        std::vector<std::reference_wrapper<const HealthProbe>> probes,
        TimestampSource timestamp_source = {});

    [[nodiscard]] ActivationResult activate(
        const ActivationRequest& request) const;
    [[nodiscard]] ActivationRecoveryResult recover_pending() const;

private:
    const RevisionStore& revision_store_;
    const ActivationTransactionStore& transaction_store_;
    const PfctlValidator& validator_;
    const PfctlLoader& loader_;
    const logging::OperationJournal& journal_;
    const ActivationAuthorizer& authorizer_;
    const ConfirmationGate& confirmation_gate_;
    std::vector<std::reference_wrapper<const HealthProbe>> probes_;
    TimestampSource timestamp_source_;
    mutable std::mutex activation_mutex_;
};

}  // namespace sasd::gatehold::firewall
