#include "gatehold/firewall/activation_service.hpp"

#include <chrono>
#include <cstdint>
#include <ctime>
#include <iomanip>
#include <set>
#include <sstream>
#include <string_view>
#include <utility>

namespace sasd::gatehold::firewall {
namespace {

constexpr std::chrono::milliseconds minimum_confirmation_timeout{1000};
constexpr std::chrono::milliseconds maximum_confirmation_timeout{600000};
constexpr std::chrono::milliseconds minimum_probe_timeout{100};
constexpr std::chrono::milliseconds maximum_probe_timeout{60000};

std::string system_utc_timestamp() {
    const auto now = std::chrono::system_clock::now();
    const std::time_t time = std::chrono::system_clock::to_time_t(now);
    struct tm utc_time {};
    if (::gmtime_r(&time, &utc_time) == nullptr) {
        return "1970-01-01T00:00:00Z";
    }

    std::ostringstream output;
    output << std::put_time(&utc_time, "%Y-%m-%dT%H:%M:%SZ");
    return output.str();
}

bool valid_identifier(std::string_view value) noexcept {
    if (value.empty() || value.size() > 128U) {
        return false;
    }
    for (const char character : value) {
        const bool alpha_numeric =
            (character >= 'a' && character <= 'z') ||
            (character >= 'A' && character <= 'Z') ||
            (character >= '0' && character <= '9');
        if (!alpha_numeric && character != '-' && character != '_' &&
            character != '.' && character != ':') {
            return false;
        }
    }
    return true;
}

logging::Event activation_event(
    std::string timestamp,
    logging::Severity severity,
    std::string event_id,
    std::string operation_id,
    std::string action,
    std::string outcome,
    std::string message,
    std::uint64_t revision) {
    return {
        .timestamp = std::move(timestamp),
        .severity = severity,
        .event_id = std::move(event_id),
        .component = "pf-activation-service",
        .operation_id = std::move(operation_id),
        .action = std::move(action),
        .outcome = std::move(outcome),
        .message = std::move(message),
        .attributes = {{"revision", std::to_string(revision)}}};
}

logging::Event load_event(
    const PfctlLoadResult& load,
    std::string timestamp,
    const std::string& operation_id,
    std::uint64_t revision,
    std::string action) {
    std::string outcome = "failed";
    if (load.status == PfctlLoadStatus::loaded) {
        outcome = "succeeded";
    } else if (load.status == PfctlLoadStatus::rejected ||
               load.status == PfctlLoadStatus::unsafe_revision) {
        outcome = "rejected";
    } else if (load.status == PfctlLoadStatus::timed_out) {
        outcome = "timed_out";
    }

    auto event = activation_event(
        std::move(timestamp),
        load.ok() ? logging::Severity::info : logging::Severity::error,
        load.event_id,
        operation_id,
        std::move(action),
        std::move(outcome),
        load.message,
        revision);
    event.attributes.emplace("exit_code", std::to_string(load.exit_code));
    event.attributes.emplace(
        "output_truncated", load.output_truncated ? "true" : "false");
    return event;
}

logging::Event transaction_event(
    const ActivationTransactionResult& transaction,
    std::string timestamp,
    const std::string& operation_id,
    std::uint64_t revision,
    std::string action) {
    auto event = activation_event(
        std::move(timestamp),
        transaction.ok() ? logging::Severity::info : logging::Severity::error,
        transaction.event_id,
        operation_id,
        std::move(action),
        transaction.ok() ? "succeeded" : "failed",
        transaction.message,
        revision);
    if (transaction.transaction.has_value()) {
        event.attributes.emplace(
            "phase", to_string(transaction.transaction->phase));
        event.attributes.emplace(
            "rollback_revision",
            std::to_string(transaction.transaction->rollback_revision));
    }
    return event;
}

std::string_view authorization_event_id(AuthorizationStatus status) noexcept {
    switch (status) {
        case AuthorizationStatus::authorized:
            return "GH-AUTH-0001";
        case AuthorizationStatus::denied:
            return "GH-AUTH-1001";
        case AuthorizationStatus::unavailable:
            return "GH-AUTH-2001";
    }
    return "GH-AUTH-2001";
}

std::string_view probe_event_id(HealthProbeStatus status) noexcept {
    switch (status) {
        case HealthProbeStatus::healthy:
            return "GH-PROBE-0001";
        case HealthProbeStatus::unhealthy:
            return "GH-PROBE-1001";
        case HealthProbeStatus::timed_out:
            return "GH-PROBE-2001";
        case HealthProbeStatus::execution_error:
            return "GH-PROBE-2002";
    }
    return "GH-PROBE-2002";
}

std::string_view confirmation_event_id(ConfirmationStatus status) noexcept {
    switch (status) {
        case ConfirmationStatus::confirmed:
            return "GH-CONF-0001";
        case ConfirmationStatus::rejected:
            return "GH-CONF-1001";
        case ConfirmationStatus::timed_out:
            return "GH-CONF-1002";
        case ConfirmationStatus::unavailable:
            return "GH-CONF-2001";
    }
    return "GH-CONF-2001";
}

}  // namespace

bool AuthorizationResult::ok() const noexcept {
    return status == AuthorizationStatus::authorized;
}

bool HealthProbeResult::ok() const noexcept {
    return status == HealthProbeStatus::healthy;
}

bool ConfirmationResult::ok() const noexcept {
    return status == ConfirmationStatus::confirmed;
}

bool ActivationResult::ok() const noexcept {
    return status == ActivationStatus::committed ||
           status == ActivationStatus::committed_with_warning ||
           status == ActivationStatus::committed_cleanup_pending;
}

bool ActivationRecoveryResult::ok() const noexcept {
    return status == ActivationRecoveryStatus::no_pending ||
           status == ActivationRecoveryStatus::rolled_back ||
           status == ActivationRecoveryStatus::committed_cleaned ||
           status == ActivationRecoveryStatus::audit_failed_recovered;
}

PfActivationService::PfActivationService(
    const RevisionStore& revision_store,
    const ActivationTransactionStore& transaction_store,
    const PfctlValidator& validator,
    const PfctlLoader& loader,
    const logging::OperationJournal& journal,
    const ActivationAuthorizer& authorizer,
    const ConfirmationGate& confirmation_gate,
    std::vector<std::reference_wrapper<const HealthProbe>> probes,
    TimestampSource timestamp_source)
    : revision_store_{revision_store},
      transaction_store_{transaction_store},
      validator_{validator},
      loader_{loader},
      journal_{journal},
      authorizer_{authorizer},
      confirmation_gate_{confirmation_gate},
      probes_{std::move(probes)},
      timestamp_source_{std::move(timestamp_source)} {
    if (!timestamp_source_) {
        timestamp_source_ = system_utc_timestamp;
    }
}

ActivationResult PfActivationService::activate(
    const ActivationRequest& request) const {
    const std::scoped_lock activation_lock{activation_mutex_};
    ActivationResult result;
    std::string audit_event_id;
    std::string audit_message;

    const auto append = [this, &result, &audit_event_id, &audit_message](
                            logging::Event event) {
        const auto journal_result = journal_.append(event);
        if (!journal_result.ok()) {
            if (audit_event_id.empty()) {
                audit_event_id = journal_result.event_id;
                audit_message = journal_result.message;
            }
            return false;
        }
        result.journaled_events.push_back(std::move(event));
        return true;
    };

    const auto fail_before_activation = [&result](
                                            ActivationStatus status,
                                            std::string event_id,
                                            std::string message) {
        result.status = status;
        result.event_id = std::move(event_id);
        result.message = std::move(message);
        return result;
    };

    if (!valid_identifier(request.operation_id) || request.revision == 0 ||
        !valid_identifier(request.authorization_reference) ||
        request.probe_timeout < minimum_probe_timeout ||
        request.probe_timeout > maximum_probe_timeout ||
        request.confirmation_timeout < minimum_confirmation_timeout ||
        request.confirmation_timeout > maximum_confirmation_timeout) {
        return fail_before_activation(
            ActivationStatus::invalid_request,
            "GH-ACT-1001",
            "Activation request identifiers, revision, or confirmation timeout are invalid.");
    }

    std::set<std::string> probe_ids;
    for (const auto& probe_reference : probes_) {
        const auto probe_id = probe_reference.get().id();
        if (!valid_identifier(probe_id) || !probe_ids.insert(probe_id).second) {
            return fail_before_activation(
                ActivationStatus::invalid_request,
                "GH-ACT-1002",
                "Health probes must have unique safe identifiers.");
        }
    }
    if (probes_.empty()) {
        return fail_before_activation(
            ActivationStatus::invalid_request,
            "GH-ACT-1003",
            "At least one health probe is required for activation.");
    }

    if (!append(activation_event(
            timestamp_source_(),
            logging::Severity::info,
            "GH-ACT-0001",
            request.operation_id,
            "pf.activate",
            "started",
            "PF activation workflow started.",
            request.revision))) {
        return fail_before_activation(
            ActivationStatus::audit_failed, audit_event_id, audit_message);
    }

    AuthorizationResult authorization;
    try {
        authorization = authorizer_.authorize(
            request.operation_id,
            request.revision,
            request.authorization_reference);
    } catch (...) {
        authorization = {
            .status = AuthorizationStatus::unavailable,
            .decision_id = {},
            .message = "Authorization provider failed."};
    }
    if (authorization.ok() && !valid_identifier(authorization.decision_id)) {
        authorization = {
            .status = AuthorizationStatus::unavailable,
            .decision_id = {},
            .message = "Authorization provider returned an invalid decision identifier."};
    }
    result.authorization = authorization;

    auto authorization_event = activation_event(
        timestamp_source_(),
        authorization.ok() ? logging::Severity::info : logging::Severity::warning,
        std::string{authorization_event_id(authorization.status)},
        request.operation_id,
        "authorization.verify",
        authorization.ok()
            ? "authorized"
            : authorization.status == AuthorizationStatus::denied ? "denied"
                                                                  : "failed",
        authorization.ok()
            ? "Activation authorization was verified."
            : authorization.status == AuthorizationStatus::denied
                  ? "Activation authorization was denied."
                  : "Activation authorization could not be verified.",
        request.revision);
    if (authorization.ok()) {
        authorization_event.attributes.emplace(
            "decision_id", authorization.decision_id);
    }
    if (!append(std::move(authorization_event))) {
        return fail_before_activation(
            ActivationStatus::audit_failed, audit_event_id, audit_message);
    }
    if (!authorization.ok()) {
        return fail_before_activation(
            authorization.status == AuthorizationStatus::denied
                ? ActivationStatus::authorization_denied
                : ActivationStatus::authorization_error,
            std::string{authorization_event_id(authorization.status)},
            authorization.message);
    }

    const auto previous = revision_store_.last_known_good();
    if (!previous.ok() || !previous.revision.has_value()) {
        auto event = activation_event(
            timestamp_source_(),
            logging::Severity::warning,
            "GH-ACT-1004",
            request.operation_id,
            "pf.rollback.resolve",
            "failed",
            "No safe last-known-good revision is available for rollback.",
            request.revision);
        event.attributes.emplace("revision_event_id", previous.event_id);
        if (!append(std::move(event))) {
            return fail_before_activation(
                ActivationStatus::audit_failed, audit_event_id, audit_message);
        }
        return fail_before_activation(
            ActivationStatus::last_known_good_unavailable,
            "GH-ACT-1004",
            "Activation requires an available last-known-good revision.");
    }
    result.rollback_revision = previous.revision;

    if (*previous.revision == request.revision) {
        if (!append(activation_event(
                timestamp_source_(),
                logging::Severity::warning,
                "GH-ACT-1005",
                request.operation_id,
                "pf.activate",
                "rejected",
                "Requested revision is already last known good.",
                request.revision))) {
            return fail_before_activation(
                ActivationStatus::audit_failed, audit_event_id, audit_message);
        }
        return fail_before_activation(
            ActivationStatus::invalid_request,
            "GH-ACT-1005",
            "Requested revision is already last known good.");
    }

    const auto target = revision_store_.load(request.revision);
    if (!target.ok()) {
        auto event = activation_event(
            timestamp_source_(),
            logging::Severity::warning,
            "GH-ACT-1006",
            request.operation_id,
            "pf.revision.resolve",
            "failed",
            "Target revision is unavailable or unsafe.",
            request.revision);
        event.attributes.emplace("revision_event_id", target.event_id);
        if (!append(std::move(event))) {
            return fail_before_activation(
                ActivationStatus::audit_failed, audit_event_id, audit_message);
        }
        return fail_before_activation(
            ActivationStatus::target_unavailable,
            "GH-ACT-1006",
            "Target revision is unavailable or unsafe.");
    }

    const auto rollback_to_previous = [
                                          this,
                                          &append,
                                          &audit_event_id,
                                          &audit_message,
                                          &request,
                                          &result,
                                          previous](
                                          ActivationStatus desired_status,
                                          std::string desired_event_id,
                                          std::string desired_message,
                                          bool audit_compromised) {
        bool rollback_audit_ok = append(activation_event(
            timestamp_source_(),
            logging::Severity::warning,
            "GH-ACT-0008",
            request.operation_id,
            "pf.rollback",
            "started",
            "Rollback to last-known-good revision started.",
            *previous.revision));
        audit_compromised = audit_compromised || !rollback_audit_ok;

        const auto rollback_path =
            revision_store_.revision_path(*previous.revision);
        const auto rollback_validation = validator_.validate(rollback_path);
        rollback_audit_ok = append(make_validation_event(
            rollback_validation,
            timestamp_source_(),
            request.operation_id,
            *previous.revision));
        audit_compromised = audit_compromised || !rollback_audit_ok;

        PfctlLoadResult rollback_load;
        if (rollback_validation.ok()) {
            rollback_load = loader_.load(rollback_path);
            result.rollback = rollback_load;
            result.rollback_performed = rollback_load.ok();
            rollback_audit_ok = append(load_event(
                rollback_load,
                timestamp_source_(),
                request.operation_id,
                *previous.revision,
                "pf.rollback.load"));
            audit_compromised = audit_compromised || !rollback_audit_ok;
        }

        LastKnownGoodResult marker_result;
        if (rollback_validation.ok() && rollback_load.ok()) {
            marker_result = revision_store_.mark_last_known_good(*previous.revision);
            auto marker_event = activation_event(
                timestamp_source_(),
                marker_result.ok() ? logging::Severity::info
                                   : logging::Severity::critical,
                marker_result.event_id,
                request.operation_id,
                "pf.rollback.marker",
                marker_result.ok() ? "succeeded" : "failed",
                marker_result.message,
                *previous.revision);
            rollback_audit_ok = append(std::move(marker_event));
            audit_compromised = audit_compromised || !rollback_audit_ok;
        }

        if (!rollback_validation.ok() || !rollback_load.ok() ||
            !marker_result.ok()) {
            result.status = ActivationStatus::rollback_failed;
            result.event_id = "GH-ACT-2001";
            result.message =
                "Rollback could not restore both PF and the last-known-good marker.";
            static_cast<void>(append(activation_event(
                timestamp_source_(),
                logging::Severity::critical,
                result.event_id,
                request.operation_id,
                "pf.rollback",
                "failed",
                result.message,
                *previous.revision)));
            return result;
        }

        const auto cleared = transaction_store_.clear(request.operation_id);
        result.transaction = cleared;
        rollback_audit_ok = append(transaction_event(
            cleared,
            timestamp_source_(),
            request.operation_id,
            request.revision,
            "pf.activation_transaction.clear"));
        audit_compromised = audit_compromised || !rollback_audit_ok;
        if (cleared.status != ActivationTransactionStatus::cleared) {
            result.status = ActivationStatus::rollback_failed;
            result.event_id = "GH-ACT-2001";
            result.message =
                "Rollback restored PF but could not clear its pending transaction.";
            return result;
        }

        rollback_audit_ok = append(activation_event(
            timestamp_source_(),
            logging::Severity::warning,
            "GH-ACT-0009",
            request.operation_id,
            "pf.rollback",
            "succeeded",
            "Last-known-good PF revision was restored.",
            *previous.revision));
        audit_compromised = audit_compromised || !rollback_audit_ok;

        if (audit_compromised) {
            result.status = ActivationStatus::audit_failed_rolled_back;
            result.event_id = audit_event_id.empty() ? "GH-AUDIT-2001"
                                                     : audit_event_id;
            result.message = audit_message.empty()
                                 ? "Audit failed after activation; rollback succeeded."
                                 : audit_message;
        } else {
            result.status = desired_status;
            result.event_id = std::move(desired_event_id);
            result.message = std::move(desired_message);
        }
        return result;
    };

    if (!append(activation_event(
            timestamp_source_(),
            logging::Severity::info,
            "GH-ACT-0002",
            request.operation_id,
            "pf.ruleset.revalidate",
            "started",
            "Native validation immediately before activation started.",
            request.revision))) {
        return fail_before_activation(
            ActivationStatus::audit_failed, audit_event_id, audit_message);
    }

    const auto validation = validator_.validate(
        revision_store_.revision_path(request.revision));
    result.native_validation = validation;
    if (!append(make_validation_event(
            validation,
            timestamp_source_(),
            request.operation_id,
            request.revision))) {
        return fail_before_activation(
            ActivationStatus::audit_failed, audit_event_id, audit_message);
    }
    if (!validation.ok()) {
        return fail_before_activation(
            ActivationStatus::native_revalidation_failed,
            validation.event_id,
            validation.message);
    }

    if (!append(activation_event(
            timestamp_source_(),
            logging::Severity::info,
            "GH-ACT-0010",
            request.operation_id,
            "pf.activation_transaction.begin",
            "started",
            "Durable activation transaction creation started.",
            request.revision))) {
        return fail_before_activation(
            ActivationStatus::audit_failed, audit_event_id, audit_message);
    }

    const auto transaction_begin = transaction_store_.begin({
        .operation_id = request.operation_id,
        .target_revision = request.revision,
        .rollback_revision = *previous.revision,
        .phase = ActivationPhase::prepared_for_load});
    result.transaction = transaction_begin;
    if (!append(transaction_event(
            transaction_begin,
            timestamp_source_(),
            request.operation_id,
            request.revision,
            "pf.activation_transaction.begin"))) {
        if (transaction_begin.status == ActivationTransactionStatus::created) {
            const auto cleared = transaction_store_.clear(request.operation_id);
            result.transaction = cleared;
            if (cleared.status != ActivationTransactionStatus::cleared) {
                return fail_before_activation(
                    ActivationStatus::transaction_store_failed,
                    cleared.event_id,
                    cleared.message);
            }
        }
        return fail_before_activation(
            ActivationStatus::audit_failed, audit_event_id, audit_message);
    }
    if (transaction_begin.status != ActivationTransactionStatus::created) {
        return fail_before_activation(
            transaction_begin.status == ActivationTransactionStatus::conflict
                ? ActivationStatus::transaction_conflict
                : ActivationStatus::transaction_store_failed,
            transaction_begin.event_id,
            transaction_begin.message);
    }

    auto activation_intent = activation_event(
        timestamp_source_(),
        logging::Severity::warning,
        "GH-ACT-0003",
        request.operation_id,
        "pf.activate.load",
        "started",
        "Native PF ruleset replacement started.",
        request.revision);
    activation_intent.attributes.emplace(
        "rollback_revision", std::to_string(*previous.revision));
    activation_intent.attributes.emplace(
        "decision_id", authorization.decision_id);
    if (!append(std::move(activation_intent))) {
        const auto cleared = transaction_store_.clear(request.operation_id);
        result.transaction = cleared;
        if (cleared.status != ActivationTransactionStatus::cleared) {
            return fail_before_activation(
                ActivationStatus::transaction_store_failed,
                cleared.event_id,
                cleared.message);
        }
        return fail_before_activation(
            ActivationStatus::audit_failed, audit_event_id, audit_message);
    }

    const auto activated = loader_.load(
        revision_store_.revision_path(request.revision));
    result.activation = activated;
    if (!append(load_event(
            activated,
            timestamp_source_(),
            request.operation_id,
            request.revision,
            "pf.activate.load"))) {
        return rollback_to_previous(
            ActivationStatus::activation_failed,
            activated.event_id,
            activated.message,
            true);
    }
    if (!activated.ok()) {
        return rollback_to_previous(
            ActivationStatus::activation_failed,
            activated.event_id,
            activated.message,
            false);
    }

    const auto target_loaded = transaction_store_.advance(
        request.operation_id, ActivationPhase::target_loaded);
    result.transaction = target_loaded;
    const bool target_loaded_audited = append(transaction_event(
        target_loaded,
        timestamp_source_(),
        request.operation_id,
        request.revision,
        "pf.activation_transaction.advance"));
    if (target_loaded.status != ActivationTransactionStatus::advanced) {
        return rollback_to_previous(
            ActivationStatus::transaction_store_failed,
            target_loaded.event_id,
            target_loaded.message,
            !target_loaded_audited);
    }
    if (!target_loaded_audited) {
        return rollback_to_previous(
            ActivationStatus::transaction_store_failed,
            target_loaded.event_id,
            target_loaded.message,
            true);
    }

    for (const auto& probe_reference : probes_) {
        const auto& probe = probe_reference.get();
        const auto probe_id = probe.id();
        auto probe_intent = activation_event(
            timestamp_source_(),
            logging::Severity::info,
            "GH-ACT-0004",
            request.operation_id,
            "pf.health_probe",
            "started",
            "Post-activation health probe started.",
            request.revision);
        probe_intent.attributes.emplace("probe_id", probe_id);
        if (!append(std::move(probe_intent))) {
            return rollback_to_previous(
                ActivationStatus::verification_failed_rolled_back,
                "GH-PROBE-2002",
                "Health verification could not be audited.",
                true);
        }

        HealthProbeResult probe_result;
        try {
            probe_result = probe.run(request.probe_timeout);
        } catch (...) {
            probe_result = {
                .status = HealthProbeStatus::execution_error,
                .message = "Health probe raised an unexpected exception."};
        }
        result.probe_results.push_back(probe_result);

        auto probe_event = activation_event(
            timestamp_source_(),
            probe_result.ok() ? logging::Severity::info
                              : logging::Severity::error,
            std::string{probe_event_id(probe_result.status)},
            request.operation_id,
            "pf.health_probe",
            probe_result.ok()
                ? "succeeded"
                : probe_result.status == HealthProbeStatus::timed_out
                      ? "timed_out"
                      : "failed",
            probe_result.ok() ? "Post-activation health probe passed."
                              : "Post-activation health probe failed.",
            request.revision);
        probe_event.attributes.emplace("probe_id", probe_id);
        if (!append(std::move(probe_event))) {
            return rollback_to_previous(
                ActivationStatus::verification_failed_rolled_back,
                std::string{probe_event_id(probe_result.status)},
                probe_result.message,
                true);
        }
        if (!probe_result.ok()) {
            return rollback_to_previous(
                ActivationStatus::verification_failed_rolled_back,
                std::string{probe_event_id(probe_result.status)},
                probe_result.message,
                false);
        }
    }

    const auto verified = transaction_store_.advance(
        request.operation_id, ActivationPhase::verified);
    result.transaction = verified;
    const bool verified_audited = append(transaction_event(
        verified,
        timestamp_source_(),
        request.operation_id,
        request.revision,
        "pf.activation_transaction.advance"));
    if (verified.status != ActivationTransactionStatus::advanced ||
        !verified_audited) {
        return rollback_to_previous(
            ActivationStatus::transaction_store_failed,
            verified.event_id,
            verified.message,
            !verified_audited);
    }

    const auto awaiting_confirmation = transaction_store_.advance(
        request.operation_id, ActivationPhase::awaiting_confirmation);
    result.transaction = awaiting_confirmation;
    const bool awaiting_confirmation_audited = append(transaction_event(
        awaiting_confirmation,
        timestamp_source_(),
        request.operation_id,
        request.revision,
        "pf.activation_transaction.advance"));
    if (awaiting_confirmation.status != ActivationTransactionStatus::advanced ||
        !awaiting_confirmation_audited) {
        return rollback_to_previous(
            ActivationStatus::transaction_store_failed,
            awaiting_confirmation.event_id,
            awaiting_confirmation.message,
            !awaiting_confirmation_audited);
    }

    if (!append(activation_event(
            timestamp_source_(),
            logging::Severity::warning,
            "GH-ACT-0005",
            request.operation_id,
            "pf.confirmation",
            "pending",
            "PF activation is awaiting explicit confirmation.",
            request.revision))) {
        return rollback_to_previous(
            ActivationStatus::confirmation_failed_rolled_back,
            "GH-CONF-2001",
            "Confirmation could not be audited.",
            true);
    }

    ConfirmationResult confirmation;
    try {
        confirmation = confirmation_gate_.await_confirmation(
            request.operation_id,
            request.revision,
            request.confirmation_timeout);
    } catch (...) {
        confirmation = {
            .status = ConfirmationStatus::unavailable,
            .confirmation_id = {},
            .message = "Confirmation provider failed."};
    }
    if (confirmation.ok() && !valid_identifier(confirmation.confirmation_id)) {
        confirmation = {
            .status = ConfirmationStatus::unavailable,
            .confirmation_id = {},
            .message = "Confirmation provider returned an invalid identifier."};
    }
    result.confirmation = confirmation;

    auto confirmation_event = activation_event(
        timestamp_source_(),
        confirmation.ok() ? logging::Severity::info : logging::Severity::warning,
        std::string{confirmation_event_id(confirmation.status)},
        request.operation_id,
        "pf.confirmation",
        confirmation.ok()
            ? "confirmed"
            : confirmation.status == ConfirmationStatus::timed_out
                  ? "timed_out"
                  : confirmation.status == ConfirmationStatus::rejected ? "rejected"
                                                                        : "failed",
        confirmation.ok() ? "PF activation was explicitly confirmed."
                          : "PF activation was not confirmed.",
        request.revision);
    if (confirmation.ok()) {
        confirmation_event.attributes.emplace(
            "confirmation_id", confirmation.confirmation_id);
    }
    if (!append(std::move(confirmation_event))) {
        return rollback_to_previous(
            ActivationStatus::confirmation_failed_rolled_back,
            std::string{confirmation_event_id(confirmation.status)},
            confirmation.message,
            true);
    }
    if (!confirmation.ok()) {
        return rollback_to_previous(
            ActivationStatus::confirmation_failed_rolled_back,
            std::string{confirmation_event_id(confirmation.status)},
            confirmation.message,
            false);
    }

    const auto committing = transaction_store_.advance(
        request.operation_id, ActivationPhase::committing);
    result.transaction = committing;
    const bool committing_audited = append(transaction_event(
        committing,
        timestamp_source_(),
        request.operation_id,
        request.revision,
        "pf.activation_transaction.advance"));
    if (committing.status != ActivationTransactionStatus::advanced ||
        !committing_audited) {
        return rollback_to_previous(
            ActivationStatus::transaction_store_failed,
            committing.event_id,
            committing.message,
            !committing_audited);
    }

    if (!append(activation_event(
            timestamp_source_(),
            logging::Severity::info,
            "GH-ACT-0006",
            request.operation_id,
            "pf.commit",
            "started",
            "Confirmed PF revision commit started.",
            request.revision))) {
        return rollback_to_previous(
            ActivationStatus::commit_failed_rolled_back,
            "GH-ACT-2002",
            "Commit could not be audited.",
            true);
    }

    const auto marker = revision_store_.mark_last_known_good(request.revision);
    auto marker_event = activation_event(
        timestamp_source_(),
        marker.ok() ? logging::Severity::info : logging::Severity::critical,
        marker.event_id,
        request.operation_id,
        "pf.commit.marker",
        marker.ok() ? "succeeded" : "failed",
        marker.message,
        request.revision);
    if (!append(std::move(marker_event))) {
        return rollback_to_previous(
            ActivationStatus::commit_failed_rolled_back,
            marker.event_id,
            marker.message,
            true);
    }
    if (!marker.ok()) {
        return rollback_to_previous(
            ActivationStatus::commit_failed_rolled_back,
            marker.event_id,
            marker.message,
            false);
    }

    const auto committed_transaction = transaction_store_.advance(
        request.operation_id, ActivationPhase::committed);
    result.transaction = committed_transaction;
    if (committed_transaction.status != ActivationTransactionStatus::advanced) {
        static_cast<void>(append(transaction_event(
            committed_transaction,
            timestamp_source_(),
            request.operation_id,
            request.revision,
            "pf.activation_transaction.advance")));
        return rollback_to_previous(
            ActivationStatus::transaction_store_failed,
            committed_transaction.event_id,
            committed_transaction.message,
            false);
    }
    const bool committed_transaction_audited = append(transaction_event(
        committed_transaction,
        timestamp_source_(),
        request.operation_id,
        request.revision,
        "pf.activation_transaction.advance"));

    const bool final_commit_audited = append(activation_event(
            timestamp_source_(),
            logging::Severity::info,
            "GH-ACT-0007",
            request.operation_id,
            "pf.activate",
            "committed",
            "PF activation was verified, confirmed, and committed.",
            request.revision));

    const auto cleared = transaction_store_.clear(request.operation_id);
    result.transaction = cleared;
    if (cleared.status != ActivationTransactionStatus::cleared) {
        result.status = ActivationStatus::committed_cleanup_pending;
        result.event_id = cleared.event_id;
        result.message =
            "PF revision committed, but durable transaction cleanup is pending.";
        return result;
    }

    if (!committed_transaction_audited || !final_commit_audited) {
        result.status = ActivationStatus::committed_with_warning;
        result.event_id = audit_event_id.empty() ? "GH-AUDIT-2001"
                                                 : audit_event_id;
        result.message =
            "PF revision committed, but a post-commit audit append failed.";
        return result;
    }

    result.status = ActivationStatus::committed;
    result.event_id = "GH-ACT-0007";
    result.message = "PF revision activated and committed successfully.";
    return result;
}

ActivationRecoveryResult PfActivationService::recover_pending() const {
    const std::scoped_lock activation_lock{activation_mutex_};
    ActivationRecoveryResult result;
    std::string audit_event_id;
    std::string audit_message;

    const auto append = [this, &result, &audit_event_id, &audit_message](
                            logging::Event event) {
        const auto journal_result = journal_.append(event);
        if (!journal_result.ok()) {
            if (audit_event_id.empty()) {
                audit_event_id = journal_result.event_id;
                audit_message = journal_result.message;
            }
            return false;
        }
        result.journaled_events.push_back(std::move(event));
        return true;
    };

    const auto pending_result = transaction_store_.load();
    if (pending_result.status == ActivationTransactionStatus::no_pending) {
        result.status = ActivationRecoveryStatus::no_pending;
        result.event_id = pending_result.event_id;
        result.message = pending_result.message;
        return result;
    }
    if (pending_result.status != ActivationTransactionStatus::loaded ||
        !pending_result.transaction.has_value()) {
        result.status = ActivationRecoveryStatus::failed;
        result.event_id = pending_result.event_id;
        result.message = pending_result.message;
        return result;
    }

    const PendingActivation pending = *pending_result.transaction;
    result.transaction = pending;
    bool audit_ok = append(activation_event(
        timestamp_source_(),
        logging::Severity::warning,
        "GH-REC-0001",
        pending.operation_id,
        "pf.recovery",
        "started",
        "Pending activation recovery started.",
        pending.target_revision));

    if (pending.phase == ActivationPhase::committed) {
        const auto last_known_good = revision_store_.last_known_good();
        if (!last_known_good.ok() || !last_known_good.revision.has_value() ||
            *last_known_good.revision != pending.target_revision) {
            result.status = ActivationRecoveryStatus::failed;
            result.event_id = "GH-REC-2001";
            result.message =
                "Committed transaction does not match the last-known-good marker.";
            static_cast<void>(append(activation_event(
                timestamp_source_(),
                logging::Severity::critical,
                result.event_id,
                pending.operation_id,
                "pf.recovery",
                "failed",
                result.message,
                pending.target_revision)));
            return result;
        }

        const auto cleared = transaction_store_.clear(pending.operation_id);
        audit_ok = append(transaction_event(
                       cleared,
                       timestamp_source_(),
                       pending.operation_id,
                       pending.target_revision,
                       "pf.activation_transaction.clear")) &&
                   audit_ok;
        if (cleared.status != ActivationTransactionStatus::cleared) {
            result.status = ActivationRecoveryStatus::failed;
            result.event_id = cleared.event_id;
            result.message = cleared.message;
            return result;
        }

        audit_ok = append(activation_event(
                       timestamp_source_(),
                       logging::Severity::info,
                       "GH-REC-0003",
                       pending.operation_id,
                       "pf.recovery",
                       "committed_cleanup",
                       "Committed activation transaction cleanup completed.",
                       pending.target_revision)) &&
                   audit_ok;
        result.status = audit_ok ? ActivationRecoveryStatus::committed_cleaned
                                 : ActivationRecoveryStatus::audit_failed_recovered;
        result.event_id = audit_ok ? "GH-REC-0003" : audit_event_id;
        result.message = audit_ok
                             ? "Committed activation transaction cleaned up."
                             : audit_message;
        return result;
    }

    const auto rollback_revision =
        revision_store_.load(pending.rollback_revision);
    if (!rollback_revision.ok()) {
        result.status = ActivationRecoveryStatus::failed;
        result.event_id = "GH-REC-2002";
        result.message = "Recovery rollback revision is unavailable or unsafe.";
        static_cast<void>(append(activation_event(
            timestamp_source_(),
            logging::Severity::critical,
            result.event_id,
            pending.operation_id,
            "pf.recovery",
            "failed",
            result.message,
            pending.rollback_revision)));
        return result;
    }

    const auto rollback_path =
        revision_store_.revision_path(pending.rollback_revision);
    const auto validation = validator_.validate(rollback_path);
    result.native_validation = validation;
    audit_ok = append(make_validation_event(
                   validation,
                   timestamp_source_(),
                   pending.operation_id,
                   pending.rollback_revision)) &&
               audit_ok;
    if (!validation.ok()) {
        result.status = ActivationRecoveryStatus::failed;
        result.event_id = validation.event_id;
        result.message = validation.message;
        return result;
    }

    const auto rollback_load = loader_.load(rollback_path);
    result.rollback = rollback_load;
    audit_ok = append(load_event(
                   rollback_load,
                   timestamp_source_(),
                   pending.operation_id,
                   pending.rollback_revision,
                   "pf.recovery.rollback")) &&
               audit_ok;
    if (!rollback_load.ok()) {
        result.status = ActivationRecoveryStatus::failed;
        result.event_id = rollback_load.event_id;
        result.message = rollback_load.message;
        return result;
    }

    const auto marker =
        revision_store_.mark_last_known_good(pending.rollback_revision);
    audit_ok = append(activation_event(
                   timestamp_source_(),
                   marker.ok() ? logging::Severity::info
                               : logging::Severity::critical,
                   marker.event_id,
                   pending.operation_id,
                   "pf.recovery.marker",
                   marker.ok() ? "succeeded" : "failed",
                   marker.message,
                   pending.rollback_revision)) &&
               audit_ok;
    if (!marker.ok()) {
        result.status = ActivationRecoveryStatus::failed;
        result.event_id = marker.event_id;
        result.message = marker.message;
        return result;
    }

    const auto cleared = transaction_store_.clear(pending.operation_id);
    audit_ok = append(transaction_event(
                   cleared,
                   timestamp_source_(),
                   pending.operation_id,
                   pending.target_revision,
                   "pf.activation_transaction.clear")) &&
               audit_ok;
    if (cleared.status != ActivationTransactionStatus::cleared) {
        result.status = ActivationRecoveryStatus::failed;
        result.event_id = cleared.event_id;
        result.message = cleared.message;
        return result;
    }

    audit_ok = append(activation_event(
                   timestamp_source_(),
                   logging::Severity::warning,
                   "GH-REC-0002",
                   pending.operation_id,
                   "pf.recovery",
                   "rolled_back",
                   "Pending activation was restored to last known good.",
                   pending.rollback_revision)) &&
               audit_ok;
    result.status = audit_ok ? ActivationRecoveryStatus::rolled_back
                             : ActivationRecoveryStatus::audit_failed_recovered;
    result.event_id = audit_ok ? "GH-REC-0002" : audit_event_id;
    result.message = audit_ok
                         ? "Pending activation recovered by rollback."
                         : audit_message;
    return result;
}

}  // namespace sasd::gatehold::firewall
