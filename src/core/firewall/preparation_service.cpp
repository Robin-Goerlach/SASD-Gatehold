#include "gatehold/firewall/preparation_service.hpp"

#include "gatehold/firewall/pf_renderer.hpp"

#include <chrono>
#include <cstdint>
#include <ctime>
#include <iomanip>
#include <sstream>
#include <string_view>
#include <utility>

namespace sasd::gatehold::firewall {
namespace {

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

logging::Event operation_event(
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
        .component = "pf-preparation-service",
        .operation_id = std::move(operation_id),
        .action = std::move(action),
        .outcome = std::move(outcome),
        .message = std::move(message),
        .attributes = {{"revision", std::to_string(revision)}}};
}

PreparationStatus map_native_status(NativeValidationStatus status) noexcept {
    switch (status) {
        case NativeValidationStatus::valid:
            return PreparationStatus::prepared;
        case NativeValidationStatus::rejected:
            return PreparationStatus::native_rejected;
        case NativeValidationStatus::timed_out:
            return PreparationStatus::native_timed_out;
        case NativeValidationStatus::execution_error:
            return PreparationStatus::native_execution_error;
        case NativeValidationStatus::unsafe_candidate:
            return PreparationStatus::unsafe_candidate;
    }
    return PreparationStatus::native_execution_error;
}

}  // namespace

bool PreparationResult::ok() const noexcept {
    return status == PreparationStatus::prepared;
}

PfPreparationService::PfPreparationService(
    const CandidateStore& candidate_store,
    const PfctlValidator& native_validator,
    const RevisionStore& revision_store,
    const logging::OperationJournal& journal,
    TimestampSource timestamp_source)
    : candidate_store_{candidate_store},
      native_validator_{native_validator},
      revision_store_{revision_store},
      journal_{journal},
      timestamp_source_{std::move(timestamp_source)} {
    if (!timestamp_source_) {
        timestamp_source_ = system_utc_timestamp;
    }
}

PreparationResult PfPreparationService::prepare(
    const PreparationRequest& request) const {
    PreparationResult result;

    const auto append = [this, &result](logging::Event event) {
        const auto journal_result = journal_.append(event);
        if (!journal_result.ok()) {
            result.status = PreparationStatus::audit_failed;
            result.event_id = journal_result.event_id;
            result.message = journal_result.message;
            return false;
        }
        result.journaled_events.push_back(std::move(event));
        return true;
    };

    if (!append(operation_event(
            timestamp_source_(),
            logging::Severity::info,
            "GH-OP-0001",
            request.operation_id,
            "pf.prepare",
            "started",
            "PF preparation operation started.",
            request.rule_set.revision))) {
        return result;
    }

    const auto rendered = PfRenderer{}.render(request.rule_set);
    if (!rendered.ok()) {
        result.status = PreparationStatus::invalid_model;
        result.event_id = rendered.validation.issues().empty()
                              ? "GH-CFG-1000"
                              : rendered.validation.issues().front().code;
        result.message = "Portable firewall-model validation rejected the request.";
        result.validation_issues = rendered.validation.issues();

        auto event = operation_event(
            timestamp_source_(),
            logging::Severity::warning,
            result.event_id,
            request.operation_id,
            "pf.ruleset.render",
            "rejected",
            result.message,
            request.rule_set.revision);
        event.attributes.emplace(
            "issue_count", std::to_string(result.validation_issues.size()));
        if (!result.validation_issues.empty()) {
            event.attributes.emplace(
                "first_issue_code", result.validation_issues.front().code);
        }
        if (!append(std::move(event))) {
            return result;
        }
        return result;
    }

    auto rendered_event = operation_event(
        timestamp_source_(),
        logging::Severity::info,
        "GH-OP-0002",
        request.operation_id,
        "pf.ruleset.render",
        "succeeded",
        "PF candidate rendered successfully.",
        request.rule_set.revision);
    rendered_event.attributes.emplace(
        "candidate_bytes", std::to_string(rendered.ruleset.size()));
    rendered_event.attributes.emplace(
        "rule_count", std::to_string(request.rule_set.rules.size()));
    if (!append(std::move(rendered_event))) {
        return result;
    }

    if (!append(operation_event(
            timestamp_source_(),
            logging::Severity::info,
            "GH-OP-0003",
            request.operation_id,
            "pf.candidate.stage",
            "started",
            "PF candidate staging started.",
            request.rule_set.revision))) {
        return result;
    }

    const auto staged = candidate_store_.stage(request.operation_id, rendered.ruleset);
    result.stage_result = staged;
    result.candidate_path = staged.candidate_path;
    auto staged_event = operation_event(
        timestamp_source_(),
        staged.ok() ? logging::Severity::info : logging::Severity::warning,
        staged.event_id,
        request.operation_id,
        "pf.candidate.stage",
        staged.ok() ? "succeeded" : "failed",
        staged.message,
        request.rule_set.revision);
    if (staged.ok()) {
        staged_event.attributes.emplace(
            "candidate_name", staged.candidate_path.filename().string());
    }
    if (!append(std::move(staged_event))) {
        return result;
    }
    if (!staged.ok()) {
        result.status = PreparationStatus::staging_failed;
        result.event_id = staged.event_id;
        result.message = staged.message;
        return result;
    }

    if (!append(operation_event(
            timestamp_source_(),
            logging::Severity::info,
            "GH-OP-0004",
            request.operation_id,
            "pf.ruleset.validate",
            "started",
            "Native PF validation started.",
            request.rule_set.revision))) {
        return result;
    }

    const auto native = native_validator_.validate(staged.candidate_path);
    result.native_validation = native;
    if (!append(make_validation_event(
            native,
            timestamp_source_(),
            request.operation_id,
            request.rule_set.revision))) {
        return result;
    }

    result.status = map_native_status(native.status);
    result.event_id = native.event_id;
    result.message = native.message;
    if (!native.ok()) {
        return result;
    }

    if (!append(operation_event(
            timestamp_source_(),
            logging::Severity::info,
            "GH-OP-0005",
            request.operation_id,
            "pf.revision.store",
            "started",
            "Immutable PF revision storage started.",
            request.rule_set.revision))) {
        return result;
    }

    const auto revision_write = revision_store_.store(
        request.rule_set.revision, staged.candidate_path);
    result.revision_write = revision_write;
    result.revision_path = revision_write.revision_path;
    auto revision_event = operation_event(
        timestamp_source_(),
        revision_write.ok() ? logging::Severity::info : logging::Severity::warning,
        revision_write.event_id,
        request.operation_id,
        "pf.revision.store",
        revision_write.ok() ? "succeeded" : "failed",
        revision_write.message,
        request.rule_set.revision);
    if (revision_write.ok()) {
        revision_event.attributes.emplace(
            "revision_name", revision_write.revision_path.filename().string());
    }
    if (!append(std::move(revision_event))) {
        return result;
    }
    if (!revision_write.ok()) {
        result.status = PreparationStatus::revision_store_failed;
        result.event_id = revision_write.event_id;
        result.message = revision_write.message;
        return result;
    }

    if (!append(operation_event(
            timestamp_source_(),
            logging::Severity::info,
            "GH-OP-0006",
            request.operation_id,
            "pf.prepare",
            "prepared",
            "PF candidate is rendered, staged, natively validated, and stored as an immutable revision.",
            request.rule_set.revision))) {
        return result;
    }

    result.status = PreparationStatus::prepared;
    result.event_id = "GH-OP-0006";
    result.message = "PF candidate prepared successfully; no activation was performed.";
    return result;
}

}  // namespace sasd::gatehold::firewall
