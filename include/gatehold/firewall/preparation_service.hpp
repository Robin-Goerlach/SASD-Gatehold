#pragma once

#include "gatehold/firewall/candidate_store.hpp"
#include "gatehold/firewall/model.hpp"
#include "gatehold/firewall/native_validator.hpp"
#include "gatehold/firewall/revision_store.hpp"
#include "gatehold/logging/event.hpp"
#include "gatehold/logging/operation_journal.hpp"

#include <filesystem>
#include <functional>
#include <optional>
#include <string>
#include <vector>

namespace sasd::gatehold::firewall {

enum class PreparationStatus {
    prepared,
    invalid_model,
    staging_failed,
    native_rejected,
    native_timed_out,
    native_execution_error,
    unsafe_candidate,
    revision_store_failed,
    audit_failed
};

struct PreparationRequest {
    std::string operation_id;
    RuleSet rule_set;
};

struct PreparationResult {
    PreparationStatus status{PreparationStatus::audit_failed};
    std::string event_id;
    std::string message;
    std::filesystem::path candidate_path;
    std::vector<ValidationIssue> validation_issues;
    std::optional<StageResult> stage_result;
    std::optional<NativeValidationResult> native_validation;
    std::optional<RevisionWriteResult> revision_write;
    std::filesystem::path revision_path;
    std::vector<logging::Event> journaled_events;

    [[nodiscard]] bool ok() const noexcept;
};

using TimestampSource = std::function<std::string()>;

class PfPreparationService {
public:
    PfPreparationService(
        const CandidateStore& candidate_store,
        const PfctlValidator& native_validator,
        const RevisionStore& revision_store,
        const logging::OperationJournal& journal,
        TimestampSource timestamp_source = {});

    [[nodiscard]] PreparationResult prepare(
        const PreparationRequest& request) const;

private:
    const CandidateStore& candidate_store_;
    const PfctlValidator& native_validator_;
    const RevisionStore& revision_store_;
    const logging::OperationJournal& journal_;
    TimestampSource timestamp_source_;
};

}  // namespace sasd::gatehold::firewall
