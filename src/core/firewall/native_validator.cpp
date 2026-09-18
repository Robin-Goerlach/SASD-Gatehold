#include "gatehold/firewall/native_validator.hpp"

#include <sys/stat.h>
#include <unistd.h>

#include <string_view>
#include <utility>
#include <vector>

namespace sasd::gatehold::firewall {
namespace {

NativeValidationResult unsafe_candidate(std::string message) {
    return {
        .status = NativeValidationStatus::unsafe_candidate,
        .event_id = "GH-PF-1001",
        .exit_code = -1,
        .output_truncated = false,
        .standard_output = {},
        .standard_error = {},
        .message = std::move(message)};
}

std::string_view outcome(NativeValidationStatus status) noexcept {
    switch (status) {
        case NativeValidationStatus::valid:
            return "succeeded";
        case NativeValidationStatus::rejected:
        case NativeValidationStatus::unsafe_candidate:
            return "rejected";
        case NativeValidationStatus::timed_out:
            return "timed_out";
        case NativeValidationStatus::execution_error:
            return "failed";
    }
    return "failed";
}

}  // namespace

bool NativeValidationResult::ok() const noexcept {
    return status == NativeValidationStatus::valid;
}

logging::Event make_validation_event(
    const NativeValidationResult& result,
    std::string timestamp,
    std::string operation_id,
    std::uint64_t revision) {
    return {
        .timestamp = std::move(timestamp),
        .severity = result.ok() ? logging::Severity::info : logging::Severity::warning,
        .event_id = result.event_id,
        .component = "native-pf-validator",
        .operation_id = std::move(operation_id),
        .action = "pf.ruleset.validate",
        .outcome = std::string{outcome(result.status)},
        .message = result.message,
        .attributes = {
            {"exit_code", std::to_string(result.exit_code)},
            {"output_truncated", result.output_truncated ? "true" : "false"},
            {"revision", std::to_string(revision)}}};
}

PfctlValidator::PfctlValidator(
    std::filesystem::path executable,
    std::chrono::milliseconds timeout)
    : executable_{std::move(executable)}, timeout_{timeout} {}

NativeValidationResult PfctlValidator::validate(
    const std::filesystem::path& candidate_path) const {
    if (!candidate_path.is_absolute()) {
        return unsafe_candidate("Candidate path must be absolute.");
    }

    struct stat candidate_status {};
    if (::lstat(candidate_path.c_str(), &candidate_status) != 0 ||
        !S_ISREG(candidate_status.st_mode) ||
        candidate_status.st_uid != ::geteuid() ||
        (candidate_status.st_mode & (S_IRWXG | S_IRWXO)) != 0) {
        return unsafe_candidate(
            "Candidate must be a private regular, non-symlink file owned by the current user.");
    }

    const auto process = process_runner_.run(
        executable_, {"-nf", candidate_path.string()}, timeout_);

    if (!process.launched || process.exit_code == 126 ||
        process.exit_code == 127 || !process.error_message.empty()) {
        return {
            .status = NativeValidationStatus::execution_error,
            .event_id = "GH-PF-2001",
            .exit_code = process.exit_code,
            .output_truncated = process.output_truncated,
            .standard_output = process.standard_output,
            .standard_error = process.standard_error,
            .message = process.error_message.empty()
                           ? "Could not execute native PF validation."
                           : process.error_message};
    }

    if (process.timed_out) {
        return {
            .status = NativeValidationStatus::timed_out,
            .event_id = "GH-PF-2002",
            .exit_code = process.exit_code,
            .output_truncated = process.output_truncated,
            .standard_output = process.standard_output,
            .standard_error = process.standard_error,
            .message = "Native PF validation exceeded its time limit."};
    }

    if (process.exit_code != 0) {
        return {
            .status = NativeValidationStatus::rejected,
            .event_id = "GH-PF-1002",
            .exit_code = process.exit_code,
            .output_truncated = process.output_truncated,
            .standard_output = process.standard_output,
            .standard_error = process.standard_error,
            .message = "Native PF validation rejected the candidate."};
    }

    return {
        .status = NativeValidationStatus::valid,
        .event_id = "GH-PF-0001",
        .exit_code = process.exit_code,
        .output_truncated = process.output_truncated,
        .standard_output = process.standard_output,
        .standard_error = process.standard_error,
        .message = "Native PF validation accepted the candidate."};
}

}  // namespace sasd::gatehold::firewall
