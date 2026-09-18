#pragma once

#include "gatehold/logging/event.hpp"
#include "gatehold/system/posix_process_runner.hpp"

#include <chrono>
#include <cstdint>
#include <filesystem>
#include <string>

namespace sasd::gatehold::firewall {

enum class NativeValidationStatus {
    valid,
    rejected,
    timed_out,
    execution_error,
    unsafe_candidate
};

struct NativeValidationResult {
    NativeValidationStatus status{NativeValidationStatus::execution_error};
    std::string event_id;
    int exit_code{-1};
    bool output_truncated{false};
    std::string standard_output;
    std::string standard_error;
    std::string message;

    [[nodiscard]] bool ok() const noexcept;
};

[[nodiscard]] logging::Event make_validation_event(
    const NativeValidationResult& result,
    std::string timestamp,
    std::string operation_id,
    std::uint64_t revision);

class PfctlValidator {
public:
    static constexpr std::chrono::milliseconds default_timeout{5000};

    explicit PfctlValidator(
        std::filesystem::path executable = "/sbin/pfctl",
        std::chrono::milliseconds timeout = default_timeout);

    [[nodiscard]] NativeValidationResult validate(
        const std::filesystem::path& candidate_path) const;

private:
    std::filesystem::path executable_;
    std::chrono::milliseconds timeout_;
    system::PosixProcessRunner process_runner_;
};

}  // namespace sasd::gatehold::firewall
