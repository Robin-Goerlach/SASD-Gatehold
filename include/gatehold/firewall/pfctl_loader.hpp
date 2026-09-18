#pragma once

#include "gatehold/system/posix_process_runner.hpp"

#include <chrono>
#include <filesystem>
#include <string>

namespace sasd::gatehold::firewall {

enum class PfctlLoadStatus {
    loaded,
    rejected,
    timed_out,
    execution_error,
    unsafe_revision
};

struct PfctlLoadResult {
    PfctlLoadStatus status{PfctlLoadStatus::execution_error};
    std::string event_id;
    int exit_code{-1};
    bool output_truncated{false};
    std::string standard_output;
    std::string standard_error;
    std::string message;

    [[nodiscard]] bool ok() const noexcept;
};

class PfctlLoader {
public:
    static constexpr std::chrono::milliseconds default_timeout{5000};

    explicit PfctlLoader(
        std::filesystem::path executable = "/sbin/pfctl",
        std::chrono::milliseconds timeout = default_timeout);

    [[nodiscard]] PfctlLoadResult load(
        const std::filesystem::path& revision_path) const;

private:
    std::filesystem::path executable_;
    std::chrono::milliseconds timeout_;
    system::PosixProcessRunner process_runner_;
};

}  // namespace sasd::gatehold::firewall
