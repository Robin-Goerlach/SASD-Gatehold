#pragma once

#include <chrono>
#include <cstddef>
#include <filesystem>
#include <string>
#include <vector>

namespace sasd::gatehold::system {

struct ProcessResult {
    bool launched{false};
    bool timed_out{false};
    bool output_truncated{false};
    int exit_code{-1};
    std::string standard_output;
    std::string standard_error;
    std::string error_message;
};

class PosixProcessRunner {
public:
    static constexpr std::size_t maximum_captured_output = 64U * 1024U;

    [[nodiscard]] ProcessResult run(
        const std::filesystem::path& executable,
        const std::vector<std::string>& arguments,
        std::chrono::milliseconds timeout) const;
};

}  // namespace sasd::gatehold::system

