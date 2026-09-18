#pragma once

#include <cstddef>
#include <filesystem>
#include <string>
#include <string_view>

namespace sasd::gatehold::firewall {

enum class StageStatus {
    staged,
    invalid_operation_id,
    invalid_content,
    unsafe_root,
    already_exists,
    io_error
};

struct StageResult {
    StageStatus status{StageStatus::io_error};
    std::filesystem::path candidate_path;
    std::string event_id;
    std::string message;

    [[nodiscard]] bool ok() const noexcept;
};

class CandidateStore {
public:
    static constexpr std::size_t maximum_candidate_size = 1024U * 1024U;

    explicit CandidateStore(std::filesystem::path root_directory);

    [[nodiscard]] StageResult stage(
        std::string_view operation_id,
        std::string_view candidate) const;

    [[nodiscard]] const std::filesystem::path& root_directory() const noexcept;

private:
    std::filesystem::path root_directory_;
};

}  // namespace sasd::gatehold::firewall

