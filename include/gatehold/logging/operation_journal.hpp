#pragma once

#include "gatehold/logging/event.hpp"

#include <cstddef>
#include <filesystem>
#include <string>

namespace sasd::gatehold::logging {

enum class JournalStatus {
    appended,
    invalid_event,
    unsafe_root,
    unsafe_journal,
    capacity_exceeded,
    io_error
};

struct JournalResult {
    JournalStatus status{JournalStatus::io_error};
    std::string event_id;
    std::string message;

    [[nodiscard]] bool ok() const noexcept;
};

class OperationJournal {
public:
    static constexpr std::size_t maximum_entry_size = 64U * 1024U;
    static constexpr std::size_t maximum_journal_size = 16U * 1024U * 1024U;

    explicit OperationJournal(std::filesystem::path root_directory);

    [[nodiscard]] JournalResult append(const Event& event) const;
    [[nodiscard]] std::filesystem::path journal_path() const;

private:
    std::filesystem::path root_directory_;
};

}  // namespace sasd::gatehold::logging
