#pragma once

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>

namespace sasd::gatehold::firewall {

enum class RevisionStatus {
    stored,
    loaded,
    marked_last_known_good,
    last_known_good_found,
    invalid_revision,
    unsafe_root,
    unsafe_source,
    already_exists,
    not_found,
    corrupt_pointer,
    too_large,
    io_error
};

struct RevisionWriteResult {
    RevisionStatus status{RevisionStatus::io_error};
    std::string event_id;
    std::string message;
    std::filesystem::path revision_path;

    [[nodiscard]] bool ok() const noexcept;
};

struct RevisionReadResult {
    RevisionStatus status{RevisionStatus::io_error};
    std::string event_id;
    std::string message;
    std::string content;

    [[nodiscard]] bool ok() const noexcept;
};

struct LastKnownGoodResult {
    RevisionStatus status{RevisionStatus::io_error};
    std::string event_id;
    std::string message;
    std::optional<std::uint64_t> revision;

    [[nodiscard]] bool ok() const noexcept;
};

class RevisionStore {
public:
    static constexpr std::size_t maximum_revision_size = 1024U * 1024U;

    explicit RevisionStore(std::filesystem::path root_directory);

    [[nodiscard]] RevisionWriteResult store(
        std::uint64_t revision,
        const std::filesystem::path& validated_candidate) const;
    [[nodiscard]] RevisionReadResult load(std::uint64_t revision) const;
    [[nodiscard]] LastKnownGoodResult mark_last_known_good(
        std::uint64_t revision) const;
    [[nodiscard]] LastKnownGoodResult last_known_good() const;
    [[nodiscard]] std::filesystem::path revision_path(
        std::uint64_t revision) const;

private:
    std::filesystem::path root_directory_;
};

}  // namespace sasd::gatehold::firewall

