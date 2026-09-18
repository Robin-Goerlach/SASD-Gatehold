#pragma once

#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>

namespace sasd::gatehold::firewall {

enum class ActivationPhase {
    prepared_for_load,
    target_loaded,
    verified,
    awaiting_confirmation,
    committing,
    committed
};

struct PendingActivation {
    std::string operation_id;
    std::uint64_t target_revision{0};
    std::uint64_t rollback_revision{0};
    ActivationPhase phase{ActivationPhase::prepared_for_load};
};

enum class ActivationTransactionStatus {
    created,
    advanced,
    loaded,
    cleared,
    no_pending,
    conflict,
    invalid_record,
    invalid_transition,
    unsafe_root,
    unsafe_file,
    io_error
};

struct ActivationTransactionResult {
    ActivationTransactionStatus status{ActivationTransactionStatus::io_error};
    std::string event_id;
    std::string message;
    std::optional<PendingActivation> transaction;

    [[nodiscard]] bool ok() const noexcept;
};

class ActivationTransactionStore {
public:
    explicit ActivationTransactionStore(std::filesystem::path root_directory);

    [[nodiscard]] ActivationTransactionResult begin(
        const PendingActivation& transaction) const;
    [[nodiscard]] ActivationTransactionResult advance(
        const std::string& operation_id,
        ActivationPhase next_phase) const;
    [[nodiscard]] ActivationTransactionResult load() const;
    [[nodiscard]] ActivationTransactionResult clear(
        const std::string& operation_id) const;
    [[nodiscard]] std::filesystem::path transaction_path() const;

private:
    std::filesystem::path root_directory_;
};

[[nodiscard]] std::string to_string(ActivationPhase phase);

}  // namespace sasd::gatehold::firewall
