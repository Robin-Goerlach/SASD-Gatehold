#include "gatehold/firewall/activation_transaction_store.hpp"

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <array>
#include <atomic>
#include <cerrno>
#include <charconv>
#include <cstring>
#include <string_view>
#include <utility>

namespace sasd::gatehold::firewall {
namespace {

constexpr std::string_view transaction_filename = "pending-activation";
constexpr std::string_view format_header = "gatehold-activation-v1";
constexpr std::size_t maximum_record_size = 1024U;
std::atomic<std::uint64_t> temporary_sequence{0};

ActivationTransactionResult failure(
    ActivationTransactionStatus status,
    std::string event_id,
    std::string message) {
    return {
        .status = status,
        .event_id = std::move(event_id),
        .message = std::move(message),
        .transaction = std::nullopt};
}

bool valid_identifier(std::string_view value) noexcept {
    if (value.empty() || value.size() > 128U) {
        return false;
    }
    for (const char character : value) {
        const bool alpha_numeric =
            (character >= 'a' && character <= 'z') ||
            (character >= 'A' && character <= 'Z') ||
            (character >= '0' && character <= '9');
        if (!alpha_numeric && character != '-' && character != '_' &&
            character != '.' && character != ':') {
            return false;
        }
    }
    return true;
}

bool valid_transaction(const PendingActivation& transaction) noexcept {
    return valid_identifier(transaction.operation_id) &&
           transaction.target_revision > 0 &&
           transaction.rollback_revision > 0 &&
           transaction.target_revision != transaction.rollback_revision;
}

int open_safe_root(const std::filesystem::path& root) noexcept {
    if (!root.is_absolute()) {
        errno = EINVAL;
        return -1;
    }
    const int descriptor =
        ::open(root.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (descriptor < 0) {
        return -1;
    }

    struct stat status {};
    if (::fstat(descriptor, &status) != 0 || !S_ISDIR(status.st_mode) ||
        status.st_uid != ::geteuid() ||
        (status.st_mode & (S_IWGRP | S_IWOTH)) != 0) {
        ::close(descriptor);
        errno = EPERM;
        return -1;
    }
    return descriptor;
}

bool private_regular_file(const struct stat& status) noexcept {
    return S_ISREG(status.st_mode) && status.st_uid == ::geteuid() &&
           (status.st_mode & (S_IRWXG | S_IRWXO)) == 0;
}

bool write_all(int descriptor, std::string_view content) noexcept {
    std::size_t offset = 0;
    while (offset < content.size()) {
        const auto written = ::write(
            descriptor, content.data() + offset, content.size() - offset);
        if (written < 0) {
            if (errno == EINTR) {
                continue;
            }
            return false;
        }
        if (written == 0) {
            errno = EIO;
            return false;
        }
        offset += static_cast<std::size_t>(written);
    }
    return true;
}

bool read_all(int descriptor, std::size_t size, std::string& content) {
    content.assign(size, '\0');
    std::size_t offset = 0;
    while (offset < size) {
        const auto count = ::read(descriptor, content.data() + offset, size - offset);
        if (count < 0) {
            if (errno == EINTR) {
                continue;
            }
            return false;
        }
        if (count == 0) {
            errno = EIO;
            return false;
        }
        offset += static_cast<std::size_t>(count);
    }
    return true;
}

std::string serialize(const PendingActivation& transaction) {
    return std::string{format_header} + "\noperation_id=" +
           transaction.operation_id + "\ntarget_revision=" +
           std::to_string(transaction.target_revision) + "\nrollback_revision=" +
           std::to_string(transaction.rollback_revision) + "\nphase=" +
           to_string(transaction.phase) + "\n";
}

std::optional<ActivationPhase> parse_phase(std::string_view value) noexcept {
    if (value == "prepared_for_load") {
        return ActivationPhase::prepared_for_load;
    }
    if (value == "target_loaded") {
        return ActivationPhase::target_loaded;
    }
    if (value == "verified") {
        return ActivationPhase::verified;
    }
    if (value == "awaiting_confirmation") {
        return ActivationPhase::awaiting_confirmation;
    }
    if (value == "committing") {
        return ActivationPhase::committing;
    }
    if (value == "committed") {
        return ActivationPhase::committed;
    }
    return std::nullopt;
}

bool parse_revision(std::string_view value, std::uint64_t& revision) noexcept {
    revision = 0;
    const auto [end, error] =
        std::from_chars(value.data(), value.data() + value.size(), revision);
    return error == std::errc{} && end == value.data() + value.size() &&
           revision > 0;
}

std::optional<PendingActivation> parse(std::string_view content) {
    std::array<std::string_view, 5> lines{};
    std::size_t line_index = 0;
    std::size_t position = 0;
    while (position < content.size() && line_index < lines.size()) {
        const auto end = content.find('\n', position);
        if (end == std::string_view::npos) {
            return std::nullopt;
        }
        lines[line_index++] = content.substr(position, end - position);
        position = end + 1U;
    }
    if (line_index != lines.size() || position != content.size() ||
        lines[0] != format_header) {
        return std::nullopt;
    }

    constexpr std::string_view operation_prefix = "operation_id=";
    constexpr std::string_view target_prefix = "target_revision=";
    constexpr std::string_view rollback_prefix = "rollback_revision=";
    constexpr std::string_view phase_prefix = "phase=";
    if (!lines[1].starts_with(operation_prefix) ||
        !lines[2].starts_with(target_prefix) ||
        !lines[3].starts_with(rollback_prefix) ||
        !lines[4].starts_with(phase_prefix)) {
        return std::nullopt;
    }

    PendingActivation transaction;
    transaction.operation_id = lines[1].substr(operation_prefix.size());
    if (!parse_revision(
            lines[2].substr(target_prefix.size()), transaction.target_revision) ||
        !parse_revision(
            lines[3].substr(rollback_prefix.size()),
            transaction.rollback_revision)) {
        return std::nullopt;
    }
    const auto phase = parse_phase(lines[4].substr(phase_prefix.size()));
    if (!phase.has_value()) {
        return std::nullopt;
    }
    transaction.phase = *phase;
    if (!valid_transaction(transaction)) {
        return std::nullopt;
    }
    return transaction;
}

bool valid_transition(ActivationPhase current, ActivationPhase next) noexcept {
    return static_cast<int>(next) == static_cast<int>(current) + 1;
}

ActivationTransactionResult persist_replacement(
    int directory_descriptor,
    const PendingActivation& transaction) {
    const auto sequence = temporary_sequence.fetch_add(1U);
    const std::string temporary_name =
        ".pending-activation." + std::to_string(::getpid()) + "." +
        std::to_string(sequence) + ".tmp";
    const int descriptor = ::openat(
        directory_descriptor,
        temporary_name.c_str(),
        O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
        S_IRUSR | S_IWUSR);
    if (descriptor < 0) {
        return failure(
            ActivationTransactionStatus::io_error,
            "GH-TXN-2003",
            std::string{"Could not create transaction update: "} +
                std::strerror(errno));
    }

    const std::string content = serialize(transaction);
    bool successful = write_all(descriptor, content);
    if (successful && ::fsync(descriptor) != 0) {
        successful = false;
    }
    if (::close(descriptor) != 0) {
        successful = false;
    }
    if (successful &&
        ::renameat(
            directory_descriptor,
            temporary_name.c_str(),
            directory_descriptor,
            transaction_filename.data()) != 0) {
        successful = false;
    }
    if (successful && ::fsync(directory_descriptor) != 0) {
        successful = false;
    }
    if (!successful) {
        const int write_error = errno;
        ::unlinkat(directory_descriptor, temporary_name.c_str(), 0);
        return failure(
            ActivationTransactionStatus::io_error,
            "GH-TXN-2004",
            std::string{"Could not atomically update transaction: "} +
                std::strerror(write_error));
    }

    return {
        .status = ActivationTransactionStatus::advanced,
        .event_id = "GH-TXN-0002",
        .message = "Pending activation transaction advanced durably.",
        .transaction = transaction};
}

}  // namespace

std::string to_string(ActivationPhase phase) {
    switch (phase) {
        case ActivationPhase::prepared_for_load:
            return "prepared_for_load";
        case ActivationPhase::target_loaded:
            return "target_loaded";
        case ActivationPhase::verified:
            return "verified";
        case ActivationPhase::awaiting_confirmation:
            return "awaiting_confirmation";
        case ActivationPhase::committing:
            return "committing";
        case ActivationPhase::committed:
            return "committed";
    }
    return "prepared_for_load";
}

bool ActivationTransactionResult::ok() const noexcept {
    return status == ActivationTransactionStatus::created ||
           status == ActivationTransactionStatus::advanced ||
           status == ActivationTransactionStatus::loaded ||
           status == ActivationTransactionStatus::cleared ||
           status == ActivationTransactionStatus::no_pending;
}

ActivationTransactionStore::ActivationTransactionStore(
    std::filesystem::path root_directory)
    : root_directory_{std::move(root_directory)} {}

std::filesystem::path ActivationTransactionStore::transaction_path() const {
    return root_directory_ / transaction_filename;
}

ActivationTransactionResult ActivationTransactionStore::begin(
    const PendingActivation& transaction) const {
    if (!valid_transaction(transaction) ||
        transaction.phase != ActivationPhase::prepared_for_load) {
        return failure(
            ActivationTransactionStatus::invalid_record,
            "GH-TXN-1001",
            "Pending activation transaction is invalid.");
    }

    const int directory_descriptor = open_safe_root(root_directory_);
    if (directory_descriptor < 0) {
        return failure(
            ActivationTransactionStatus::unsafe_root,
            "GH-TXN-1002",
            "Transaction root is not a safe owner-controlled directory.");
    }

    const auto sequence = temporary_sequence.fetch_add(1U);
    const std::string temporary_name =
        ".pending-activation.begin." + std::to_string(::getpid()) + "." +
        std::to_string(sequence) + ".tmp";
    const int descriptor = ::openat(
        directory_descriptor,
        temporary_name.c_str(),
        O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
        S_IRUSR | S_IWUSR);
    if (descriptor < 0) {
        const int open_error = errno;
        ::close(directory_descriptor);
        return failure(
            ActivationTransactionStatus::io_error,
            "GH-TXN-2001",
            std::string{"Could not create pending transaction temporary file: "} +
                std::strerror(open_error));
    }

    const std::string content = serialize(transaction);
    bool successful = write_all(descriptor, content);
    if (successful && ::fsync(descriptor) != 0) {
        successful = false;
    }
    if (::close(descriptor) != 0) {
        successful = false;
    }
    if (!successful) {
        const int write_error = errno;
        ::unlinkat(directory_descriptor, temporary_name.c_str(), 0);
        ::close(directory_descriptor);
        return failure(
            ActivationTransactionStatus::io_error,
            "GH-TXN-2002",
            std::string{"Could not persist pending transaction temporary file: "} +
                std::strerror(write_error));
    }

    if (::linkat(
            directory_descriptor,
            temporary_name.c_str(),
            directory_descriptor,
            transaction_filename.data(),
            0) != 0) {
        const int link_error = errno;
        ::unlinkat(directory_descriptor, temporary_name.c_str(), 0);
        ::close(directory_descriptor);
        if (link_error == EEXIST) {
            return failure(
                ActivationTransactionStatus::conflict,
                "GH-TXN-1003",
                "Another pending activation transaction already exists.");
        }
        return failure(
            ActivationTransactionStatus::io_error,
            "GH-TXN-2002",
            std::string{"Could not publish pending transaction atomically: "} +
                std::strerror(link_error));
    }
    ::unlinkat(directory_descriptor, temporary_name.c_str(), 0);
    if (::fsync(directory_descriptor) != 0) {
        const int sync_error = errno;
        ::close(directory_descriptor);
        return failure(
            ActivationTransactionStatus::io_error,
            "GH-TXN-2002",
            std::string{"Could not synchronize pending transaction: "} +
                std::strerror(sync_error));
    }
    ::close(directory_descriptor);

    return {
        .status = ActivationTransactionStatus::created,
        .event_id = "GH-TXN-0001",
        .message = "Pending activation transaction created durably.",
        .transaction = transaction};
}

ActivationTransactionResult ActivationTransactionStore::load() const {
    const int directory_descriptor = open_safe_root(root_directory_);
    if (directory_descriptor < 0) {
        return failure(
            ActivationTransactionStatus::unsafe_root,
            "GH-TXN-1002",
            "Transaction root is not a safe owner-controlled directory.");
    }

    const int descriptor = ::openat(
        directory_descriptor,
        transaction_filename.data(),
        O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (descriptor < 0) {
        const int open_error = errno;
        ::close(directory_descriptor);
        if (open_error == ENOENT) {
            return {
                .status = ActivationTransactionStatus::no_pending,
                .event_id = "GH-TXN-0005",
                .message = "No pending activation transaction exists.",
                .transaction = std::nullopt};
        }
        return failure(
            ActivationTransactionStatus::unsafe_file,
            "GH-TXN-1004",
            "Pending activation transaction could not be opened safely.");
    }

    struct stat status {};
    if (::fstat(descriptor, &status) != 0 || !private_regular_file(status) ||
        status.st_size <= 0 ||
        static_cast<std::uintmax_t>(status.st_size) > maximum_record_size) {
        ::close(descriptor);
        ::close(directory_descriptor);
        return failure(
            ActivationTransactionStatus::unsafe_file,
            "GH-TXN-1004",
            "Pending activation transaction failed safety checks.");
    }

    std::string content;
    const bool read_successful = read_all(
        descriptor, static_cast<std::size_t>(status.st_size), content);
    const int read_error = errno;
    ::close(descriptor);
    ::close(directory_descriptor);
    if (!read_successful) {
        return failure(
            ActivationTransactionStatus::io_error,
            "GH-TXN-2005",
            std::string{"Could not read pending transaction: "} +
                std::strerror(read_error));
    }

    const auto transaction = parse(content);
    if (!transaction.has_value()) {
        return failure(
            ActivationTransactionStatus::invalid_record,
            "GH-TXN-1005",
            "Pending activation transaction is malformed or unsupported.");
    }
    return {
        .status = ActivationTransactionStatus::loaded,
        .event_id = "GH-TXN-0003",
        .message = "Pending activation transaction loaded safely.",
        .transaction = transaction};
}

ActivationTransactionResult ActivationTransactionStore::advance(
    const std::string& operation_id,
    ActivationPhase next_phase) const {
    const auto current = load();
    if (current.status != ActivationTransactionStatus::loaded ||
        !current.transaction.has_value()) {
        return current;
    }
    if (current.transaction->operation_id != operation_id ||
        !valid_transition(current.transaction->phase, next_phase)) {
        return failure(
            ActivationTransactionStatus::invalid_transition,
            "GH-TXN-1006",
            "Pending activation transaction transition is invalid.");
    }

    auto updated = *current.transaction;
    updated.phase = next_phase;
    const int directory_descriptor = open_safe_root(root_directory_);
    if (directory_descriptor < 0) {
        return failure(
            ActivationTransactionStatus::unsafe_root,
            "GH-TXN-1002",
            "Transaction root is not a safe owner-controlled directory.");
    }
    auto result = persist_replacement(directory_descriptor, updated);
    ::close(directory_descriptor);
    return result;
}

ActivationTransactionResult ActivationTransactionStore::clear(
    const std::string& operation_id) const {
    const auto current = load();
    if (current.status != ActivationTransactionStatus::loaded ||
        !current.transaction.has_value()) {
        return current;
    }
    if (current.transaction->operation_id != operation_id) {
        return failure(
            ActivationTransactionStatus::conflict,
            "GH-TXN-1007",
            "Pending transaction belongs to a different operation.");
    }

    const int directory_descriptor = open_safe_root(root_directory_);
    if (directory_descriptor < 0) {
        return failure(
            ActivationTransactionStatus::unsafe_root,
            "GH-TXN-1002",
            "Transaction root is not a safe owner-controlled directory.");
    }
    if (::unlinkat(directory_descriptor, transaction_filename.data(), 0) != 0 ||
        ::fsync(directory_descriptor) != 0) {
        const int clear_error = errno;
        ::close(directory_descriptor);
        return failure(
            ActivationTransactionStatus::io_error,
            "GH-TXN-2006",
            std::string{"Could not clear pending transaction: "} +
                std::strerror(clear_error));
    }
    ::close(directory_descriptor);
    return {
        .status = ActivationTransactionStatus::cleared,
        .event_id = "GH-TXN-0004",
        .message = "Pending activation transaction cleared durably.",
        .transaction = current.transaction};
}

}  // namespace sasd::gatehold::firewall
