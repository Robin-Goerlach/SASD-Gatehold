#include "gatehold/firewall/pfctl_loader.hpp"

#include <sys/stat.h>
#include <unistd.h>

#include <utility>
#include <vector>

namespace sasd::gatehold::firewall {
namespace {

PfctlLoadResult unsafe_revision(std::string message) {
    return {
        .status = PfctlLoadStatus::unsafe_revision,
        .event_id = "GH-PF-1003",
        .exit_code = -1,
        .output_truncated = false,
        .standard_output = {},
        .standard_error = {},
        .message = std::move(message)};
}

}  // namespace

bool PfctlLoadResult::ok() const noexcept {
    return status == PfctlLoadStatus::loaded;
}

PfctlLoader::PfctlLoader(
    std::filesystem::path executable,
    std::chrono::milliseconds timeout)
    : executable_{std::move(executable)}, timeout_{timeout} {}

PfctlLoadResult PfctlLoader::load(
    const std::filesystem::path& revision_path) const {
    if (!revision_path.is_absolute()) {
        return unsafe_revision("Revision path must be absolute.");
    }

    struct stat revision_status {};
    if (::lstat(revision_path.c_str(), &revision_status) != 0 ||
        !S_ISREG(revision_status.st_mode) ||
        revision_status.st_uid != ::geteuid() ||
        (revision_status.st_mode & (S_IRWXG | S_IRWXO)) != 0) {
        return unsafe_revision(
            "Revision must be a private regular, non-symlink file owned by the current user.");
    }

    const auto process = process_runner_.run(
        executable_, {"-f", revision_path.string()}, timeout_);

    if (!process.launched || process.exit_code == 126 ||
        process.exit_code == 127 || !process.error_message.empty()) {
        return {
            .status = PfctlLoadStatus::execution_error,
            .event_id = "GH-PF-2003",
            .exit_code = process.exit_code,
            .output_truncated = process.output_truncated,
            .standard_output = process.standard_output,
            .standard_error = process.standard_error,
            .message = process.error_message.empty()
                           ? "Could not execute native PF activation."
                           : process.error_message};
    }

    if (process.timed_out) {
        return {
            .status = PfctlLoadStatus::timed_out,
            .event_id = "GH-PF-2004",
            .exit_code = process.exit_code,
            .output_truncated = process.output_truncated,
            .standard_output = process.standard_output,
            .standard_error = process.standard_error,
            .message = "Native PF activation exceeded its time limit."};
    }

    if (process.exit_code != 0) {
        return {
            .status = PfctlLoadStatus::rejected,
            .event_id = "GH-PF-1004",
            .exit_code = process.exit_code,
            .output_truncated = process.output_truncated,
            .standard_output = process.standard_output,
            .standard_error = process.standard_error,
            .message = "Native PF activation rejected the revision."};
    }

    return {
        .status = PfctlLoadStatus::loaded,
        .event_id = "GH-PF-0002",
        .exit_code = process.exit_code,
        .output_truncated = process.output_truncated,
        .standard_output = process.standard_output,
        .standard_error = process.standard_error,
        .message = "Native PF activation loaded the revision."};
}

}  // namespace sasd::gatehold::firewall
