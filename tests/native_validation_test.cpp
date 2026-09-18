#include "gatehold/firewall/candidate_store.hpp"
#include "gatehold/firewall/native_validator.hpp"
#include "gatehold/logging/json_event_formatter.hpp"
#include "gatehold/system/posix_process_runner.hpp"
#include "test_support.hpp"

#include <sys/stat.h>

#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <string>

namespace firewall = sasd::gatehold::firewall;

namespace {

class TemporaryDirectory {
public:
    TemporaryDirectory() {
        std::string pattern = "/tmp/gatehold-native-test-XXXXXX";
        pattern.push_back('\0');
        char* created = ::mkdtemp(pattern.data());
        if (created != nullptr) {
            path_ = created;
        }
    }

    ~TemporaryDirectory() {
        std::error_code ignored;
        std::filesystem::remove_all(path_, ignored);
    }

    TemporaryDirectory(const TemporaryDirectory&) = delete;
    TemporaryDirectory& operator=(const TemporaryDirectory&) = delete;

    [[nodiscard]] const std::filesystem::path& path() const noexcept {
        return path_;
    }

private:
    std::filesystem::path path_;
};

std::filesystem::perms file_permissions(const std::filesystem::path& path) {
    std::error_code error;
    return std::filesystem::status(path, error).permissions();
}

}  // namespace

int main(int argc, char* argv[]) {
    gatehold::test::Context test;
    test.check(argc == 2, "test receives the fake pfctl executable path");
    if (argc != 2) {
        return test.result();
    }

    const TemporaryDirectory temporary;
    test.check(!temporary.path().empty(), "temporary directory was created");
    if (temporary.path().empty()) {
        return test.result();
    }

    const auto special_root = temporary.path() / "staging;not-a-command";
    std::filesystem::create_directory(special_root);
    std::filesystem::permissions(
        special_root,
        std::filesystem::perms::owner_all,
        std::filesystem::perm_options::replace);

    const firewall::CandidateStore store{special_root};
    const auto invalid_id = store.stage("../../escape", "block all\n");
    test.check(
        invalid_id.status == firewall::StageStatus::invalid_operation_id,
        "path traversal in operation ID is rejected");

    const std::string with_nul{"block all\0pass all", 18};
    const auto invalid_content = store.stage("nul-content", with_nul);
    test.check(
        invalid_content.status == firewall::StageStatus::invalid_content,
        "NUL byte in candidate is rejected");

    const std::string oversized(
        firewall::CandidateStore::maximum_candidate_size + 1U, 'x');
    const auto oversized_result = store.stage("oversized", oversized);
    test.check(
        oversized_result.status == firewall::StageStatus::invalid_content,
        "oversized candidate is rejected");

    const auto staged = store.stage("op-valid-1", "block log all\n");
    test.check(staged.ok(), "valid candidate is staged");
    test.check(
        std::filesystem::is_regular_file(staged.candidate_path),
        "staged candidate is a regular file");

    const auto permissions = file_permissions(staged.candidate_path);
    const auto unwanted_permissions =
        std::filesystem::perms::group_all | std::filesystem::perms::others_all;
    test.check(
        (permissions & unwanted_permissions) == std::filesystem::perms::none,
        "candidate is inaccessible to group and others");

    const auto duplicate = store.stage("op-valid-1", "pass all\n");
    test.check(
        duplicate.status == firewall::StageStatus::already_exists,
        "candidate is write-once for an operation ID");

    const auto symlink_root = temporary.path() / "linked-stage";
    std::filesystem::create_directory_symlink(special_root, symlink_root);
    const firewall::CandidateStore symlink_store{symlink_root};
    test.check(
        symlink_store.stage("op-link", "block all\n").status ==
            firewall::StageStatus::unsafe_root,
        "symlink staging root is rejected");

    const std::filesystem::path fake_pfctl =
        std::filesystem::absolute(std::filesystem::path{argv[1]});
    const firewall::PfctlValidator validator{
        fake_pfctl, std::chrono::milliseconds{1000}};
    const auto accepted = validator.validate(staged.candidate_path);
    test.check(accepted.ok(), "native validator accepts valid candidate");
    test.check(
        accepted.event_id == "GH-PF-0001",
        "successful validation has a stable event ID");
    test.check(
        accepted.standard_output.find("syntax ok") != std::string::npos,
        "validator captures standard output");

    const auto accepted_event = firewall::make_validation_event(
        accepted, "2026-09-18T12:00:00Z", "op-valid-1", 42);
    const auto accepted_json =
        sasd::gatehold::logging::JsonEventFormatter{}.format(accepted_event);
    test.check(
        accepted_json.find("\"event_id\":\"GH-PF-0001\"") !=
            std::string::npos,
        "validation result becomes a structured event");
    test.check(
        accepted_json.find("\"revision\":\"42\"") != std::string::npos,
        "validation event carries configuration revision");
    test.check(
        accepted_json.find("syntax ok") == std::string::npos,
        "native output is not copied into the audit event by default");

    const auto rejected_stage = store.stage("op-rejected", "FAKE_REJECT\n");
    const auto rejected = validator.validate(rejected_stage.candidate_path);
    test.check(
        rejected.status == firewall::NativeValidationStatus::rejected,
        "nonzero pfctl exit rejects candidate");
    test.check(
        rejected.standard_error.find("syntax error") != std::string::npos,
        "validator captures diagnostic errors");

    const auto sleeping_stage = store.stage("op-timeout", "FAKE_SLEEP\n");
    const firewall::PfctlValidator short_validator{
        fake_pfctl, std::chrono::milliseconds{30}};
    const auto timed_out = short_validator.validate(sleeping_stage.candidate_path);
    test.check(
        timed_out.status == firewall::NativeValidationStatus::timed_out,
        "validation process is terminated after timeout");

    const auto flood_stage = store.stage("op-flood", "FAKE_FLOOD\n");
    const auto flooded = validator.validate(flood_stage.candidate_path);
    test.check(flooded.ok(), "large-output validation can still succeed");
    test.check(flooded.output_truncated, "large output is marked as truncated");
    test.check(
        flooded.standard_output.size() <=
            sasd::gatehold::system::PosixProcessRunner::maximum_captured_output,
        "captured output remains bounded");

    const auto linked_candidate = temporary.path() / "candidate-link";
    std::filesystem::create_symlink(staged.candidate_path, linked_candidate);
    test.check(
        validator.validate(linked_candidate).status ==
            firewall::NativeValidationStatus::unsafe_candidate,
        "symlink candidate is rejected");

    const firewall::PfctlValidator missing_validator{
        temporary.path() / "missing-pfctl", std::chrono::milliseconds{100}};
    test.check(
        missing_validator.validate(staged.candidate_path).status ==
            firewall::NativeValidationStatus::execution_error,
        "missing native validator is reported as an execution error");

    return test.result();
}
