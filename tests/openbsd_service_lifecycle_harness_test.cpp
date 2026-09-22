#include "test_support.hpp"

#include <sys/stat.h>

#include <filesystem>
#include <fstream>
#include <string>
#include <string_view>

namespace {

std::string read_file(const std::filesystem::path& path) {
    std::ifstream input{path, std::ios::binary};
    return {std::istreambuf_iterator<char>{input},
            std::istreambuf_iterator<char>{}};
}

bool contains(std::string_view text, std::string_view expected) {
    return text.find(expected) != std::string_view::npos;
}

}  // namespace

int main(int argc, char* argv[]) {
    gatehold::test::Context test;
    test.check(argc == 2, "lifecycle harness test receives repository root");
    if (argc != 2) {
        return test.result();
    }

    const std::filesystem::path root{argv[1]};
    const auto harness_path =
        root / "tests/openbsd/service_lifecycle_test.ksh";
    const auto guide_path =
        root / "docs/lab/openbsd-service-lifecycle-test.md";
    const auto harness = read_file(harness_path);
    const auto guide = read_file(guide_path);

    struct stat status {};
    test.check(
        ::lstat(harness_path.c_str(), &status) == 0 &&
            S_ISREG(status.st_mode) && (status.st_mode & 0111) != 0 &&
            (status.st_mode & 0022) == 0,
        "lifecycle harness is executable but not group or world writable");
    test.check(
        harness.starts_with("#!/bin/ksh\n") &&
            contains(harness, "set -eu") &&
            contains(harness, "--confirm-disposable-lab") &&
            contains(harness, "$(uname -s)") &&
            contains(harness, "$(id -u)"),
        "harness requires explicit confirmation, OpenBSD, and root");
    test.check(
        contains(harness, "pending-activation") &&
            contains(harness, "rcctl check") &&
            contains(harness, "The test refuses to take ownership") &&
            contains(harness, "cleanup_required=yes") &&
            contains(harness, "cleanup_required=no"),
        "harness rejects recovery and ownership ambiguity");
    test.check(
        contains(harness, "rcctl configtest") &&
            contains(harness, "journal_before") &&
            contains(harness, "journal_after") &&
            contains(harness, "rcctl start") &&
            contains(harness, "rcctl restart") &&
            contains(harness, "rcctl stop"),
        "harness verifies configtest and the native service lifecycle");
    test.check(
        contains(harness, "root:${api_user}:660") &&
            contains(harness, "GH-DMN-0001") &&
            contains(harness, "GH-SVC-0002") &&
            contains(harness, "GH-SIG-0002") &&
            contains(harness, "GH-DMN-0002") &&
            contains(harness, "GH-LAB-0001") &&
            contains(harness, "GH-LAB-1001") &&
            contains(harness, "GH-LAB-1002"),
        "harness checks socket delegation and stable lifecycle events");
    test.check(
        !contains(harness, "eval ") && !contains(harness, "sh -c") &&
            !contains(harness, "rm ") && !contains(harness, "pfctl") &&
            !contains(harness, "pkill") && !contains(harness, "kill ") &&
            !contains(harness, "unlink") && !contains(harness, "sudo") &&
            !contains(harness, "doas"),
        "harness contains no evaluation, PF mutation, signals, or deletion");
    test.check(
        contains(guide, "native execution evidence pending") &&
            contains(guide, "pending-activation") &&
            contains(guide, "does not reboot") &&
            contains(guide, "GH-LAB-1002") &&
            contains(guide, "redacted journal lines"),
        "lab guide records safety limits, remaining gaps, and evidence");

    return test.result();
}
