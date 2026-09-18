#include "gatehold/firewall/pfctl_loader.hpp"
#include "temporary_directory.hpp"
#include "test_support.hpp"

#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <string>

namespace firewall = sasd::gatehold::firewall;

namespace {

void write_private_file(
    const std::filesystem::path& path,
    const std::string& content) {
    {
        std::ofstream output{path, std::ios::binary};
        output << content;
    }
    std::filesystem::permissions(
        path,
        std::filesystem::perms::owner_read | std::filesystem::perms::owner_write,
        std::filesystem::perm_options::replace);
}

std::string read_file(const std::filesystem::path& path) {
    std::ifstream input{path, std::ios::binary};
    return {std::istreambuf_iterator<char>{input},
            std::istreambuf_iterator<char>{}};
}

}  // namespace

int main(int argc, char* argv[]) {
    gatehold::test::Context test;
    test.check(argc == 2, "test receives the fake pfctl executable path");
    if (argc != 2) {
        return test.result();
    }

    const gatehold::test::TemporaryDirectory temporary{"gatehold-loader-test"};
    const auto fake_pfctl =
        std::filesystem::absolute(std::filesystem::path{argv[1]});
    const auto trace = temporary.path() / "loads.trace";
    ::setenv("GATEHOLD_FAKE_PFCTL_TRACE", trace.c_str(), 1);

    const auto valid = temporary.path() / "valid.pf.conf";
    write_private_file(valid, "block all\n");
    const firewall::PfctlLoader loader{
        fake_pfctl, std::chrono::milliseconds{1000}};
    const auto loaded = loader.load(valid);
    test.check(loaded.ok(), "private revision is loaded by native pfctl");
    test.check(
        loaded.event_id == "GH-PF-0002",
        "successful load has a stable event ID");
    test.check(
        read_file(trace).find("valid.pf.conf") != std::string::npos,
        "native load reaches the controlled helper");

    test.check(
        loader.load("relative.pf.conf").status ==
            firewall::PfctlLoadStatus::unsafe_revision,
        "relative revision path is rejected");

    const auto linked = temporary.path() / "linked.pf.conf";
    std::filesystem::create_symlink(valid, linked);
    test.check(
        loader.load(linked).status == firewall::PfctlLoadStatus::unsafe_revision,
        "symlink revision is rejected");

    const auto public_revision = temporary.path() / "public.pf.conf";
    write_private_file(public_revision, "block all\n");
    std::filesystem::permissions(
        public_revision,
        std::filesystem::perms::group_read,
        std::filesystem::perm_options::add);
    test.check(
        loader.load(public_revision).status ==
            firewall::PfctlLoadStatus::unsafe_revision,
        "group-readable revision is rejected");

    const auto rejected = temporary.path() / "rejected.pf.conf";
    write_private_file(rejected, "FAKE_LOAD_FAIL\n");
    test.check(
        loader.load(rejected).status == firewall::PfctlLoadStatus::rejected,
        "nonzero pfctl exit rejects activation");

    const auto sleeping = temporary.path() / "sleeping.pf.conf";
    write_private_file(sleeping, "FAKE_LOAD_SLEEP\n");
    const firewall::PfctlLoader short_loader{
        fake_pfctl, std::chrono::milliseconds{30}};
    test.check(
        short_loader.load(sleeping).status ==
            firewall::PfctlLoadStatus::timed_out,
        "hung native activation is terminated");

    const firewall::PfctlLoader missing_loader{
        temporary.path() / "missing-pfctl", std::chrono::milliseconds{100}};
    test.check(
        missing_loader.load(valid).status ==
            firewall::PfctlLoadStatus::execution_error,
        "missing native loader is an execution error");

    ::unsetenv("GATEHOLD_FAKE_PFCTL_TRACE");
    return test.result();
}
