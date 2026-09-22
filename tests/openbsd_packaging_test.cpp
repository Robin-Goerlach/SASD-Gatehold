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
    test.check(argc == 2, "packaging test receives the repository root");
    if (argc != 2) {
        return test.result();
    }

    const std::filesystem::path root{argv[1]};
    const auto script_path = root / "packaging/openbsd/rc.d/gateholdd";
    const auto readme_path = root / "packaging/openbsd/README.md";
    const auto cmake_path = root / "src/CMakeLists.txt";
    const auto script = read_file(script_path);
    const auto readme = read_file(readme_path);
    const auto cmake = read_file(cmake_path);

    struct stat status {};
    test.check(
        ::lstat(script_path.c_str(), &status) == 0 &&
            S_ISREG(status.st_mode) && (status.st_mode & 0111) != 0 &&
            (status.st_mode & 0022) == 0,
        "rc.d script is executable but not group or world writable");
    test.check(
        script.starts_with("#!/bin/ksh\n") &&
            contains(
                script,
                "daemon=\"/usr/local/sbin/gateholdd serve-read-only\"") &&
            contains(script, "daemon_logger=\"daemon.info\"") &&
            contains(script, ". /etc/rc.d/rc.subr") &&
            contains(
                script,
                "pexp=\"/usr/local/sbin/gateholdd serve-read-only\"") &&
            contains(script, "rc_bg=YES") &&
            contains(script, "rc_reload=NO") &&
            contains(
                script,
                "rc_exec \"/usr/local/sbin/gateholdd check-config "
                "${daemon_flags}\"") &&
            contains(script, "rc_cmd $1"),
        "rc.d script declares the foreground daemon and native control hooks");
    test.check(
        !contains(script, "eval") && !contains(script, "sh -c") &&
            !contains(script, "rm ") && !contains(script, "`") &&
            !contains(script, "$(") && !contains(script, "su "),
        "rc.d script contains no custom evaluation or destructive cleanup");
    test.check(
        contains(readme, "/var/log/gatehold") &&
            contains(readme, "/var/db/gatehold/revisions") &&
            contains(readme, "/var/db/gatehold/transactions") &&
            contains(readme, "/var/run/gatehold") &&
            contains(readme, "root:_gateholdapi") &&
            contains(readme, "0750") &&
            contains(readme, "rcctl configtest gateholdd") &&
            contains(readme, "not yet an OpenBSD package"),
        "packaging guide records trust roots, configtest, and pre-alpha limits");
    test.check(
        contains(cmake, "CMAKE_INSTALL_BINDIR") &&
            contains(cmake, "CMAKE_INSTALL_SBINDIR") &&
            contains(cmake, "CMAKE_SYSTEM_NAME STREQUAL \"OpenBSD\"") &&
            contains(cmake, "packaging/openbsd/rc.d/gateholdd") &&
            contains(cmake, "OWNER_READ OWNER_EXECUTE"),
        "install rules separate user and system binaries with read-only modes");

    return test.result();
}
