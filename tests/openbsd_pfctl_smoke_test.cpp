#include "gatehold/firewall/candidate_store.hpp"
#include "gatehold/firewall/native_validator.hpp"
#include "temporary_directory.hpp"
#include "test_support.hpp"

#include <filesystem>
#include <iostream>

int main() {
    gatehold::test::Context test;
    const gatehold::test::TemporaryDirectory temporary{"gatehold-openbsd-pf"};
    test.check(!temporary.path().empty(), "temporary directory was created");
    if (temporary.path().empty()) {
        return test.result();
    }

    const auto staging = temporary.path() / "staging";
    std::filesystem::create_directory(staging);
    std::filesystem::permissions(
        staging,
        std::filesystem::perms::owner_all,
        std::filesystem::perm_options::replace);

    const sasd::gatehold::firewall::CandidateStore store{staging};
    const auto candidate = store.stage(
        "openbsd-native-smoke",
        "set block-policy drop\nset skip on lo\nblock log all\n");
    test.check(candidate.ok(), "native smoke candidate is staged safely");
    if (!candidate.ok()) {
        return test.result();
    }

    const sasd::gatehold::firewall::PfctlValidator validator;
    const auto validation = validator.validate(candidate.candidate_path);
    if (!validation.ok()) {
        std::cerr << validation.event_id << ": " << validation.message << '\n'
                  << validation.standard_error;
    }
    test.check(validation.ok(), "real /sbin/pfctl accepts the smoke candidate");
    return test.result();
}
