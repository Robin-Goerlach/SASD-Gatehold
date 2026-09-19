#include "gatehold/daemon/process_lock.hpp"
#include "temporary_directory.hpp"
#include "test_support.hpp"

#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include <filesystem>
#include <fstream>
#include <string>

namespace daemon_api = sasd::gatehold::daemon;

namespace {

constexpr auto lock_filename = ".gateholdd.lock";

void create_private_directory(const std::filesystem::path& path) {
    std::filesystem::create_directory(path);
    std::filesystem::permissions(
        path,
        std::filesystem::perms::owner_all,
        std::filesystem::perm_options::replace);
}

bool hides_path(
    const daemon_api::DaemonProcessLockResult& result,
    const std::filesystem::path& path) {
    return result.message.find(path.string()) == std::string::npos;
}

uid_t different_user() noexcept {
    return ::geteuid() == 0U ? 1U : 0U;
}

}  // namespace

int main() {
    gatehold::test::Context test;

    {
        const gatehold::test::TemporaryDirectory temporary{
            "gatehold-process-lock-exclusive"};
        const auto root = temporary.path() / "transactions";
        create_private_directory(root);

        auto first = daemon_api::DaemonProcessLock::acquire(root, ::geteuid());
        test.check(
            first.ok() && first.event_id == "GH-DMN-0004" &&
                hides_path(first, root),
            "the first daemon acquires a non-disclosing process lock");

        const auto second =
            daemon_api::DaemonProcessLock::acquire(root, ::geteuid());
        test.check(
            second.status ==
                    daemon_api::DaemonProcessLockStatus::already_running &&
                second.event_id == "GH-DMN-1005" && hides_path(second, root),
            "a competing lock attempt fails without blocking");

        const pid_t child = ::fork();
        test.check(child >= 0, "process-lock contention child can be forked");
        if (child == 0) {
            const auto child_result =
                daemon_api::DaemonProcessLock::acquire(root, ::geteuid());
            ::_exit(
                child_result.status ==
                        daemon_api::DaemonProcessLockStatus::already_running
                    ? 0
                    : 1);
        }
        if (child > 0) {
            int status = 0;
            const auto waited = ::waitpid(child, &status, 0);
            test.check(
                waited == child && WIFEXITED(status) &&
                    WEXITSTATUS(status) == 0,
                "process exclusivity is enforced across forked processes");
        }

        first.lock.reset();
        auto replacement =
            daemon_api::DaemonProcessLock::acquire(root, ::geteuid());
        test.check(
            replacement.ok(),
            "lock ownership is released automatically with the RAII handle");

        struct stat lock_status {};
        test.check(
            ::lstat((root / lock_filename).c_str(), &lock_status) == 0 &&
                S_ISREG(lock_status.st_mode) && lock_status.st_nlink == 1 &&
                (lock_status.st_mode & (S_IRWXG | S_IRWXO)) == 0,
            "the persistent lock entry is a private single-link regular file");
    }

    {
        const gatehold::test::TemporaryDirectory temporary{
            "gatehold-process-lock-symlink"};
        const auto root = temporary.path() / "transactions";
        create_private_directory(root);
        const auto target = temporary.path() / "target";
        std::ofstream{target} << "not-a-lock";
        std::filesystem::create_symlink(target, root / lock_filename);

        const auto result =
            daemon_api::DaemonProcessLock::acquire(root, ::geteuid());
        test.check(
            result.status ==
                    daemon_api::DaemonProcessLockStatus::unsafe_lock_file &&
                result.event_id == "GH-DMN-1006" && hides_path(result, target),
            "a symlink cannot become the daemon process lock");
    }

    {
        const gatehold::test::TemporaryDirectory temporary{
            "gatehold-process-lock-permissions"};
        const auto root = temporary.path() / "transactions";
        create_private_directory(root);
        const auto lock_path = root / lock_filename;
        std::ofstream{lock_path} << "";
        std::filesystem::permissions(
            lock_path,
            std::filesystem::perms::group_read,
            std::filesystem::perm_options::add);

        const auto result =
            daemon_api::DaemonProcessLock::acquire(root, ::geteuid());
        test.check(
            result.status ==
                daemon_api::DaemonProcessLockStatus::unsafe_lock_file,
            "a process-lock file whose mode is not 0600 is rejected");
    }

    {
        const gatehold::test::TemporaryDirectory temporary{
            "gatehold-process-lock-hardlink"};
        const auto root = temporary.path() / "transactions";
        create_private_directory(root);
        const auto lock_path = root / lock_filename;
        std::ofstream{lock_path} << "";
        std::filesystem::permissions(
            lock_path,
            std::filesystem::perms::owner_read |
                std::filesystem::perms::owner_write,
            std::filesystem::perm_options::replace);
        std::filesystem::create_hard_link(
            lock_path, temporary.path() / "second-link");

        const auto result =
            daemon_api::DaemonProcessLock::acquire(root, ::geteuid());
        test.check(
            result.status ==
                daemon_api::DaemonProcessLockStatus::unsafe_lock_file,
            "a multiply linked process-lock file is rejected");
    }

    {
        const gatehold::test::TemporaryDirectory temporary{
            "gatehold-process-lock-root"};
        const auto root = temporary.path() / "transactions";
        create_private_directory(root);

        const auto wrong_owner =
            daemon_api::DaemonProcessLock::acquire(root, different_user());
        test.check(
            wrong_owner.status ==
                daemon_api::DaemonProcessLockStatus::unsafe_lock_file,
            "a process-lock root owned by another user is rejected");

        std::filesystem::permissions(
            root,
            std::filesystem::perms::group_write,
            std::filesystem::perm_options::add);
        const auto writable =
            daemon_api::DaemonProcessLock::acquire(root, ::geteuid());
        test.check(
            writable.status ==
                daemon_api::DaemonProcessLockStatus::unsafe_lock_file,
            "a group-writable process-lock root is rejected");
    }

    {
        const gatehold::test::TemporaryDirectory temporary{
            "gatehold-process-lock-missing"};
        const auto missing = temporary.path() / "missing";
        const auto result =
            daemon_api::DaemonProcessLock::acquire(missing, ::geteuid());
        test.check(
            result.status == daemon_api::DaemonProcessLockStatus::io_error &&
                result.event_id == "GH-DMN-2003" && hides_path(result, missing),
            "a missing lock root fails closed without path disclosure");
    }

    return test.result();
}
