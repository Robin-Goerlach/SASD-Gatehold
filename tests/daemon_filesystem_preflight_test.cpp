#include "gatehold/daemon/filesystem_preflight.hpp"
#include "temporary_directory.hpp"
#include "test_support.hpp"

#include <sys/stat.h>
#include <unistd.h>

#include <filesystem>
#include <fstream>
#include <string>
#include <string_view>

namespace daemon_api = sasd::gatehold::daemon;

namespace {

void create_private_directory(
    const std::filesystem::path& path,
    std::filesystem::perms permissions = std::filesystem::perms::owner_all) {
    std::filesystem::create_directory(path);
    std::filesystem::permissions(
        path, permissions, std::filesystem::perm_options::replace);
}

struct Fixture {
    explicit Fixture(std::string_view name) : temporary{name} {
        journal = temporary.path() / "journal";
        revisions = temporary.path() / "revisions";
        transactions = temporary.path() / "transactions";
        socket_parent = temporary.path() / "run";
        create_private_directory(journal);
        create_private_directory(revisions);
        create_private_directory(transactions);
        create_private_directory(socket_parent);
    }

    [[nodiscard]] daemon_api::DaemonConfig config() const {
        return {
            .journal_root = journal,
            .revision_root = revisions,
            .transaction_root = transactions,
            .socket_path = socket_parent / "controller.sock",
            .allowed_user_id = ::geteuid(),
            .allowed_group_id = std::nullopt};
    }

    gatehold::test::TemporaryDirectory temporary;
    std::filesystem::path journal;
    std::filesystem::path revisions;
    std::filesystem::path transactions;
    std::filesystem::path socket_parent;
};

daemon_api::DaemonFilesystemResult preflight(
    const daemon_api::DaemonConfig& config,
    mode_t socket_mode = 0600,
    uid_t user_id = ::geteuid(),
    gid_t group_id = ::getegid()) {
    return daemon_api::preflight_daemon_filesystem(
        config, socket_mode, user_id, group_id);
}

bool hides_paths(
    const daemon_api::DaemonFilesystemResult& result,
    const daemon_api::DaemonConfig& config) {
    return result.message.find(config.journal_root.string()) ==
               std::string::npos &&
           result.message.find(config.revision_root.string()) ==
               std::string::npos &&
           result.message.find(config.transaction_root.string()) ==
               std::string::npos &&
           result.message.find(config.socket_path.string()) ==
               std::string::npos;
}

}  // namespace

int main() {
    gatehold::test::Context test;

    {
        Fixture fixture{"gatehold-preflight-ready"};
        const auto config = fixture.config();
        const auto result = preflight(config);
        test.check(
            result.ok() && result.journal_root_ready &&
                result.event_id == "GH-DMN-0003" && hides_paths(result, config),
            "private directories and an absent socket path pass preflight");
    }

    {
        Fixture fixture{"gatehold-preflight-group"};
        std::filesystem::permissions(
            fixture.socket_parent,
            std::filesystem::perms::owner_all |
                std::filesystem::perms::group_read |
                std::filesystem::perms::group_exec,
            std::filesystem::perm_options::replace);
        auto config = fixture.config();
        config.allowed_group_id = ::getegid();
        test.check(
            preflight(config, 0660).ok(),
            "group socket mode accepts a matching group-traversable directory");
    }

    {
        Fixture fixture{"gatehold-preflight-missing-journal"};
        const auto config = fixture.config();
        std::filesystem::remove(fixture.journal);
        const auto result = preflight(config);
        test.check(
            !result.ok() && !result.journal_root_ready &&
                result.failed_role == daemon_api::DaemonDirectoryRole::journal &&
                result.event_id == "GH-DMN-1003" && hides_paths(result, config),
            "a missing journal root fails before an audit location is trusted");
    }

    {
        Fixture fixture{"gatehold-preflight-missing-revision"};
        const auto config = fixture.config();
        std::filesystem::remove(fixture.revisions);
        const auto result = preflight(config);
        test.check(
            !result.ok() && result.journal_root_ready &&
                result.failed_role ==
                    daemon_api::DaemonDirectoryRole::revisions,
            "later trust-root failures remain auditable in the verified journal");
    }

    {
        Fixture fixture{"gatehold-preflight-regular-file"};
        const auto config = fixture.config();
        std::filesystem::remove(fixture.transactions);
        std::ofstream{fixture.transactions} << "not-a-directory";
        const auto result = preflight(config);
        test.check(
            !result.ok() && result.failed_role ==
                                daemon_api::DaemonDirectoryRole::transactions,
            "a regular file cannot replace a storage trust root");
    }

    {
        Fixture fixture{"gatehold-preflight-symlink"};
        auto config = fixture.config();
        const auto alias = fixture.temporary.path() / "revision-alias";
        std::filesystem::create_directory_symlink(fixture.revisions, alias);
        config.revision_root = alias;
        const auto result = preflight(config);
        test.check(
            !result.ok() && result.failed_role ==
                                daemon_api::DaemonDirectoryRole::revisions,
            "a symlink cannot alias a daemon trust root");
    }

    {
        Fixture fixture{"gatehold-preflight-ancestor-symlink"};
        auto config = fixture.config();
        const auto alias_parent = fixture.temporary.path() / "alias-parent";
        std::filesystem::create_directory_symlink(
            fixture.temporary.path(), alias_parent);
        config.revision_root = alias_parent / "revisions";
        const auto result = preflight(config);
        test.check(
            !result.ok() && result.failed_role ==
                                daemon_api::DaemonDirectoryRole::revisions,
            "a symlinked ancestor cannot alias a daemon trust root");
    }

    {
        Fixture fixture{"gatehold-preflight-owner"};
        const auto config = fixture.config();
        const uid_t other_user = ::geteuid() == 0U ? 1U : 0U;
        const auto result = preflight(config, 0600, other_user, ::getegid());
        test.check(
            !result.ok() && result.failed_role ==
                                daemon_api::DaemonDirectoryRole::journal,
            "a trust root owned by another effective user is rejected");
    }

    {
        Fixture fixture{"gatehold-preflight-writable"};
        const auto config = fixture.config();
        std::filesystem::permissions(
            fixture.revisions,
            std::filesystem::perms::group_write,
            std::filesystem::perm_options::add);
        const auto result = preflight(config);
        test.check(
            !result.ok() && result.failed_role ==
                                daemon_api::DaemonDirectoryRole::revisions,
            "group-writable storage roots are rejected");
    }

    {
        Fixture fixture{"gatehold-preflight-public-socket-dir"};
        const auto config = fixture.config();
        std::filesystem::permissions(
            fixture.socket_parent,
            std::filesystem::perms::others_read,
            std::filesystem::perm_options::add);
        const auto result = preflight(config);
        test.check(
            !result.ok() && result.failed_role ==
                                daemon_api::DaemonDirectoryRole::socket_parent,
            "socket directories with permissions for other users are rejected");
    }

    {
        Fixture fixture{"gatehold-preflight-group-mismatch"};
        auto config = fixture.config();
        config.allowed_group_id = ::getegid() == 0U ? 1U : 0U;
        const auto result = preflight(config, 0660);
        test.check(
            !result.ok() && result.failed_role ==
                                daemon_api::DaemonDirectoryRole::socket_parent,
            "group socket mode requires the configured effective group");
    }

    {
        Fixture fixture{"gatehold-preflight-group-traversal"};
        auto config = fixture.config();
        config.allowed_group_id = ::getegid();
        const auto result = preflight(config, 0660);
        test.check(
            !result.ok() && result.failed_role ==
                                daemon_api::DaemonDirectoryRole::socket_parent,
            "group socket mode requires group traversal on the socket directory");
    }

    {
        Fixture fixture{"gatehold-preflight-occupied"};
        const auto config = fixture.config();
        std::ofstream{config.socket_path} << "occupied";
        const auto result = preflight(config);
        test.check(
            result.status ==
                    daemon_api::DaemonFilesystemStatus::socket_path_occupied &&
                result.event_id == "GH-DMN-1004" &&
                result.failed_role ==
                    daemon_api::DaemonDirectoryRole::socket_parent &&
                hides_paths(result, config),
            "an occupied controller socket path fails closed without disclosure");
    }

    return test.result();
}
