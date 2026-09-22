#include "gatehold/daemon/config.hpp"
#include "test_support.hpp"

#include <array>
#include <string_view>
#include <vector>

namespace daemon_api = sasd::gatehold::daemon;

namespace {

daemon_api::DaemonConfigResult parse(
    std::initializer_list<std::string_view> arguments) {
    const std::vector<std::string_view> values{arguments};
    return daemon_api::parse_daemon_arguments(values);
}

daemon_api::DaemonConfigResult parse_with_uid(std::string_view uid) {
    return parse({
        "serve-read-only",
        "--journal-root",
        "/var/log/gatehold",
        "--revision-root",
        "/var/db/gatehold/revisions",
        "--transaction-root",
        "/var/db/gatehold/transactions",
        "--socket-path",
        "/run/gatehold/controller.sock",
        "--allowed-uid",
        uid});
}

}  // namespace

int main() {
    gatehold::test::Context test;

    test.check(
        parse({"--help"}).status ==
            daemon_api::DaemonConfigStatus::help_requested,
        "help is recognized without daemon configuration");
    test.check(
        parse({"-V"}).status ==
            daemon_api::DaemonConfigStatus::version_requested,
        "short version option is recognized");
    test.check(
        !parse({}).ok() && !parse({"serve"}).ok() &&
            !parse({"serve-read-only", "--allowed-uid"}).ok(),
        "missing command, implicit serve, and missing values are rejected");

    const auto valid = parse({
        "serve-read-only",
        "--journal-root",
        "/var/log/gatehold",
        "--revision-root",
        "/var/db/gatehold/revisions",
        "--transaction-root",
        "/var/db/gatehold/transactions",
        "--socket-path",
        "/var/run/gatehold/controller.sock",
        "--allowed-uid",
        "1001",
        "--allowed-gid",
        "1002"});
    test.check(
        valid.ok() && valid.config.has_value() &&
            valid.command == daemon_api::DaemonCommand::serve_read_only &&
            valid.config->allowed_user_id == 1001U &&
            valid.config->allowed_group_id == 1002U &&
            valid.config->socket_path ==
                "/var/run/gatehold/controller.sock",
        "complete read-only daemon configuration is parsed exactly");
    if (valid.config.has_value()) {
        const auto group_identity = daemon_api::validate_daemon_identity(
            *valid.config, 0, 1002);
        test.check(
            group_identity.valid && group_identity.socket_mode == 0660 &&
                group_identity.socket_group_id == 1002U,
            "matching daemon group selects group-accessible socket mode");
        const auto delegated_identity = daemon_api::validate_daemon_identity(
            *valid.config, 0, 2002);
        test.check(
            delegated_identity.valid &&
                delegated_identity.socket_mode == 0660 &&
                delegated_identity.socket_group_id == 1002U,
            "root may delegate the socket to the configured API group");
        test.check(
            !daemon_api::validate_daemon_identity(*valid.config, 1001, 2002)
                 .valid,
            "an unprivileged daemon cannot delegate to another group");
    }

    const auto without_group = parse({
        "serve-read-only",
        "--allowed-uid",
        "0",
        "--socket-path",
        "/run/gatehold/controller.sock",
        "--transaction-root",
        "/var/db/gatehold/transactions",
        "--journal-root",
        "/var/log/gatehold",
        "--revision-root",
        "/var/db/gatehold/revisions"});
    test.check(
        without_group.ok() && without_group.config.has_value() &&
            !without_group.config->allowed_group_id.has_value(),
        "GID restriction is optional and option order is irrelevant");
    if (without_group.config.has_value()) {
        test.check(
            daemon_api::validate_daemon_identity(
                *without_group.config, 0, 9000)
                    .socket_mode == 0600 &&
                !daemon_api::validate_daemon_identity(
                     *without_group.config, 0, 9000)
                     .socket_group_id.has_value() &&
                !daemon_api::validate_daemon_identity(
                     *without_group.config, 1, 9000)
                     .valid,
            "mode 0600 permits only the daemon effective UID");
    }

    test.check(
        !parse({
             "serve-read-only",
             "--journal-root",
             "/var/log/gatehold",
             "--journal-root",
             "/var/log/other",
             "--revision-root",
             "/var/db/gatehold/revisions",
             "--transaction-root",
             "/var/db/gatehold/transactions",
             "--socket-path",
             "/run/gatehold/controller.sock",
             "--allowed-uid",
             "1"})
             .ok(),
        "duplicate options are rejected");
    test.check(
        !parse({
             "serve-read-only",
             "--journal-root",
             "/var/log/gatehold",
             "--revision-root",
             "/var/db/gatehold/revisions",
             "--transaction-root",
             "/var/db/gatehold/transactions",
             "--socket-path",
             "/run/gatehold/controller.sock",
             "--allowed-uid",
             "1",
             "--unexpected",
             "secret-value"})
             .ok(),
        "unknown options are rejected without accepting their value");

    const std::array invalid_uids{
        "-1", "+1", "user", "18446744073709551616"};
    for (const auto invalid_uid : invalid_uids) {
        test.check(
            !parse_with_uid(invalid_uid).ok(),
            "invalid numeric UID is rejected");
    }

    test.check(
        !parse({
             "serve-read-only",
             "--journal-root",
             "relative/journal",
             "--revision-root",
             "/var/db/gatehold/revisions",
             "--transaction-root",
             "/var/db/gatehold/transactions",
             "--socket-path",
             "/run/gatehold/controller.sock",
             "--allowed-uid",
             "1"})
             .ok(),
        "relative storage roots are rejected");
    test.check(
        !parse({
             "serve-read-only",
             "--journal-root",
             "/var/log/../log/gatehold",
             "--revision-root",
             "/var/db/gatehold/revisions",
             "--transaction-root",
             "/var/db/gatehold/transactions",
             "--socket-path",
             "/run/gatehold/controller.sock",
             "--allowed-uid",
             "1"})
             .ok(),
        "non-normalized path aliases are rejected");
    test.check(
        !parse({
             "serve-read-only",
             "--journal-root",
             "/var/db/gatehold",
             "--revision-root",
             "/var/db/gatehold/revisions",
             "--transaction-root",
             "/var/db/gatehold/transactions",
             "--socket-path",
             "/run/gatehold/controller.sock",
             "--allowed-uid",
             "1"})
             .ok(),
        "nested storage trust roots are rejected");
    test.check(
        !parse({
             "serve-read-only",
             "--journal-root",
             "/var/log/gatehold",
             "--revision-root",
             "/var/db/gatehold/revisions",
             "--transaction-root",
             "/var/db/gatehold/transactions",
             "--socket-path",
             "/var/log/gatehold/controller.sock",
             "--allowed-uid",
             "1"})
             .ok(),
        "socket directory cannot overlap durable storage roots");

    const auto unknown = parse({"serve-read-only", "--mystery", "token-123"});
    test.check(
        unknown.message.find("token-123") == std::string::npos,
        "configuration errors do not echo rejected option values");

    return test.result();
}
