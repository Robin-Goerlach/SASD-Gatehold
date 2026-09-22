#include "gatehold/controller/controller_service.hpp"
#include "gatehold/controller/local_listener.hpp"
#include "gatehold/controller/local_protocol.hpp"
#include "gatehold/controller/privileged_pf_controller.hpp"
#include "gatehold/daemon/config.hpp"
#include "gatehold/daemon/filesystem_preflight.hpp"
#include "gatehold/daemon/process_lock.hpp"
#include "gatehold/daemon/process_sandbox.hpp"
#include "gatehold/daemon/read_only_activation_policy.hpp"
#include "gatehold/firewall/activation_service.hpp"
#include "gatehold/firewall/activation_transaction_store.hpp"
#include "gatehold/firewall/native_validator.hpp"
#include "gatehold/firewall/pfctl_loader.hpp"
#include "gatehold/firewall/revision_store.hpp"
#include "gatehold/logging/event.hpp"
#include "gatehold/logging/operation_journal.hpp"
#include "gatehold/system/posix_signal_stop_bridge.hpp"
#include "gatehold/version.hpp"

#include <chrono>
#include <ctime>
#include <functional>
#include <iomanip>
#include <iostream>
#include <optional>
#include <sstream>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <unistd.h>

namespace controller = sasd::gatehold::controller;
namespace daemon_api = sasd::gatehold::daemon;
namespace firewall = sasd::gatehold::firewall;
namespace logging = sasd::gatehold::logging;
namespace system_api = sasd::gatehold::system;

namespace {

constexpr int usage_exit_code = 2;
constexpr int startup_exit_code = 3;
constexpr int service_exit_code = 4;
constexpr int cleanup_exit_code = 5;

std::string utc_timestamp() {
    const auto now = std::chrono::system_clock::now();
    const std::time_t time = std::chrono::system_clock::to_time_t(now);
    struct tm utc_time {};
    if (::gmtime_r(&time, &utc_time) == nullptr) {
        return "1970-01-01T00:00:00Z";
    }

    std::ostringstream output;
    output << std::put_time(&utc_time, "%Y-%m-%dT%H:%M:%SZ");
    return output.str();
}

logging::Event daemon_event(
    logging::Severity severity,
    std::string event_id,
    std::string outcome,
    std::string message) {
    return {
        .timestamp = utc_timestamp(),
        .severity = severity,
        .event_id = std::move(event_id),
        .component = "gateholdd",
        .operation_id = "daemon-lifetime",
        .action = "daemon.serve-read-only",
        .outcome = std::move(outcome),
        .message = std::move(message),
        .attributes = {{"activation_policy", "deny-all"}}};
}

void print_help(std::ostream& output) {
    output
        << sasd::gatehold::product_name() << " privileged controller daemon\n\n"
        << "Usage:\n"
        << "  gateholdd --help\n"
        << "  gateholdd --version\n"
        << "  gateholdd check-config OPTIONS\n"
        << "  gateholdd serve-read-only \\\n"
        << "    --journal-root ABSOLUTE_PATH \\\n"
        << "    --revision-root ABSOLUTE_PATH \\\n"
        << "    --transaction-root ABSOLUTE_PATH \\\n"
        << "    --socket-path ABSOLUTE_PATH \\\n"
        << "    --allowed-uid NUMERIC_UID [--allowed-gid NUMERIC_GID]\n\n"
        << "The bootstrap daemon performs startup recovery and serves status,\n"
        << "but denies every new PF activation. It stays in the foreground.\n";
}

int check_daemon_configuration(const daemon_api::DaemonConfig& config) {
    const auto identity = daemon_api::validate_daemon_identity(
        config, ::geteuid(), ::getegid());
    if (!identity.valid) {
        std::cerr << identity.event_id << ": " << identity.message << '\n';
        return usage_exit_code;
    }

    const auto filesystem =
        daemon_api::validate_daemon_filesystem_configuration(
            config, identity.socket_mode, ::geteuid());
    if (!filesystem.ok()) {
        std::cerr << filesystem.event_id << ": " << filesystem.message
                  << '\n';
        return startup_exit_code;
    }

    std::cout << "GH-DMN-0005: Daemon configuration is valid.\n";
    return 0;
}

int run_read_only_daemon(const daemon_api::DaemonConfig& config) {
    const auto identity = daemon_api::validate_daemon_identity(
        config, ::geteuid(), ::getegid());
    if (!identity.valid) {
        std::cerr << identity.event_id << ": " << identity.message << '\n';
        return usage_exit_code;
    }

    const auto filesystem = daemon_api::preflight_daemon_filesystem(
        config, identity.socket_mode, ::geteuid());
    if (!filesystem.ok()) {
        if (filesystem.journal_root_ready) {
            const logging::OperationJournal journal{config.journal_root};
            auto event = daemon_event(
                filesystem.status ==
                        daemon_api::DaemonFilesystemStatus::io_error
                    ? logging::Severity::error
                    : logging::Severity::warning,
                filesystem.event_id,
                "rejected",
                filesystem.message);
            event.attributes.emplace(
                "directory_role",
                daemon_api::to_string(filesystem.failed_role));
            if (!journal.append(event).ok()) {
                std::cerr
                    << "GH-DMN-2001: Daemon startup could not be audited.\n";
            }
        }
        std::cerr << filesystem.event_id << ": " << filesystem.message
                  << '\n';
        return startup_exit_code;
    }

    auto process_lock = daemon_api::DaemonProcessLock::acquire(
        config.transaction_root, ::geteuid());
    if (!process_lock.ok()) {
        const logging::OperationJournal journal{config.journal_root};
        auto event = daemon_event(
            process_lock.status == daemon_api::DaemonProcessLockStatus::io_error
                ? logging::Severity::error
                : logging::Severity::warning,
            process_lock.event_id,
            "rejected",
            process_lock.message);
        event.attributes.emplace("startup_gate", "process-lock");
        if (!journal.append(event).ok()) {
            std::cerr << "GH-DMN-2001: Daemon startup could not be audited.\n";
        }
        std::cerr << process_lock.event_id << ": " << process_lock.message
                  << '\n';
        return startup_exit_code;
    }

    const logging::OperationJournal journal{config.journal_root};
    auto filesystem_event = daemon_event(
        logging::Severity::info,
        filesystem.event_id,
        "accepted",
        filesystem.message);
    filesystem_event.attributes.emplace("directory_count", "4");
    if (!journal.append(filesystem_event).ok()) {
        std::cerr << "GH-DMN-2001: Daemon startup could not be audited.\n";
        return startup_exit_code;
    }
    auto process_lock_event = daemon_event(
        logging::Severity::info,
        process_lock.event_id,
        "accepted",
        process_lock.message);
    process_lock_event.attributes.emplace("startup_gate", "process-lock");
    if (!journal.append(process_lock_event).ok()) {
        std::cerr << "GH-DMN-2001: Daemon startup could not be audited.\n";
        return startup_exit_code;
    }
    if (!journal
             .append(daemon_event(
                 logging::Severity::info,
                 "GH-DMN-0001",
                 "starting",
                 "Read-only privileged controller daemon is starting."))
             .ok()) {
        std::cerr << "GH-DMN-2001: Daemon startup could not be audited.\n";
        return startup_exit_code;
    }

    daemon_api::NativeSandboxSystem sandbox_system;
    const auto sandbox = daemon_api::apply_daemon_sandbox(
        daemon_api::make_read_only_daemon_sandbox_policy(config),
        sandbox_system);
    auto sandbox_event = daemon_event(
        sandbox.enforced() ? logging::Severity::info
                           : sandbox.can_continue() ? logging::Severity::warning
                                                    : logging::Severity::error,
        sandbox.event_id,
        sandbox.enforced() ? "accepted"
                           : sandbox.can_continue() ? "unavailable" : "rejected",
        sandbox.message);
    sandbox_event.attributes.emplace(
        "sandbox_enforced", sandbox.enforced() ? "true" : "false");
    if (!journal.append(sandbox_event).ok()) {
        std::cerr << "GH-DMN-2001: Daemon startup could not be audited.\n";
        return startup_exit_code;
    }
    if (!sandbox.can_continue()) {
        std::cerr << sandbox.event_id << ": " << sandbox.message << '\n';
        return startup_exit_code;
    }

    system_api::PosixSignalStopBridge signal_bridge{journal};
    const auto signal_start = signal_bridge.start();
    if (!signal_start.ok()) {
        std::cerr << signal_start.event_id << ": " << signal_start.message
                  << '\n';
        return startup_exit_code;
    }

    const firewall::RevisionStore revisions{config.revision_root};
    const firewall::ActivationTransactionStore transactions{
        config.transaction_root};
    const firewall::PfctlValidator validator;
    const firewall::PfctlLoader loader;
    const daemon_api::ReadOnlyActivationAuthorizer authorizer;
    const daemon_api::UnavailableConfirmationGate confirmation;
    const daemon_api::FailClosedActivationHealthProbe probe;
    const std::vector<std::reference_wrapper<const firewall::HealthProbe>> probes{
        std::cref(probe)};
    const firewall::PfActivationService activation_service{
        revisions,
        transactions,
        validator,
        loader,
        journal,
        authorizer,
        confirmation,
        probes};
    controller::PrivilegedPfController pf_controller{
        activation_service, journal};
    const controller::PeerCredentialPolicy peer_policy{
        config.allowed_user_id, config.allowed_group_id};
    const controller::ControllerProtocolSession protocol_session{
        pf_controller, journal, peer_policy};
    controller::LocalControllerListener listener{
        protocol_session,
        journal,
        controller::LocalListenerConfig{
            .socket_path = config.socket_path,
            .socket_mode = identity.socket_mode,
            .socket_group_id = identity.socket_group_id,
            .listen_backlog = 8}};
    controller::ControllerService service{
        pf_controller, listener, journal};

    const auto service_result = service.run(signal_bridge.stop_token());
    const auto signal_stop = signal_bridge.stop();
    const bool signal_audit_ok = signal_bridge.signal_event_audited();

    if (!service_result.ok()) {
        std::cerr << service_result.event_id << ": " << service_result.message
                  << '\n';
    }
    if (!signal_stop.ok()) {
        std::cerr << signal_stop.event_id << ": " << signal_stop.message
                  << '\n';
    }
    if (!signal_audit_ok) {
        std::cerr << "GH-DMN-2004: Termination signal audit failed.\n";
    }

    const bool clean_shutdown =
        service_result.ok() && signal_stop.ok() && signal_audit_ok;
    const bool shutdown_audited = journal
                                      .append(daemon_event(
                                          clean_shutdown
                                              ? logging::Severity::info
                                              : logging::Severity::error,
                                          "GH-DMN-0002",
                                          clean_shutdown ? "stopped" : "failed",
                                          "Read-only privileged controller "
                                          "daemon stopped."))
                                      .ok();
    if (!shutdown_audited) {
        std::cerr << "GH-DMN-2004: Daemon shutdown audit failed.\n";
    }
    if (!service_result.ok()) {
        return service_exit_code;
    }
    if (!signal_stop.ok() || !signal_audit_ok || !shutdown_audited) {
        return cleanup_exit_code;
    }
    return 0;
}

}  // namespace

int main(int argc, char* argv[]) {
    try {
        std::vector<std::string_view> arguments;
        arguments.reserve(argc > 1 ? static_cast<std::size_t>(argc - 1) : 0U);
        for (int index = 1; index < argc; ++index) {
            arguments.emplace_back(argv[index]);
        }

        const auto parsed = daemon_api::parse_daemon_arguments(
            std::span<const std::string_view>{arguments});
        if (parsed.status == daemon_api::DaemonConfigStatus::help_requested) {
            print_help(std::cout);
            return 0;
        }
        if (parsed.status == daemon_api::DaemonConfigStatus::version_requested) {
            std::cout << sasd::gatehold::product_name() << " daemon "
                      << sasd::gatehold::version() << '\n';
            return 0;
        }
        if (!parsed.ok() || !parsed.config.has_value()) {
            std::cerr << parsed.event_id << ": " << parsed.message << '\n'
                      << "Run 'gateholdd --help' for usage information.\n";
            return usage_exit_code;
        }
        if (parsed.command == daemon_api::DaemonCommand::check_configuration) {
            return check_daemon_configuration(*parsed.config);
        }
        return run_read_only_daemon(*parsed.config);
    } catch (...) {
        std::cerr << "GH-DMN-2005: Daemon terminated after an internal error.\n";
        return startup_exit_code;
    }
}
