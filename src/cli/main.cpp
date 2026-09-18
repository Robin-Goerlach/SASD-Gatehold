#include "gatehold/version.hpp"
#include "gatehold/firewall/model.hpp"
#include "gatehold/firewall/pf_renderer.hpp"
#include "gatehold/logging/json_event_formatter.hpp"

#include <iostream>
#include <map>
#include <string_view>
#include <utility>

namespace {

void print_help(std::ostream& output) {
    output << sasd::gatehold::product_name() << " command-line interface\n\n"
           << "Usage:\n"
           << "  gateholdctl --help       Show this help\n"
           << "  gateholdctl --version    Show version information\n\n"
           << "Development commands:\n"
           << "  gateholdctl render-example  Render a safe example PF ruleset\n"
           << "  gateholdctl event-example   Emit a sanitized example event\n\n"
           << "Gatehold is in pre-alpha development. Firewall management commands\n"
           << "will be added only after their validation and rollback paths exist.\n";
}

sasd::gatehold::firewall::RuleSet make_example_ruleset() {
    using sasd::gatehold::firewall::Action;
    using sasd::gatehold::firewall::AddressFamily;
    using sasd::gatehold::firewall::Direction;
    using sasd::gatehold::firewall::Endpoint;
    using sasd::gatehold::firewall::Protocol;
    using sasd::gatehold::firewall::Rule;
    using sasd::gatehold::firewall::RuleSet;

    Rule allow_https{
        .id = "allow-lan-https",
        .description = "Allow LAN clients to reach HTTPS services",
        .action = Action::pass,
        .direction = Direction::inbound,
        .address_family = AddressFamily::inet,
        .interface = "em1",
        .protocol = Protocol::tcp,
        .source = Endpoint{.network = "192.0.2.0/24"},
        .destination = Endpoint{.network = "any", .port = 443},
        .log = true,
        .quick = true,
        .enabled = true};

    return RuleSet{.revision = 1, .rules = {std::move(allow_https)}};
}

int render_example() {
    const sasd::gatehold::firewall::PfRenderer renderer;
    const auto result = renderer.render(make_example_ruleset());
    if (!result.ok()) {
        for (const auto& issue : result.validation.issues()) {
            std::cerr << issue.code << " [" << issue.field << "]: "
                      << issue.message << '\n';
        }
        return 1;
    }

    std::cout << result.ruleset;
    return 0;
}

int emit_example_event() {
    using sasd::gatehold::logging::Event;
    using sasd::gatehold::logging::JsonEventFormatter;
    using sasd::gatehold::logging::Severity;

    const Event event{
        .timestamp = "2026-09-18T12:00:00Z",
        .severity = Severity::info,
        .event_id = "GH-CFG-0001",
        .component = "gateholdctl",
        .operation_id = "example-operation",
        .action = "pf.ruleset.render",
        .outcome = "succeeded",
        .message = "Example ruleset rendered without activation.",
        .attributes = {{"revision", "1"}, {"rule_count", "1"}}};

    std::cout << JsonEventFormatter{}.format(event) << '\n';
    return 0;
}

}  // namespace

int main(int argc, char* argv[]) {
    if (argc == 1) {
        print_help(std::cout);
        return 0;
    }

    const std::string_view argument{argv[1]};
    if (argument == "--help" || argument == "-h" || argument == "help") {
        print_help(std::cout);
        return 0;
    }

    if (argument == "--version" || argument == "-V" || argument == "version") {
        std::cout << sasd::gatehold::product_name() << ' '
                  << sasd::gatehold::version() << '\n';
        return 0;
    }

    if (argument == "render-example") {
        return render_example();
    }

    if (argument == "event-example") {
        return emit_example_event();
    }

    std::cerr << "Unknown command: " << argument << "\n"
              << "Run 'gateholdctl --help' for usage information.\n";
    return 2;
}
