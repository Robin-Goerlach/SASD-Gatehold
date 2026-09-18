#include "gatehold/firewall/model.hpp"

#include <arpa/inet.h>

#include <algorithm>
#include <array>
#include <charconv>
#include <cstddef>
#include <set>
#include <string_view>
#include <utility>

namespace sasd::gatehold::firewall {
namespace {

constexpr std::size_t maximum_rule_id_length = 64;
constexpr std::size_t maximum_description_length = 160;
constexpr std::size_t maximum_interface_length = 15;

bool is_ascii_digit(char value) noexcept {
    return value >= '0' && value <= '9';
}

bool is_ascii_letter(char value) noexcept {
    return (value >= 'A' && value <= 'Z') ||
           (value >= 'a' && value <= 'z');
}

bool is_ascii_alphanumeric(char value) noexcept {
    return is_ascii_letter(value) || is_ascii_digit(value);
}

bool is_identifier_character(char value) noexcept {
    return is_ascii_alphanumeric(value) || value == '.' || value == '_' ||
           value == '-';
}

bool is_valid_rule_id(std::string_view value) noexcept {
    if (value.empty() || value.size() > maximum_rule_id_length) {
        return false;
    }

    return is_ascii_alphanumeric(value.front()) &&
           std::ranges::all_of(value, is_identifier_character);
}

bool is_valid_interface(std::string_view value) noexcept {
    if (value.empty()) {
        return true;
    }

    if (value.size() > maximum_interface_length) {
        return false;
    }

    return is_ascii_letter(value.front()) &&
           std::ranges::all_of(value, is_identifier_character);
}

bool contains_control_character(std::string_view value) noexcept {
    return std::ranges::any_of(value, [](char character) {
        const auto byte = static_cast<unsigned char>(character);
        return byte < 0x20U || byte == 0x7fU;
    });
}

struct ParsedNetwork {
    bool valid{false};
    AddressFamily family{AddressFamily::any};
};

ParsedNetwork parse_network(std::string_view network) noexcept {
    if (network == "any") {
        return {.valid = true, .family = AddressFamily::any};
    }

    const auto slash = network.find('/');
    if (slash != std::string_view::npos &&
        network.find('/', slash + 1) != std::string_view::npos) {
        return {};
    }

    const auto address = network.substr(0, slash);
    if (address.empty()) {
        return {};
    }

    std::array<unsigned char, 16> binary{};
    AddressFamily family = AddressFamily::any;
    unsigned int maximum_prefix = 0;

    const std::string address_text{address};
    if (inet_pton(AF_INET, address_text.c_str(), binary.data()) == 1) {
        family = AddressFamily::inet;
        maximum_prefix = 32;
    } else if (inet_pton(AF_INET6, address_text.c_str(), binary.data()) == 1) {
        family = AddressFamily::inet6;
        maximum_prefix = 128;
    } else {
        return {};
    }

    if (slash == std::string_view::npos) {
        return {.valid = true, .family = family};
    }

    const auto prefix_text = network.substr(slash + 1);
    if (prefix_text.empty()) {
        return {};
    }

    unsigned int prefix = 0;
    const auto [end, error] = std::from_chars(
        prefix_text.data(), prefix_text.data() + prefix_text.size(), prefix);
    if (error != std::errc{} || end != prefix_text.data() + prefix_text.size() ||
        prefix > maximum_prefix) {
        return {};
    }

    return {.valid = true, .family = family};
}

void validate_endpoint(
    ValidationReport& report,
    const Endpoint& endpoint,
    std::string_view field,
    AddressFamily expected_family) {
    const auto parsed = parse_network(endpoint.network);
    if (!parsed.valid) {
        report.add(
            "GH-CFG-1004",
            std::string{field} + ".network",
            "Network must be 'any' or a numeric IPv4/IPv6 address with an optional prefix.");
        return;
    }

    if (expected_family != AddressFamily::any &&
        parsed.family != AddressFamily::any && parsed.family != expected_family) {
        report.add(
            "GH-CFG-1005",
            std::string{field} + ".network",
            "Network does not match the rule address family.");
    }
}

}  // namespace

bool ValidationReport::ok() const noexcept {
    return issues_.empty();
}

const std::vector<ValidationIssue>& ValidationReport::issues() const noexcept {
    return issues_;
}

void ValidationReport::add(
    std::string code,
    std::string field,
    std::string message) {
    issues_.push_back(
        {.code = std::move(code),
         .field = std::move(field),
         .message = std::move(message)});
}

ValidationReport validate(const Rule& rule) {
    ValidationReport report;

    if (!is_valid_rule_id(rule.id)) {
        report.add(
            "GH-CFG-1001",
            "id",
            "Rule ID must be 1-64 ASCII letters, digits, dots, underscores, or hyphens and start with a letter or digit.");
    }

    if (rule.description.size() > maximum_description_length ||
        contains_control_character(rule.description)) {
        report.add(
            "GH-CFG-1002",
            "description",
            "Description must be at most 160 characters and contain no control characters.");
    }

    if (!is_valid_interface(rule.interface)) {
        report.add(
            "GH-CFG-1003",
            "interface",
            "Interface must be empty or a safe OpenBSD interface name of at most 15 characters.");
    }

    validate_endpoint(report, rule.source, "source", rule.address_family);
    validate_endpoint(report, rule.destination, "destination", rule.address_family);

    const auto source_family = parse_network(rule.source.network).family;
    const auto destination_family = parse_network(rule.destination.network).family;
    if (rule.address_family == AddressFamily::any &&
        source_family != AddressFamily::any &&
        destination_family != AddressFamily::any &&
        source_family != destination_family) {
        report.add(
            "GH-CFG-1006",
            "address_family",
            "Source and destination must use the same address family.");
    }

    if ((rule.source.port.has_value() || rule.destination.port.has_value()) &&
        rule.protocol != Protocol::tcp && rule.protocol != Protocol::udp) {
        report.add(
            "GH-CFG-1007",
            "protocol",
            "Ports are allowed only for TCP or UDP rules.");
    }

    if (rule.protocol == Protocol::icmp &&
        rule.address_family == AddressFamily::inet6) {
        report.add(
            "GH-CFG-1008",
            "protocol",
            "ICMP cannot be used with the inet6 address family; use ICMPv6.");
    }

    if (rule.protocol == Protocol::icmp6 &&
        rule.address_family == AddressFamily::inet) {
        report.add(
            "GH-CFG-1009",
            "protocol",
            "ICMPv6 cannot be used with the inet address family.");
    }

    return report;
}

ValidationReport validate(const RuleSet& rule_set) {
    ValidationReport report;
    std::set<std::string> identifiers;

    if (rule_set.revision == 0) {
        report.add(
            "GH-CFG-1011",
            "revision",
            "Revision number must be greater than zero.");
    }

    for (std::size_t index = 0; index < rule_set.rules.size(); ++index) {
        const auto& rule = rule_set.rules[index];
        auto rule_report = validate(rule);
        for (const auto& issue : rule_report.issues()) {
            report.add(
                issue.code,
                "rules[" + std::to_string(index) + "]." + issue.field,
                issue.message);
        }

        if (!rule.id.empty() && !identifiers.insert(rule.id).second) {
            report.add(
                "GH-CFG-1010",
                "rules[" + std::to_string(index) + "].id",
                "Rule IDs must be unique within a ruleset.");
        }
    }

    return report;
}

std::string_view to_string(Action value) noexcept {
    switch (value) {
        case Action::block:
            return "block";
        case Action::pass:
            return "pass";
    }
    return "block";
}

std::string_view to_string(Direction value) noexcept {
    switch (value) {
        case Direction::any:
            return "";
        case Direction::inbound:
            return "in";
        case Direction::outbound:
            return "out";
    }
    return "";
}

std::string_view to_string(AddressFamily value) noexcept {
    switch (value) {
        case AddressFamily::any:
            return "";
        case AddressFamily::inet:
            return "inet";
        case AddressFamily::inet6:
            return "inet6";
    }
    return "";
}

std::string_view to_string(Protocol value) noexcept {
    switch (value) {
        case Protocol::any:
            return "";
        case Protocol::tcp:
            return "tcp";
        case Protocol::udp:
            return "udp";
        case Protocol::icmp:
            return "icmp";
        case Protocol::icmp6:
            return "icmp6";
    }
    return "";
}

}  // namespace sasd::gatehold::firewall
