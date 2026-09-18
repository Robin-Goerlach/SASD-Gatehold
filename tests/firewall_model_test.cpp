#include "gatehold/firewall/model.hpp"
#include "test_support.hpp"

#include <algorithm>
#include <string_view>

namespace firewall = sasd::gatehold::firewall;

namespace {

firewall::Rule valid_rule() {
    return firewall::Rule{
        .id = "allow-lan-web",
        .description = "Allow web traffic from the LAN",
        .action = firewall::Action::pass,
        .direction = firewall::Direction::inbound,
        .address_family = firewall::AddressFamily::inet,
        .interface = "em1",
        .protocol = firewall::Protocol::tcp,
        .source = firewall::Endpoint{.network = "192.0.2.0/24"},
        .destination = firewall::Endpoint{.network = "198.51.100.10", .port = 443},
        .log = true,
        .quick = true,
        .enabled = true};
}

bool has_issue(
    const firewall::ValidationReport& report,
    std::string_view code) {
    return std::ranges::any_of(report.issues(), [code](const auto& issue) {
        return issue.code == code;
    });
}

}  // namespace

int main() {
    gatehold::test::Context test;

    test.check(firewall::validate(valid_rule()).ok(), "valid rule is accepted");

    auto injected_interface = valid_rule();
    injected_interface.interface = "em0\npass all";
    const auto injected_report = firewall::validate(injected_interface);
    test.check(!injected_report.ok(), "interface injection is rejected");
    test.check(
        has_issue(injected_report, "GH-CFG-1003"),
        "interface injection has a stable error code");

    auto injected_description = valid_rule();
    injected_description.description = "safe\npass all";
    test.check(
        has_issue(firewall::validate(injected_description), "GH-CFG-1002"),
        "description line injection is rejected");

    auto invalid_rule_id = valid_rule();
    invalid_rule_id.id = "allow web; pass all";
    test.check(
        has_issue(firewall::validate(invalid_rule_id), "GH-CFG-1001"),
        "free-form PF text in a rule ID is rejected");

    auto long_interface = valid_rule();
    long_interface.interface = "interface-name-is-too-long";
    test.check(
        has_issue(firewall::validate(long_interface), "GH-CFG-1003"),
        "overlong interface name is rejected");

    auto invalid_network = valid_rule();
    invalid_network.source.network = "192.0.2.0/33";
    test.check(
        has_issue(firewall::validate(invalid_network), "GH-CFG-1004"),
        "invalid IPv4 prefix is rejected");

    auto invalid_ipv6_network = valid_rule();
    invalid_ipv6_network.address_family = firewall::AddressFamily::inet6;
    invalid_ipv6_network.source.network = "2001:db8::/129";
    invalid_ipv6_network.destination.network = "any";
    test.check(
        has_issue(firewall::validate(invalid_ipv6_network), "GH-CFG-1004"),
        "invalid IPv6 prefix is rejected");

    auto family_mismatch = valid_rule();
    family_mismatch.address_family = firewall::AddressFamily::inet6;
    test.check(
        has_issue(firewall::validate(family_mismatch), "GH-CFG-1005"),
        "explicit address-family mismatch is rejected");

    auto mixed_families = valid_rule();
    mixed_families.address_family = firewall::AddressFamily::any;
    mixed_families.destination.network = "2001:db8::1";
    test.check(
        has_issue(firewall::validate(mixed_families), "GH-CFG-1006"),
        "mixed address families are rejected");

    auto invalid_port_protocol = valid_rule();
    invalid_port_protocol.protocol = firewall::Protocol::icmp;
    test.check(
        has_issue(firewall::validate(invalid_port_protocol), "GH-CFG-1007"),
        "ports on ICMP rules are rejected");

    auto invalid_icmp_family = valid_rule();
    invalid_icmp_family.protocol = firewall::Protocol::icmp6;
    invalid_icmp_family.destination.port.reset();
    test.check(
        has_issue(firewall::validate(invalid_icmp_family), "GH-CFG-1009"),
        "ICMPv6 on an IPv4 rule is rejected");

    const auto duplicate = valid_rule();
    const firewall::RuleSet duplicate_rules{
        .revision = 2, .rules = {duplicate, duplicate}};
    test.check(
        has_issue(firewall::validate(duplicate_rules), "GH-CFG-1010"),
        "duplicate rule IDs are rejected");

    return test.result();
}
