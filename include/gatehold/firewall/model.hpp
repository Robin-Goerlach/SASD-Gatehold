#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace sasd::gatehold::firewall {

enum class Action { block, pass };
enum class Direction { any, inbound, outbound };
enum class AddressFamily { any, inet, inet6 };
enum class Protocol { any, tcp, udp, icmp, icmp6 };

struct Endpoint {
    std::string network{"any"};
    std::optional<std::uint16_t> port{};
};

struct Rule {
    std::string id;
    std::string description;
    Action action{Action::block};
    Direction direction{Direction::any};
    AddressFamily address_family{AddressFamily::any};
    std::string interface;
    Protocol protocol{Protocol::any};
    Endpoint source{};
    Endpoint destination{};
    bool log{true};
    bool quick{true};
    bool enabled{true};
};

struct RuleSet {
    std::uint64_t revision{0};
    std::vector<Rule> rules;
};

struct ValidationIssue {
    std::string code;
    std::string field;
    std::string message;
};

class ValidationReport {
public:
    [[nodiscard]] bool ok() const noexcept;
    [[nodiscard]] const std::vector<ValidationIssue>& issues() const noexcept;

    void add(std::string code, std::string field, std::string message);

private:
    std::vector<ValidationIssue> issues_;
};

[[nodiscard]] ValidationReport validate(const Rule& rule);
[[nodiscard]] ValidationReport validate(const RuleSet& rule_set);

[[nodiscard]] std::string_view to_string(Action value) noexcept;
[[nodiscard]] std::string_view to_string(Direction value) noexcept;
[[nodiscard]] std::string_view to_string(AddressFamily value) noexcept;
[[nodiscard]] std::string_view to_string(Protocol value) noexcept;

}  // namespace sasd::gatehold::firewall

