#include "gatehold/logging/json_event_formatter.hpp"
#include "test_support.hpp"

#include <string>

namespace logging = sasd::gatehold::logging;

int main() {
    gatehold::test::Context test;
    const logging::JsonEventFormatter formatter;
    const logging::Event event{
        .timestamp = "2026-09-18T12:00:00Z",
        .severity = logging::Severity::warning,
        .event_id = "GH-PF-1042",
        .component = "config-controller",
        .operation_id = "op-7d2140",
        .action = "pf.ruleset.validate",
        .outcome = "rejected",
        .message = "Rule contains a \"forbidden\" value.\nNo change applied.",
        .attributes = {
            {"api_token", "must-not-leak"},
            {"revision", "38"},
            {"source_interface", "em1"}}};

    const auto json = formatter.format(event);
    test.check(json.starts_with('{') && json.ends_with('}'), "event is a JSON object");
    test.check(
        json.find("\"schema\":\"gatehold.event.v1\"") != std::string::npos,
        "event contains a versioned schema");
    test.check(
        json.find("GH-PF-1042") != std::string::npos,
        "event contains its stable event ID");
    test.check(
        json.find("\\\"forbidden\\\"") != std::string::npos &&
            json.find("\\nNo change applied.") != std::string::npos,
        "message is JSON escaped");
    test.check(
        json.find("must-not-leak") == std::string::npos,
        "sensitive attribute value is absent");
    test.check(
        json.find("\"api_token\":\"[REDACTED]\"") != std::string::npos,
        "sensitive attribute is explicitly redacted");
    test.check(
        json.find("\"revision\":\"38\"") != std::string::npos,
        "non-sensitive diagnostic attribute is retained");
    test.check(
        logging::JsonEventFormatter::is_sensitive_key("Authorization"),
        "sensitive-key detection is case-insensitive");

    return test.result();
}

