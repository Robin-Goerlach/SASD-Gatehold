#include "gatehold/logging/json_event_formatter.hpp"

#include <algorithm>
#include <array>
#include <iterator>
#include <sstream>
#include <string>
#include <string_view>
#include <utility>

namespace sasd::gatehold::logging {
namespace {

constexpr std::string_view redacted_value = "[REDACTED]";

std::string_view to_string(Severity severity) noexcept {
    switch (severity) {
        case Severity::debug:
            return "debug";
        case Severity::info:
            return "info";
        case Severity::warning:
            return "warning";
        case Severity::error:
            return "error";
        case Severity::critical:
            return "critical";
    }
    return "info";
}

void append_escaped(std::ostringstream& output, std::string_view value) {
    constexpr std::array<char, 16> hexadecimal{
        '0', '1', '2', '3', '4', '5', '6', '7',
        '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};

    output << '"';
    for (const char raw_character : value) {
        const auto character = static_cast<unsigned char>(raw_character);
        switch (character) {
            case '"':
                output << "\\\"";
                break;
            case '\\':
                output << "\\\\";
                break;
            case '\b':
                output << "\\b";
                break;
            case '\f':
                output << "\\f";
                break;
            case '\n':
                output << "\\n";
                break;
            case '\r':
                output << "\\r";
                break;
            case '\t':
                output << "\\t";
                break;
            default:
                if (character < 0x20U) {
                    output << "\\u00"
                           << hexadecimal[(character >> 4U) & 0x0fU]
                           << hexadecimal[character & 0x0fU];
                } else {
                    output << raw_character;
                }
        }
    }
    output << '"';
}

void append_field(
    std::ostringstream& output,
    std::string_view key,
    std::string_view value,
    bool& first) {
    if (!first) {
        output << ',';
    }
    first = false;
    append_escaped(output, key);
    output << ':';
    append_escaped(output, value);
}

std::string lowercase(std::string_view value) {
    std::string lowered;
    lowered.reserve(value.size());
    std::ranges::transform(value, std::back_inserter(lowered), [](char character) {
        if (character >= 'A' && character <= 'Z') {
            return static_cast<char>(character + ('a' - 'A'));
        }
        return character;
    });
    return lowered;
}

}  // namespace

bool JsonEventFormatter::is_sensitive_key(std::string_view key) {
    const auto lowered = lowercase(key);
    constexpr std::array<std::string_view, 13> sensitive_fragments{
        "password",
        "passwd",
        "secret",
        "token",
        "api_key",
        "api-key",
        "apikey",
        "private_key",
        "cookie",
        "authorization",
        "credential",
        "session",
        "bearer"};

    return std::ranges::any_of(sensitive_fragments, [&lowered](auto fragment) {
        return lowered.find(fragment) != std::string::npos;
    });
}

std::string JsonEventFormatter::format(const Event& event) const {
    std::ostringstream output;
    bool first = true;
    output << '{';
    append_field(output, "schema", "gatehold.event.v1", first);
    append_field(output, "timestamp", event.timestamp, first);
    append_field(output, "severity", to_string(event.severity), first);
    append_field(output, "event_id", event.event_id, first);
    append_field(output, "component", event.component, first);
    append_field(output, "operation_id", event.operation_id, first);
    append_field(output, "action", event.action, first);
    append_field(output, "outcome", event.outcome, first);
    append_field(output, "message", event.message, first);

    if (!first) {
        output << ',';
    }
    append_escaped(output, "attributes");
    output << ":{";
    bool first_attribute = true;
    for (const auto& [key, value] : event.attributes) {
        append_field(
            output,
            key,
            is_sensitive_key(key) ? redacted_value : std::string_view{value},
            first_attribute);
    }
    output << "}}";
    return output.str();
}

}  // namespace sasd::gatehold::logging
