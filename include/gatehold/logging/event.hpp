#pragma once

#include <map>
#include <string>

namespace sasd::gatehold::logging {

enum class Severity { debug, info, warning, error, critical };

struct Event {
    std::string timestamp;
    Severity severity{Severity::info};
    std::string event_id;
    std::string component;
    std::string operation_id;
    std::string action;
    std::string outcome;
    std::string message;
    std::map<std::string, std::string> attributes;
};

}  // namespace sasd::gatehold::logging

