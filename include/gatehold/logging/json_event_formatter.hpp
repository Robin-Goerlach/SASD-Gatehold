#pragma once

#include "gatehold/logging/event.hpp"

#include <string>
#include <string_view>

namespace sasd::gatehold::logging {

class JsonEventFormatter {
public:
    [[nodiscard]] std::string format(const Event& event) const;

    [[nodiscard]] static bool is_sensitive_key(std::string_view key);
};

}  // namespace sasd::gatehold::logging

