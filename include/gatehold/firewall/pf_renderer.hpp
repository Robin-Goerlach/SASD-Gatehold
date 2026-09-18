#pragma once

#include "gatehold/firewall/model.hpp"

#include <string>

namespace sasd::gatehold::firewall {

struct RenderResult {
    std::string ruleset;
    ValidationReport validation;

    [[nodiscard]] bool ok() const noexcept;
};

class PfRenderer {
public:
    [[nodiscard]] RenderResult render(const RuleSet& rule_set) const;
};

}  // namespace sasd::gatehold::firewall

