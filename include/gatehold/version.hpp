#pragma once

#include <string_view>

namespace sasd::gatehold {

[[nodiscard]] constexpr std::string_view product_name() noexcept {
    return "SASD Gatehold";
}

[[nodiscard]] std::string_view version() noexcept;

}  // namespace sasd::gatehold

