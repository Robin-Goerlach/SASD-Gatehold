#pragma once

#include <iostream>
#include <string_view>

namespace gatehold::test {

class Context {
public:
    void check(bool condition, std::string_view description) {
        if (!condition) {
            std::cerr << "FAILED: " << description << '\n';
            ++failures_;
        }
    }

    [[nodiscard]] int result() const noexcept {
        return failures_ == 0 ? 0 : 1;
    }

private:
    int failures_{0};
};

}  // namespace gatehold::test

