#include "gatehold/version.hpp"

#include <iostream>

int main() {
    if (sasd::gatehold::product_name().empty()) {
        std::cerr << "Product name must not be empty.\n";
        return 1;
    }

    if (sasd::gatehold::version().empty()) {
        std::cerr << "Version must not be empty.\n";
        return 1;
    }

    return 0;
}

