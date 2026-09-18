#include "gatehold/version.hpp"

#include <iostream>
#include <string_view>

namespace {

void print_help(std::ostream& output) {
    output << sasd::gatehold::product_name() << " command-line interface\n\n"
           << "Usage:\n"
           << "  gateholdctl --help       Show this help\n"
           << "  gateholdctl --version    Show version information\n\n"
           << "Gatehold is in pre-alpha development. Firewall management commands\n"
           << "will be added only after their validation and rollback paths exist.\n";
}

}  // namespace

int main(int argc, char* argv[]) {
    if (argc == 1) {
        print_help(std::cout);
        return 0;
    }

    const std::string_view argument{argv[1]};
    if (argument == "--help" || argument == "-h" || argument == "help") {
        print_help(std::cout);
        return 0;
    }

    if (argument == "--version" || argument == "-V" || argument == "version") {
        std::cout << sasd::gatehold::product_name() << ' '
                  << sasd::gatehold::version() << '\n';
        return 0;
    }

    std::cerr << "Unknown command: " << argument << "\n"
              << "Run 'gateholdctl --help' for usage information.\n";
    return 2;
}

