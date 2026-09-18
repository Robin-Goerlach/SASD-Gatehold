#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <string>
#include <thread>

int main(int argc, char* argv[]) {
    if (argc != 3 ||
        (std::string{argv[1]} != "-nf" && std::string{argv[1]} != "-f")) {
        std::cerr << "fake pfctl: expected '-nf <candidate>' or '-f <revision>'\n";
        return 64;
    }

    std::ifstream candidate{argv[2], std::ios::binary};
    if (!candidate) {
        std::cerr << "fake pfctl: could not open candidate\n";
        return 66;
    }

    const std::string content{
        std::istreambuf_iterator<char>{candidate}, std::istreambuf_iterator<char>{}};
    if (content.find("FAKE_SLEEP") != std::string::npos) {
        std::this_thread::sleep_for(std::chrono::milliseconds{250});
    }
    if (content.find("FAKE_FLOOD") != std::string::npos) {
        for (int index = 0; index < 70000; ++index) {
            std::cout << 'x';
        }
        std::cout << '\n';
    }
    if (content.find("FAKE_REJECT") != std::string::npos) {
        std::cerr << "fake pfctl: syntax error\n";
        return 1;
    }

    if (std::string{argv[1]} == "-f") {
        if (content.find("FAKE_LOAD_SLEEP") != std::string::npos) {
            std::this_thread::sleep_for(std::chrono::milliseconds{250});
        }
        if (content.find("FAKE_LOAD_FAIL") != std::string::npos) {
            std::cerr << "fake pfctl: load failed\n";
            return 1;
        }
        if (const char* trace_path = std::getenv("GATEHOLD_FAKE_PFCTL_TRACE");
            trace_path != nullptr) {
            std::ofstream trace{trace_path, std::ios::app};
            trace << std::filesystem::path{argv[2]}.filename().string() << '\n';
        }
        std::cout << "fake pfctl: ruleset loaded\n";
        return 0;
    }

    std::cout << "fake pfctl: syntax ok\n";
    return 0;
}
