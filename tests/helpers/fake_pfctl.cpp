#include <chrono>
#include <fstream>
#include <iostream>
#include <iterator>
#include <string>
#include <thread>

int main(int argc, char* argv[]) {
    if (argc != 3 || std::string{argv[1]} != "-nf") {
        std::cerr << "fake pfctl: expected exactly '-nf <candidate>'\n";
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

    std::cout << "fake pfctl: syntax ok\n";
    return 0;
}

