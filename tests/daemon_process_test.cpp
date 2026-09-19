#include "temporary_directory.hpp"
#include "test_support.hpp"

#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

#include <array>
#include <cerrno>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>
#include <string_view>
#include <thread>

namespace {

class Descriptor final {
public:
    explicit Descriptor(int value) noexcept : value_{value} {}
    ~Descriptor() {
        if (value_ >= 0) {
            ::close(value_);
        }
    }

    Descriptor(const Descriptor&) = delete;
    Descriptor& operator=(const Descriptor&) = delete;

    [[nodiscard]] int get() const noexcept {
        return value_;
    }

private:
    int value_{-1};
};

void create_private_directory(const std::filesystem::path& path) {
    std::filesystem::create_directory(path);
    std::filesystem::permissions(
        path,
        std::filesystem::perms::owner_all,
        std::filesystem::perm_options::replace);
}

std::string read_file(const std::filesystem::path& path) {
    std::ifstream input{path, std::ios::binary};
    return {std::istreambuf_iterator<char>{input},
            std::istreambuf_iterator<char>{}};
}

bool send_all(int socket, const void* data, std::size_t size) {
    const auto* bytes = static_cast<const unsigned char*>(data);
    std::size_t offset = 0;
    while (offset < size) {
        const auto sent = ::send(socket, bytes + offset, size - offset, 0);
        if (sent > 0) {
            offset += static_cast<std::size_t>(sent);
            continue;
        }
        if (sent < 0 && errno == EINTR) {
            continue;
        }
        return false;
    }
    return true;
}

bool receive_all(int socket, void* data, std::size_t size) {
    auto* bytes = static_cast<unsigned char*>(data);
    std::size_t offset = 0;
    while (offset < size) {
        const auto received = ::recv(socket, bytes + offset, size - offset, 0);
        if (received > 0) {
            offset += static_cast<std::size_t>(received);
            continue;
        }
        if (received < 0 && errno == EINTR) {
            continue;
        }
        return false;
    }
    return true;
}

std::string exchange(
    const std::filesystem::path& socket_path,
    std::string_view payload) {
    const Descriptor socket{::socket(AF_UNIX, SOCK_STREAM, 0)};
    if (socket.get() < 0) {
        return {};
    }

    sockaddr_un address{};
    address.sun_family = AF_UNIX;
    const auto native_path = socket_path.native();
    if (native_path.size() >= sizeof(address.sun_path)) {
        return {};
    }
    std::memcpy(
        address.sun_path, native_path.c_str(), native_path.size() + 1U);
    const auto address_size = static_cast<socklen_t>(
        offsetof(sockaddr_un, sun_path) + native_path.size() + 1U);
    if (::connect(
            socket.get(),
            reinterpret_cast<const sockaddr*>(&address),
            address_size) != 0) {
        return {};
    }

    const auto payload_size = static_cast<std::uint32_t>(payload.size());
    const std::array<unsigned char, 4> header{
        static_cast<unsigned char>((payload_size >> 24U) & 0xffU),
        static_cast<unsigned char>((payload_size >> 16U) & 0xffU),
        static_cast<unsigned char>((payload_size >> 8U) & 0xffU),
        static_cast<unsigned char>(payload_size & 0xffU)};
    if (!send_all(socket.get(), header.data(), header.size()) ||
        !send_all(socket.get(), payload.data(), payload.size())) {
        return {};
    }

    std::array<unsigned char, 4> response_header{};
    if (!receive_all(
            socket.get(), response_header.data(), response_header.size())) {
        return {};
    }
    const auto response_size =
        (static_cast<std::uint32_t>(response_header[0]) << 24U) |
        (static_cast<std::uint32_t>(response_header[1]) << 16U) |
        (static_cast<std::uint32_t>(response_header[2]) << 8U) |
        static_cast<std::uint32_t>(response_header[3]);
    if (response_size == 0U || response_size > 4096U) {
        return {};
    }
    std::string response(response_size, '\0');
    if (!receive_all(socket.get(), response.data(), response.size())) {
        return {};
    }
    return response;
}

bool wait_for_socket(
    const std::filesystem::path& socket_path,
    pid_t child) {
    for (int attempt = 0; attempt < 5000; ++attempt) {
        struct stat status {};
        if (::lstat(socket_path.c_str(), &status) == 0 &&
            S_ISSOCK(status.st_mode)) {
            return true;
        }
        int child_status = 0;
        if (::waitpid(child, &child_status, WNOHANG) == child) {
            return false;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds{1});
    }
    return false;
}

bool wait_for_exit(pid_t child, int& status) {
    for (int attempt = 0; attempt < 5000; ++attempt) {
        if (::waitpid(child, &status, WNOHANG) == child) {
            return true;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds{1});
    }
    return false;
}

}  // namespace

int main(int argc, char* argv[]) {
    gatehold::test::Context test;
    test.check(argc == 2, "daemon process test receives the daemon executable");
    if (argc != 2) {
        return test.result();
    }

    const int capability_check = ::socket(AF_UNIX, SOCK_STREAM, 0);
    if (capability_check < 0 && (errno == EPERM || errno == EACCES)) {
        std::cout
            << "SKIPPED: runtime policy denies creation of AF_UNIX sockets\n";
        return 0;
    }
    test.check(capability_check >= 0, "AF_UNIX capability check succeeds");
    if (capability_check < 0) {
        return test.result();
    }
    ::close(capability_check);

    const gatehold::test::TemporaryDirectory temporary{
        "gatehold-daemon-process-test"};
    const auto journal_root = temporary.path() / "journal";
    const auto revision_root = temporary.path() / "revisions";
    const auto transaction_root = temporary.path() / "transactions";
    const auto socket_root = temporary.path() / "run";
    const auto socket_path = socket_root / "controller.sock";
    create_private_directory(journal_root);
    create_private_directory(revision_root);
    create_private_directory(transaction_root);
    create_private_directory(socket_root);

    const std::string uid = std::to_string(::geteuid());
    const pid_t child = ::fork();
    test.check(child >= 0, "daemon test process can be forked");
    if (child == 0) {
        ::execl(
            argv[1],
            argv[1],
            "serve-read-only",
            "--journal-root",
            journal_root.c_str(),
            "--revision-root",
            revision_root.c_str(),
            "--transaction-root",
            transaction_root.c_str(),
            "--socket-path",
            socket_path.c_str(),
            "--allowed-uid",
            uid.c_str(),
            static_cast<char*>(nullptr));
        ::_exit(127);
    }
    if (child < 0) {
        return test.result();
    }

    const bool socket_ready = wait_for_socket(socket_path, child);
    test.check(socket_ready, "daemon reaches authenticated listener readiness");
    if (!socket_ready) {
        static_cast<void>(::kill(child, SIGKILL));
        int status = 0;
        static_cast<void>(::waitpid(child, &status, 0));
        return test.result();
    }

    const auto status_response = exchange(
        socket_path,
        "gatehold-controller-v1\n"
        "request_id=daemon-status\n"
        "operation=status\n");
    test.check(
        status_response.find("result=completed") != std::string::npos &&
            status_response.find("controller_state=ready") !=
                std::string::npos,
        "daemon serves lifecycle status after recovery");

    const auto activation_response = exchange(
        socket_path,
        "gatehold-controller-v1\n"
        "request_id=daemon-activation\n"
        "operation=activate\n"
        "operation_id=daemon-operation\n"
        "revision=17\n"
        "authorization_reference=process-test-secret\n"
        "probe_timeout_ms=1000\n"
        "confirmation_timeout_ms=10000\n");
    test.check(
        activation_response.find("activation_status=authorization_denied") !=
                std::string::npos &&
            activation_response.find("process-test-secret") ==
                std::string::npos,
        "daemon denies activation without reflecting authorization data");

    test.check(
        ::kill(child, SIGTERM) == 0,
        "SIGTERM is delivered to the running daemon");
    int child_status = 0;
    const bool exited = wait_for_exit(child, child_status);
    if (!exited) {
        static_cast<void>(::kill(child, SIGKILL));
        static_cast<void>(::waitpid(child, &child_status, 0));
    }
    test.check(
        exited && WIFEXITED(child_status) && WEXITSTATUS(child_status) == 0,
        "daemon exits cleanly after cooperative signal stop");
    test.check(
        !std::filesystem::exists(socket_path),
        "daemon removes its owned socket during shutdown");

    const auto journal_text = read_file(journal_root / "operations.jsonl");
    test.check(
        journal_text.find("GH-DMN-0001") != std::string::npos &&
            journal_text.find("GH-DMN-0002") != std::string::npos &&
            journal_text.find("GH-SIG-0002") != std::string::npos &&
            journal_text.find("GH-AUTH-1001") != std::string::npos &&
            journal_text.find("process-test-secret") == std::string::npos,
        "daemon lifetime and denial are audited without authorization data");

    return test.result();
}
