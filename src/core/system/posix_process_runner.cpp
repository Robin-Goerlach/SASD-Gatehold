#include "gatehold/system/posix_process_runner.hpp"

#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <chrono>
#include <cstring>
#include <string_view>

namespace sasd::gatehold::system {
namespace {

void close_descriptor(int& descriptor) noexcept {
    if (descriptor >= 0) {
        ::close(descriptor);
        descriptor = -1;
    }
}

bool set_nonblocking(int descriptor) noexcept {
    const int flags = ::fcntl(descriptor, F_GETFL);
    return flags >= 0 && ::fcntl(descriptor, F_SETFL, flags | O_NONBLOCK) == 0;
}

void append_bounded(
    std::string& destination,
    std::string_view chunk,
    bool& truncated) {
    if (destination.size() >= PosixProcessRunner::maximum_captured_output) {
        truncated = true;
        return;
    }

    const auto available =
        PosixProcessRunner::maximum_captured_output - destination.size();
    const auto count = std::min(available, chunk.size());
    destination.append(chunk.data(), count);
    if (count < chunk.size()) {
        truncated = true;
    }
}

void drain_descriptor(
    int& descriptor,
    std::string& destination,
    bool& truncated) {
    if (descriptor < 0) {
        return;
    }

    std::array<char, 4096> buffer{};
    for (;;) {
        const auto count = ::read(descriptor, buffer.data(), buffer.size());
        if (count > 0) {
            append_bounded(
                destination,
                std::string_view{buffer.data(), static_cast<std::size_t>(count)},
                truncated);
            continue;
        }
        if (count == 0) {
            close_descriptor(descriptor);
            return;
        }
        if (errno == EINTR) {
            continue;
        }
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return;
        }
        close_descriptor(descriptor);
        return;
    }
}

void close_pipe(std::array<int, 2>& descriptors) noexcept {
    close_descriptor(descriptors[0]);
    close_descriptor(descriptors[1]);
}

}  // namespace

ProcessResult PosixProcessRunner::run(
    const std::filesystem::path& executable,
    const std::vector<std::string>& arguments,
    std::chrono::milliseconds timeout) const {
    ProcessResult result;
    if (!executable.is_absolute() || timeout <= std::chrono::milliseconds::zero()) {
        result.error_message =
            "Executable path must be absolute and timeout must be positive.";
        return result;
    }

    std::array<int, 2> output_pipe{-1, -1};
    std::array<int, 2> error_pipe{-1, -1};
    if (::pipe(output_pipe.data()) != 0 || ::pipe(error_pipe.data()) != 0) {
        const int pipe_error = errno;
        close_pipe(output_pipe);
        close_pipe(error_pipe);
        result.error_message = std::string{"Could not create output pipes: "} +
                               std::strerror(pipe_error);
        return result;
    }

    std::vector<char*> argument_vector;
    argument_vector.reserve(arguments.size() + 2U);
    argument_vector.push_back(const_cast<char*>(executable.c_str()));
    for (const auto& argument : arguments) {
        argument_vector.push_back(const_cast<char*>(argument.c_str()));
    }
    argument_vector.push_back(nullptr);

    const pid_t child = ::fork();
    if (child < 0) {
        const int fork_error = errno;
        close_pipe(output_pipe);
        close_pipe(error_pipe);
        result.error_message = std::string{"Could not create validation process: "} +
                               std::strerror(fork_error);
        return result;
    }

    if (child == 0) {
        if (::dup2(output_pipe[1], STDOUT_FILENO) < 0 ||
            ::dup2(error_pipe[1], STDERR_FILENO) < 0) {
            _exit(126);
        }
        close_pipe(output_pipe);
        close_pipe(error_pipe);
        ::execv(executable.c_str(), argument_vector.data());
        constexpr std::string_view failure_message = "execv failed\n";
        const auto ignored = ::write(
            STDERR_FILENO, failure_message.data(), failure_message.size());
        static_cast<void>(ignored);
        _exit(127);
    }

    result.launched = true;
    close_descriptor(output_pipe[1]);
    close_descriptor(error_pipe[1]);
    if (!set_nonblocking(output_pipe[0]) || !set_nonblocking(error_pipe[0])) {
        ::kill(child, SIGKILL);
        int ignored_status = 0;
        ::waitpid(child, &ignored_status, 0);
        close_pipe(output_pipe);
        close_pipe(error_pipe);
        result.error_message = "Could not configure non-blocking output capture.";
        result.exit_code = 128 + SIGKILL;
        return result;
    }

    const auto deadline = std::chrono::steady_clock::now() + timeout;
    bool child_finished = false;
    int child_status = 0;

    while (!child_finished || output_pipe[0] >= 0 || error_pipe[0] >= 0) {
        drain_descriptor(
            output_pipe[0], result.standard_output, result.output_truncated);
        drain_descriptor(
            error_pipe[0], result.standard_error, result.output_truncated);

        if (!child_finished) {
            const auto waited = ::waitpid(child, &child_status, WNOHANG);
            if (waited == child) {
                child_finished = true;
            } else if (waited < 0 && errno != EINTR) {
                result.error_message = std::string{"waitpid failed: "} +
                                       std::strerror(errno);
                child_finished = true;
            }
        }

        if (!child_finished && std::chrono::steady_clock::now() >= deadline) {
            result.timed_out = true;
            ::kill(child, SIGKILL);
            while (::waitpid(child, &child_status, 0) < 0 && errno == EINTR) {
            }
            child_finished = true;
        }

        if (child_finished && output_pipe[0] < 0 && error_pipe[0] < 0) {
            break;
        }

        std::array<struct pollfd, 2> poll_descriptors{{
            {.fd = output_pipe[0], .events = POLLIN | POLLHUP, .revents = 0},
            {.fd = error_pipe[0], .events = POLLIN | POLLHUP, .revents = 0}}};
        const int poll_timeout = child_finished ? 0 : 10;
        const auto poll_result =
            ::poll(poll_descriptors.data(), poll_descriptors.size(), poll_timeout);
        if (poll_result < 0 && errno != EINTR) {
            result.error_message = std::string{"poll failed: "} +
                                   std::strerror(errno);
            break;
        }
    }

    drain_descriptor(output_pipe[0], result.standard_output, result.output_truncated);
    drain_descriptor(error_pipe[0], result.standard_error, result.output_truncated);
    close_pipe(output_pipe);
    close_pipe(error_pipe);

    if (WIFEXITED(child_status)) {
        result.exit_code = WEXITSTATUS(child_status);
    } else if (WIFSIGNALED(child_status)) {
        result.exit_code = 128 + WTERMSIG(child_status);
    }
    return result;
}

}  // namespace sasd::gatehold::system

