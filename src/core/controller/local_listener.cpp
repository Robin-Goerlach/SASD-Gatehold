#if defined(__linux__) && !defined(_GNU_SOURCE)
#define _GNU_SOURCE
#endif

#include "gatehold/controller/local_listener.hpp"

#include "gatehold/logging/event.hpp"

#include <fcntl.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <chrono>
#include <cstddef>
#include <cstring>
#include <ctime>
#include <iomanip>
#include <sstream>
#include <string>
#include <string_view>
#include <utility>

namespace sasd::gatehold::controller {
namespace {

class ServingClaim final {
public:
    explicit ServingClaim(std::atomic_flag& flag) noexcept
        : flag_{flag}, acquired_{!flag_.test_and_set()} {}

    ~ServingClaim() {
        if (acquired_) {
            flag_.clear();
        }
    }

    ServingClaim(const ServingClaim&) = delete;
    ServingClaim& operator=(const ServingClaim&) = delete;

    [[nodiscard]] bool acquired() const noexcept {
        return acquired_;
    }

private:
    std::atomic_flag& flag_;
    bool acquired_{false};
};

class SocketDescriptor final {
public:
    explicit SocketDescriptor(int descriptor) noexcept
        : descriptor_{descriptor} {}

    ~SocketDescriptor() {
        if (descriptor_ >= 0) {
            ::close(descriptor_);
        }
    }

    SocketDescriptor(const SocketDescriptor&) = delete;
    SocketDescriptor& operator=(const SocketDescriptor&) = delete;

    [[nodiscard]] int get() const noexcept {
        return descriptor_;
    }

private:
    int descriptor_{-1};
};

std::string system_utc_timestamp() {
    const auto now = std::chrono::system_clock::now();
    const std::time_t time = std::chrono::system_clock::to_time_t(now);
    struct tm utc_time {};
    if (::gmtime_r(&time, &utc_time) == nullptr) {
        return "1970-01-01T00:00:00Z";
    }

    std::ostringstream output;
    output << std::put_time(&utc_time, "%Y-%m-%dT%H:%M:%SZ");
    return output.str();
}

logging::Event listener_event(
    std::string timestamp,
    logging::Severity severity,
    std::string event_id,
    std::string outcome,
    std::string message) {
    return {
        .timestamp = std::move(timestamp),
        .severity = severity,
        .event_id = std::move(event_id),
        .component = "controller-local-listener",
        .operation_id = "controller-listener",
        .action = "controller.listener",
        .outcome = std::move(outcome),
        .message = std::move(message),
        .attributes = {}};
}

LocalListenerResult result(
    LocalListenerStatus status,
    std::string event_id,
    std::string message,
    std::optional<ProtocolSessionResult> session = std::nullopt) {
    return {
        .status = status,
        .event_id = std::move(event_id),
        .message = std::move(message),
        .session = std::move(session)};
}

bool configure_descriptor(int descriptor) noexcept {
    const int status_flags = ::fcntl(descriptor, F_GETFL, 0);
    if (status_flags < 0 ||
        ::fcntl(descriptor, F_SETFL, status_flags | O_NONBLOCK) != 0) {
        return false;
    }
    const int descriptor_flags = ::fcntl(descriptor, F_GETFD, 0);
    return descriptor_flags >= 0 &&
           ::fcntl(
               descriptor,
               F_SETFD,
               descriptor_flags | FD_CLOEXEC) == 0;
}

int remaining_timeout(
    std::chrono::steady_clock::time_point deadline) noexcept {
    const auto now = std::chrono::steady_clock::now();
    if (now >= deadline) {
        return 0;
    }
    auto remaining =
        std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now);
    if (remaining < deadline - now) {
        remaining += std::chrono::milliseconds{1};
    }
    return static_cast<int>(remaining.count());
}

int accept_protected(int listener) noexcept {
#if defined(__OpenBSD__) || defined(__linux__)
    int flags = SOCK_NONBLOCK | SOCK_CLOEXEC;
#if defined(SOCK_CLOFORK)
    flags |= SOCK_CLOFORK;
#endif
    return ::accept4(listener, nullptr, nullptr, flags);
#else
    const int accepted = ::accept(listener, nullptr, nullptr);
    if (accepted >= 0 && !configure_descriptor(accepted)) {
        ::close(accepted);
        return -1;
    }
    return accepted;
#endif
}

bool valid_timeout(std::chrono::milliseconds timeout) noexcept {
    return timeout > std::chrono::milliseconds::zero() &&
           timeout <= LocalControllerListener::maximum_accept_timeout;
}

void bounded_rate_limit_delay(
    std::chrono::milliseconds retry_after,
    std::chrono::milliseconds accept_timeout) noexcept {
    const auto delay = std::min(retry_after, accept_timeout);
    if (delay <= std::chrono::milliseconds::zero()) {
        return;
    }
    static_cast<void>(::poll(nullptr, 0, static_cast<int>(delay.count())));
}

}  // namespace

bool LocalListenerResult::ok() const noexcept {
    return status == LocalListenerStatus::listening ||
           status == LocalListenerStatus::stopped ||
           status == LocalListenerStatus::session_completed;
}

LocalControllerListener::LocalControllerListener(
    const ControllerProtocolSession& protocol_session,
    const logging::OperationJournal& journal,
    LocalListenerConfig config,
    TimestampSource timestamp_source)
    : protocol_session_{protocol_session},
      journal_{journal},
      config_{std::move(config)},
      admission_rate_limiter_{config_.admission_rate_limit},
      timestamp_source_{std::move(timestamp_source)} {
    if (!timestamp_source_) {
        timestamp_source_ = system_utc_timestamp;
    }
}

LocalControllerListener::~LocalControllerListener() {
    const std::scoped_lock lock{lifecycle_mutex_};
    close_descriptors();
    static_cast<void>(cleanup_socket_path());
}

LocalListenerResult LocalControllerListener::start() {
    const std::scoped_lock lock{lifecycle_mutex_};
    const auto append = [this](logging::Event event) {
        return journal_.append(event).ok();
    };
    const auto audited_failure = [this, &append](
                                     LocalListenerStatus status,
                                     logging::Severity severity,
                                     std::string event_id,
                                     std::string message) {
        static_cast<void>(append(listener_event(
            timestamp_source_(),
            severity,
            event_id,
            "rejected",
            message)));
        return result(status, std::move(event_id), std::move(message));
    };

    if (listener_descriptor_ >= 0) {
        return result(
            LocalListenerStatus::listening,
            "GH-LSN-0002",
            "Local controller listener is already active.");
    }

    const auto normalized = config_.socket_path.lexically_normal();
    const auto native_path = config_.socket_path.native();
    const auto filename = config_.socket_path.filename().native();
    const bool supported_mode = config_.socket_mode == 0600 ||
                                config_.socket_mode == 0660;
    const bool supported_group =
        (config_.socket_mode == 0600 &&
         !config_.socket_group_id.has_value()) ||
        (config_.socket_mode == 0660 &&
         config_.socket_group_id.has_value());
    if (!config_.socket_path.is_absolute() ||
        normalized != config_.socket_path || filename.empty() ||
        filename == "." || filename == ".." ||
        native_path.find('\0') != std::string::npos ||
        native_path.size() >= sizeof(sockaddr_un::sun_path) ||
        !supported_mode || !supported_group || config_.listen_backlog < 1 ||
        config_.listen_backlog > maximum_listen_backlog ||
        !admission_rate_limiter_.valid()) {
        return audited_failure(
            LocalListenerStatus::invalid_configuration,
            logging::Severity::warning,
            "GH-LSN-1001",
            "Local listener configuration is outside safe bounds.");
    }

    if (!append(listener_event(
            timestamp_source_(),
            logging::Severity::info,
            "GH-LSN-0001",
            "starting",
            "Local controller listener startup was requested."))) {
        return result(
            LocalListenerStatus::audit_failed,
            "GH-LSN-2002",
            "Local listener startup could not be audited.");
    }

    const auto parent = config_.socket_path.parent_path();
    std::error_code canonical_error;
    const auto canonical_parent =
        std::filesystem::canonical(parent, canonical_error);
    struct stat parent_status {};
    if (canonical_error || canonical_parent != parent ||
        ::lstat(parent.c_str(), &parent_status) != 0 ||
        !S_ISDIR(parent_status.st_mode) ||
        parent_status.st_uid != ::geteuid() ||
        (parent_status.st_mode & S_IWGRP) != 0 ||
        (parent_status.st_mode & S_IRWXO) != 0) {
        return audited_failure(
            LocalListenerStatus::unsafe_directory,
            logging::Severity::error,
            "GH-LSN-1002",
            "Local listener parent must be a trusted non-writable directory.");
    }

    const int directory = ::open(
        parent.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (directory < 0) {
        return audited_failure(
            LocalListenerStatus::unsafe_directory,
            logging::Severity::error,
            "GH-LSN-1002",
            "Local listener parent could not be opened safely.");
    }
    struct stat opened_parent {};
    if (::fstat(directory, &opened_parent) != 0 ||
        opened_parent.st_dev != parent_status.st_dev ||
        opened_parent.st_ino != parent_status.st_ino) {
        ::close(directory);
        return audited_failure(
            LocalListenerStatus::unsafe_directory,
            logging::Severity::error,
            "GH-LSN-1002",
            "Local listener parent identity changed during startup.");
    }

    struct stat existing {};
    if (::fstatat(
            directory,
            filename.c_str(),
            &existing,
            AT_SYMLINK_NOFOLLOW) == 0) {
        ::close(directory);
        return audited_failure(
            LocalListenerStatus::address_in_use,
            logging::Severity::warning,
            "GH-LSN-1003",
            "Local listener refuses to replace an existing filesystem entry.");
    }
    if (errno != ENOENT) {
        ::close(directory);
        return audited_failure(
            LocalListenerStatus::io_error,
            logging::Severity::error,
            "GH-LSN-2001",
            "Local listener address availability could not be verified.");
    }

    const int listener = ::socket(AF_UNIX, SOCK_STREAM, 0);
    if (listener < 0 || !configure_descriptor(listener)) {
        if (listener >= 0) {
            ::close(listener);
        }
        ::close(directory);
        return audited_failure(
            LocalListenerStatus::io_error,
            logging::Severity::error,
            "GH-LSN-2001",
            "Local listener socket could not be created safely.");
    }

    sockaddr_un address{};
#if defined(__OpenBSD__)
    address.sun_len = static_cast<decltype(address.sun_len)>(
        offsetof(sockaddr_un, sun_path) + native_path.size() + 1U);
#endif
    address.sun_family = AF_UNIX;
    std::memcpy(address.sun_path, native_path.c_str(), native_path.size() + 1U);
    const auto address_size = static_cast<socklen_t>(
        offsetof(sockaddr_un, sun_path) + native_path.size() + 1U);
    if (::bind(
            listener,
            reinterpret_cast<const sockaddr*>(&address),
            address_size) != 0) {
        ::close(listener);
        ::close(directory);
        return audited_failure(
            LocalListenerStatus::io_error,
            logging::Severity::error,
            "GH-LSN-2001",
            "Local listener address could not be bound.");
    }

    directory_descriptor_ = directory;
    listener_descriptor_ = listener;
    socket_filename_ = filename;
    owns_socket_path_ = true;

    struct stat bound {};
    const bool secured = ::fstatat(
                             directory_descriptor_,
                             socket_filename_.c_str(),
                             &bound,
                             AT_SYMLINK_NOFOLLOW) == 0 &&
                         S_ISSOCK(bound.st_mode) &&
                         bound.st_uid == ::geteuid();
    if (secured) {
        socket_device_ = bound.st_dev;
        socket_inode_ = bound.st_ino;
    }
    const bool group_set =
        secured &&
        (!config_.socket_group_id.has_value() ||
         ::fchownat(
             directory_descriptor_,
             socket_filename_.c_str(),
             bound.st_uid,
             *config_.socket_group_id,
             AT_SYMLINK_NOFOLLOW) == 0);
    const bool permissions_set =
        group_set &&
        ::fchmodat(
            directory_descriptor_,
            socket_filename_.c_str(),
            config_.socket_mode,
            0) == 0;
    struct stat verified {};
    const bool permissions_verified =
        permissions_set &&
        ::fstatat(
            directory_descriptor_,
            socket_filename_.c_str(),
            &verified,
            AT_SYMLINK_NOFOLLOW) == 0 &&
        S_ISSOCK(verified.st_mode) && verified.st_dev == socket_device_ &&
        verified.st_ino == socket_inode_ &&
        verified.st_uid == ::geteuid() &&
        (verified.st_mode & 0777) == config_.socket_mode &&
        (!config_.socket_group_id.has_value() ||
         verified.st_gid == *config_.socket_group_id);
    if (!permissions_verified ||
        ::listen(listener_descriptor_, config_.listen_backlog) != 0) {
        close_descriptors();
        static_cast<void>(cleanup_socket_path());
        return audited_failure(
            LocalListenerStatus::io_error,
            logging::Severity::error,
            "GH-LSN-2001",
            "Local listener could not secure and activate its socket.");
    }

    auto ready = listener_event(
        timestamp_source_(),
        logging::Severity::info,
        "GH-LSN-0002",
        "listening",
        "Local controller listener is accepting one bounded session at a time.");
    ready.attributes.emplace(
        "listen_backlog", std::to_string(config_.listen_backlog));
    ready.attributes.emplace(
        "socket_mode",
        config_.socket_mode == 0600 ? "0600" : "0660");
    ready.attributes.emplace(
        "socket_group_delegated",
        config_.socket_group_id.has_value() ? "true" : "false");
    ready.attributes.emplace(
        "admission_limit",
        std::to_string(config_.admission_rate_limit.maximum_admissions));
    ready.attributes.emplace(
        "admission_window_ms",
        std::to_string(config_.admission_rate_limit.window.count()));
    if (!append(std::move(ready))) {
        close_descriptors();
        static_cast<void>(cleanup_socket_path());
        return result(
            LocalListenerStatus::audit_failed,
            "GH-LSN-2002",
            "Local listener readiness could not be audited.");
    }

    admission_rate_limiter_.reset();
    return result(
        LocalListenerStatus::listening,
        "GH-LSN-0002",
        "Local controller listener is active.");
}

LocalListenerResult LocalControllerListener::serve_one(
    std::chrono::milliseconds accept_timeout,
    std::chrono::milliseconds session_timeout) {
    ServingClaim claim{serving_};
    if (!claim.acquired()) {
        static_cast<void>(journal_.append(listener_event(
            timestamp_source_(),
            logging::Severity::warning,
            "GH-LSN-1004",
            "rejected",
            "Concurrent local listener admission was rejected.")));
        return result(
            LocalListenerStatus::busy,
            "GH-LSN-1004",
            "Local listener already has an active admission call.");
    }

    int listener = -1;
    {
        const std::scoped_lock lock{lifecycle_mutex_};
        listener = listener_descriptor_;
    }
    if (listener < 0) {
        return result(
            LocalListenerStatus::not_listening,
            "GH-LSN-1001",
            "Local listener has not been started.");
    }
    if (!valid_timeout(accept_timeout) ||
        !valid_timeout(session_timeout)) {
        return result(
            LocalListenerStatus::invalid_configuration,
            "GH-LSN-1001",
            "Local listener timeout is outside safe bounds.");
    }

    const auto deadline = std::chrono::steady_clock::now() + accept_timeout;
    for (;;) {
        const int timeout = remaining_timeout(deadline);
        if (timeout == 0) {
            return result(
                LocalListenerStatus::accept_timed_out,
                "GH-LSN-1005",
                "No local controller connection arrived before the deadline.");
        }
        struct pollfd descriptor {
            .fd = listener, .events = POLLIN, .revents = 0
        };
        const int polled = ::poll(&descriptor, 1, timeout);
        if (polled == 0) {
            return result(
                LocalListenerStatus::accept_timed_out,
                "GH-LSN-1005",
                "No local controller connection arrived before the deadline.");
        }
        if (polled < 0) {
            if (errno == EINTR) {
                continue;
            }
            break;
        }
        if ((descriptor.revents & POLLNVAL) != 0) {
            break;
        }

        const int accepted = accept_protected(listener);
        if (accepted >= 0) {
            SocketDescriptor connection{accepted};
            const auto admission = admission_rate_limiter_.try_admit(
                std::chrono::steady_clock::now());
            if (!admission.admitted) {
                bounded_rate_limit_delay(
                    admission.retry_after, accept_timeout);
                return result(
                    LocalListenerStatus::rate_limited,
                    "GH-LSN-1006",
                    "Local controller connection was rate limited.");
            }
            auto session = protocol_session_.serve(accepted, session_timeout);
            return result(
                LocalListenerStatus::session_completed,
                session.event_id,
                "Local controller connection reached a terminal session result.",
                std::move(session));
        }
        if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK ||
            errno == ECONNABORTED) {
            continue;
        }
        break;
    }

    static_cast<void>(journal_.append(listener_event(
        timestamp_source_(),
        logging::Severity::error,
        "GH-LSN-2003",
        "failed",
        "Local listener could not accept a pending connection.")));
    return result(
        LocalListenerStatus::io_error,
        "GH-LSN-2003",
        "Local listener could not accept a pending connection.");
}

LocalListenerResult LocalControllerListener::stop() {
    const std::scoped_lock lock{lifecycle_mutex_};
    if (serving_.test()) {
        return result(
            LocalListenerStatus::busy,
            "GH-LSN-1004",
            "Local listener cannot stop while a session admission is active.");
    }
    if (listener_descriptor_ < 0 && !owns_socket_path_) {
        return result(
            LocalListenerStatus::stopped,
            "GH-LSN-0003",
            "Local controller listener is already stopped.");
    }

    close_descriptors();
    if (!cleanup_socket_path()) {
        static_cast<void>(journal_.append(listener_event(
            timestamp_source_(),
            logging::Severity::error,
            "GH-LSN-2004",
            "failed",
            "Local listener socket path could not be removed safely.")));
        return result(
            LocalListenerStatus::cleanup_failed,
            "GH-LSN-2004",
            "Local listener socket path could not be removed safely.");
    }

    if (!journal_
             .append(listener_event(
                 timestamp_source_(),
                 logging::Severity::info,
                 "GH-LSN-0003",
                 "stopped",
                 "Local controller listener stopped cleanly."))
             .ok()) {
        return result(
            LocalListenerStatus::audit_failed,
            "GH-LSN-2002",
            "Local listener shutdown could not be audited.");
    }
    return result(
        LocalListenerStatus::stopped,
        "GH-LSN-0003",
        "Local controller listener stopped cleanly.");
}

bool LocalControllerListener::is_listening() const {
    const std::scoped_lock lock{lifecycle_mutex_};
    return listener_descriptor_ >= 0;
}

bool LocalControllerListener::has_active_admission() const noexcept {
    return serving_.test();
}

const std::filesystem::path& LocalControllerListener::socket_path() const
    noexcept {
    return config_.socket_path;
}

bool LocalControllerListener::cleanup_socket_path() noexcept {
    if (!owns_socket_path_) {
        return true;
    }
    bool removed = false;
    if (directory_descriptor_ >= 0 && !socket_filename_.empty()) {
        struct stat current {};
        if (::fstatat(
                directory_descriptor_,
                socket_filename_.c_str(),
                &current,
                AT_SYMLINK_NOFOLLOW) != 0) {
            removed = errno == ENOENT;
        } else if (S_ISSOCK(current.st_mode) &&
                   current.st_dev == socket_device_ &&
                   current.st_ino == socket_inode_) {
            removed = ::unlinkat(
                          directory_descriptor_,
                          socket_filename_.c_str(),
                          0) == 0 ||
                      errno == ENOENT;
        }
    }
    owns_socket_path_ = false;
    socket_device_ = 0;
    socket_inode_ = 0;
    socket_filename_.clear();
    if (directory_descriptor_ >= 0) {
        ::close(directory_descriptor_);
        directory_descriptor_ = -1;
    }
    return removed;
}

void LocalControllerListener::close_descriptors() noexcept {
    if (listener_descriptor_ >= 0) {
        ::close(listener_descriptor_);
        listener_descriptor_ = -1;
    }
}

}  // namespace sasd::gatehold::controller
