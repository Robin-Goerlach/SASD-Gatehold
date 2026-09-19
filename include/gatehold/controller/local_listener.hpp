#pragma once

#include "gatehold/controller/local_protocol.hpp"
#include "gatehold/logging/operation_journal.hpp"

#include <sys/types.h>

#include <atomic>
#include <chrono>
#include <filesystem>
#include <functional>
#include <mutex>
#include <optional>
#include <string>

namespace sasd::gatehold::controller {

struct LocalListenerConfig {
    std::filesystem::path socket_path;
    mode_t socket_mode{0600};
    int listen_backlog{8};
};

enum class LocalListenerStatus {
    listening,
    stopped,
    session_completed,
    accept_timed_out,
    busy,
    not_listening,
    invalid_configuration,
    unsafe_directory,
    address_in_use,
    audit_failed,
    io_error,
    cleanup_failed
};

struct LocalListenerResult {
    LocalListenerStatus status{LocalListenerStatus::io_error};
    std::string event_id;
    std::string message;
    std::optional<ProtocolSessionResult> session;

    [[nodiscard]] bool ok() const noexcept;
};

class LocalControllerListener final {
public:
    using TimestampSource = std::function<std::string()>;

    static constexpr std::chrono::milliseconds maximum_accept_timeout{60000};
    static constexpr int maximum_listen_backlog = 64;

    LocalControllerListener(
        const ControllerProtocolSession& protocol_session,
        const logging::OperationJournal& journal,
        LocalListenerConfig config,
        TimestampSource timestamp_source = {});
    ~LocalControllerListener();

    LocalControllerListener(const LocalControllerListener&) = delete;
    LocalControllerListener& operator=(const LocalControllerListener&) = delete;
    LocalControllerListener(LocalControllerListener&&) = delete;
    LocalControllerListener& operator=(LocalControllerListener&&) = delete;

    [[nodiscard]] LocalListenerResult start();
    [[nodiscard]] LocalListenerResult serve_one(
        std::chrono::milliseconds accept_timeout,
        std::chrono::milliseconds session_timeout);
    [[nodiscard]] LocalListenerResult stop();

    [[nodiscard]] bool is_listening() const;
    [[nodiscard]] bool has_active_admission() const noexcept;
    [[nodiscard]] const std::filesystem::path& socket_path() const noexcept;

private:
    [[nodiscard]] bool cleanup_socket_path() noexcept;
    void close_descriptors() noexcept;

    const ControllerProtocolSession& protocol_session_;
    const logging::OperationJournal& journal_;
    LocalListenerConfig config_;
    TimestampSource timestamp_source_;
    mutable std::mutex lifecycle_mutex_;
    std::atomic_flag serving_ = ATOMIC_FLAG_INIT;
    int listener_descriptor_{-1};
    int directory_descriptor_{-1};
    std::string socket_filename_;
    dev_t socket_device_{0};
    ino_t socket_inode_{0};
    bool owns_socket_path_{false};
};

}  // namespace sasd::gatehold::controller
