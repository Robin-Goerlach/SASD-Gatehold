#pragma once

#include "gatehold/controller/privileged_pf_controller.hpp"
#include "gatehold/logging/operation_journal.hpp"

#include <sys/types.h>

#include <chrono>
#include <cstddef>
#include <functional>
#include <optional>
#include <string>

namespace sasd::gatehold::controller {

enum class PeerCredentialStatus { available, unavailable };

struct PeerCredentialResult {
    PeerCredentialStatus status{PeerCredentialStatus::unavailable};
    uid_t user_id{0};
    gid_t group_id{0};
    std::string event_id;
    std::string message;

    [[nodiscard]] bool ok() const noexcept;
};

class PeerCredentialReader {
public:
    [[nodiscard]] PeerCredentialResult read(int connected_socket) const;
};

class PeerCredentialPolicy {
public:
    explicit PeerCredentialPolicy(
        uid_t allowed_user_id,
        std::optional<gid_t> allowed_group_id = std::nullopt);

    [[nodiscard]] bool allows(const PeerCredentialResult& credentials) const
        noexcept;

private:
    uid_t allowed_user_id_{0};
    std::optional<gid_t> allowed_group_id_;
};

enum class ProtocolSessionStatus {
    completed,
    peer_rejected,
    timed_out,
    invalid_request,
    audit_failed,
    io_error
};

struct ProtocolSessionResult {
    ProtocolSessionStatus status{ProtocolSessionStatus::io_error};
    std::string event_id;
    std::string message;
    std::optional<uid_t> peer_user_id;
    std::optional<gid_t> peer_group_id;

    [[nodiscard]] bool ok() const noexcept;
};

class ControllerProtocolSession {
public:
    using TimestampSource = std::function<std::string()>;

    static constexpr std::size_t maximum_payload_size = 4096U;
    static constexpr std::chrono::milliseconds maximum_io_timeout{60000};

    ControllerProtocolSession(
        PrivilegedPfController& controller,
        const logging::OperationJournal& journal,
        PeerCredentialPolicy peer_policy,
        TimestampSource timestamp_source = {});

    [[nodiscard]] ProtocolSessionResult serve(
        int connected_socket,
        std::chrono::milliseconds io_timeout) const;

private:
    PrivilegedPfController& controller_;
    const logging::OperationJournal& journal_;
    PeerCredentialPolicy peer_policy_;
    TimestampSource timestamp_source_;
    PeerCredentialReader credential_reader_;
};

}  // namespace sasd::gatehold::controller
