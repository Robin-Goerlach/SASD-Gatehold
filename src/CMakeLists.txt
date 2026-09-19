add_library(
    gatehold_core
    core/controller/controller_service.cpp
    core/controller/local_listener.cpp
    core/controller/local_protocol.cpp
    core/controller/privileged_pf_controller.cpp
    core/daemon/config.cpp
    core/daemon/filesystem_preflight.cpp
    core/daemon/read_only_activation_policy.cpp
    core/firewall/model.cpp
    core/firewall/activation_transaction_store.cpp
    core/firewall/candidate_store.cpp
    core/firewall/health_probes.cpp
    core/firewall/native_validator.cpp
    core/firewall/pfctl_loader.cpp
    core/firewall/pf_renderer.cpp
    core/firewall/activation_service.cpp
    core/firewall/preparation_service.cpp
    core/firewall/revision_store.cpp
    core/logging/json_event_formatter.cpp
    core/logging/operation_journal.cpp
    core/system/posix_process_runner.cpp
    core/system/posix_signal_stop_bridge.cpp
    core/version.cpp
)

target_include_directories(
    gatehold_core
    PUBLIC
        ${PROJECT_SOURCE_DIR}/include
)

target_link_libraries(
    gatehold_core
    PUBLIC
        gatehold_project_options
        gatehold_project_warnings
    PRIVATE
        Threads::Threads
)

add_executable(
    gateholdctl
    cli/main.cpp
)

target_link_libraries(
    gateholdctl
    PRIVATE
        gatehold_core
)

add_executable(
    gateholdd
    daemon/main.cpp
)

target_link_libraries(
    gateholdd
    PRIVATE
        gatehold_core
)

install(TARGETS gateholdctl gateholdd RUNTIME DESTINATION bin)
