add_executable(
    gatehold_version_test
    version_test.cpp
)

target_link_libraries(
    gatehold_version_test
    PRIVATE
        gatehold_core
)

add_test(NAME gatehold.version COMMAND gatehold_version_test)

add_executable(
    gatehold_firewall_model_test
    firewall_model_test.cpp
)

target_link_libraries(
    gatehold_firewall_model_test
    PRIVATE
        gatehold_core
)

add_test(NAME gatehold.firewall.model COMMAND gatehold_firewall_model_test)

add_executable(
    gatehold_pf_renderer_test
    pf_renderer_test.cpp
)

target_link_libraries(
    gatehold_pf_renderer_test
    PRIVATE
        gatehold_core
)

add_test(NAME gatehold.firewall.pf_renderer COMMAND gatehold_pf_renderer_test)

add_executable(
    gatehold_json_event_formatter_test
    json_event_formatter_test.cpp
)

target_link_libraries(
    gatehold_json_event_formatter_test
    PRIVATE
        gatehold_core
)

add_test(NAME gatehold.logging.json_event COMMAND gatehold_json_event_formatter_test)

add_test(NAME gatehold.cli.version COMMAND gateholdctl --version)
add_test(NAME gatehold.cli.render_example COMMAND gateholdctl render-example)
add_test(NAME gatehold.cli.event_example COMMAND gateholdctl event-example)

add_executable(
    gatehold_fake_pfctl
    helpers/fake_pfctl.cpp
)

target_link_libraries(
    gatehold_fake_pfctl
    PRIVATE
        gatehold_project_options
        gatehold_project_warnings
        Threads::Threads
)

add_executable(
    gatehold_native_validation_test
    native_validation_test.cpp
)

target_link_libraries(
    gatehold_native_validation_test
    PRIVATE
        gatehold_core
)

add_test(
    NAME gatehold.firewall.native_validation
    COMMAND gatehold_native_validation_test $<TARGET_FILE:gatehold_fake_pfctl>
)

add_executable(
    gatehold_operation_journal_test
    operation_journal_test.cpp
)

target_link_libraries(
    gatehold_operation_journal_test
    PRIVATE
        gatehold_core
        Threads::Threads
)

add_test(NAME gatehold.logging.operation_journal COMMAND gatehold_operation_journal_test)

add_executable(
    gatehold_preparation_service_test
    preparation_service_test.cpp
)

target_link_libraries(
    gatehold_preparation_service_test
    PRIVATE
        gatehold_core
)

add_test(
    NAME gatehold.firewall.preparation_service
    COMMAND gatehold_preparation_service_test $<TARGET_FILE:gatehold_fake_pfctl>
)

add_executable(
    gatehold_revision_store_test
    revision_store_test.cpp
)

target_link_libraries(
    gatehold_revision_store_test
    PRIVATE
        gatehold_core
        Threads::Threads
)

add_test(NAME gatehold.firewall.revision_store COMMAND gatehold_revision_store_test)

add_executable(
    gatehold_pfctl_loader_test
    pfctl_loader_test.cpp
)

target_link_libraries(
    gatehold_pfctl_loader_test
    PRIVATE
        gatehold_core
)

add_test(
    NAME gatehold.firewall.pfctl_loader
    COMMAND gatehold_pfctl_loader_test $<TARGET_FILE:gatehold_fake_pfctl>
)

add_executable(
    gatehold_activation_service_test
    activation_service_test.cpp
)

target_link_libraries(
    gatehold_activation_service_test
    PRIVATE
        gatehold_core
)

add_test(
    NAME gatehold.firewall.activation_service
    COMMAND gatehold_activation_service_test $<TARGET_FILE:gatehold_fake_pfctl>
)

add_executable(
    gatehold_activation_transaction_store_test
    activation_transaction_store_test.cpp
)

target_link_libraries(
    gatehold_activation_transaction_store_test
    PRIVATE
        gatehold_core
        Threads::Threads
)

add_test(
    NAME gatehold.firewall.activation_transaction_store
    COMMAND gatehold_activation_transaction_store_test
)

add_executable(
    gatehold_privileged_pf_controller_test
    privileged_pf_controller_test.cpp
)

target_link_libraries(
    gatehold_privileged_pf_controller_test
    PRIVATE
        gatehold_core
        Threads::Threads
)

add_test(
    NAME gatehold.controller.privileged_pf
    COMMAND gatehold_privileged_pf_controller_test $<TARGET_FILE:gatehold_fake_pfctl>
)

add_executable(
    gatehold_health_probes_test
    health_probes_test.cpp
)

target_link_libraries(
    gatehold_health_probes_test
    PRIVATE
        gatehold_core
        Threads::Threads
)

add_test(
    NAME gatehold.firewall.health_probes
    COMMAND gatehold_health_probes_test $<TARGET_FILE:gatehold_fake_pfctl>
)

add_executable(
    gatehold_local_protocol_test
    local_protocol_test.cpp
)

target_link_libraries(
    gatehold_local_protocol_test
    PRIVATE
        gatehold_core
        Threads::Threads
)

add_test(
    NAME gatehold.controller.local_protocol
    COMMAND gatehold_local_protocol_test $<TARGET_FILE:gatehold_fake_pfctl>
)

add_executable(
    gatehold_local_listener_test
    local_listener_test.cpp
)

target_link_libraries(
    gatehold_local_listener_test
    PRIVATE
        gatehold_core
        Threads::Threads
)

add_test(
    NAME gatehold.controller.local_listener
    COMMAND gatehold_local_listener_test
)

add_executable(
    gatehold_controller_service_test
    controller_service_test.cpp
)

target_link_libraries(
    gatehold_controller_service_test
    PRIVATE
        gatehold_core
        Threads::Threads
)

add_test(
    NAME gatehold.controller.service
    COMMAND gatehold_controller_service_test
)

add_executable(
    gatehold_posix_signal_stop_bridge_test
    posix_signal_stop_bridge_test.cpp
)

target_link_libraries(
    gatehold_posix_signal_stop_bridge_test
    PRIVATE
        gatehold_core
        Threads::Threads
)

add_test(
    NAME gatehold.system.posix_signal_stop_bridge
    COMMAND gatehold_posix_signal_stop_bridge_test
)

add_executable(
    gatehold_daemon_config_test
    daemon_config_test.cpp
)

target_link_libraries(
    gatehold_daemon_config_test
    PRIVATE
        gatehold_core
)

add_test(NAME gatehold.daemon.config COMMAND gatehold_daemon_config_test)
add_test(NAME gatehold.daemon.help COMMAND gateholdd --help)
add_test(NAME gatehold.daemon.version COMMAND gateholdd --version)

add_executable(
    gatehold_daemon_filesystem_preflight_test
    daemon_filesystem_preflight_test.cpp
)

target_link_libraries(
    gatehold_daemon_filesystem_preflight_test
    PRIVATE
        gatehold_core
)

add_test(
    NAME gatehold.daemon.filesystem_preflight
    COMMAND gatehold_daemon_filesystem_preflight_test
)

add_executable(
    gatehold_daemon_process_lock_test
    daemon_process_lock_test.cpp
)

target_link_libraries(
    gatehold_daemon_process_lock_test
    PRIVATE
        gatehold_core
)

add_test(
    NAME gatehold.daemon.process_lock
    COMMAND gatehold_daemon_process_lock_test
)

add_executable(
    gatehold_daemon_process_sandbox_test
    daemon_process_sandbox_test.cpp
)

target_link_libraries(
    gatehold_daemon_process_sandbox_test
    PRIVATE
        gatehold_core
)

add_test(
    NAME gatehold.daemon.process_sandbox
    COMMAND gatehold_daemon_process_sandbox_test
)

add_executable(
    gatehold_read_only_activation_policy_test
    read_only_activation_policy_test.cpp
)

target_link_libraries(
    gatehold_read_only_activation_policy_test
    PRIVATE
        gatehold_core
)

add_test(
    NAME gatehold.daemon.read_only_activation_policy
    COMMAND gatehold_read_only_activation_policy_test
)

add_executable(
    gatehold_daemon_process_test
    daemon_process_test.cpp
)

target_link_libraries(
    gatehold_daemon_process_test
    PRIVATE
        gatehold_core
        Threads::Threads
)

add_test(
    NAME gatehold.daemon.process
    COMMAND gatehold_daemon_process_test $<TARGET_FILE:gateholdd>
)

if(GATEHOLD_ENABLE_OPENBSD_PF_TESTS)
    if(NOT CMAKE_SYSTEM_NAME STREQUAL "OpenBSD")
        message(FATAL_ERROR "Real PF tests can only be enabled on OpenBSD")
    endif()

    add_executable(
        gatehold_openbsd_pfctl_smoke_test
        openbsd_pfctl_smoke_test.cpp
    )

    target_link_libraries(
        gatehold_openbsd_pfctl_smoke_test
        PRIVATE
            gatehold_core
    )

    add_test(
        NAME gatehold.openbsd.pfctl_smoke
        COMMAND gatehold_openbsd_pfctl_smoke_test
    )
    set_tests_properties(
        gatehold.openbsd.pfctl_smoke
        PROPERTIES LABELS "openbsd;integration"
    )
endif()
