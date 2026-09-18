find_package(Threads REQUIRED)

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
