add_library(
    gatehold_core
    core/firewall/model.cpp
    core/firewall/pf_renderer.cpp
    core/logging/json_event_formatter.cpp
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

install(TARGETS gateholdctl RUNTIME DESTINATION bin)
