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

