cmake_minimum_required(VERSION 3.20)

project(
    SASDGatehold
    VERSION 0.1.0
    DESCRIPTION "OpenBSD-native firewall and secure routing platform"
    LANGUAGES CXX
)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(Threads REQUIRED)

option(GATEHOLD_BUILD_TESTS "Build the Gatehold test suite" ON)
option(GATEHOLD_WARNINGS_AS_ERRORS "Treat compiler warnings as errors" OFF)
option(
    GATEHOLD_ENABLE_OPENBSD_PF_TESTS
    "Enable opt-in tests against the real OpenBSD /sbin/pfctl"
    OFF
)

add_library(gatehold_project_options INTERFACE)
target_compile_features(gatehold_project_options INTERFACE cxx_std_23)

add_library(gatehold_project_warnings INTERFACE)
if(CMAKE_CXX_COMPILER_ID MATCHES "Clang|GNU")
    target_compile_options(
        gatehold_project_warnings
        INTERFACE
            -Wall
            -Wextra
            -Wpedantic
            -Wconversion
            -Wsign-conversion
    )
    if(GATEHOLD_WARNINGS_AS_ERRORS)
        target_compile_options(gatehold_project_warnings INTERFACE -Werror)
    endif()
elseif(MSVC)
    target_compile_options(gatehold_project_warnings INTERFACE /W4 /permissive-)
    if(GATEHOLD_WARNINGS_AS_ERRORS)
        target_compile_options(gatehold_project_warnings INTERFACE /WX)
    endif()
endif()

add_subdirectory(src)

if(GATEHOLD_BUILD_TESTS)
    include(CTest)
    enable_testing()
    add_subdirectory(tests)
endif()
