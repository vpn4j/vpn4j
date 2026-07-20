cmake_minimum_required(VERSION 3.25)
project(vpn4j_native LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

option(VPN4J_BUILD_TESTS "Build and register C++ unit tests (GoogleTest)" ON)

if(NOT DEFINED ENV{JAVA_HOME})
    message(FATAL_ERROR "JAVA_HOME must be set to build vpn4j-native")
else()
    set(JAVA_HOME $ENV{JAVA_HOME})
endif()

set(JNI_INCLUDE_DIRS
    ${JAVA_HOME}/include
    ${JAVA_HOME}/include/linux)

set(VPN4J_CORE_SRC
    src/status.cpp
    src/tun_device.cpp
)

add_library(vpn4j_native SHARED
    ${VPN4J_CORE_SRC}
    src/vpn4j_jni.cpp
)

target_include_directories(vpn4j_native PRIVATE
    ${JNI_INCLUDE_DIRS}
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(vpn4j_native PRIVATE -O2 -fPIC -Wall -Wextra -Wpedantic)
endif()

set_target_properties(vpn4j_native PROPERTIES
    OUTPUT_NAME "vpn4j_native"
    LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib"
)

install(TARGETS vpn4j_native LIBRARY DESTINATION lib)

if(VPN4J_BUILD_TESTS)
    include(FetchContent)
    FetchContent_Declare(
        googletest
        URL https://github.com/google/googletest/archive/refs/tags/v1.15.2.zip
        DOWNLOAD_EXTRACT_TIMESTAMP TRUE
    )
    set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
    FetchContent_MakeAvailable(googletest)

    enable_testing()

    add_executable(vpn4j_native_tests
        tests/test_status.cpp
        ${VPN4J_CORE_SRC}
    )

    target_include_directories(vpn4j_native_tests PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
    )

    target_link_libraries(vpn4j_native_tests PRIVATE GTest::gtest_main)

    if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
        target_compile_options(vpn4j_native_tests PRIVATE -Wall -Wextra -Wpedantic)
    endif()

    include(GoogleTest)
    gtest_discover_tests(vpn4j_native_tests)
endif()
