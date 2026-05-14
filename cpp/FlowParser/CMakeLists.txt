cmake_minimum_required(VERSION 3.16)
project(pcap_flow_parser LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(PcapPlusPlus CONFIG REQUIRED)

add_library(flow_parser_core STATIC
        src/FlowParser.cpp
        src/JA4TlsParser.cpp
        src/TcpStreamReassembler.cpp
)

target_include_directories(flow_parser_core PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_link_libraries(flow_parser_core PUBLIC
        PcapPlusPlus::Pcap++
)

add_executable(pcap_flow_parser
        src/main.cpp
)

target_link_libraries(pcap_flow_parser PRIVATE
        flow_parser_core
)

option(FLOWGUARD_BUILD_CPP_TESTS "Build FlowGuard C++ parser unit tests" OFF)

if(FLOWGUARD_BUILD_CPP_TESTS)
    include(FetchContent)

    FetchContent_Declare(
            googletest
            URL https://github.com/google/googletest/archive/refs/tags/v1.14.0.zip
    )

    # For Windows compatibility; harmless on Linux.
    set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)

    FetchContent_MakeAvailable(googletest)

    enable_testing()

    add_executable(pcap_flow_parser_unit_tests
            tests/test_tcp_stream_reassembler.cpp
            tests/test_ja4_tls_parser.cpp
    )

    target_link_libraries(pcap_flow_parser_unit_tests PRIVATE
            flow_parser_core
            GTest::gtest_main
    )

    include(GoogleTest)
    gtest_discover_tests(pcap_flow_parser_unit_tests)
endif()
