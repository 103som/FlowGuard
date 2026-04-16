cmake_minimum_required(VERSION 3.16)
project(pcap_flow_parser LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(PcapPlusPlus CONFIG REQUIRED)

add_executable(pcap_flow_parser
        src/main.cpp
        src/FlowParser.cpp
        src/JA4TlsParser.cpp
        include/TcpStreamReassembler.h
        src/TcpStreamReassembler.cpp
)

target_include_directories(pcap_flow_parser PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_link_libraries(pcap_flow_parser PRIVATE
        PcapPlusPlus::Pcap++
)