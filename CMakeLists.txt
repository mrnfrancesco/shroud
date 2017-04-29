cmake_minimum_required(VERSION 3.7)
project(shroud)

set(CMAKE_C_STANDARD 99)

set(SOURCE_FILES shroud.c)
add_executable(shroud ${SOURCE_FILES})

target_link_libraries(shroud net pcap)
