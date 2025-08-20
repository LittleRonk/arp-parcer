cmake_minimum_required(VERSION 3.30)

project(arp_parser, LANGUAGES C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

if (NOT CMAKE_C_COMPILER)
    message(FATAL_ERROR "C compiler not found")
endif()

add_library(parser
    STATIC
    ${PROJECT_SOURCE_DIR}/src/arp_parser.c)

target_include_directories(parser
    PUBLIC
    ${PROJECT_SOURCE_DIR}/include)

add_subdirectory(${PROJECT_SOURCE_DIR}/tests)
add_subdirectory(${PROJECT_SOURCE_DIR}/examples)
