cmake_minimum_required(VERSION 3.28)
# cmake_policy(SET CMP0119 NEW)
set (CMAKE_CONFIGURATION_TYPES "Debug;Release")

project(lwipcore)

set(CMAKE_CXX_STANDARD 20)

set(LWIP_DIR ${CMAKE_CURRENT_SOURCE_DIR})
set (LWIP_INCLUDE_DIRS
    "${LWIP_DIR}/src/include"
    "d2s-cli/lwip"
)
include(src/Filelists.cmake)

add_library(lwipcore STATIC ${lwipcore_SRCS} ${lwipcore4_SRCS} ${lwipcore6_SRCS})
# set_target_properties(lwipcore PROPERTIES LANGUAGE CXX LINKER_LANGUAGE CXX)
target_compile_options(lwipcore PRIVATE /utf-8 /TP)
target_include_directories(lwipcore PRIVATE ${LWIP_INCLUDE_DIRS})

# set (LWIP_DEFINITIONS LWIP_DEBUG=1)
# target_compile_definitions(lwipcore PRIVATE ${LWIP_DEFINITIONS})

add_subdirectory(d2s-cli)

