cmake_minimum_required(VERSION 3.10)

set (CMAKE_CONFIGURATION_TYPES "Debug;Release")

project(lwIP)

# Example lwIP application
set(LWIP_DIR ${CMAKE_CURRENT_SOURCE_DIR})

set (LWIP_DEFINITIONS LWIP_DEBUG=1)

# Generate docs before creating source package
include(src/Filelists.cmake)

