cmake_minimum_required(VERSION 3.28)

project(d2s-cli LANGUAGES CXX)

#QTDIR=X:/Qt/6.7.2/msvc2019_64
list(APPEND CMAKE_PREFIX_PATH $ENV{QTDIR})
# set(CMAKE_CXX_STANDARD 20)


add_subdirectory(lwip_core)
add_subdirectory(base)

add_executable(d2s-cli 
    main.cpp
    ring_buf.hpp
    ring_buf_impl.hpp
    netpacket_pool.h
    spsc_queue.h
    io.hpp
    socks_client.hpp
    lwipstack.h
    iocontext.h
    iocontext.cpp
    driver2socks.h
    driver2socks.cpp
    asio_coro_util.hpp
    lwip/sys_arch.h
    lwip/sys_arch.cpp
    app_config.h
    windivert_driver.h
    windivert_driver.cpp
    mpmc_queue.h
    adapters_info.h
    vcpkg.json
)

find_package(Qt6 REQUIRED COMPONENTS Core)
find_package(folly CONFIG REQUIRED)
find_package(asio CONFIG REQUIRED)
find_package(nlohmann_json CONFIG REQUIRED)
find_package(async_simple CONFIG REQUIRED)


target_include_directories(d2s-cli PRIVATE 
    lwip_core/src/include
    ../driver/common
    lwip
    base
)

if(CMAKE_BUILD_TYPE AND (CMAKE_BUILD_TYPE STREQUAL "Debug"))
    target_link_libraries(${CMAKE_PROJECT_NAME} PRIVATE
        "../../../driver/x64/Debug/WinDivertLiteDll"
    )
elseif(CMAKE_BUILD_TYPE AND (CMAKE_BUILD_TYPE STREQUAL "Release"))
    target_link_libraries(${CMAKE_PROJECT_NAME} PRIVATE
        "../../../driver/x64/Release/WinDivertLiteDll"
    )
endif()
target_link_libraries(d2s-cli PRIVATE
    Qt6::Core
    Folly::folly
    async_simple::async_simple_header_only
    base
    lwipcore Winmm Iphlpapi)
target_compile_options(d2s-cli PRIVATE /utf-8)
target_compile_definitions(d2s-cli PRIVATE WIN32_LEAN_AND_MEAN)
