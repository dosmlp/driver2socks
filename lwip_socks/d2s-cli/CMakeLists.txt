cmake_minimum_required(VERSION 3.28)

project(d2s-cli LANGUAGES CXX)
set(CMAKE_CXX_STANDARD 20)

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
)


target_compile_definitions(d2s-cli PRIVATE WIN32_LEAN_AND_MEAN)

target_include_directories(d2s-cli PRIVATE 
    ${LWIP_INCLUDE_DIRS} 
    ../../driver/common 
    asio/include 
    lwip
    include
)

# if(CMAKE_BUILD_TYPE AND (CMAKE_BUILD_TYPE STREQUAL "Debug"))
    # target_link_directories(${CMAKE_PROJECT_NAME} PRIVATE
        # ../../driver/x64/Debug
    # )
# elseif(CMAKE_BUILD_TYPE AND (CMAKE_BUILD_TYPE STREQUAL "Release"))
    # target_link_directories(${CMAKE_PROJECT_NAME} PRIVATE
        # ../../driver/x64/Release
    # )
# endif()
target_link_libraries(d2s-cli PRIVATE lwipcore)
target_link_libraries(d2s-cli PRIVATE "..\\..\\..\\driver\\x64\\Debug\\WinDivertLiteDll" Winmm)
