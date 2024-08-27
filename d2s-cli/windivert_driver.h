#pragma once
#include <windivert.h>
#include <iostream>
#include <thread>
#include <string>
#include <functional>
#include <atomic>
#include <winsock2.h>

#include "ring_buf.hpp"
#include "netpacket_pool.h"

using cb_outbound_data = std::function<void(std::shared_ptr<NetPacket>,size_t)>;

class WindivertDriver : public std::enable_shared_from_this<WindivertDriver>
{

public:
    typedef std::shared_ptr<WindivertDriver> Ptr;
    WindivertDriver(const WindivertDriver &) = delete;
    WindivertDriver(const std::vector<std::string> &app_names);
    ~WindivertDriver();
    void run(cb_outbound_data out);
    //向驱动注入入站数据包
    void doWrite(std::shared_ptr<NetPacket> buffer,size_t len);
    void doWrite(uint8_t* buf, size_t len);
private:
    //获取IP包的总大小
    bool getPacketLen(uint8_t* packet,uint16_t& packet_len);
	HANDLE w_handle_ = INVALID_HANDLE_VALUE;
    std::unique_ptr<void,void(*)(void*)> recv_data_;
	std::thread thread_;
	std::thread thread_2_;
	cb_outbound_data cb_out_data_;
    std::atomic_bool is_stop_;
	lockfree::spsc::RingBuf<uint8_t, 4096 * 100> buf_inject_;
    wchar_t* app_names_ = nullptr;

    void _runInject();

    void _run();
};


