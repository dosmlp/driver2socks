#pragma once
#include <windivert.h>
#include <iostream>
#include <thread>
#include <chrono>
#include <string>
#include <functional>
#include <atomic>
#include <winsock2.h>

#include "spsc_queue.h"
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
    void doWrite(NetPacket::Ptr buffer,size_t len);
    void stop();
private:
	HANDLE w_handle_ = INVALID_HANDLE_VALUE;
    std::unique_ptr<void,void(*)(void*)> recv_data_;
    std::unique_ptr<void,void(*)(void*)> inject_data_;
    std::unique_ptr<wchar_t,void(*)(wchar_t*)> app_names_;
    std::thread thread_read_;
    std::thread thread_write_;
	cb_outbound_data cb_out_data_;
    std::atomic_bool is_stop_;
    SPSCQueue<NetPacket::Ptr> queue_inject_;
    //获取IP包的总大小
    bool getPacketLen(uint8_t* packet,uint16_t& packet_len);
    void _runWrite();
    void _runRead();
};


