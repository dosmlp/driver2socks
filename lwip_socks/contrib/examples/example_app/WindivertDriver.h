#pragma once
#include <windivert.h>
#include <iostream>
#include <thread>
#include <functional>
#include <atomic>
#include <winsock2.h>

#include "lwip/pbuf.h"
#include  "lwip/ip.h"
#include "ring_buf.hpp"

using cb_outbound_data = std::function<void(std::shared_ptr<void>,size_t)>;

class WindivertDriver : public std::enable_shared_from_this<WindivertDriver>
{
public:
	WindivertDriver():is_stop_(true)
	{
		recv_data_ = _aligned_malloc(WINDIVERT_MTU_MAX, 16);
	}
	~WindivertDriver()
	{
		is_stop_ = true;
		WinDivertClose(w_handle_);
		if (recv_data_) {
			_aligned_free(recv_data_);
			recv_data_ = nullptr;
		}
		thread_.join();
		thread_2_.join();
	}
	void run(cb_outbound_data out)
	{
		is_stop_ = false;
		cb_out_data_ = out;
		thread_ = std::thread([this]() {this->_run(); });
		//thread_2_ = std::thread([this]() {this->_runInject(); });
		//this->_run();
	}
	void doWrite(std::unique_ptr<uint8_t[]>&& buffer,size_t len)
	{
#if 0
		//std::cout << "inject_buf write size:" << len << "\n";
		bool ret = buf_inject_.Write(buffer.get(), len);
		//Sleep(10);
		if (!ret) {
			std::cout << "buf_inject write fail\n";
		}
#else
		WINDIVERT_ADDRESS addr;
		addr.Network.IfIdx = 6;
		addr.Network.SubIfIdx = 0;
		addr.Outbound = 0;
		addr.TCPChecksum = 1;
		addr.UDPChecksum = 1;
		addr.IPChecksum = 1;
		addr.Impostor = 1;
		addr.IPv6 = 0;

		if (IP_HDR_GET_VERSION(buffer.get()) == 6) {
			addr.IPv6 = 1;
		}
		WinDivertSend(w_handle_, buffer.get(), len, NULL, &addr);
#endif

	}
	void doWrite(uint8_t* buf, size_t len)
	{
		//std::cout << "inject_buf write size:" << len<< " write tag:"<<*((uint16_t*)buf)<<"\n";
		bool ret = buf_inject_.Write(buf, len);
		if (!ret) {
			std::cout << "buf_inject write fail2\n";
		}
	}
private:
	HANDLE w_handle_ = INVALID_HANDLE_VALUE;
	void* recv_data_ = nullptr;
	std::thread thread_;
	std::thread thread_2_;
	cb_outbound_data cb_out_data_;
	std::atomic_bool is_stop_;
	std::atomic_uint32_t recv_total_ = 0;
	std::atomic_uint32_t inject_total_ = 0;
	lockfree::spsc::RingBuf<uint8_t, 4096 * 100> buf_inject_;
#undef max
	void _runInject()
	{
		WINDIVERT_ADDRESS addr;
		addr.Network.IfIdx = 6;
		addr.Network.SubIfIdx = 0;
		addr.Outbound = 0;
		addr.TCPChecksum = 1;
		addr.UDPChecksum = 1;
		addr.IPChecksum = 1;
		addr.Impostor = 1;
		addr.IPv6 = 0;

		uint8_t* inject_data = new uint8_t[65536];
		uint16_t inject_size = 0;

		for (;;) {
			auto s = buf_inject_.GetAvailable();
			if (s == 0) {
				Sleep(1);
				continue;
			}
			if (inject_size > 0) {
				bool ret = buf_inject_.Read(inject_data, inject_size);
				if (!ret) {
					std::cout << "windivert read inject_buf fail "<<inject_size<<"Available size:"<< s <<"\n";
					Sleep(1);
					continue;
				}
				
			} else {
				bool ret = buf_inject_.Read((uint8_t*)&inject_size, sizeof(uint16_t));
				if (!ret) {
					inject_size = 0;
					std::cout << "windivert read inject_size fail\n";
				}
				continue;
			}

			if (IP_HDR_GET_VERSION(inject_data) == 6) {
				addr.IPv6 = 1;
			}
			WinDivertSend(w_handle_, inject_data, inject_size, NULL, &addr);
			inject_size = 0;
		}

		
	}

	void _run()
	{
		static uint32_t totla = 0;
		
		w_handle_ = WinDivertOpen("outbound and ip.DstAddr == 111.111.111.111", WINDIVERT_LAYER_NETWORK, 776, 0);
		if (w_handle_ == INVALID_HANDLE_VALUE) {
			std::cerr << "INVALID_HANDLE_VALUE" << "\n";
			return;
		}
		WinDivertSetParam(w_handle_, WINDIVERT_PARAM_QUEUE_TIME, WINDIVERT_PARAM_QUEUE_TIME_MAX);
		WinDivertSetParam(w_handle_, WINDIVERT_PARAM_QUEUE_LENGTH, WINDIVERT_PARAM_QUEUE_LENGTH_MAX);
		WinDivertSetParam(w_handle_, WINDIVERT_PARAM_QUEUE_SIZE, WINDIVERT_PARAM_QUEUE_SIZE_MAX);

		WINDIVERT_ADDRESS windivert_addr;
		uint32_t recv_size = 0;
		for (;;) {
			memset(&windivert_addr, 0, sizeof(WINDIVERT_ADDRESS));
			if (!WinDivertRecv(w_handle_, recv_data_, WINDIVERT_MTU_MAX, &recv_size, &windivert_addr)) {
				std::cerr << "failed to read packet " << GetLastError() << "\n";
				break;
			}
			if (is_stop_) return;

			if (windivert_addr.Event != WINDIVERT_LAYER_NETWORK) {
				continue;
			}
			if (windivert_addr.Network.Protocol == WINDIVERT_IP_PROTOCOL_UDP) {
				continue;
			}
			if (windivert_addr.Network.IfIdx != 6) {
				continue;
			}
			if (windivert_addr.IPv6) {
				std::cout << "ipv6 ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n";
			}

			WinDivertHelperCalcChecksums(recv_data_, recv_size, &windivert_addr, 0);

			//pbuf* buf = pbuf_alloc(PBUF_RAW, recv_size, PBUF_POOL);
			//if (buf == NULL) {
			//	std::cerr << "pbuf_alloc fail\n";
			//	continue;
			//}

			//pbuf_take(buf, recv_data_, recv_size);
			std::shared_ptr<void> buf(malloc(recv_size), [](void* p) {free(p); });
			memcpy(buf.get(), recv_data_, recv_size);
			if (cb_out_data_) cb_out_data_(buf,recv_size);
		}
		
	}
};