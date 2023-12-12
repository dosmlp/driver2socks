#pragma once
#include <windivert.h>
#include <iostream>
#include <thread>
#include <functional>
#include <atomic>
#include "lwip/pbuf.h"
#include  "lwip/ip.h"

using cb_outbound_data = std::function<void(pbuf* buf)>;

class WindivertDriver
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
	}
	void run(cb_outbound_data out)
	{
		is_stop_ = false;
		cb_out_data_ = out;
		thread_ = std::thread([this]() {this->_run(); });
	}
	void doWrite(std::unique_ptr<uint8_t[]>&& buffer,size_t len)
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

		if (IP_HDR_GET_VERSION(buffer.get()) == 6) {
			addr.IPv6 = 1;
		}


		//if (p->len < 64) {
		//	uint8_t d[64] = { 0 };
		//	memcpy(d, p->payload, p->len);
		//	WinDivertSend(windiver_handle, d, 64, nullptr, &addr);
		//} else {
			WinDivertSend(w_handle_, buffer.get(), len, nullptr, &addr);
		//}
	}
private:
	HANDLE w_handle_ = INVALID_HANDLE_VALUE;
	void* recv_data_ = nullptr;
	std::thread thread_;
	cb_outbound_data cb_out_data_;
	std::atomic_bool is_stop_;

	void _run()
	{
		w_handle_ = WinDivertOpen("outbound and ip.DstAddr == 111.111.111.111", WINDIVERT_LAYER_NETWORK, 1, 0);
		if (w_handle_ == INVALID_HANDLE_VALUE) {
			std::cerr << "INVALID_HANDLE_VALUE" << std::endl;
			return;
		}

		WINDIVERT_ADDRESS windivert_addr;
		uint32_t recv_size = 0;
		for (;;) {
			memset(&windivert_addr, 0, sizeof(WINDIVERT_ADDRESS));
			if (!WinDivertRecv(w_handle_, recv_data_, WINDIVERT_MTU_MAX, &recv_size, &windivert_addr)) {
				std::cerr << "failed to read packet " << GetLastError() << std::endl;
				break;
			}
			if (is_stop_) return;

			if (windivert_addr.Event != WINDIVERT_LAYER_NETWORK) {
				continue;
			}

			WinDivertHelperCalcChecksums(recv_data_, recv_size, &windivert_addr, 0);
			pbuf* buf = pbuf_alloc(PBUF_RAW, recv_size, PBUF_POOL);
			if (buf == NULL) {
				std::cerr << "pbuf_alloc fail" << std::endl;
				continue;
			}
			pbuf_take(buf, recv_data_, recv_size);
			if (cb_out_data_) cb_out_data_(buf);
		}
	}
};