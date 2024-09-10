#pragma once
#include <regex>
#include <stdint.h>
#include <new>
#include "spsc_queue.h"
#include "mpmc_queue.h"

static const uint16_t NETPACKET_DATA_SIZE = 2048;

struct  NetPacket
{
	typedef std::shared_ptr<NetPacket> Ptr;
	uint16_t capacity_size;
	uint16_t data_len;
	uint8_t* data;
	NetPacket* next = nullptr;
	/*
	NetPacket(NetPacket&& p) noexcept
	{
		swap(std::move(p));
	}
	*/
	NetPacket() = delete;
	NetPacket(NetPacket&) = delete;
	
	NetPacket(const uint16_t s)
	{
		data_len = 0;
		capacity_size = s;
        data = (uint8_t*)_aligned_malloc(s,16);
	}
	~NetPacket()
	{
		data_len = 0;
		capacity_size = 0;
        _aligned_free(data);
		data = nullptr;
	}
	/*
	void swap(NetPacket&& p) noexcept
	{
		std::swap(p.size, this->size);
		std::swap(p.data, this->data);
	}
	NetPacket& operator=(const NetPacket&) = delete;
	NetPacket& operator=(NetPacket&& p) noexcept
	{
		swap(std::move(p));
		return *this;
	}
	*/
};

class LockFreeStack
{
public:
	void push(NetPacket* packet)
	{
		packet->next = head_.load();
		while (!head_.compare_exchange_weak(packet->next, packet)) {
		}
	}
	NetPacket* pop()
	{
		NetPacket* old_head = head_.load();
		while (old_head && !head_.compare_exchange_weak(old_head, old_head->next)) {
		}
		return old_head;
	}
private:
	std::atomic<NetPacket*> head_;
};

#define _NetPacketPool NetPacketPool::Instance()

class NetPacketPool
{
public:
	static NetPacketPool* Instance()
	{
		static NetPacketPool pool;
		return &pool;
	}
    NetPacket* getPacket(uint32_t size)
	{
        NetPacket* p = nullptr;
        queue_.pop(p);
		while (p == nullptr) {
            queue_.pop(p);
			std::cerr << "NetPacketPool is empty!\n";
		}
        p->data_len = size;
		return p;
    }
    NetPacket::Ptr getSharedPacket(uint32_t size)
    {
        NetPacket* p = nullptr;
        queue_.pop(p);
        while (p == nullptr) {
            queue_.pop(p);
            std::cerr << "NetPacketPool is empty!\n";
        }
        p->data_len = size;
        return std::shared_ptr<NetPacket>(p,&NetPacketPool::deletePacket);
    }
    static void deletePacket(NetPacket* p)
    {
        _NetPacketPool->freePacket(p);
    }
	void freePacket(NetPacket* p)
	{
        // stack_.push(p);
        queue_.push(p);
	}
	~NetPacketPool()
    {
        while (!queue_.empty()) {
            NetPacket* p = nullptr;
            queue_.pop(p);
            delete p;
        }

	}
private:
    NetPacketPool():queue_(256)
	{
        for (uint32_t i = 0;i < 256;++i) {
            auto p = new NetPacket(NETPACKET_DATA_SIZE);
            // stack_.push(p);

            queue_.push(p);
        }

	}
    // LockFreeStack stack_;

    rigtorp::mpmc::Queue<NetPacket*> queue_;
};
