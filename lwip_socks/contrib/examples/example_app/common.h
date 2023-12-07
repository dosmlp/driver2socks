#pragma once

#include "lwip/netif.h"

#include <iostream>
#include <unordered_map>
#include <memory>
#include <mutex>
#include <Windows.h>
#include "socks_client.hpp"

struct ConnectCtx
{
    struct netif net_if;
    UINT32 IfIdx;                       /* Packet's interface index. */
    UINT32 SubIfIdx;                    /* Packet's sub-interface index. */
    
};
struct InitTcpArg {
    struct netif* net_if;
    uint32_t ip[4];
    uint16_t port;
    bool is_ipv4;
    void* msg;
    InitTcpArg()
    {
        net_if = nullptr;
        memset(ip, 0, 16);
        port = 0;
        is_ipv4 = true;
        msg = nullptr;
    }
};

static uint32_t copy2Pbuf(pbuf* p, void* data, uint32_t len)
{
    uint8_t* d = (uint8_t*)data;
    struct pbuf* q;
    if (len <= p->len) {
        memcpy(p->payload, data, len);
        return len;
    }
    int32_t remaining_len = len;
    for (q = p; q != NULL && remaining_len > 0; q = q->next) {
        int32_t copy_len = std::min<int32_t>(q->len, remaining_len);
        memcpy(q->payload, d, copy_len);
        d += copy_len;
        q->len = copy_len;
        q->tot_len = remaining_len;
        remaining_len -= copy_len;
    }
    return len - remaining_len;
}

static uint32_t pbuf2Data(pbuf* p,void* data, const uint32_t len)
{
    if (len < p->tot_len) {
        return 0;
    }
    uint32_t total = 0;
    uint8_t* u = (uint8_t*)data;

    for (pbuf* b = p; b != nullptr; b = b->next) {
        memcpy(u, b->payload, b->len);
        u += b->len;
        total += b->len;
    }
    return total;
}