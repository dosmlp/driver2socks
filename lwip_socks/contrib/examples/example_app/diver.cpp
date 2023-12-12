extern "C" {
#include <windivert.h>
}
#include <iostream>
#include <map>
#include <thread>

#include "lwip/opt.h"

#include "lwip/sys.h"
#include "lwip/timeouts.h"
#include "lwip/debug.h"
#include "lwip/stats.h"
#include "lwip/init.h"
#include "lwip/tcpip.h"
#include "lwip/netif.h"
#include "lwip/api.h"
#include "lwip/ip_addr.h"

#include "lwip/tcp.h"
#include "lwip/priv/tcpip_priv.h"
#include "lwip/udp.h"
#include "lwip/dns.h"
#include "lwip/dhcp.h"
#include "lwip/autoip.h"
#include "lwip/priv/tcpip_priv.h"
#include <asio.hpp>
#include "async_simple/coro/Lazy.h"
/* lwIP netif includes */
#include "lwip/etharp.h"
#include "netif/ethernet.h"
#include "lwip/ethip6.h"
#include "tcpecho_raw.h"
#include "crc64.h"
#include "socks_client.hpp"
#include "iocontext.h"
#include "common.h"


HANDLE windiver_handle = NULL;



static void
status_callback(struct netif* state_netif)
{
    if (netif_is_up(state_netif)) {
#if LWIP_IPV4
        printf("status_callback==UP, local interface IP is %s\n", ip4addr_ntoa(netif_ip4_addr(state_netif)));
#else
        printf("status_callback==UP\n");
#endif
    }
    else {
        printf("status_callback==DOWN\n");
    }
}

static void
link_callback(struct netif* state_netif)
{
    if (netif_is_link_up(state_netif)) {
        printf("link_callback==UP\n");
    }
    else {
        printf("link_callback==DOWN\n");
    }
}
err_t netif_ip_outputv4(struct netif* netif, struct pbuf* p, const ip4_addr_t* ipaddr);
err_t netif_ip_outputv6(struct netif* netif, struct pbuf* p, const ip6_addr_t* ipaddr);
void netifInit(struct netif* net_if, VOID* dest_ip, uint16_t port, bool is_ipv4);

void netifIp4Init(struct netif* net_if, UINT32 ip)
{
    net_if->ip_addr.u_addr.ip4.addr = ip;
    net_if->gw.u_addr.ip4.addr = ip;
    IP4_ADDR(ip_2_ip4(&(net_if->netmask)), 255, 255, 255, 0);

    net_if->name[0] = 'q';
    net_if->name[1] = 'w';
    net_if->linkoutput = NULL;
#if LWIP_IPV4
    net_if->output = netif_ip_outputv4;
#endif /* LWIP_IPV4 */
#if LWIP_IPV6
    net_if->output_ip6 = ethip6_output;
#endif /* LWIP_IPV6 */
    net_if->mtu = 1500;
    net_if->flags |= NETIF_FLAG_ETHERNET;
#if LWIP_IPV6 && LWIP_IPV6_MLD
    net_if->flags |= NETIF_FLAG_MLD6;
#endif /* LWIP_IPV6 && LWIP_IPV6_MLD */
    net_if->hwaddr_len = ETH_HWADDR_LEN;
}

std::map<uint64_t, ConnectCtx*> map_connect;
ConnectCtx* getConnectCtx(PWINDIVERT_ADDRESS paddr)
{
    WINDIVERT_ADDRESS addr;
    memcpy(&addr, paddr, sizeof(WINDIVERT_ADDRESS));
    if (addr.Layer == WINDIVERT_LAYER_NETWORK) {
        uint32_t len = offsetof(WINDIVERT_DATA_NETWORK, Protocol) - offsetof(WINDIVERT_DATA_NETWORK, LocalAddr) + 1;
        uint64_t crc = crc64((const char*)(addr.Network.LocalAddr), len);
        
        ConnectCtx* ctx = map_connect[crc];
        if (ctx) {
            ctx->IfIdx = addr.Network.IfIdx;
            ctx->SubIfIdx = addr.Network.SubIfIdx;
        }
        return ctx;
    } else if (addr.Event == WINDIVERT_EVENT_SOCKET_CONNECT) {
        if (addr.IPv6) {
            WinDivertHelperHtonIpv6Address(addr.Socket.LocalAddr, addr.Socket.LocalAddr);
            WinDivertHelperHtonIpv6Address(addr.Socket.RemoteAddr, addr.Socket.RemoteAddr);
        } else {
            addr.Socket.LocalAddr[0] = htonl(addr.Socket.LocalAddr[0]);
            addr.Socket.LocalAddr[1] = 0;
            addr.Socket.RemoteAddr[0] = htonl(addr.Socket.RemoteAddr[0]);
            addr.Socket.RemoteAddr[1] = 0;
        }
        
        addr.Socket.LocalPort = htons(addr.Socket.LocalPort);
        addr.Socket.RemotePort = htons(addr.Socket.RemotePort);
        uint32_t len = offsetof(WINDIVERT_DATA_SOCKET, Protocol) - offsetof(WINDIVERT_DATA_SOCKET, LocalAddr) + 1;
        uint64_t crc = crc64((const char*)(addr.Socket.LocalAddr), len);
        
        ConnectCtx* ctx = map_connect[crc];
        if (ctx) {
            return ctx;
        }
        ctx = new ConnectCtx();
        memset(ctx, 0, sizeof(ConnectCtx));
        netifInit(&ctx->net_if, addr.Socket.RemoteAddr, paddr->Socket.RemotePort, !addr.IPv6);
        ctx->net_if.state = ctx;

        map_connect[crc] = ctx;
        return ctx;
    }

}
err_t netif_ip_outputv4(struct netif* netif, struct pbuf* p, const ip4_addr_t* ipaddr)
{
    ConnectCtx* ctx = (ConnectCtx*)netif->state;
    WINDIVERT_ADDRESS addr;
    addr.Network.IfIdx = ctx->IfIdx;
    addr.Network.SubIfIdx = ctx->SubIfIdx;
    addr.Outbound = 0;
    addr.TCPChecksum = 1;
    addr.UDPChecksum = 1;
    addr.IPChecksum = 1;
    addr.Impostor = 1;
    

    
    if (p->len < 64) {
        uint8_t d[64] = { 0 };
        memcpy(d, p->payload, p->len);
        WinDivertSend(windiver_handle, d, 64, nullptr, &addr);
    } else {
        WinDivertSend(windiver_handle, p->payload, p->len, nullptr, &addr);
    }
    return ERR_OK;
}
err_t netif_ip_outputv6(struct netif* netif, struct pbuf* p, const ip6_addr_t* ipaddr)
{
    return netif_ip_outputv4(netif, p, nullptr);
}

err_t
pcapif_init(struct netif* netif)
{
    netif->name[0] = 'q';
    netif->name[1] = 'w';
    netif->linkoutput = NULL;
#if LWIP_IPV4
    netif->output = netif_ip_outputv4;
#endif /* LWIP_IPV4 */
#if LWIP_IPV6
    netif->output_ip6 = netif_ip_outputv6;
#endif /* LWIP_IPV6 */
    netif->mtu = 1500;
    netif->flags |= NETIF_FLAG_ETHERNET;
    netif->flags |= NETIF_FLAG_MLD6;
    netif->hwaddr_len = ETH_HWADDR_LEN;
    return ERR_OK;
}

void addTcp(void* arg)
{
    InitTcpArg* tcp_arg = (InitTcpArg*)arg;
    tcpecho_raw_init(tcp_arg->net_if, tcp_arg->ip, tcp_arg->port, tcp_arg->is_ipv4);

    tcpip_callbackmsg_delete((tcpip_callback_msg*)tcp_arg->msg);
    delete tcp_arg;
}

void netifInit(struct netif* net_if,VOID* dest_ip,uint16_t port,bool is_ipv4)
{
    uint32_t* ip = (uint32_t*)dest_ip;
    if (is_ipv4) {

        ip4_addr_t ipaddr, netmask, gw;
        ipaddr.addr = ip[0];
        IP4_ADDR(&netmask, 0, 0, 0, 0);
        gw.addr = ip[0];
        ip4_addr_set(ip_2_ip4(&net_if->ip_addr), &ipaddr);
        ip4_addr_set(ip_2_ip4(&net_if->netmask), &netmask);
        ip4_addr_set(ip_2_ip4(&net_if->gw), &gw);
        pcapif_init(net_if);
        //netif_add(net_if, &ipaddr, &netmask, &gw, NULL, pcapif_init, tcpip_input);
        //netif_set_status_callback(net_if, status_callback);
        //netif_set_link_callback(net_if, link_callback);
        //netif_set_link_up(net_if);
        net_if->flags |= NETIF_FLAG_LINK_UP;
        net_if->flags |= NETIF_FLAG_UP;
        //netif_set_up(net_if);
        net_if->mtu = 1500;

        InitTcpArg* tcp_arg = new InitTcpArg;
        struct tcpip_callback_msg* cb_msg = tcpip_callbackmsg_new(addTcp, tcp_arg);
        tcp_arg->net_if = net_if;
        memcpy(tcp_arg->ip, ip, 4 * sizeof(uint32_t));
        tcp_arg->port = port;
        tcp_arg->is_ipv4 = is_ipv4;
        tcp_arg->msg = cb_msg;
        
        tcpip_callbackmsg_trycallback(cb_msg);
    } else {
        WinDivertHelperHtonIpv6Address(ip, ip);

        //ip6_addr_t ipaddr, netmask, gw;
        //memcpy(ipaddr.addr, ip, 16);
        net_if->ip6_addr[0].type = IPADDR_TYPE_V6;
        memcpy(net_if->ip6_addr[0].u_addr.ip6.addr, ip, 16);
        //netif_create_ip6_linklocal_address(net_if, 1);
        //netif_ip6_addr_set_state(net_if, 0, IP6_ADDR_VALID);
        net_if->ip6_addr_state[0] = IP6_ADDR_VALID;
        //netif_set_status_callback(net_if, status_callback);
        //netif_set_link_callback(net_if, link_callback);
        pcapif_init(net_if);
        net_if->flags |= NETIF_FLAG_LINK_UP;
        net_if->flags |= NETIF_FLAG_UP;
        //netif_set_up(net_if);
        net_if->mtu = 1500;
        net_if->mtu6 = 1500;

        InitTcpArg* tcp_arg = new InitTcpArg;
        struct tcpip_callback_msg* cb_msg = tcpip_callbackmsg_new(addTcp, tcp_arg);
        tcp_arg->net_if = net_if;
        memcpy(tcp_arg->ip, ip, 4 * sizeof(uint32_t));
        tcp_arg->port = port;
        tcp_arg->is_ipv4 = is_ipv4;
        tcp_arg->msg = cb_msg;

        tcpip_callbackmsg_trycallback(cb_msg);
    }

}

void lwipInit()
{
    //lwip_init();
    //myinit(NULL);
    tcpip_init(nullptr, nullptr);

}



static BOOL ctrlHandler(DWORD CtrlType)
{
    switch (CtrlType) {
    case CTRL_C_EVENT:
    case CTRL_BREAK_EVENT:
    case CTRL_CLOSE_EVENT:
    case CTRL_LOGOFF_EVENT:
    case CTRL_SHUTDOWN_EVENT:
        if (windiver_handle) {
            WinDivertClose(windiver_handle);
        }
        return TRUE;
    }
    return FALSE;
}
int main3(int argc, char* argv[])
{
    if (!SetConsoleCtrlHandler(ctrlHandler, TRUE)) {
        std::cerr << "Failed to set console handler" << std::endl;
        return -1;
    }
    lwipInit();
    WINDIVERT_ADDRESS windivert_addr;
	windiver_handle = WinDivertOpen("outbound and ip.DstAddr == 111.111.111.111", WINDIVERT_LAYER_NETWORK, 1, 0);
	if (windiver_handle == INVALID_HANDLE_VALUE) {
		std::cerr << "INVALID_HANDLE_VALUE:" << GetLastError() << std::endl;
		return -1;
	}
    
    void* data = _aligned_malloc(WINDIVERT_MTU_MAX, 16);
    uint32_t recv_size = 0;
    for (;;)
    {
        memset(&windivert_addr, 0, sizeof(WINDIVERT_ADDRESS));
        if (!WinDivertRecv(windiver_handle, data, WINDIVERT_MTU_MAX, &recv_size, &windivert_addr)) {
            if (windivert_addr.Layer == WINDIVERT_LAYER_REFLECT && windivert_addr.Event == WINDIVERT_EVENT_REFLECT_CLOSE) {
                std::cout << "WINDIVERT_EVENT_REFLECT_CLOSE" << std::endl;
                break;
            }
            std::cerr<<"failed to read packet "<< GetLastError() << std::endl;
            continue;
        }
        if (windivert_addr.Layer == WINDIVERT_LAYER_NETWORK) {
            //tcp:6 udp:17 icmp:1
            if (windivert_addr.Network.Protocol == WINDIVERT_IP_PROTOCOL_UDP) {
                continue;
            }
            ConnectCtx* ctx = getConnectCtx(&windivert_addr);
            if (ctx == nullptr) {
                std::cerr << "ctx is null" << std::endl;
                continue;
            }


            WinDivertHelperCalcChecksums(data, recv_size, &windivert_addr, 0);
            //std::cout << "rec" << std::endl;
            pbuf* buf = pbuf_alloc(PBUF_RAW, recv_size, PBUF_POOL);
            if (buf == NULL) {
                std::cerr << "pbuf_alloc fail" << std::endl;
                continue;
            }
            copy2Pbuf(buf, data, recv_size);

            //ip_input(buf, &ctx->net_if);
            if (tcpip_inpkt(buf, &ctx->net_if, ip_input) != ERR_OK) {
                pbuf_free(buf);
            }
        }
        if (windivert_addr.Layer == WINDIVERT_LAYER_SOCKET) {
            //tcp:6 udp:17 icmp:1
            if (windivert_addr.Socket.Protocol == WINDIVERT_IP_PROTOCOL_TCP) {
                if (windivert_addr.Event == WINDIVERT_EVENT_SOCKET_CONNECT) {
                    ConnectCtx* ctx = getConnectCtx(&windivert_addr);
                    if (ctx == nullptr) {
                        std::cerr << "ctx is null" << std::endl;
                        continue;
                    }
                }
            }
            
        }
    }
    _aligned_free(data);
	system("pause");    
	return 0;
}