#include "driver2socks.h"
#include <array>
#include <cctype>
#include <cstdio>
#include <cstring>
#include <deque>
#include <memory>
#include <memory>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>
#include <unordered_map>

#include <windivert.h>
#include "asio.hpp"
#include "lwipstack.h"
#include "windivert_driver.h"
#include "iocontext.h"
#include "socks_client.hpp"
#include  "netpacket_pool.h"
extern "C"{
#include "lwip/priv/tcp_priv.h"
}


using namespace driver2socks;

static const Driver2SocksConfig* g_config;

err_t tcp_on_recv(void* arg, struct tcp_pcb *tpcb, struct pbuf *p, err_t err) {
    if (tpcb == NULL)
        return ERR_VAL;
    if (err != ERR_OK || p == NULL || 0 == p->len) { // p == NULL indicates EOF
        std::cout << "tcp_on_recv "<<(int64_t)p<<"\n";

        LWIPStack::getInstance().strand_tcp_close(tpcb,[](err_t){});
        return ERR_OK;
    }
    uint16_t data_len = p->tot_len;

    auto buffer = std::shared_ptr<uint8_t>((uint8_t*)malloc(data_len), [](uint8_t* p) { if (p) free(p); });
    auto tp = buffer.get();
    pbuf_copy_partial(p, tp, data_len, 0);
    pbuf_free(p);


    auto tcparg = static_cast<TcpArg*>(tpcb->callback_arg);

    bool ret = false;
    for (int i = 10;i < 20 ;++i) {
        ret = tcparg->sc_client->sendData(tp, data_len);
        if (ret) break;
        Sleep(i);
    }
    if (!ret) {
        std::cout << "LLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLL\n";
        LWIPStack::getInstance().strand_tcp_close(tpcb,[](err_t){});
        return  ERR_ABRT;
    }

    LWIPStack::getInstance().lwip_tcp_recved(tpcb, data_len);
    return ERR_OK;
}


//虚拟tcp接收到连接成功回调,构造一个socks5客户端然后连接到目标
err_t tcp_on_accept(void *arg, struct tcp_pcb *newpcb, err_t err) {
    if (err != ERR_OK || newpcb == NULL)
        return ERR_VAL;

    char strlocalip[64] = { 0 };
    uint32_t localip[4] = { 0 };
    if (newpcb->local_ip.type == IPADDR_TYPE_V4) {
        localip[0] = WinDivertHelperNtohl(newpcb->local_ip.u_addr.ip4.addr);
        WinDivertHelperFormatIPv4Address(localip[0], strlocalip, 64);
    } else {
        WinDivertHelperNtohIpv6Address(newpcb->local_ip.u_addr.ip6.addr, localip);
        WinDivertHelperFormatIPv6Address(localip, strlocalip, 64);
    }
    char strremoteip[64] = { 0 };
    uint32_t remoteip[4] = { 0 };
    if (newpcb->remote_ip.type == IPADDR_TYPE_V4) {
        remoteip[0] = WinDivertHelperNtohl(newpcb->remote_ip.u_addr.ip4.addr);
        WinDivertHelperFormatIPv4Address(remoteip[0], strremoteip, 64);
    } else {
        WinDivertHelperNtohIpv6Address(newpcb->remote_ip.u_addr.ip6.addr, remoteip);
        WinDivertHelperFormatIPv6Address(remoteip, strremoteip, 64);
    }
    std::cout << "newtcp local ip:" << strlocalip << " local port:"<<(int)newpcb->local_port<< " remote ip:" << strremoteip << " remote port:" << (int)newpcb->remote_port << "\n";



    //创建一个socks5代理客户端并关联tcp_pcb
    std::shared_ptr<driver2socks::socks_client> context = std::make_shared<driver2socks::socks_client>(IoContext::getIoContext());
    TcpArg* targ = new TcpArg;
    targ->sc_client = context;
    newpcb->callback_arg = targ;
    context->lwip_tcp_pcb_ = newpcb;
    //设置tcp堆栈接收数据回调
    LWIPStack::lwip_tcp_receive(newpcb, tcp_on_recv);
    //tcp_nagle_disable(newpcb);

    auto callback_socksclient_recv = [](const asio::error_code& err, std::shared_ptr<NetPacket> buffer, std::size_t sz, tcp_pcb* tcp) {
        if (err) {
            std::cerr << "callback_socksclient_recv error,close tcp_pcb" << std::endl;
            LWIPStack::getInstance().strand_tcp_close(tcp,[](err_t){});
            return;
        }
        
        LWIPStack::getInstance().strand_tcp_write(tcp, buffer, (u16_t)sz, TCP_WRITE_FLAG_COPY,
            [](err_t err) {
                if (err != ERR_OK) {
                    std::cerr << "tcp_write error:" << (int)err << "\n";
                }
            });

        };

    //建立代理通道
    char hoststr[64] = { 0 };
    uint32_t ip[4] = { 0 };
    if (newpcb->local_ip.type == IPADDR_TYPE_V4) {
        ip[0] = WinDivertHelperNtohl(newpcb->local_ip.u_addr.ip4.addr);
        WinDivertHelperFormatIPv4Address(ip[0], hoststr, 64);
    } else {
        WinDivertHelperNtohIpv6Address(newpcb->local_ip.u_addr.ip6.addr, ip);
        WinDivertHelperFormatIPv6Address(ip, hoststr, 64);
    }
    //开始socks5客户端（建立到服务器的连接并握手）
    context->start_socks(g_config->socks5_server_ip, g_config->socks5_server_port, 
        std::string(hoststr), newpcb->local_port, 
        callback_socksclient_recv,
        [](asio::error_code ec) {});

    return ERR_OK;
}

void driver2socks_start(const driver2socks::Driver2SocksConfig* config) {

    g_config = config;
    WindivertDriver::Ptr driver(new WindivertDriver(config->app_names));
    LWIPStack::getInstance().init(IoContext::getIoContext());
    auto t_pcb = LWIPStack::tcp_listen_any();
    auto u_pcb = LWIPStack::udp_listen_any();

    LWIPStack::lwip_tcp_arg(t_pcb, nullptr);
    //注册tcp接收到新的连接时回调函数
    LWIPStack::lwip_tcp_accept(t_pcb, tcp_on_accept);

    //tcp数据注入到驱动入站方向
    LWIPStack::getInstance().set_output_function([driver](struct netif *netif, struct pbuf *p, const ip4_addr_t *ipaddr)->err_t {
        std::shared_ptr<NetPacket> buffer(_NetPacketPool->getPacket(p->tot_len), [](NetPacket* p) {_NetPacketPool->freePacket(p); });
        pbuf_copy_partial(p, buffer->data, p->tot_len, 0);
        uint16_t len = p->tot_len;
        //driver->doWrite((uint8_t*)&len, sizeof(uint16_t));
        driver->doWrite(buffer, p->tot_len);
        return ERR_OK;
    });
    if (config->enable_ipv6) {
        LWIPStack::getInstance().set_outputv6_function([driver](struct netif* netif, struct pbuf* p, const ip6_addr_t* ipaddr)->err_t {
            std::shared_ptr<NetPacket> buffer(_NetPacketPool->getPacket(p->tot_len), [](NetPacket* p) {_NetPacketPool->freePacket(p); });
            pbuf_copy_partial(p, buffer->data, p->tot_len, 0);
            uint16_t len = p->tot_len;
            //driver->doWrite((uint8_t*)&len, sizeof(uint16_t));
            driver->doWrite(buffer, p->tot_len);
            return ERR_OK;
            });
    }

        
    //从驱动中读取数据
    driver->run([](std::shared_ptr<NetPacket> bf,size_t size) {
        LWIPStack::getInstance().strand_ip_input(bf,size, [](err_t err){
	        if (err != ERR_OK) {
                std::cerr << "input_ip err" << std::endl;
	        }
        }); 
    });

    system("pause");
    //std::thread(driver2socks_dns_listen).detach();

}
