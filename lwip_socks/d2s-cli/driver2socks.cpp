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


#define MAX_DOMAINNAME_LEN  255
#define DNS_PORT            53
#define DNS_TYPE_SIZE       2
#define DNS_CLASS_SIZE      2
#define DNS_TTL_SIZE        4
#define DNS_DATALEN_SIZE    2
#define DNS_TYPE_A          0x0001 // 1 a host address
#define DNS_TYPE_CNAME      0x0005 // 5 the canonical name for an alias
#define DNS_PACKET_MAX_SIZE (sizeof(DNSHeader) + MAX_DOMAINNAME_LEN + DNS_TYPE_SIZE + DNS_CLASS_SIZE)

struct DNSHeader
{
    uint16_t			usTransID;			// 标识符
    uint16_t			usFlags;			// 各种标志位
    uint16_t			usQuestionCount;	// Question字段个数 
    uint16_t			usAnswerCount;		// Answer字段个数
    uint16_t			usAuthorityCount;	// Authority字段个数
    uint16_t			usAdditionalCount;	// Additional字段个数
};

using namespace driver2socks;

static HANDLE g_tap_handle = INVALID_HANDLE_VALUE;
static bool to_read = true;
static const Driver2SocksConfig* g_config;
static std::atomic<int> g_addr2seeds;
static std::mutex g_syncdns_metex;
static std::unordered_map<u32_t, std::string> g_addr2host;
static std::unordered_map<std::string, u32_t> g_host2addr;

u32_t driver2socks_dns_alloc(const std::string& hostname) {
    g_syncdns_metex.lock();

    u32_t address = 0;
    std::unordered_map<std::string, u32_t>::iterator iter = g_host2addr.find(hostname);
    if (iter != g_host2addr.end()) {
        address = iter->second;
        goto RETN_0;
    }

    if (0 == g_addr2seeds) {
        g_addr2seeds = ntohl(inet_addr("198.18.0.0"));
    }

    address = g_addr2seeds++;
    while (0 == *(char*)&address) {
        address = g_addr2seeds++;
    }

    g_host2addr.insert(std::make_pair(hostname, address));
    g_addr2host.insert(std::make_pair(address, hostname));

RETN_0:
    g_syncdns_metex.unlock();
    return address;
}

bool driver2socks_dns_resolve(u32_t address, std::string& hostname) {
    hostname = "";

    g_syncdns_metex.lock();

    bool success = false;
    std::unordered_map<u32_t, std::string>::iterator iter = g_addr2host.find(address);
    if (iter != g_addr2host.end()) {
        success |= true;
        hostname = iter->second;
    }

    g_syncdns_metex.unlock();
    return success;
}

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

int driver2socks_dns_fill_hostname(const char* hostname, unsigned int hostname_len, char*& payload) {
    char* current_payload_pos = payload;
    {
        char domain[MAX_PATH] = "";
        strncat(domain, hostname, hostname_len);

        char* encoding_bytes = strtok(domain, ".");
        while (NULL != encoding_bytes)
        {
            int max_encoding_bytes = (int)strlen(encoding_bytes);
            if (max_encoding_bytes > 0xc0)
            {
                max_encoding_bytes = 0xc0;
            }

            *payload++ = (char)max_encoding_bytes;
            memcpy(payload, encoding_bytes, max_encoding_bytes);
            payload += max_encoding_bytes;

            encoding_bytes = strtok(NULL, ".");
        }
        *payload++ = '\x0';
    }
    return (int)(payload - current_payload_pos);
}

static void driver2socks_dns_listen() {
    auto fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

    struct sockaddr_in bindaddr;
    memset(&bindaddr, 0, sizeof(bindaddr));

    bindaddr.sin_family = AF_INET;
    bindaddr.sin_port = ntohs(53);
    bindaddr.sin_addr.s_addr = 0;

    bind(fd, (struct sockaddr*)&bindaddr, sizeof(bindaddr));
    while (1) {
        struct sockaddr_in fromaddr;
        memset(&fromaddr, 0, sizeof(fromaddr));

        fromaddr.sin_family = AF_INET;
        fromaddr.sin_port = 0;
        fromaddr.sin_addr.s_addr = 0;

        char sz[1500];
        int fromaddr_len = sizeof(fromaddr);
        int buffer_len = recvfrom(fd, sz, sizeof(sz), 0, (struct sockaddr*)&fromaddr, &fromaddr_len);
        if (buffer_len > 0) {
            struct pbuf sp;
            memset(&sp, 0, sizeof(sp));

            sp.payload = sz;
            sp.len = sizeof(sz);
            sp.tot_len = sizeof(sz);

            // 设当前收取到的UDP帧长度不足DNS协议头的长度则返回假。
            if (sp.len < sizeof(DNSHeader)) {
                continue;
            }

            auto request = (DNSHeader*)sp.payload;
            request->usTransID = htons(request->usTransID);
            request->usFlags = htons(request->usFlags);
            request->usQuestionCount = htons(request->usQuestionCount);
            request->usAnswerCount = htons(request->usAnswerCount);
            request->usAuthorityCount = htons(request->usAuthorityCount);
            request->usAdditionalCount = htons(request->usAdditionalCount);

            // 不支持除A4地址解析以外的任何DNS协议（不过按照INETv4以太网卡也不可能出现A6地址析请求）
            // A6根本不需要虚拟网卡链路层网络远程桥接，先天的scope机制就足以抵御外部入侵的防火长城。
            if (0 == (request->usFlags & 0x0100)) {
                continue;
            }

            // 若客户端查询问题是空直接不给客户端应答就让它卡在那里用户态（RING3）通过系统DNS服务进行解析不太可能是请求空答案。
            // 虽然这会造成系统内核使用处于等待数据包应答的状态；句柄资源无法释放但是已经不太重要了；底层也不太好操作把上层
            // 搞崩溃，搞太猛系统就蓝屏了；当然倒是可以强制把目标进程的内存全部设置为WPOFF让它死的难看至极。
            // 不过这么搞了就必须要在RING0做防护了；万一逗逼跑来强制从内核卸载怎么办，一定要让这些人付出代价必须蓝屏死机。
            // 虽然这并不是没有办法。对付小小的用户态程式方法真的太多，搞死它只要你想轻而易举；毕竟应用层都是最低贱的程式。
            if (0 == request->usQuestionCount) {
                continue;
            }

            // 应答客户端查询DNS的请求，DNS地址污染并且强制劫持到分配的保留地址段假IP。
            auto payload = (char*)(request + 1);

            // 从DNS协议流中获取需要解析的域名。
            std::string hostname = "";
            while (*payload) {
                u8_t len = (u8_t)*payload++;
                if (!hostname.empty()) {
                    hostname += ".";
                }
                hostname += std::string(payload, len);
                payload += len;
            }
            payload++; // 查询字符串的最后一个字节是\x0中止符号。

                       // 问题所需求的查询类型。
            u16_t usQType = ntohs(*(u16_t*)payload);
            payload += sizeof(u16_t);

            // 问题所需求的查询类别。
            u16_t usQClass = ntohs(*(u16_t*)payload);
            payload += sizeof(u16_t);

            // 构建DNS应答数据报文。
            std::shared_ptr<pbuf> p(
                pbuf_alloc(pbuf_layer::PBUF_TRANSPORT, 1500, pbuf_type::PBUF_RAM),
                [](pbuf* _p) {
                pbuf_free(_p);
            });

            payload = (char*)p->payload;
            p->tot_len = 0;
            p->len = 0;

            // 构建虚假DNS服务响应头。
            auto response = (DNSHeader*)payload;
            response->usTransID = htons(request->usTransID); // usFlags & 0xfb7f -- RFC1035 4.1.1(Header section format)
            response->usFlags = htons(0x8180);
            response->usAuthorityCount = 0;
            response->usAdditionalCount = 0;
            response->usAnswerCount = 0;
            response->usQuestionCount = htons(1);

            payload += sizeof(DNSHeader);
            driver2socks_dns_fill_hostname(hostname.data(), hostname.length(), payload);

            *(u16_t*)payload = ntohs(usQType);
            payload += sizeof(u16_t);
            *(u16_t*)payload = ntohs(usQClass);
            payload += sizeof(u16_t);

            if (usQClass & 1) {
#pragma pack(push, 1)
                driver2socks_dns_fill_hostname(hostname.data(), hostname.length(), payload);

                struct Answer
                {
                    u16_t usQType;
                    u16_t usQClass;
                    u32_t uTTL;
                    u16_t usRDLength;
                };

                Answer* answer = (Answer*)payload;
                answer->usQType = ntohs(usQType);
                answer->usQClass = ntohs(usQClass);
                answer->uTTL = ntohl(0x7f);
                answer->usRDLength = 0;

                if (usQType & 1) {
                    answer->usQType = ntohs(1);

                    struct AnswerAddress {
                        Answer stAnswer;
                        u32_t dwAddress;
                    };

                    AnswerAddress* rrA = (AnswerAddress*)answer;
                    answer->usRDLength = ntohs(4);
                    rrA->dwAddress = ntohl(driver2socks_dns_alloc(hostname));

                    payload += sizeof(AnswerAddress);
                    response->usAnswerCount = ntohs(1);

                    //printf("NS Lookup[A, IN]: %s hijacked -> %s\n", hostname.data(), get_address_string(rrA->dwAddress).data());
                }
                else if (usQType & 5) {
                    answer->usQType = ntohs(5);

                    payload += sizeof(Answer);

                    int resouces_data_length = driver2socks_dns_fill_hostname(hostname.data(), hostname.length(), payload);
                    answer->usRDLength = ntohs(resouces_data_length);

                    response->usAnswerCount = ntohs(1);
                }
#pragma pack(pop)
            }

            // 设置当前应答客户的流的总长度。
            p->tot_len = p->len = (payload - (char*)p->payload);
            sendto(fd, (char*)p->payload, p->len, 0, (struct sockaddr*)&fromaddr, fromaddr_len);
        }
    }
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
        std::shared_ptr<NetPacket> buffer(_NetPacketPool->getPacket(), [](NetPacket* p) {_NetPacketPool->freePacket(p); });
        pbuf_copy_partial(p, buffer->data, p->tot_len, 0);
        buffer->data_len = p->tot_len;
        uint16_t len = p->tot_len;
        //driver->doWrite((uint8_t*)&len, sizeof(uint16_t));
        driver->doWrite(buffer, p->tot_len);
        return ERR_OK;
    });
    if (config->enable_ipv6) {
        LWIPStack::getInstance().set_outputv6_function([driver](struct netif* netif, struct pbuf* p, const ip6_addr_t* ipaddr)->err_t {
            std::shared_ptr<NetPacket> buffer(_NetPacketPool->getPacket(), [](NetPacket* p) {_NetPacketPool->freePacket(p); });
            pbuf_copy_partial(p, buffer->data, p->tot_len, 0);
            buffer->data_len = p->tot_len;
            uint16_t len = p->tot_len;
            //driver->doWrite((uint8_t*)&len, sizeof(uint16_t));
            driver->doWrite(buffer, p->tot_len);
            return ERR_OK;
            });
    }

        
    //从驱动中读取数据
    driver->run([](std::shared_ptr<void> bf,size_t size) {
        LWIPStack::getInstance().strand_ip_input(bf,size, [](err_t err){
	        if (err != ERR_OK) {
                std::cerr << "input_ip err" << std::endl;
	        }
        }); 
    });

    system("pause");
    //std::thread(driver2socks_dns_listen).detach();

}
