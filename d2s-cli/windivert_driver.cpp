#include "windivert_driver.h"
#include "lwip/ip.h"

static const uint32_t APP_NAMES_SIZE = 2048;

void WindivertDriver::_runWrite()
{
using namespace std::chrono_literals;
    WINDIVERT_ADDRESS addr;
    addr.Network.IfIdx = 6;
    addr.Network.SubIfIdx = 0;
    addr.Outbound = 0;
    addr.TCPChecksum = 1;
    addr.UDPChecksum = 1;
    addr.IPChecksum = 1;
    addr.Impostor = 1;
    addr.IPv6 = 0;

    for (;;) {
        if (is_stop_.load()) return;

        auto buffer = queue_inject_.front();
        if (!buffer) {
            std::this_thread::sleep_for(1ms);
            continue;
        }
        NetPacket::Ptr p = *buffer;
        queue_inject_.pop();
        if (IP_HDR_GET_VERSION(p->data) == 6) {
            addr.IPv6 = 1;
        }

        WinDivertSend(w_handle_, p->data, p->data_len, NULL, &addr);
    }


}

void WindivertDriver::_runRead()
{

    WINDIVERT_ADDRESS windivert_addr[10];
    uint32_t recv_size = 0;
    for (;;) {
        uint32_t addr_len = 10*sizeof(WINDIVERT_ADDRESS);
        memset(windivert_addr, 0, addr_len);
        // if (!WinDivertRecvEx(w_handle_, recv_data_.get(), WINDIVERT_MTU_MAX, &recv_size, &windivert_addr,)) {
        //     std::cerr << "failed to read packet " << GetLastError() << "\n";
        //     break;
        // }
        if (!WinDivertRecvEx(w_handle_, recv_data_.get(), 10*1500, &recv_size, 0, windivert_addr, &addr_len, nullptr)) {
            std::cerr << "failed to read packet " << GetLastError() << "\n";
            break;
        }
        if (is_stop_) return;
        
        uint8_t* data = (uint8_t*)recv_data_.get();
        for (int i = 0;i < addr_len/sizeof(WINDIVERT_ADDRESS);++i) {
            if (windivert_addr[i].Event != WINDIVERT_LAYER_NETWORK) {
                continue;
            }
            if (windivert_addr[i].Network.Protocol == WINDIVERT_IP_PROTOCOL_UDP) {
                continue;
            }
            if (windivert_addr[i].Network.IfIdx != 6) {
                continue;
            }
            uint16_t packet_len = 0;
            if (getPacketLen(data,packet_len)) {
                WinDivertHelperCalcChecksums(data, packet_len, &windivert_addr[i], 0);

                std::shared_ptr<NetPacket> buf(_NetPacketPool->getPacket(packet_len), [](NetPacket* p) {_NetPacketPool->freePacket(p); });
                memcpy(buf->data, data, packet_len);
                if (cb_out_data_) cb_out_data_(buf,packet_len);
                data += packet_len;
            } else {
                std::cerr << "getPacketLen Error\n";
            }

        }
    }
}

void WindivertDriver::doWrite(NetPacket::Ptr buffer, size_t len)
{
    queue_inject_.emplace(buffer);
#if 0
    WINDIVERT_ADDRESS addr;
    addr.Network.IfIdx = 6;
    addr.Network.SubIfIdx = 0;
    addr.Outbound = 0;
    addr.TCPChecksum = 1;
    addr.UDPChecksum = 1;
    addr.IPChecksum = 1;
    addr.Impostor = 1;
    addr.IPv6 = 0;

    if (IP_HDR_GET_VERSION(buffer->data) == 6) {
        addr.IPv6 = 1;
    }

    WinDivertSend(w_handle_, buffer->data, len, NULL, &addr);
#endif
}

void WindivertDriver::stop()
{
    is_stop_.store(true);
}

bool WindivertDriver::getPacketLen(uint8_t *packet, uint16_t &packet_len)
{
    PWINDIVERT_IPHDR ip_header = (PWINDIVERT_IPHDR)packet;
    PWINDIVERT_IPV6HDR ipv6_header = NULL;
    if (ip_header->Version == 4) {
        packet_len = (UINT)ntohs(ip_header->Length);
        return true;
    } else if (ip_header->Version == 6) {
        ipv6_header = (PWINDIVERT_IPV6HDR)packet;
        packet_len = (UINT)ntohs(ipv6_header->Length) +
                    sizeof(WINDIVERT_IPV6HDR);
        return true;
    }
    return false;
}

WindivertDriver::WindivertDriver(const std::vector<std::string> &app_names):
    is_stop_(true),
    recv_data_(_aligned_malloc(15008, 16),[](void* p) {_aligned_free(p);}),
    app_names_((wchar_t*)_aligned_malloc(APP_NAMES_SIZE, 16),[](wchar_t* p) {_aligned_free(p);}),
    queue_inject_(256)
{
    auto apps_ptr = app_names_.get();
    memset(apps_ptr,0, APP_NAMES_SIZE);
    uint32_t index = 0;
    for (const std::string& app_name : app_names) {
        int char_size = MultiByteToWideChar(CP_UTF8,0,app_name.data(), app_name.length(),apps_ptr+index, APP_NAMES_SIZE -index);
        index += char_size;
        ++index;
        if (index >= APP_NAMES_SIZE) break;
    }

    w_handle_ = WinDivertOpen((const char*)apps_ptr, WINDIVERT_LAYER_NETWORK, 776, 0);
    if (w_handle_ == INVALID_HANDLE_VALUE) {
        std::cerr << "INVALID_HANDLE_VALUE" << "\n";
        stop();
        return;
    }
    WinDivertSetParam(w_handle_, WINDIVERT_PARAM_QUEUE_TIME, WINDIVERT_PARAM_QUEUE_TIME_MAX);
    WinDivertSetParam(w_handle_, WINDIVERT_PARAM_QUEUE_LENGTH, WINDIVERT_PARAM_QUEUE_LENGTH_MAX);
    WinDivertSetParam(w_handle_, WINDIVERT_PARAM_QUEUE_SIZE, WINDIVERT_PARAM_QUEUE_SIZE_MAX);
}

WindivertDriver::~WindivertDriver()
{
    is_stop_.store(true);

    WinDivertClose(w_handle_);

    //thread_read_.join();
    thread_write_.join();
}

void WindivertDriver::run(cb_outbound_data out)
{
    is_stop_.store(false);

    cb_out_data_ = out;
    //thread_read_ = std::thread(std::bind(&WindivertDriver::_runRead,this));
    thread_write_ = std::thread(std::bind(&WindivertDriver::_runWrite,this));
    _runRead();
}
