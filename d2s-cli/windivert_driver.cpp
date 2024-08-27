#include "windivert_driver.h"
#include "lwip/ip.h"

static const uint32_t APP_NAMES_SIZE = 2048;

void WindivertDriver::_runInject()
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

void WindivertDriver::_run()
{
    w_handle_ = WinDivertOpen((const char*)app_names_, WINDIVERT_LAYER_NETWORK, 776, 0);
    if (w_handle_ == INVALID_HANDLE_VALUE) {
        std::cerr << "INVALID_HANDLE_VALUE" << "\n";
        return;
    }
    WinDivertSetParam(w_handle_, WINDIVERT_PARAM_QUEUE_TIME, WINDIVERT_PARAM_QUEUE_TIME_MAX);
    WinDivertSetParam(w_handle_, WINDIVERT_PARAM_QUEUE_LENGTH, WINDIVERT_PARAM_QUEUE_LENGTH_MAX);
    WinDivertSetParam(w_handle_, WINDIVERT_PARAM_QUEUE_SIZE, WINDIVERT_PARAM_QUEUE_SIZE_MAX);

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
                memcpy(buf->data, recv_data_.get(), packet_len);
                if (cb_out_data_) cb_out_data_(buf,packet_len);
                data += packet_len;
            } else {
                std::cerr << "getPacketLen Error\n";
            }

        }
    }
}

void WindivertDriver::doWrite(std::shared_ptr<NetPacket> buffer, size_t len)
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

    if (IP_HDR_GET_VERSION(buffer->data) == 6) {
        addr.IPv6 = 1;
    }

    WinDivertSend(w_handle_, buffer->data, len, NULL, &addr);
#endif

}

void WindivertDriver::doWrite(uint8_t *buf, size_t len)
{
    //std::cout << "inject_buf write size:" << len<< " write tag:"<<*((uint16_t*)buf)<<"\n";
    bool ret = buf_inject_.Write(buf, len);
    if (!ret) {
        std::cout << "buf_inject write fail2\n";
    }
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
    recv_data_(_aligned_malloc(15008, 16),[](void* p) {_aligned_free(p);})
{
    app_names_ = new wchar_t[APP_NAMES_SIZE];
    memset(app_names_,0, APP_NAMES_SIZE);
    uint32_t index = 0;
    for (const std::string& app_name : app_names) {
        int char_size = MultiByteToWideChar(CP_UTF8,0,app_name.data(), app_name.length(),app_names_+index, APP_NAMES_SIZE -index);
        index += char_size;
        ++index;
        if (index >= APP_NAMES_SIZE) break;
    }
}

WindivertDriver::~WindivertDriver()
{
    is_stop_.store(true);

    WinDivertClose(w_handle_);

    if (app_names_) {
        delete app_names_;
        app_names_ = nullptr;
    }
    thread_.join();
}

void WindivertDriver::run(cb_outbound_data out)
{
    is_stop_.store(false);

    cb_out_data_ = out;
    thread_ = std::thread([this]() {this->_run(); });
    //thread_2_ = std::thread([this]() {this->_runInject(); });
    //this->_run();
}
