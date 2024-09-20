#ifndef ADAPTERS_INFO_H
#define ADAPTERS_INFO_H
#include <string>
#include <memory>
#include <vector>
#include <Windows.h>
#include <winsock2.h>
#include <iphlpapi.h>
#include <stdint.h>
#include <QString>

struct AdapterInterface
{
    typedef std::shared_ptr<AdapterInterface> Ptr;
    QString Id;
    QString Name;
    QString Description;
    QString Address;
    QString Mask;
    QString GatewayServer;
    QString DhcpServer;
    QString PrimaryWinsServer;
    QString SecondaryWinsServer;
    QString MacAddress;
    int IfIndex;
    int IfType; // ipifcons.h IFTYPE
    IF_OPER_STATUS Status;
};


QString BytesToMacAddress(const void* data, int size) noexcept
{
    if ((size < 1) || (NULL != data && size < 1)) {
        data = NULL;
        size = 0;
    }

    // Set default MAC address
    unsigned char default_byte_arr[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
    int num_of_bytes_to_copy = (size <= 6) ? size : 6;
    memcpy(default_byte_arr, data, num_of_bytes_to_copy);

    char mac_str[18];
    sprintf(mac_str, "%02X:%02X:%02X:%02X:%02X:%02X",
            default_byte_arr[0], default_byte_arr[1], default_byte_arr[2],
            default_byte_arr[3], default_byte_arr[4], default_byte_arr[5]);
    return mac_str;
}


bool GetAllAdapterInterfaces(std::vector<AdapterInterface::Ptr>& interfaces) noexcept
{
    ULONG structSize = sizeof(IP_ADAPTER_ADDRESSES);
    std::shared_ptr<IP_ADAPTER_ADDRESSES> pArray = std::shared_ptr<IP_ADAPTER_ADDRESSES>((IP_ADAPTER_ADDRESSES*)malloc(structSize),
                                                                               [](IP_ADAPTER_ADDRESSES* p) noexcept
                                                                               {
                                                                                   free(p);
                                                                               });

    int err = GetAdaptersAddresses(AF_UNSPEC, 0, NULL, pArray.get(), &structSize);
    if (err == ERROR_BUFFER_OVERFLOW)  {
        // Buffer was too small, reallocate the correct size for the buffer.
        pArray = std::shared_ptr<IP_ADAPTER_ADDRESSES>((IP_ADAPTER_ADDRESSES*)malloc(structSize),
                                                  [](IP_ADAPTER_ADDRESSES* p) noexcept
                                                  {
                                                      free(p);
                                                  });

        err = GetAdaptersAddresses(AF_UNSPEC, 0, NULL, pArray.get(), &structSize);
    }
    if (err != ERROR_SUCCESS) {
        return false;
    }

    IP_ADAPTER_ADDRESSES* pEntry = pArray.get();
    QString any = "0.0.0.0";
    while (pEntry) {
        // Retrieve the adapter info from the memory address
        IP_ADAPTER_ADDRESSES& entry = *pEntry;
        AdapterInterface::Ptr interfacex = std::make_shared<AdapterInterface>();
        interfacex->Id = entry.AdapterName;
        interfacex->IfIndex = entry.IfIndex;
        interfacex->Name = QString::fromWCharArray(entry.FriendlyName);
        interfacex->Description = QString::fromWCharArray(entry.Description);
        // interfacex->Address = entry.IpAddressList.IpAddress.String;
        // interfacex->Mask = entry.IpAddressList.IpMask.String;
        // interfacex->GatewayServer = entry.GatewayList.IpAddress.String;
        interfacex->IfType = entry.IfType;
        interfacex->Status = entry.OperStatus;
        interfacex->MacAddress =  BytesToMacAddress(entry.PhysicalAddress, (int)entry.PhysicalAddressLength);

        interfaces.emplace_back(interfacex);
        // if (entry.DhcpEnabled != 0)
        // {
        //     interfacex->DhcpServer = entry.DhcpServer.IpAddress.String;
        // }

        // if (entry.HaveWins)
        // {
        //     interfacex->PrimaryWinsServer = entry.PrimaryWinsServer.IpAddress.String;
        //     interfacex->SecondaryWinsServer = entry.SecondaryWinsServer.IpAddress.String;
        // }

        if (interfacex->Address.isEmpty()) interfacex->Address = any;
        if (interfacex->Mask.isEmpty()) interfacex->Mask = any;
        if (interfacex->GatewayServer.isEmpty()) interfacex->GatewayServer = any;
        if (interfacex->DhcpServer.isEmpty()) interfacex->DhcpServer = any;
        if (interfacex->PrimaryWinsServer.isEmpty()) interfacex->PrimaryWinsServer = any;
        if (interfacex->SecondaryWinsServer.isEmpty()) interfacex->SecondaryWinsServer = any;

        // Get next adapter (if any)
        pEntry = entry.Next;
    }

    return err == ERROR_SUCCESS;
}
#endif // ADAPTERS_INFO_H
