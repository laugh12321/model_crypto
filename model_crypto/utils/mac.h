#pragma once

#include <iostream>
#include <string>

#ifdef _WIN32
#include <windows.h>
#include <iphlpapi.h>
#pragma comment(lib, "IPHLPAPI.lib")
#else
#include <ifaddrs.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif

inline std::string GetMACAddress() {
    std::string macAddress = "";

#ifdef _WIN32
    IP_ADAPTER_INFO* adapterInfo = nullptr;
    ULONG bufferSize = 0;

    if (GetAdaptersInfo(adapterInfo, &bufferSize) == ERROR_BUFFER_OVERFLOW) {
        adapterInfo = new IP_ADAPTER_INFO[bufferSize / sizeof(IP_ADAPTER_INFO)];
        if (GetAdaptersInfo(adapterInfo, &bufferSize) == ERROR_SUCCESS) {
            for (PIP_ADAPTER_INFO adapter = adapterInfo; adapter; adapter = adapter->Next) {
                if (adapter->Type == MIB_IF_TYPE_ETHERNET) {
                    char mac[18];
                    snprintf(mac, sizeof(mac), "%.2X:%.2X:%.2X:%.2X:%.2X:%.2X",
                        adapter->Address[0], adapter->Address[1], adapter->Address[2],
                        adapter->Address[3], adapter->Address[4], adapter->Address[5]);
                    macAddress = mac;
                    break;
                }
            }
        }
        delete[] adapterInfo;
    }
#else
    struct ifaddrs *ifaddr, *ifa;
    if (getifaddrs(&ifaddr) != -1) {
        for (ifa = ifaddr; ifa != nullptr; ifa = ifa->ifa_next) {
            if (ifa->ifa_addr == nullptr || ifa->ifa_addr->sa_family != AF_PACKET) {
                continue;
            }

            struct sockaddr_ll *s = reinterpret_cast<struct sockaddr_ll*>(ifa->ifa_addr);
            char mac[18];
            snprintf(mac, sizeof(mac), "%.2X:%.2X:%.2X:%.2X:%.2X:%.2X",
                s->sll_addr[0], s->sll_addr[1], s->sll_addr[2],
                s->sll_addr[3], s->sll_addr[4], s->sll_addr[5]);
            macAddress = mac;
            break;
        }
        freeifaddrs(ifaddr);
    }
#endif

    return macAddress;
}
