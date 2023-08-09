#ifndef UTIL_H
#define UTIL_H

#include <iostream>
#include <fstream>
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


inline std::string fileRead(const std::string& filename) {
    std::ifstream ifs(filename, std::ios::in | std::ios::binary | std::ios::ate);

    std::ifstream::pos_type fileSize = ifs.tellg();
    ifs.seekg(0, std::ios::beg);

    std::string fileContent(fileSize, '\0');
    ifs.read(&fileContent[0], fileSize);
    ifs.close();

    return fileContent;
}


inline void fileWrite(const std::string& filename, const std::string& data) {
    std::ofstream ofs(filename, std::ios::out | std::ios::binary | std::ios::trunc);
    if (ofs.good()) {
        ofs.write(data.c_str(), data.size());
        ofs.close();
    } else {
        std::cerr << "Error opening file for writing" << std::endl;
        exit(1);
    }

    return;
}

inline std::string GetMACAddress() {
#ifdef _WIN32
    IP_ADAPTER_INFO adapterInfo[16];
    DWORD bufferSize = sizeof(adapterInfo);
    DWORD result = GetAdaptersInfo(adapterInfo, &bufferSize);

    if (result == ERROR_BUFFER_OVERFLOW) {
        // Resize buffer and try again
        IP_ADAPTER_INFO *newBuffer = new IP_ADAPTER_INFO[bufferSize / sizeof(IP_ADAPTER_INFO)];
        result = GetAdaptersInfo(newBuffer, &bufferSize);
        if (result != ERROR_SUCCESS) {
            delete[] newBuffer;
            return "";
        }
        delete[] newBuffer;
    }
    else if (result != ERROR_SUCCESS) {
        return "";
    }

    for (PIP_ADAPTER_INFO adapter = adapterInfo; adapter; adapter = adapter->Next) {
        if (adapter->Type == MIB_IF_TYPE_ETHERNET) {
            char macAddress[18];
            snprintf(macAddress, sizeof(macAddress), "%.2X:%.2X:%.2X:%.2X:%.2X:%.2X",
                adapter->Address[0], adapter->Address[1], adapter->Address[2],
                adapter->Address[3], adapter->Address[4], adapter->Address[5]);
            return macAddress;
        }
    }
#else
    struct ifaddrs *ifaddr, *ifa;
    if (getifaddrs(&ifaddr) == -1) {
        return "";
    }

    for (ifa = ifaddr; ifa != nullptr; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == nullptr || ifa->ifa_addr->sa_family != AF_PACKET) {
            continue;
        }
        
        struct sockaddr_ll *s = reinterpret_cast<struct sockaddr_ll*>(ifa->ifa_addr);
        char macAddress[18];
        snprintf(macAddress, sizeof(macAddress), "%.2X:%.2X:%.2X:%.2X:%.2X:%.2X",
            s->sll_addr[0], s->sll_addr[1], s->sll_addr[2],
            s->sll_addr[3], s->sll_addr[4], s->sll_addr[5]);
        freeifaddrs(ifaddr);
        return macAddress;
    }
    freeifaddrs(ifaddr);
#endif

    return "";
}

#endif // UTIL_H