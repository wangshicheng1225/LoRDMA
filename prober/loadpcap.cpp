#include "loadpcap.h"
#include <fstream>
#include <iostream>
#include <arpa/inet.h>

// PCAP file header
struct PcapHeader {
    uint32_t magic_number;
    uint16_t version_major;
    uint16_t version_minor;
    int32_t thiszone;
    uint32_t sigfigs;
    uint32_t snaplen;
    uint32_t network;
};

// Packet header structure
struct PacketHeader {
    uint32_t ts_sec;
    uint32_t ts_usec;
    uint32_t incl_len;
    uint32_t orig_len;
};

// Ethernet frame header structure
struct EthernetHeader {
    uint8_t dest_mac[6];
    uint8_t src_mac[6];
    uint16_t ether_type;
};

// IPv4 packet header structure
struct IPv4Header {
    uint8_t version_and_header_length;
    uint8_t dscp_and_ecn;
    uint16_t total_length;
    uint16_t identification;
    uint16_t flags_and_fragment_offset;
    uint8_t time_to_live;
    uint8_t protocol;
    uint16_t checksum;
    uint32_t source_ip;
    uint32_t dest_ip;
};

void print_mac_address(const uint8_t* mac_address) {
    printf("%02X:%02X:%02X:%02X:%02X:%02X", mac_address[0], mac_address[1], mac_address[2], mac_address[3], mac_address[4], mac_address[5]);
}

void print_ip_address(uint32_t ip_address) {
    struct in_addr addr;
    addr.s_addr = ip_address;
    printf("%s", inet_ntoa(addr));
}

void process_packet_data(const char* packet_data) {
    const EthernetHeader* eth_header = reinterpret_cast<const EthernetHeader*>(packet_data);
    const IPv4Header* ip_header = reinterpret_cast<const IPv4Header*>(packet_data + sizeof(EthernetHeader));

    std::cout << "Source MAC: ";
    print_mac_address(eth_header->src_mac);
    std::cout << std::endl;

    std::cout << "Destination MAC: ";
    print_mac_address(eth_header->dest_mac);
    std::cout << std::endl;

    std::cout << "Source IP: ";
    print_ip_address(ip_header->source_ip);
    std::cout << std::endl;

    std::cout << "Destination IP: ";
    print_ip_address(ip_header->dest_ip);
    std::cout << std::endl;
}

PacketData load_pcap(const char* filename, int n) {
    std::ifstream file(filename, std::ios::binary);
    PacketData result = {nullptr, 0};
    // result.data = nullptr;
    // result.length = 0;
    // {nullptr, 0};

    if (!file.is_open()) {
        std::cerr << "Error opening pcap file" << std::endl;
        return result;
    }

    // Read PCAP file header
    PcapHeader pcap_header;
    file.read(reinterpret_cast<char*>(&pcap_header), sizeof(PcapHeader));

    // Move to the n-th packet
    for (int i = 0; i < n - 1; i++) {
        PacketHeader packet_header;
        file.read(reinterpret_cast<char*>(&packet_header), sizeof(PacketHeader));
        file.seekg(packet_header.incl_len, std::ios::cur);
    }

    // Read the n-th packet
    PacketHeader packet_header;
    file.read(reinterpret_cast<char*>(&packet_header), sizeof(PacketHeader));
    if (file.eof()) {
        std::cerr << "Packet " << n << " not found in pcap file." << std::endl;
        return result;
    }

    // Allocate memory and copy packet data to char*
    char* packet_data = new char[packet_header.incl_len];
    file.read(packet_data, packet_header.incl_len);

    file.close();

    result.data = packet_data;
    result.length = packet_header.incl_len;

    return result;
}




// int main() {
//     const char* pcap_filename = "your_pcap_file.pcap";
//     int packet_number = 1;

//     char* packet_data = load_pcap(pcap_filename, packet_number);
//     if (packet_data != nullptr) {
//         std::cout << "Packet " << packet_number << " data: " << std::endl;
//         process_packet_data(packet_data); // Print source/destination MAC and IP addresses
//         delete[] packet_data;
//     }

//     return 0;
// }