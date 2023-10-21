#ifndef LOADPCAP_H
#define LOADPCAP_H
#include <cstddef>
struct PacketData {
    char* data;
    size_t length;
};
PacketData load_pcap(const char* filename, int n);
void process_packet_data(const char* packet_data);
#endif // LOADPCAP_H
