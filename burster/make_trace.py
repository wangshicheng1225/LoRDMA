#!/usr/bin/python
from scapy.all import *



pcap_filepath = "replay.pcap"


with PcapWriter(pcap_filepath) as pcap:
     for j in range(4):
          for i in range(1,255):
               p = (Ether(src='08:c0:eb:6f:a8:ba', dst='0c:42:a1:a4:94:00') /
                    IP(src='10.0.0.135', dst='10.0.0.136') /
                    UDP(sport=50000+i, dport=4791))
               pcap.write(p / Raw('\x0a' * (1500 - len(p))))