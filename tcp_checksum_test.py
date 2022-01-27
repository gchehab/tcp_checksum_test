#! /usr/bin/env python
from scapy.all import *
from pprint import pprint as pp

hashes={}

# Create a sequence of numbers whose binary representations differs only by 16-bit
for i in range (0,655350,65535):
    packet = IP(dst='localhost', src='localhost')/TCP(sport=1,dport=2)/Raw(i.to_bytes(1000,'big'),)
    packet = IP(raw(packet))

    checksum_scapy = hex(packet[TCP].chksum)

    hashes[checksum_scapy] = hashes[checksum_scapy] + 1 if checksum_scapy in hashes else 1

print ('Total different checksums: %d'%len(hashes))
print ('Checksums: number of times it was generated:')
pp(hashes)