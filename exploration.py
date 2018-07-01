from scapy.all import *

# rdpcap comes from scapy and loads in our pcap file
packets = rdpcap('example.pcap')

connections = set()

for packet in packets:
    if 'IP' in packet:
        ip_layer = packet['IP']
        connections.add((ip_layer.src, 
                         ip_layer.dst, 
                         ip_layer.dport))

print(connections)