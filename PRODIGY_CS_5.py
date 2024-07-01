from scapy.all import *

def packet_callback(packet):
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        proto = packet[IP].proto
        print(f"Source IP: {src_ip}, Destination IP: {dst_ip}, Protocol: {proto}")
    elif packet.haslayer(TCP):
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
        flags = packet[TCP].flags
        print(f"Source Port: {src_port}, Destination Port: {dst_port}, Flags: {flags}")
    elif packet.haslayer(UDP):
        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport
        print(f"Source Port: {src_port}, Destination Port: {dst_port}")
    elif packet.haslayer(DNS):
        qname = packet[DNS].qd.qname
        print(f"DNS Query: {qname}")

sniff(prn=packet_callback, filter="ip or tcp or udp or dns", store=False)