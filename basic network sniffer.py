from scapy.all import sniff

def packet_callback(packet):
    # Print packet summary
    print(packet.summary())

# Capture packets on all interfaces
sniff(prn=packet_callback, count=10)
sniff(filter="tcp", prn=packet_callback, count=10)

def packet_callback(packet):
    if packet.haslayer(TCP):
        print(f"Source IP: {packet[IP].src}")
        print(f"Destination IP: {packet[IP].dst}")
        print(f"Source Port: {packet[TCP].sport}")
        print(f"Destination Port: {packet[TCP].dport}")
        print(f"Payload: {packet[TCP].payload}")
