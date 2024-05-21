from scapy.all import sniff, IP, TCP, UDP
import datetime

# Function to analyze packets
def analyze_packet(packet):
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        protocol = packet[IP].proto
        timestamp = datetime.datetime.now()

        # Check for TCP/UDP packets
        if protocol == 6:  # TCP
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            print(f"[{timestamp}] TCP Packet: {ip_src}:{src_port} -> {ip_dst}:{dst_port}")
        elif protocol == 17:  # UDP
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
            print(f"[{timestamp}] UDP Packet: {ip_src}:{src_port} -> {ip_dst}:{dst_port}")
        else:
            print(f"[{timestamp}] Other IP Packet: {ip_src} -> {ip_dst}")

# Function to start sniffing packets
def start_sniffing(interface):
    print(f"[*] Starting packet capture on {interface}...")
    sniff(iface=interface, prn=analyze_packet, store=False)

# Main function
def main():
    interface = input("Enter the network interface to sniff on (e.g., eth0, wlan0): ")
    start_sniffing(interface)

if __name__ == "__main__":
    main()