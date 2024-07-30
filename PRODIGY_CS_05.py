from scapy.all import sniff, IP, TCP, UDP
import sys

def packet_callback(packet):
    # Check if the packet has an IP layer
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        proto = packet[IP].proto

        # Protocols: 6 = TCP, 17 = UDP
        if proto == 6 and TCP in packet:
            protocol = "TCP"
            payload = bytes(packet[TCP].payload).decode('utf-8', errors='ignore')
        elif proto == 17 and UDP in packet:
            protocol = "UDP"
            payload = bytes(packet[UDP].payload).decode('utf-8', errors='ignore')
        else:
            protocol = "Other"
            payload = None

        print(f"Source IP: {ip_src}")
        print(f"Destination IP: {ip_dst}")
        print(f"Protocol: {protocol}")
        if payload:
            print(f"Payload: {payload}")
        print("\n" + "-"*50 + "\n")

def main():
    print("Starting packet sniffer...")
    try:
        # Start sniffing (use iface parameter to specify the interface)
        sniff(prn=packet_callback, store=0)
    except KeyboardInterrupt:
        print("Packet sniffer stopped.")
        sys.exit(0)

if __name__ == "__main__":
    main()
