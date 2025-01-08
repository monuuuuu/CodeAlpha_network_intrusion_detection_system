from scapy.all import sniff, IP, TCP, Raw

# Define the network interface to capture packets from
interface = "eth0"  # Replace with your active interface

# Intrusion detection rules
def check_rules(packet):
    try:
        if packet.haslayer(IP) and packet.haslayer(TCP):
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            dst_port = packet[TCP].dport

            # Rule 1: Detect HTTP traffic to a specific IP
            if dst_ip == "192.168.1.100" and dst_port == 80:
                print(f"[ALERT] Potential HTTP attack detected! SRC: {src_ip}, DST: {dst_ip}, PORT: {dst_port}")

            # Rule 2: Detect traffic from blacklisted IPs
            blacklist = ["10.0.0.5", "172.16.0.7"]
            if src_ip in blacklist:
                print(f"[ALERT] Blacklisted IP detected! SRC: {src_ip}")

            # Rule 3: Detect abnormal high-port usage
            if dst_port > 1024:
                print(f"[ALERT] Unusual high-port traffic detected! SRC: {src_ip}, DST: {dst_ip}, PORT: {dst_port}")

            # Rule 4: Inspect raw payload
            if packet.haslayer(Raw):
                payload = packet[Raw].load.decode(errors="ignore")
                if "malicious" in payload:
                    print(f"[ALERT] Suspicious payload detected! SRC: {src_ip}, PAYLOAD: {payload}")

    except Exception as e:
        print(f"Error processing packet: {e}")

# Start sniffing packets
def start_sniffer():
    print(f"Starting packet capture on interface: {interface}")
    sniff(iface=interface, prn=check_rules, filter="tcp", store=False)

if __name__ == "__main__":
    try:
        start_sniffer()
    except KeyboardInterrupt:
        print("\nSniffing stopped by user.")
    except Exception as e:
        print(f"Error: {e}")
