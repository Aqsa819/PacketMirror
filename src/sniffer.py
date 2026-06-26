"""
PacketMirror - Passive Network Behavior Fingerprinter
Phase 1: Packet Sniffer
Captures ARP, DNS, TCP/UDP metadata per device (MAC address)
"""

from scapy.all import sniff, ARP, DNS, IP, TCP, UDP, Ether
from datetime import datetime
import json
import os

LOG_FILE = "data/captured_packets.json"
captured = []


def process_packet(packet):
    record = {
        "timestamp": datetime.now().isoformat(),
        "mac": None,
        "ip_src": None,
        "ip_dst": None,
        "protocol": None,
        "ttl": None,
        "tcp_window": None,
        "dns_query": None,
        "length": len(packet),
    }

    # Extract MAC address
    if packet.haslayer(Ether):
        record["mac"] = packet[Ether].src

    # Extract IP info
    if packet.haslayer(IP):
        record["ip_src"] = packet[IP].src
        record["ip_dst"] = packet[IP].dst
        record["ttl"] = packet[IP].ttl

    # Protocol detection
    if packet.haslayer(TCP):
        record["protocol"] = "TCP"
        record["tcp_window"] = packet[TCP].window
    elif packet.haslayer(UDP):
        record["protocol"] = "UDP"
    elif packet.haslayer(ARP):
        record["protocol"] = "ARP"
        record["mac"] = packet[ARP].hwsrc
        record["ip_src"] = packet[ARP].psrc

    # DNS query extraction
    if packet.haslayer(DNS) and packet[DNS].qr == 0:
        try:
            record["dns_query"] = packet[DNS].qd.qname.decode()
        except Exception:
            pass

    # Only save records with a MAC address
    if record["mac"]:
        captured.append(record)
        print(f"[{record['timestamp']}] MAC: {record['mac']} | Proto: {record['protocol']} | IP: {record['ip_src']}")
        save_to_file(record)


def save_to_file(record):
    os.makedirs("data", exist_ok=True)
    with open(LOG_FILE, "a") as f:
        f.write(json.dumps(record) + "\n")


def start_sniffing(interface=None, packet_count=100):
    print("=" * 55)
    print("  PacketMirror — Passive Network Behavior Sniffer")
    print("=" * 55)
    print(f"Capturing {packet_count} packets... Press Ctrl+C to stop.\n")

    try:
        sniff(
            iface=interface,
            prn=process_packet,
            count=packet_count,
            store=False,
            filter="ip or arp"
        )
    except KeyboardInterrupt:
        print("\n[!] Sniffing stopped by user.")
    except Exception as e:
        print(f"[ERROR] {e}")
        print("[HINT] Try running as administrator / sudo")

    print(f"\n[+] Captured {len(captured)} packets. Saved to {LOG_FILE}")


if __name__ == "__main__":
    start_sniffing(interface=None, packet_count=200)