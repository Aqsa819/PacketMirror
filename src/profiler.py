"""
PacketMirror - Passive Network Behavior Fingerprinter
Phase 2: Device Profile Builder
Reads captured packet logs and builds per-device behavioral profiles
"""

import json
import sqlite3
import os
from collections import defaultdict

LOG_FILE = "data/captured_packets.json"
DB_FILE = "data/profiles.db"


def init_db():
    os.makedirs("data", exist_ok=True)
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS device_profiles (
            mac TEXT PRIMARY KEY,
            avg_ttl REAL,
            avg_tcp_window REAL,
            avg_packet_length REAL,
            packet_count INTEGER,
            dns_queries TEXT,
            protocols TEXT,
            last_seen TEXT
        )
    """)
    conn.commit()
    conn.close()
    print("[+] Database initialized.")


def load_packets():
    if not os.path.exists(LOG_FILE):
        print(f"[ERROR] No captured data found at {LOG_FILE}")
        print("[HINT] Run sniffer.py first to capture packets.")
        return []

    packets = []
    with open(LOG_FILE, "r") as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    packets.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    print(f"[+] Loaded {len(packets)} packets from log.")
    return packets


def build_profiles(packets):
    devices = defaultdict(lambda: {
        "ttls": [], "tcp_windows": [], "lengths": [],
        "dns_queries": set(), "protocols": set(), "last_seen": None
    })

    for pkt in packets:
        mac = pkt.get("mac")
        if not mac:
            continue

        d = devices[mac]
        if pkt.get("ttl"):
            d["ttls"].append(pkt["ttl"])
        if pkt.get("tcp_window"):
            d["tcp_windows"].append(pkt["tcp_window"])
        if pkt.get("length"):
            d["lengths"].append(pkt["length"])
        if pkt.get("dns_query"):
            d["dns_queries"].add(pkt["dns_query"])
        if pkt.get("protocol"):
            d["protocols"].add(pkt["protocol"])
        if pkt.get("timestamp"):
            d["last_seen"] = pkt["timestamp"]

    return devices


def save_profiles(devices):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()

    for mac, d in devices.items():
        avg_ttl = sum(d["ttls"]) / len(d["ttls"]) if d["ttls"] else 0
        avg_win = sum(d["tcp_windows"]) / len(d["tcp_windows"]) if d["tcp_windows"] else 0
        avg_len = sum(d["lengths"]) / len(d["lengths"]) if d["lengths"] else 0

        c.execute("""
            INSERT OR REPLACE INTO device_profiles
            (mac, avg_ttl, avg_tcp_window, avg_packet_length, packet_count, dns_queries, protocols, last_seen)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            mac,
            round(avg_ttl, 2),
            round(avg_win, 2),
            round(avg_len, 2),
            len(d["lengths"]),
            ", ".join(d["dns_queries"]),
            ", ".join(d["protocols"]),
            d["last_seen"]
        ))

    conn.commit()
    conn.close()
    print(f"[+] Saved {len(devices)} device profiles to {DB_FILE}")


def show_profiles():
    if not os.path.exists(DB_FILE):
        print("[ERROR] No profiles database found. Run build first.")
        return

    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT * FROM device_profiles")
    rows = c.fetchall()
    conn.close()

    print("\n" + "=" * 60)
    print("  Device Profiles")
    print("=" * 60)
    for row in rows:
        print(f"\nMAC:          {row[0]}")
        print(f"Avg TTL:      {row[1]}")
        print(f"Avg TCP Win:  {row[2]}")
        print(f"Avg Pkt Len:  {row[3]}")
        print(f"Packet Count: {row[4]}")
        print(f"Protocols:    {row[6]}")
        print(f"Last Seen:    {row[7]}")


if __name__ == "__main__":
    init_db()
    packets = load_packets()
    if packets:
        devices = build_profiles(packets)
        save_profiles(devices)
        show_profiles()
