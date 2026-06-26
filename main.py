"""
PacketMirror - Main Entry Point
Run all phases: Sniff → Profile → Detect
"""

import sys
import os

sys.path.insert(0, os.path.dirname(__file__))

from src.sniffer import start_sniffing
from src.profiler import init_db, load_packets, build_profiles, save_profiles, show_profiles
from src.detector import run_anomaly_detection


def main():
    print("""
  ____            _        _   __  __ _
 |  _ \ __ _  ___| | _____| |_|  \/  (_)_ __ _ __ ___  _ __
 | |_) / _` |/ __| |/ / _ \ __| |\/| | | '__| '__/ _ \| '__|
 |  __/ (_| | (__|   <  __/ |_| |  | | | |  | | | (_) | |
 |_|   \__,_|\___|_|\_\___|\__|_|  |_|_|_|  |_|  \___/|_|

 Passive Network Behavior Fingerprinter
    """)

    print("Select mode:")
    print("  1 - Sniff packets (Phase 1)")
    print("  2 - Build device profiles (Phase 2)")
    print("  3 - Run anomaly detection (Phase 3)")
    print("  4 - Run all phases")
    print()

    choice = input("Enter choice (1-4): ").strip()

    if choice == "1":
        count = input("How many packets to capture? [default: 200]: ").strip()
        count = int(count) if count.isdigit() else 200
        start_sniffing(packet_count=count)

    elif choice == "2":
        init_db()
        packets = load_packets()
        if packets:
            devices = build_profiles(packets)
            save_profiles(devices)
            show_profiles()

    elif choice == "3":
        run_anomaly_detection()

    elif choice == "4":
        print("\n[Phase 1] Starting sniffer...")
        start_sniffing(packet_count=200)
        print("\n[Phase 2] Building profiles...")
        init_db()
        packets = load_packets()
        if packets:
            devices = build_profiles(packets)
            save_profiles(devices)
            show_profiles()
        print("\n[Phase 3] Running anomaly detection...")
        run_anomaly_detection()

    else:
        print("Invalid choice. Run again.")


if __name__ == "__main__":
    main()