import sys
import os
sys.path.insert(0, os.path.dirname(__file__))
from src.sniffer import start_sniffing
from src.profiler import init_db, load_packets, build_profiles, save_profiles, show_profiles
from src.detector import run_anomaly_detection

def main():
    print('=== PacketMirror ===')
    print('1 - Sniff packets')
    print('2 - Build device profiles')
    print('3 - Run anomaly detection')
    print('4 - Run all phases')
    choice = input('Enter choice (1-4): ').strip()
    if choice == '1':
        start_sniffing(packet_count=200)
    elif choice == '2':
        init_db()
        packets = load_packets()
        if packets:
            devices = build_profiles(packets)
            save_profiles(devices)
            show_profiles()
    elif choice == '3':
        run_anomaly_detection()
    elif choice == '4':
        start_sniffing(packet_count=200)
        init_db()
        packets = load_packets()
        if packets:
            devices = build_profiles(packets)
            save_profiles(devices)
            show_profiles()
        run_anomaly_detection()
    else:
        print('Invalid choice')

if __name__ == '__main__':
    main()
