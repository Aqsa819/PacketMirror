import sqlite3
import os

DB_FILE = 'data/profiles.db'

def run_anomaly_detection():
    print('=== Anomaly Detection ===')
    if not os.path.exists(DB_FILE):
        print('[ERROR] No profiles found. Run Phase 2 first.')
        return
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('SELECT mac, avg_ttl, avg_tcp_window, avg_packet_length FROM device_profiles')
    rows = c.fetchall()
    conn.close()
    if len(rows) < 2:
        print('[WARN] Need at least 2 devices.')
        return
    lengths = [r[3] for r in rows]
    avg = sum(lengths) / len(lengths)
    print(f'Average packet length across devices: {avg:.2f}')
    print()
    for row in rows:
        mac, ttl, win, pkt_len = row
        diff = abs(pkt_len - avg)
        status = 'ANOMALY' if diff > avg * 0.5 else 'NORMAL'
        print(f'MAC: {mac} | Pkt Len: {pkt_len} | Status: {status}')

if __name__ == '__main__':
    run_anomaly_detection()
