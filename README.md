# PacketMirror

A passive network behavior fingerprinting tool that monitors devices on a local network and uses **Isolation Forest** (unsupervised ML) to detect anomalous or potentially spoofed devices — without sending a single active probe.

---

## How it works

**Phase 1 — Sniff:** Passively captures packets (ARP, DNS, TCP/UDP) and logs per-device metadata: MAC address, TTL, TCP window size, DNS queries, packet length.

**Phase 2 — Profile:** Builds a behavioral baseline per device stored in SQLite.

**Phase 3 — Detect:** Runs Isolation Forest on device feature vectors to flag anomalous devices.

---

## Demo Output

![PacketMirror Demo](demo.png) <img width="554" height="216" alt="PacketMirror Demo Output" src="https://github.com/user-attachments/assets/1e57ba74-933a-4a4f-8d3b-ea8635f0f2d4" />


---

## Setup

```bash
git clone https://github.com/Aqsa819/PacketMirror.git
cd PacketMirror
pip install -r requirements.txt
python main.py
```

## Tech Stack

| Tool | Purpose |
|---|---|
| Python 3.11+ | Core language |
| Scapy | Passive packet capture |
| scikit-learn | Isolation Forest |
| SQLite | Device profiles |
| Rich | CLI dashboard |

## Author

**[Aqsa Ghaffar]** — Information and Communication Engineering, The Islamia University of Bahawalpur
