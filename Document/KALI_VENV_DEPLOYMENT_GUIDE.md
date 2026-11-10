# 🐉 Kali Linux Virtual Environment (venv) Deployment Guide
## Edge Wi-Fi Evil Twin & Rogue AP Detection Framework (v2.1.2)

**Repository:** `D:\Antigravity Project\Rogue wifi`  
**Target Environments:** Kali Linux 2024.x+, Debian 12+, Raspberry Pi OS (Pi 4 / Pi 5 ARM64), Docker (`kali-detector`)  
**Compliance:** PEP 668 (Externally Managed Environments), IEEE 802.11-2020 Standards, SQLite WAL Mode  

---

## 1. Quick Start (One-Liner Turnkey Setup)

On your Kali Linux machine or terminal, execute the automated provisioner:

```bash
chmod +x setup_kali_venv.sh run_kali_ids.sh
./setup_kali_venv.sh
```

The script will automatically:
1. Detect system packages and install prerequisites (`python3-venv`, `python3-pip`, `libpcap-dev`, `wireless-tools`).
2. Create an isolated virtual environment (`./venv`).
3. Install production dependencies (`numpy`, `xgboost`, `fastembed`, `scapy`, `requests`).
4. Pre-download the FastEmbed BAAI/bge-small-en-v1.5 model weights into local cache.
5. Execute [`detector/validate_kali_env.py`](file:///d:/Antigravity%20Project/Rogue%20wifi/detector/validate_kali_env.py) to guarantee 100% pipeline integrity.

---

## 2. Directory Structure of Kali Deployment Assets

```
Rogue wifi/
├── setup_kali_venv.sh             # Turnkey venv provisioning script
├── run_kali_ids.sh                # Production runtime launcher
├── wifi-ids.service               # Systemd daemon service definition
├── detector/
│   ├── kali_ids_service.py        # Master Daemon (UDP + Scapy Sniffer + Web UI)
│   ├── validate_kali_env.py       # Health check & smoke-test validator
│   ├── requirements-kali.txt      # Pinned Python package dependencies
│   ├── Dockerfile.kali            # Modernized Kali Docker image definition
│   ├── whitelist.json             # Authorized Campus/Enterprise SSID list
│   ├── wifi_ids_v2.db             # SQLite WAL Mode IDS database
│   └── ids_v2/                    # Modular v2.1.2 Engine
│       ├── config.py              # Risk thresholds and constants
│       ├── db_manager.py          # SQLite WAL schema & LRU cache
│       ├── name_screener.py       # XGBoost + FastEmbed BGE-small
│       ├── track_4a_state.py      # Deauth demux & channel clone tracker
│       ├── track_4b_beacon.py     # Timing jitter & IE fingerprint analyzer
│       ├── risk_engine.py         # 0-100 hybrid risk scoring engine
│       └── pipeline.py            # End-to-end 802.11 frame coordinator
```

---

## 3. Operational Running Modes

### Mode A: UDP Socket Listener (Default - Port 5555)
Used for virtual laboratory simulations, Docker setups, or receiving forwarded 802.11 frames from remote forwarders over the local network:

```bash
./run_kali_ids.sh --mode udp --port 5555 --web-port 8080
```

### Mode B: Physical Wi-Fi Monitor Mode Sniffing (Live Airwaves)
Used with an external USB Wi-Fi adapter (Alfa AWUS036ACH, RTL8812AU, MT7612U) on a physical Kali laptop or Raspberry Pi:

1. **Put Wireless Card into Monitor Mode:**
   ```bash
   sudo airmon-ng check kill
   sudo airmon-ng start wlan0
   # Confirm interface name (usually wlan0mon)
   iwconfig
   ```

2. **Launch IDS with Monitor Interface:**
   ```bash
   sudo ./run_kali_ids.sh --mode live --interface wlan0mon --web-port 8080
   ```

### Mode C: Self-Test / Demo Verification Mode
Injects synthetic authorized, rogue, homoglyph, and deauth burst frames to verify detection alarms and web dashboard visualization:

```bash
./run_kali_ids.sh --mode test --web-port 8080
```

---

## 4. Live SOC Alert Dashboard (Port 8080)

Once launched, open your web browser to:
**`http://localhost:8080`** (or `http://<kali-ip>:8080`)

### Dashboard Capabilities:
* **Real-time Threat Tiers:** Color-coded badges for `HIGH` (Red, Score $\ge 70$), `MEDIUM` (Amber, Score $\ge 30$), and `LOW` (Green, Safe).
* **Multi-Vector Telemetry:** Live display of BSSID, SSID name mutation alerts, XGBoost probability, BGE-small cosine distance, and encryption type.
* **Instant Whitelist Authorization:** One-click `+ Authorize` and `Revoke` buttons to mark legitimate physical access points on the fly.
* **Zero Overhead:** Embedded HTTP server with non-blocking SQLite WAL querying.

---

## 5. Automated Systemd Service (Start on Boot)

To run the Wi-Fi IDS continuously in the background on a Raspberry Pi or dedicated Kali appliance:

1. **Copy Project Directory to `/opt/wifi-ids`:**
   ```bash
   sudo cp -r . /opt/wifi-ids
   cd /opt/wifi-ids
   sudo ./setup_kali_venv.sh
   ```

2. **Install and Enable Systemd Service:**
   ```bash
   sudo cp wifi-ids.service /etc/systemd/system/
   sudo systemctl daemon-reload
   sudo systemctl enable wifi-ids
   sudo systemctl start wifi-ids
   ```

3. **Check Service Status & Logs:**
   ```bash
   sudo systemctl status wifi-ids
   sudo journalctl -u wifi-ids -f
   ```

---

## 6. Docker Container Deployment

If running within Docker on Kali ARM64 / x86_64:

```bash
# Build the updated Kali image
docker build -t kali-detector-arm64 -f detector/Dockerfile.kali ./detector

# Start the non-destructive container
docker compose start kali-detector
# or
docker compose -f docker-compose.consolidated.yml up -d
```

---

## 7. Troubleshooting & Verification

| Issue | Root Cause | Solution |
| :--- | :--- | :--- |
| `error: externally-managed-environment` | PEP 668 prevents global pip installs on Kali | Always use `./setup_kali_venv.sh` which provisions an isolated `venv`. |
| `No module named 'scapy'` | Scapy missing or venv not activated | Activate venv via `source venv/bin/activate` or execute via `./run_kali_ids.sh`. |
| `pcap_open_live: Permission denied` | Live sniffing requires raw socket capabilities | Run live mode with `sudo` (`sudo ./run_kali_ids.sh --mode live --interface wlan0mon`). |
| `FastEmbed download timeout` | Air-gapped network during deployment | Run `./setup_kali_venv.sh` once with internet access; it pre-caches the model for offline operation. |
