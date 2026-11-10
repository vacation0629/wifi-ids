# 📡 Kismet + Wi-Fi IDS v2.1.2 Integration Guide
## Enterprise Wireless Intrusion Detection Architecture for Kali Linux

**Document:** `Document/KISMET_INTEGRATION_GUIDE.md`  
**Target Platform:** Kali Linux 2024.x+, Debian 12+, Raspberry Pi 4 / Pi 5 (ARM64)  
**Software Stack:** Kismet (C++ Capture Engine) + Wi-Fi IDS v2.1.2 (AI/ML Hybrid Brain)  

---

## 1. Architectural Synergy: Why Use Kismet with IDS v2.1.2?

Using Kismet as the physical data collection layer combined with the v2.1.2 Hybrid Risk Engine delivers a carrier-grade wireless intrusion detection system:

```
┌───────────────────────────────────────────────────────────────────────────────────┐
│                           AIRWAVES (2.4 GHz / 5 GHz / 6 GHz)                      │
└─────────────────────────────────────────┬─────────────────────────────────────────┘
                                          │ Raw IEEE 802.11 RF Signals
                                          ▼
┌───────────────────────────────────────────────────────────────────────────────────┐
│                            KISMET WIRELESS SERVER (C++)                           │
│  • Hardware Driver & Monitor Mode Abstraction                                     │
│  • High-Speed Multi-Channel Hopping (Ch 1-14, 36-165)                             │
│  • Wire-Speed 802.11 De-duplication & Radio Signal Tracking                       │
│  • Local REST API & Device Catalog (:2501)                                        │
└─────────────────────────────────────────┬─────────────────────────────────────────┘
                                          │ Live Device JSON Stream (REST API / WebSocket)
                                          ▼
┌───────────────────────────────────────────────────────────────────────────────────┐
│                   WI-FI IDS v2.1.2 - HYBRID RISK PIPELINE                         │
│  • kismet_connector.py: Translates Kismet JSON telemetry to Pipeline Frames       │
│  • Tier 1: Whitelist Hash Lookup & Physical Integrity (< 0.002 ms)                │
│  • Tier 2: XGBoost 50-Tree Orthographic Screener (Typos/Homoglyphs)               │
│  • Tier 2.5: BAAI/bge-small-en-v1.5 Semantic Screener (Zero-Overlap Lures)        │
│  • Track 4A: Tag 3 vs Radio Channel Spoof & Seq/TSF Collision Check               │
│  • Track 4B: Strict Timing Jitter & Campus IE Blueprint Matching                  │
│  • Stage 5: Hybrid Risk Score (0-100) & Coalesced SQLite WAL Logging              │
└─────────────────────────────────────────┬─────────────────────────────────────────┘
                                          │
                                          ▼
┌───────────────────────────────────────────────────────────────────────────────────┐
│                      LIVE SOC WEB ALERT DASHBOARD (PORT 8080)                     │
│  • Real-time Threat Tiers: CRITICAL HIGH (>=70) / MEDIUM (>=30) / LOW (Safe)      │
│  • One-Click AP Authorization & Manual Whitelist Management                       │
└───────────────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Step-by-Step Installation on Kali Linux

### Step 1: Install Kismet
On Kali Linux, Kismet is available directly from official APT repositories:

```bash
sudo apt update
sudo apt install -y kismet wireless-tools
```

### Step 2: Grant Non-Root Capture Permissions
Add your user to the `kismet` user group so it can put interfaces into monitor mode without requiring full root privileges:

```bash
sudo usermod -aG kismet $USER
# Log out and log back in, or run:
newgrp kismet
```

### Step 3: Install Wi-Fi IDS v2.1.2 in Kali venv
From this project directory, run the automated provisioner:

```bash
chmod +x setup_kali_venv.sh run_kali_ids.sh
./setup_kali_venv.sh
```

---

## 3. Launching the System

### Step 1: Start Kismet Server in Background
Run Kismet with your wireless card (e.g. `wlan0` or external USB adapter):

```bash
# Headless Server Mode (Recommended for Dedicated Scanners & Raspberry Pi)
kismet --no-ncurses -c wlan0
```

*(Kismet will automatically set `wlan0` into monitor mode, start hopping channels, and host its REST API at `http://localhost:2501`)*

### Step 2: Start Wi-Fi IDS v2.1.2 in Kismet Mode
In a separate terminal (or background service), start the IDS:

```bash
./run_kali_ids.sh --mode kismet --kismet-url http://localhost:2501 --web-port 8080
```

*Output:*
```text
[*] Activating virtual environment: /home/kali/Rogue wifi/venv
[*] Initializing Wi-Fi IDS v2.1.2 Pipeline...
    SQLite Database : /home/kali/Rogue wifi/detector/wifi_ids_v2.db
    Whitelist Size  : 7 authorized SSIDs
[+] Live Alert Dashboard active at: http://0.0.0.0:8080
[*] Initializing Kismet Live Bridge...
    Kismet URL : http://127.0.0.1:2501
[+] Kismet v2024-02-R1 online (Server Time: 1731215432)
[+] Kismet Bridge active! Polling every 1.5s...
[+] Live Alert Dashboard: http://localhost:8080
```

---

## 4. Kismet Authentication Options

By default, modern Kismet sets up a random admin password stored in `~/.kismet/kismet_httpd.conf`. The IDS supports all Kismet authentication modes:

### Option A: Using Kismet API Key (Recommended)
Generate an API key in Kismet Web UI (`Settings -> API Keys`), then run:
```bash
./run_kali_ids.sh --mode kismet --kismet-key "YOUR_KISMET_API_KEY"
```

### Option B: Using Username & Password
```bash
./run_kali_ids.sh --mode kismet --kismet-user "admin" --kismet-pass "YOUR_PASSWORD"
```

### Option C: Disable Kismet Authentication (For Localhost Only)
If you only access Kismet locally, you can disable authentication by editing `/etc/kismet/kismet_httpd.conf`:
```conf
httpd_auth=false
```
Then run `./run_kali_ids.sh --mode kismet` with no credentials needed.

---

## 5. Systemd Automated Service for Kismet + IDS

To run both Kismet and the IDS continuously on boot (e.g., on a Raspberry Pi):

### 1. Enable Kismet Service:
```bash
sudo systemctl enable kismet
sudo systemctl start kismet
```

### 2. Configure `/etc/systemd/system/wifi-ids.service`:
```ini
[Unit]
Description=Wi-Fi IDS v2.1.2 Kismet AI Bridge
After=network.target kismet.service
Requires=kismet.service

[Service]
Type=simple
User=kali
WorkingDirectory=/opt/wifi-ids
ExecStart=/opt/wifi-ids/run_kali_ids.sh --mode kismet --kismet-url http://127.0.0.1:2501 --web-port 8080
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable wifi-ids
sudo systemctl start wifi-ids
```

---

## 6. Real-Time Telemetry Mapping Reference

| Kismet JSON Field | IDS v2.1.2 Pipeline Field | Behavioral Detection Track |
| :--- | :--- | :--- |
| `kismet.device.base.macaddr` | `bssid` | BSSID LRU Cache & Whitelist Pinning |
| `dot11.device.advertised_ssid_map` | `ssid` | Stage 1 & 2: XGBoost + BGE-small Screener |
| `kismet.device.base.channel` | `radio_channel` | Track 4A: Multi-channel clone tracker |
| `dot11.device.beacon_channel` | `tag3_channel` | Track 4A: Tag 3 vs Radio Channel Spoof (+45 pts) |
| `dot11.device.last_seq` | `seq_num` | Track 4A: Same-channel sequence collision (+45 pts) |
| `dot11.device.last_beacon_timestamp` | `tsf_timestamp` | Track 4B: Microsecond timing jitter ($>20\text{ ms} \implies +20\text{ pts}$) |
| `kismet.common.signal.last_signal_dbm` | `rssi` | Track 4B: RSSI range volatility ($>15\text{ dB} \implies +20\text{ pts}$) |
| `kismet.device.base.crypt` | `encryption_type` | Stage 2.5: Dynamic PSK Attenuation ($0.5 \times \text{bge}$) |
| `dot11.device.num_deauth_packets` | `deauth_burst` | Pre-Stage-0: Deauth flood detector ($\ge 15/10\text{ s} \implies \text{Floor HIGH}$) |
