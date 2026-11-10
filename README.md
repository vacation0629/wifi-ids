# 🛡️ Edge Wi-Fi Evil Twin & Rogue AP Detection Framework (v2.1.2)
### Carrier-Grade Wireless Intrusion Detection for Raspberry Pi 4/5 & Kali Linux

[![Platform](https://img.shields.io/badge/Platform-Raspberry%20Pi%204%2F5%20%7C%20Kali%20Linux%20ARM64%2Fx86__64-blue.svg)](#)
[![Python](https://img.shields.io/badge/Python-3.10%20%7C%203.11%20%7C%203.12%20%7C%203.13-brightgreen.svg)](#)
[![Capture](https://img.shields.io/badge/RF%20Sniffer-Kismet%20C%2B%2B%20%7C%20Scapy%20Raw%20802.11-orange.svg)](#)
[![RAM Usage](https://img.shields.io/badge/RAM%20Footprint-%3C%2040%20MB-success.svg)](#)
[![Tests](https://img.shields.io/badge/Unit%20Tests-100%2F100%20Passing-success.svg)](#)

---

## 1. System Overview

**Wi-Fi IDS v2.1.2** is a production-grade, low-overhead Wireless Intrusion Detection System (WIDS) designed to detect **Evil Twin APs, Wi-Fi Pineapples, Karma attacks, deauthentication floods, and orthographic homoglyph lures** on edge hardware (Raspberry Pi 4 / 5, embedded Kali Linux nodes).

By combining **Kismet's wire-speed C++ RF capture** with a multi-tiered **AI/ML risk pipeline** and an in-memory SQLite WAL database, the engine operates 24/7 without cloud dependency and with an active RAM footprint under **40 MB**.

---

## 2. End-to-End Architecture

```text
┌───────────────────────────────────────────────────────────────────────────────────┐
│                           AIRWAVES (2.4 GHz / 5 GHz / 6 GHz)                      │
└─────────────────────────────────────────┬─────────────────────────────────────────┘
                                          │ Raw IEEE 802.11 RF Beacons / Deauth
                                          ▼
┌───────────────────────────────────────────────────────────────────────────────────┐
│                            KISMET WIRELESS SERVER (C++)                           │
│  • Hardware Driver & Monitor Mode Abstraction                                     │
│  • Multi-Channel Hopping (Ch 1-14, 36-165) Across Bands                           │
│  • Wire-Speed 802.11 De-duplication & Radio Signal Tracking                       │
│  • Local REST API & Device Stream (:2501)                                         │
└─────────────────────────────────────────┬─────────────────────────────────────────┘
                                          │ Live Device JSON Stream
                                          ▼
┌───────────────────────────────────────────────────────────────────────────────────┐
│                   WI-FI IDS v2.1.2 - HYBRID RISK PIPELINE                         │
│  • Stage 0: Deauth & Disassociation Ingress Demultiplexer (Addr3 routing)         │
│  • Tier 1: Whitelist Hash Lookup & Physical Integrity Check (< 0.002 ms)          │
│  • Tier 2: 50-Tree XGBoost Orthographic Screener (Homoglyphs/Typos/Mutations)     │
│  • Tier 2.5: BAAI/bge-small-en-v1.5 Semantic Embeddings (Zero-Overlap Lures)      │
│  • Track 4A: Tag 3 vs Radio Channel Spoof & Sequence/TSF Collision Check          │
│  • Track 4B: Strict Arrival Jitter & Campus IE Blueprint Matching                 │
│  • Stage 5: Hybrid Risk Scoring (0-100) & Coalesced SQLite WAL Persistence        │
└─────────────────────────────────────────┬─────────────────────────────────────────┘
                                          │ Single Source of Truth (SQLite WAL)
                                          ▼
┌───────────────────────────────────────────────────────────────────────────────────┐
│                      LIVE SOC WEB ALERT DASHBOARD (PORT 8080)                     │
│  • Real-Time Threat Tiers: 🚨 HIGH (>=70) / ⚠️ MEDIUM (>=30) / ✓ LOW (Safe)       │
│  • Interactive Search Bar (SSID, BSSID MAC, Target Whitelist)                     │
│  • Multi-Criteria Filtering (Tier, Auth Status, Mutation)                         │
│  • Interactive Column Header Sorting & Quick-Sort Dropdown                        │
│  • One-Click AP Authorization & Manual Whitelist Management                       │
└───────────────────────────────────────────────────────────────────────────────────┘
```

---

## 3. Key Framework Capabilities

### ⚡ 5-Stage Hybrid Risk Engine
1. **Pre-Stage-0 Demux:** Ingests raw subtype `0x0C` (Deauth) and `0x0A` (Disassociation) management frames directly into a sliding-window rate tracker (triggers `HIGH +75 pts` floor on $\ge 15$ frames / 10s).
2. **Fast Whitelist Integrity:** Authorized BSSIDs matching legitimate SSIDs bypass heavy machine learning in $< 0.002\text{ ms}$ while continuously verifying physical Sequence Number / TSF monotonic integrity.
3. **50-Tree XGBoost Screener:** Orthographic feature extractor identifying leetspeak, homoglyphs, zero-width spaces, and character substitutions.
4. **Dynamic Stage 2.5 Semantic Screener:** Employs `BAAI/bge-small-en-v1.5` embeddings to catch zero-overlap semantic lures (e.g. `University Free WiFi` vs `eduroam`).
5. **Physical & Timing Track 4A/4B:**
   - Detects **IE Tag 3 (`DS Parameter Set`) vs physical radio channel** mismatches (common in software AP injectors).
   - Detects **multi-channel ping-pong clones** within a 15-second sliding expiration window.
   - Evaluates arrival jitter against an un-diluted $20\text{ ms}$ threshold ($102.4\text{ ms}$ standard TU beacon interval).

### 🖥️ Decoupled Web SOC Dashboard (Port 8080)
* **Single Source of Truth:** Completely decoupled from packet capture threads; reads 100% directly from SQLite WAL queries.
* **Instant Search:** Instant substring search across SSID, MAC Address, and Whitelist Target.
* **Filter By:** Threat Tier (`HIGH`, `MEDIUM`, `LOW`), Authorization (`AUTH`, `UNAUTH`), and Mutation.
* **Sorting:** Interactive clickable table headers (`▲` / `▼`) on all key columns with persistent UI state across auto-refreshes.

---

## 4. Raspberry Pi 4 / 5 Deployment Guide

The production engine footprint is under **450 KB** and installs cleanly into a PEP 668 compliant virtual environment.

### Step 1: Clone or Copy to Raspberry Pi
```bash
# Clone the repository
git clone https://github.com/YOUR_USER/YOUR_REPO.git wifi-ids
cd wifi-ids

# Or use Git Sparse-Checkout to download ONLY production files:
git sparse-checkout set detector setup_kali_venv.sh run_kali_ids.sh wifi-ids.service
```

### Step 2: Run the 1-Step Provisioner
```bash
chmod +x setup_kali_venv.sh run_kali_ids.sh
./setup_kali_venv.sh
```
*(Installs apt prerequisites `libpcap-dev`, `python3-venv`, creates `./venv`, installs pinned ARM64 wheels, and caches the offline BGE-small ONNX model).*

### Step 3: Run the Health Validator
```bash
./venv/bin/python detector/validate_kali_env.py
```
*(Confirms SQLite WAL, XGBoost loading, and BGE-small embedding execution with a 100% pass mark).*

### Step 4: Start Kismet & Wi-Fi IDS
```bash
# 1. Start Kismet in headless mode on your Wi-Fi interface (e.g. wlan0)
sudo kismet -c wlan0 --no-ncurses &

# 2. Start Wi-Fi IDS daemon connected to Kismet
./run_kali_ids.sh --mode kismet --kismet-url http://localhost:2501 --web-port 8080
```
Then open your browser to **`http://<PI_IP>:8080`** to access the SOC Dashboard.

---

## 5. Autostart on Pi Boot as an Appliance (Systemd)

To run the IDS automatically in the background whenever the Raspberry Pi powers on:

```bash
# Copy and enable the systemd service
sudo cp wifi-ids.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now wifi-ids

# Check live service status
sudo systemctl status wifi-ids
```

---

## 6. Directory Structure

```text
Rogue wifi/
├── run_kali_ids.sh              # Production service launcher
├── setup_kali_venv.sh           # Automated Kali / Pi venv provisioner
├── wifi-ids.service             # Systemd autostart unit for Pi
├── .gitignore                   # Git exclusion rules
├── AGENTS.md                    # Operational guidelines for AI agents
├── GEMINI.md                    # Zero-destruction safety policies
│
├── detector/                    # Core Production Engine (In Use)
│   ├── ids_v2/                  # AI/ML Pipeline & Risk Engine
│   │   ├── pipeline.py          # 5-Stage Orchestrator
│   │   ├── risk_engine.py       # Final Score Floor & Ceiling logic
│   │   ├── name_screener.py     # XGBoost + BGE-small embedder
│   │   ├── track_4a_state.py    # Tag 3 channel & Seq/TSF tracker
│   │   ├── track_4b_beacon.py   # IE Blueprint & timing jitter
│   │   ├── db_manager.py        # Coalesced SQLite WAL Batching
│   │   ├── config.py            # Whitelists & thresholds
│   │   └── models/              # Pre-trained models
│   │       └── xgb_ssid_model.json
│   ├── kali_ids_service.py      # Production Daemon
│   ├── kismet_connector.py      # Kismet REST API streaming bridge
│   ├── dashboard_server.py      # Decoupled Web SOC Dashboard (:8080)
│   ├── validate_kali_env.py     # 1-Step environment validator
│   ├── requirements-kali.txt    # Lean pip requirements
│   └── wifi_ids_v2.db           # Persistent SQLite database
│
├── local_llm/                   # AI Model Repository
│   ├── models/                  # Consolidated offline models
│   │   ├── Nemotron-Mini-4B-Instruct-Q4_K_M.gguf
│   │   ├── xgb_ssid_model.json
│   │   └── fastembed_cache/     # Cached ONNX embedding models
│   └── bin/                     # llama-server executable & Vulkan DLLs
│
├── tests/                       # Testing & Verification
│   ├── test_ids_v2/             # 100/100 passing unit test suite
│   └── simulation/              # Dev virtual UDP test harness
│       ├── docker-compose.yml
│       ├── docker-compose.consolidated.yml
│       └── clients/             # Synthetic packet generators
│
├── Document/                    # Architecture Specs & Guides
│   ├── WiFi_IDS_Framework_v2.1.2/ # Complete architectural specs
│   ├── KISMET_INTEGRATION_GUIDE.md # Kismet configuration walkthrough
│   ├── KALI_VENV_DEPLOYMENT_GUIDE.md # Kali Linux deployment guide
│   └── DOCKER_CONTAINER_REGISTRY.md # Container documentation
│
└── archive/                     # Archived Legacy Artifacts
    └── legacy_v1/               # Deprecated v1 scripts & databases
```

---

## 7. Running Unit Tests

To run the automated regression test suite on your workstation:

```bash
# Windows
py -m unittest discover -s tests/test_ids_v2 -p "test_*.py"

# Linux / Kali
python3 -m unittest discover -s tests/test_ids_v2 -p "test_*.py"
```

*Result:* **`100 tests passed in ~22s (OK)`**.

---

## 8. Detailed Specifications & Reference Documents

* [WiFi IDS Architecture Spec v2.1.2](file:///d:/Antigravity%20Project/Rogue%20wifi/Document/WiFi_IDS_Framework_v2.1.2/WiFi_IDS_Arch_Spec_v2.1.2.md)
* [WiFi IDS Batching & Persistence Spec v2.1.2](file:///d:/Antigravity%20Project/Rogue%20wifi/Document/WiFi_IDS_Framework_v2.1.2/WiFi_IDS_Batching_Spec_v2.1.2.md)
* [Kismet Integration Guide](file:///d:/Antigravity%20Project/Rogue%20wifi/Document/KISMET_INTEGRATION_GUIDE.md)
* [Kali Linux Virtual Environment Guide](file:///d:/Antigravity%20Project/Rogue%20wifi/Document/KALI_VENV_DEPLOYMENT_GUIDE.md)
* [v2.1.2 Changelog](file:///d:/Antigravity%20Project/Rogue%20wifi/Document/WiFi_IDS_Framework_v2.1.2/WiFi_IDS_CHANGELOG_v2.1.2.md)
