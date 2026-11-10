# Rogue Wi-Fi & Evil Twin Detection System: Complete Workflow Architecture

This document describes the end-to-end architecture, detection pipeline, and operational workflow of the **Evil Twin Access Point Detection System** using **802.11 Frame Analysis** and the **NVIDIA Nemotron-Mini-4B Transformer**.

---

## 1. System Architecture Overview

The system utilizes a **multi-tiered hybrid architecture** designed to keep memory footprint under 30 MB on edge sensors (Raspberry Pi 4/5) while offloading complex semantic reasoning to a dedicated GPU acceleration engine (AMD Radeon RX 6700 XT with Vulkan) or cloud fallback.

```mermaid
flowchart TD
    subgraph Airwaves["1. Wireless Airwaves (Real / Virtual)"]
        AP_Legit["Legitimate AP\n(e.g., Company_Official_5G)"]
        AP_Evil["Evil Twin AP\n(e.g., Company_Officia1_5G)"]
        AP_Other["Unrelated APs\n(e.g., CoffeeShop_WiFi)"]
    end

    subgraph Sensor["2. Edge Sensor (Raspberry Pi / Kali Linux)"]
        Sniff["802.11 Frame Sniffer\n(Scapy / Raw Socket / UDP)"]
        Parser["Header & IE Parser\n(Extracts BSSID, SSID, Channel)"]
        WhitelistCheck{"Exact Match in\nAuthorized Whitelist?"}
        
        Sniff --> Parser --> WhitelistCheck
    end

    AP_Legit -->|802.11 Beacon / Probe| Sniff
    AP_Evil -->|802.11 Beacon / Probe| Sniff
    AP_Other -->|802.11 Beacon / Probe| Sniff

    WhitelistCheck -->|YES (100% Match)| SafeState["Status: AUTHORIZED\nRecord seen count & timestamp"]

    subgraph Tier2["3. Fast Semantic & Homoglyph Filter"]
        Fuzzy["Hybrid N-gram & Homoglyph Engine\n- Typos (hyphens, underscores)\n- Homoglyphs (1/l, 0/o)"]
        ThresholdCheck{"Similarity >=\nThreshold (75%)?"}
        
        WhitelistCheck -->|NO| Fuzzy --> ThresholdCheck
        ThresholdCheck -->|NO| Unrelated["Status: UNRELATED\nLog and continue"]
    end

    subgraph Tier3["4. Neural Transformer Reasoning (Nemotron-Mini-4B)"]
        Router["Inference Router\n(Checks Local Vulkan API first)"]
        VulkanLLM["Local Vulkan Server (Port 1234)\nAMD Radeon RX 6700 XT\n(~43 tokens/sec)"]
        HFFallback["Cloud Fallback (Hugging Face)\nnvidia/nemotron-mini-4b-instruct"]
        
        ThresholdCheck -->|YES (Suspicious)| Router
        Router -->|Primary: Online| VulkanLLM
        Router -->|Fallback: Offline| HFFallback
    end

    subgraph Tier4["5. Verdict, Storage & Visualization"]
        Scorer["Risk Scoring & Assessment\n(HIGH / MEDIUM / LOW + Reason)"]
        DB[(SQLite Database\nwifi_records.db)]
        WebDash["Web Dashboard (Port 8080)\nLive Real-Time Monitoring"]
        Alert["Security Alert\n(Telegram / Console Banner)"]
        
        VulkanLLM --> Scorer
        HFFallback --> Scorer
        Scorer --> DB
        SafeState --> DB
        Unrelated --> DB
        DB --> WebDash
        Scorer -->|If HIGH/MEDIUM| Alert
    end
```

---

## 2. Multi-Stage Detection Pipeline

### Stage 1: Frame Ingestion & Metadata Extraction
* **Input:** Raw IEEE 802.11 Management Frames (Beacon Frames `subtype=8` or Probe Requests `subtype=4`).
* **Processing:** Strips RadioTap headers (if present) and extracts:
  * **BSSID:** Transmitter Access Point MAC address.
  * **SSID:** Network broadcast identifier string.
  * **Signal / Channel:** Frequency parameters.

### Stage 2: Whitelist Authorization Filter
* Compares incoming SSID against `whitelist.json`.
* If exact match: Marks as `AUTHORIZED` (Safe). Zero AI inference overhead.

### Stage 3: Homoglyph & Typosquatting Filter
* When an unknown SSID is observed, calculates similarity against all whitelisted targets using:
  1. **Character normalization:** Converts homoglyphs (`1` $\leftrightarrow$ `l`, `0` $\leftrightarrow$ `o`, `-` $\leftrightarrow$ `_`).
  2. **N-gram Jaccard overlap:** Computes bi-gram token intersections.
* If similarity $\ge$ **75%**: Flags candidate as `SUSPICIOUS_EVIL_TWIN` and escalates to Stage 4.

### Stage 4: Nemotron-Mini-4B Intent Classification
* The edge detector sends an OpenAI-compatible request to the local Vulkan server:
  ```json
  {
    "model": "nvidia/nemotron-mini-4b-instruct",
    "messages": [
      {
        "role": "user",
        "content": "Analyze if the detected SSID 'Company_Officia1_5G' is an evil twin attempting to impersonate the authorized SSID 'Company_Official_5G'. Reply concisely with RISK LEVEL (HIGH/MEDIUM/LOW) and one sentence explanation."
      }
    ]
  }
  ```
* **Why Nemotron outperforms MiniLM:** MiniLM only computes vector cosine distance, confusing legitimate sibling networks (`Staff` vs `Guest`). Nemotron understands **contextual intent**, distinguishing between valid roles and phishing tricks (`_Login`, homoglyphs, brand spoofing).

### Stage 5: Persistence & Live Reporting
* **Database:** Records BSSID, SSID, similarity score, status, encounter count, and Nemotron verdict in SQLite (`wifi_records.db`).
* **Web Dashboard:** Accessible on `http://localhost:8080`, updating via `/api/aps` every 2 seconds.

---

## 3. Operational Workflow (How to Run & Stop)

### Starting the System
1. **Start the Local Nemotron Vulkan Server (Windows Host):**
   ```powershell
   cd "D:\Antigravity Project\Rogue wifi\local_llm"
   .\start_local_llm.ps1
   ```
   *(Initializes Vulkan on AMD RX 6700 XT and listens on `http://0.0.0.0:1234`)*

2. **Start the Docker Simulation Lab:**
   ```powershell
   cd "D:\Antigravity Project\Rogue wifi"
   docker compose up -d
   ```
   * Spawns `kali-detector` (sensor) and 4 frame generator clients.
   * Open `http://localhost:8080` in any browser to watch live alerts.

### Monitoring Logs
```powershell
docker logs -f kali-detector
```

### Stopping the System
```powershell
# 1. Stop all Docker simulation containers:
docker compose down

# 2. Stop the local Nemotron server:
# Press Ctrl+C in the PowerShell window running start_local_llm.ps1,
# or terminate via command line:
Get-Process -Name "*llama-server*" | Stop-Process -Force
```

---

## 4. Hardware Deployment Mapping

| Component | Simulation Mode (Your PC) | Physical Production Mode |
| :--- | :--- | :--- |
| **Sensor Node** | Docker `kali-detector-arm64` (512MB RAM cap) | **Raspberry Pi 4 / 5** with Alfa Wi-Fi USB Adapter |
| **Sniffer Mode** | UDP Virtual Frame Socket (Port 5555) | 802.11 Monitor Mode (`wlan0mon`) via Scapy/Kismet |
| **LLM Inference** | AMD RX 6700 XT (Local Vulkan, Port 1234) | Central Server / PC via LAN IP (`http://192.168.1.x:1234`) |
| **Database & UI** | SQLite + Embedded Python HTTP Server | SQLite + Embedded Python HTTP Server (Port 8080) |
