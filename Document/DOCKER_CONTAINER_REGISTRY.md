# 🐳 Docker Architecture, Container Registry & Consolidation Specification

**Repository:** `D:\Antigravity Project\Rogue wifi`  
**Generated:** 2026-11-10  
**Context:** Wi-Fi IDS Virtual Simulation Lab & Test Container Architecture  

---

## 1. Do These Containers Work in a Group?

**YES.** In the project's wireless simulation architecture, containers work cooperatively in an isolated virtual Ethernet bridge network named **`wifi-lab-net`** (`10.10.0.0/24`) defined in [`docker-compose.yml`](file:///d:/Antigravity%20Project/Rogue%20wifi/docker-compose.yml).

### The Communication Topology:
```
                                 [ wifi-lab-net: 10.10.0.0/24 ]
                                               │
               ┌───────────────────────────────┼───────────────────────────────┐
               │                               │                               │
               ▼                               ▼                               ▼
    [ client-authorized-ap ]        [ client-rogue-ap ]           [ client-fast-rogue ]
        (10.10.0.12)                    (10.10.0.11)                   (10.10.0.14)
       Legit AP Beacons               Evil Twin Beacons              Fast Roaming Beacons
        (Interval 5.0s)                (Interval 4.0s)                 (Interval 2.0s)
               │                               │                               │
               │ [Raw IEEE 802.11 Radiotap / Dot11 Frames via UDP 5555]        │
               └───────────────────────────────┬───────────────────────────────┘
                                               │
                                               ▼
                                      [ kali-detector ]
                                        (10.10.0.5)
                             • UDP Socket Server (:5555)
                             • IDS v2 Pipeline & Risk Engine
                             • Web Dashboard (:8080)
```

---

## 2. Can We Group Each Working Unit into One Container?

**YES.** Currently, the 4 traffic generators (`client-authorized-ap`, `client-rogue-ap`, `client-fast-rogue`, `client-probe-station`) run the exact same base image (`wifi-frame-client`) and the exact same Python script ([`clients/wifi_frame_generator.py`](file:///d:/Antigravity%20Project/Rogue%20wifi/clients/wifi_frame_generator.py)).

### Consolidated 2-Container Architecture:
Instead of running 5 separate containers, the entire laboratory can be consolidated into **just 2 clean units**:

1. **Unit 1: The Sensor / Detector Container (`kali-detector`)**
   - Runs `detector/ids_v2/pipeline.py` or `detector.py`.
   - Listens on `0.0.0.0:5555/udp` for incoming 802.11 frames.
   - Hosts the Web Alert Dashboard on port `8080`.
2. **Unit 2: The Unified Multi-Threaded Traffic Simulator (`wifi-traffic-simulator`)**
   - Consolidates all 4 client generators into one container running 4 background Python threads:
     - Thread 1: Authorized Campus AP Simulator (`University_Campus_5G`, `eduroam`)
     - Thread 2: Stationary Evil Twin Simulator (`Un1versity_Campus_5G`, `Free_University`)
     - Thread 3: Fast Roaming / Ping-Pong Channel Clone Simulator (Channels 1 & 6)
     - Thread 4: Mobile Client Probe Request Simulator

---

## 3. Master Container Inventory & Status

### A. Core Baseline Lab Containers (DO NOT REMOVE)
Defined in [`docker-compose.yml`](file:///d:/Antigravity%20Project/Rogue%20wifi/docker-compose.yml):
* `kali-detector` (`kali-detector-arm64:latest`): Main IDS detector node.
* `client-authorized-ap` (`wifi-frame-client:latest`): Authorized AP beacon generator.
* `client-rogue-ap` (`wifi-frame-client:latest`): Rogue AP beacon generator.
* `client-fast-rogue` (`wifi-frame-client:latest`): High-rate roaming rogue AP generator.
* `client-probe-station` (`wifi-frame-client:latest`): Client probe request station.

**Commands to Spawn / Resume:**
```bash
docker compose start
# or to launch fresh:
docker compose up -d
```

---

### B. Temporary Test Runner Containers (Cleaned Up After Verification)
Created during subagent N+1 testing rounds under the command *"test on docker crate new container"*:
* `ids-v2-full-e2e-validator`: Final 100-test suite execution (100% OK).
* `ids-v2-sync-validator`: Post-synchronization test runner (100% OK).
* `ids-v2-validator-n1-step4-adversarial-docker`: 69-assertion adversarial suite (100% OK).
* `ids-v2-step3-*`, `ids-v2-step4-*`, `ids-v2-step5-*`: Intermediate step verification runners.

**Source Command to Re-spawn Any Test Runner On Demand:**
```bash
docker run --name ids-v2-test-runner \
  -v "D:\Antigravity Project\Rogue wifi:/app" \
  -w /app \
  kali-detector-arm64:latest \
  python3 -m unittest discover -s tests -p "test_*.py"
```
