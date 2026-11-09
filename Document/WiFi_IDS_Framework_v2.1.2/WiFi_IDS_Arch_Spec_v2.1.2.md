# Edge Wi-Fi Evil Twin Detection Framework — Architecture & Team Specification (v2.1.2)

**Document ID:** ARCH-SPEC-v2.1.2  
**Target Hardware:** Raspberry Pi 5 Edge Sensor (Monitor Mode 802.11 Sniffer \+ Local SQLite WAL Engine)  
**Protected Campus Whitelist:** `['University_Campus_5G', 'University_Staff_Secure', 'University_Student_WiFi', 'University_Guest_Portal', 'eduroam']`  
**Companion Specifications:** `WiFi_IDS_Batching_Spec_v2.1.2.md`, `WiFi_IDS_Build_Plan_v2.1.2.md`, `WiFi_IDS_CHANGELOG_v2.1.2.md`

---

## Global Configuration, Batching & Dashboard UI Notes (Outside Flow Nodes)

| Parameter / Control | Setting / Location | Operational Behavior (v2.1.2) |
| :---- | :---- | :---- |
| **ENABLE\_STOPWORD\_STRIP** | `config.py` (`True` by default) | When `True`, Stage 2.5 evaluates `bge_cos_clean` (tech stopwords `wifi`, `5g`, `wlan`, `net`, `broadband` removed). When `False` (raw research mode), Stage 2.5 evaluates `bge_cos_raw`. `ssid_catalog` is strictly encryption-agnostic; `WPA2/3-PSK` is down-weighted dynamically (`0.5x`) at Stage 2.5 using the current beacon's encryption. |
| **AI Batching Policy (Q1 Adaptive)** | `name_screener.py` | **Work-Conserving Adaptive Queue:** If the inference worker is idle when 1 new SSID arrives (`N = 1`), evaluates immediately (`0 ms` queue wait, `7.2 ms` total via `Type A` \$1 \\times M\$ dot product `v @ W.T`). If a beacon flood queues multiple SSIDs while busy, drains up to 32 SSIDs in one `Type B` \$N \\times M\$ batch. |
| **SQLite Flush Policy (Q2 Coalesced)** | `db_manager.py` | **Routine Telemetry:** Buffers updates in `ram_bssids` (LRU capped at 4,096 entries) and flushes to SQLite WAL every **`3.0 seconds`** (`0.33 fsync/sec`). **Instant Alert Bypass \+ 250 ms Cooldown:** Immediately flushes (`0 ms` wait) when a BSSID escalates to `MEDIUM` or `HIGH` if `now - last_flush_ts >= 0.25s`; coalesces back-to-back flood alerts at `250 ms` intervals (max 4 commits/sec). |
| **Static Dashboard UI `[+ Add to Whitelist]`** | Global Dashboard UI Action | **Manual-Only Whitelisting:** `is_whitelisted = 1` is only set via manual admin click in the UI (never auto-whitelisted during `--learn-baseline`). Writes SQL directly to SQLite; sniffer detects `PRAGMA data_version` change and hot-reloads RAM. |

---

## Version 1 — High-Level System Logic Flow

High-level end-to-end topology with **Pre-Stage-0 Frame Demux** (routing Deauth/Disassoc frames directly to Track 4A), **Whitelisted BSSID Track 4A Integrity Check**, **Group 1: Name Screening**, and **Group 2: Parallel RF & Beacon Behavior Detection (4A & 4B)**.

```
====================================================================================================
                     GROUP 1: NAME SCREENING                   ||   GROUP 2: PARALLEL DETECTION
====================================================================================================

                         ( Start: 802.11 Frame )
                                    |
                                    v
                       < Frame Subtype Demux >
                      /                       \
          (Beacon / Probe Resp)         (Deauth / Disassoc: 0x0C / 0x0A)
                    |                                   |
                    v                                   +-------------------+
             < Read SSID > --- (No) ---> ( End )                            |
                    | (Yes)                 ^                               |
                    v                       | (Continuous Loop)             |
    +-------------------------------+       |                               |
    |  0. BSSID RAM Cache Lookup    |       |                               |
    |  • Whitelisted + Same SSID?   |-------+-------------------------------+
    |    -> Skip AI, check Track 4A |       |                               |
    |  • BSSID Name Mutation check  |       |                               |
    +-------------------------------+       |                               |
                    | (Un-whitelisted)      |                               |
                    v                       |                               |
    +-------------------------------+       |                               |
    |  1. Lexical + Semantic AI     |       |                               |
    |  • XGBoost (1.4 ms)           |       |                               |
    |  • bge-small-en-v1.5 (5.8 ms) |       |                               |
    |  • Encryption-agnostic cache  |       |                               |
    +-------------------------------+       |                               |
                    |                       |                               |
                    v                       |                               |
+---------------+  < 2.5 Suspicious >       |                               |
| Brief Logging | <--(No)-- Name?           |                               |
| (3.0s Batch)  |            |              |                               |
+---------------+            | (Yes)        |                               |
                             +--------------+-----------+-------------------+-------+
                                                        |                           |
                                                        v                           v
                                            [ PARALLEL TRACK 4A ]       [ PARALLEL TRACK 4B ]
                                            +-----------------------+   +-----------------------+
                                            | Listening for:        |   |    < RSSI Check >     |
                                            | • Deauth flood (>=15) |   |   Range volatility    |
                                            | • BSSID Seq/TSF clash |   +-----------------------+
                                            | • 15s Tag 3/61 Ch Set |        | (Yes)     | (No)
                                            | • AP age & 1h offline |        v           |
                                            +-----------------------+   < RSSI Check >   |
                                                        |                is strong?      |
                                                        v                | (Yes) | (No)  |
                                            +-----------------------+    |       v       |
                                            | Logging Behaviour     |    |   +---------+ |
                                            | To support beacon     |    |   | Monitor |<+
                                            | frame analysis        |    |   | Infreq. |
                                            +-----------------------+    |   +---------+
                                                        |                v        |
                                                        |           +-----------------------+
                                                        |           | Logging Beacon        |
                                                        |           | store full frame      |
                                                        |           +-----------------------+
                                                        |                     |
                                                        |                     v
                                                        |           +-----------------------+
                                                        |           | Beacon Analysis       |
                                                        |           | • Info mismatch       |
                                                        |           | • Strict TSF/Arr Jitt.|
                                                        |           | • DS Tag 3 Ch Spoof   |
                                                        |           +-----------------------+
                                                        |                     |
                                                        +----------+----------+
                                                                   |
                                                                   v
                                                          < 5. Risk Scoring >
                                                           Low / Med / High
                                                                   |
                                        +--------------------------+--------------------------+
                                        | (Low: <30)               | (Med: 30-69)             | (High: >=70)
                                        | [3.0s Batch Flush]       | [0ms Bypass / 250ms Cap] | [0ms Bypass / 250ms Cap]
                                        v                          v                          v
                                +---------------+          +---------------+          +---------------+
                                |   Watchlist   |          | Active Alert  |          |Security Alert |
                                | Keep tracking,|          | Prompt text   |          | Prompt text   |
                                |   no alert    |          | alert to app  |          | alert to app  |
                                +---------------+          +---------------+          +---------------+
```

---

## Version 2 — Detailed Subsystem Flows

### Version 2A: Detailed Flow of Frame Demux & Name Screening Group (Left Column)

Incorporates **Point 1** (whitelisted BSSIDs skip AI screening but route to Track 4A to verify no BSSID collision or multi-channel clone is occurring), **Point 2** (Deauth/Disassoc ingress demux), **Point 3** (encryption-agnostic `ssid_catalog` with dynamic `0.5x` PSK weighting at Stage 2.5), and **Option M2** (BSSID mutation population).

```
                     [ Incoming 802.11 Management Frame ]
                                      |
                                      v
                         < Subtype == Deauth/Disassoc? >
                        /                               \
                  (No: Beacon)                     (Yes: 0x0C / 0x0A)
                      |                                   |
                      v                                   v
         < Stage 0: BSSID in `ram_bssids`? >     +-----------------------------------+
                /                 \              | Route by `addr3` BSSID directly   |
        (Yes: Known)          (No: New BSSID)    | to Track 4A Deauth Counter        |
              /                     \            | (>= 15 frames / 10s -> HIGH +75)  |
             v                       \           +-----------------------------------+
  < db_ssid == observed_ssid? >       \
        /                 \            \
  (Yes: Match)       (No: Changed!)     \
      /                     \            \
     v                       v            \
+-------------------------+ +----------------------+
| Whitelisted BSSID?      | | BSSID Name Mutation  |
| • Yes -> Skip AI (Stg1/2)| | Detector (Option M2) |
|   & Route to Track 4A   | | • Flag is_mutated=1  |
|   for Collision/Clone!  | | • Attach +45 pts     |
+-------------------------+ +----------------------+
                         \           |            /
                          +----------+-----------+
                                     | (Un-whitelisted or Mutated BSSID)
                                     v
                 < Stage 1: observed_ssid in `ram_ssids`? >
                        /                           \
                (Yes: Cache Hit)              (No: Cache Miss -> Adaptive Worker)
                      /                               \
                     v                                 v
     +-------------------------------+  +-----------------------------------------------+
     | Load Cached Scores (0.002 ms) |  | Stage 1 & 2: Work-Conserving AI Worker        |
     | • Read xgb_prob               |  | • Queue empty (N=1): Instant 1xM (7.2 ms)     |
     | • Read bge_cos_raw & clean    |  | • Flooded (N<=32): Batch NxM ONNX + XGB       |
     +-------------------------------+  | • Save encryption-agnostic raw & clean in DB  |
                     \                  +-----------------------------------------------+
                      \                               /
                       +--------------+--------------+
                                      |
                                      v
                     < Stage 2.5: Suspicious Name? >
                     [ eff_bge = (0.5 * bge_cos) if PSK else bge_cos ]
                     [ xgb_prob >= 0.50 OR eff_bge >= 0.60           ]
                     [ OR is_mutated == True                         ]
                            /                 \
                      (No: Benign)       (Yes: Suspicious)
                          /                     \
                         v                       v
               +-------------------+   +---------------------------+
               |   Brief Logging   |   | Route to Group 2:         |
               | (3.0s RAM Buffer) |   | Parallel Tracks 4A & 4B   |
               +-------------------+   +---------------------------+
```

---

### Version 2B: Detailed Flow of the Behavioral Detection Group (Parallel 4A & 4B)

Incorporates **Point 4** (`last_seen_ts` 1-hour offline probation reset and Sister-only 24h W2 decay), **Point 7** (15s sliding IE Tag 3/61 channel map and strict un-diluted TSF/Arrival jitter), and **Point 8** (`250 ms` flush cooldown).

```
        [ From Stage 0 Whitelisted Check (4A Only), Deauth Demux (4A Only), or Stage 2.5 (4A & 4B) ]
                                                      |
                        +-----------------------------+-----------------------------+
                        | (Track 4A)                                                | (Track 4B: Un-whitelisted)
                        v                                                           v
        =================================                           =================================
          PARALLEL TRACK 4A: ACTIVE RF                                PARALLEL TRACK 4B: BEACON IEs
        =================================                           =================================
                        |                                                           |
                        v                                                           v
        +-------------------------------------------+               < 4B.1: RSSI Volatility Check >
        | 4A.1: Active RF & State Check             |               [  Delta_RSSI > 15 dB (+20 pts) ]
        | • Deauth flood (>=15 in 10s or >=30 in 60s|                        /             \
        |   -> Floor HIGH (+75 pts)                 |                  (Yes: Volatile)  (No: Stable)
        | • Same-Channel BSSID Collision            |                       |               |
        |   (Backward Seq / TSF regression)         |                       v               |
        |   -> Floor HIGH (+75 pts)                 |               < 4B.2: RSSI >= -70 dBm? >
        | • Multi-Ch BSSID Clone (Type A, +70 pts): |                      /         \      |
        |   Extract channel from IE Tag 3 / Tag 61. |                 (Yes)          (No)   |
        |   Maintain 15s sliding {ch: last_ts} map: |                  /               \    |
        |   - 1-way switch expires old ch in 15s    |                 |                 v   v
        |     & updates primary_channel (0 pts)     |                 |        +--------------------+
        |   - Simultaneous / ping-pong -> HIGH (+70)|                 |        | Monitor Infrequent |
        | • New AP Probation (Option N2 + W2 + 4A): |                 |        | (10s Summary Log)  |
        |   - If now - last_seen_ts > 3600s (1h),   |                 |        +--------------------+
        |     reset first_seen_ts = now!            |                 |                  |
        |   - Sister SSID: decays after 24h uptime  |                 +--------+---------+
        |   - Exact Whitelist SSID: keeps MED floor |                          |
        |     until manual UI `[+ Add Whitelist]`   |                          v
        +-------------------------------------------+               +-------------------------------+
                        |                                           | 4B.3: Logging Beacon Frame    |
                        v                                           | • Store full IE frame payload |
        +-------------------------------------------+               +-------------------------------+
        | 4A.2: Logging Behaviour                   |                          |
        | • Update `ram_bssids` (4096 LRU cap)      |                          v
        +-------------------------------------------+               +-------------------------------------------+
                        |                                           | 4B.4: Beacon Frame Analysis               |
                        |                                           | • Severe IE Mismatch (+55 pts)            |
                        |                                           | • DS Tag 3 vs Radio Ch Spoof (+45 pts)    |
                        |                                           | • Strict Jitter > 20 ms (+20 pts):        |
                        |                                           |   1 <= seq_diff <= 6, 60 <= dt <= 245 ms, |
                        |                                           |   k in {1,2}, max(arr_err, tsf_err)       |
                        |                                           | • Partial IE / Non-Std Ch (+15 pts)       |
                        |                                           | • 100% IE Match (-35 pts, Sister SSIDs)   |
                        |                                           +-------------------------------------------+
                        |                                                      |
                        +--------------------------+---------------------------+
                                                   |
                                                   v
                                   +-------------------------------+
                                   | 5. Hybrid Risk Scoring Engine |
                                   | • Apply Hard Floors (HIGH/MED)|
                                   | • Sum Points (0 - 100 scale)  |
                                   +-------------------------------+
                                                   |
                         +-------------------------+-------------------------+
                         | (< 30 pts: Low)         | (30 - 69 pts: Med)      | (>= 70 pts: High)
                         | [3.0s Periodic Flush]   | [0ms Bypass / 250ms Cap]| [0ms Bypass / 250ms Cap]
                         v                         v                         v
                 +---------------+         +---------------+         +---------------+
                 |   Watchlist   |         | Active Alert  |         |Security Alert |
                 +---------------+         +---------------+         +---------------+
```

---

## Version 3 — Step-by-Step Component Info Cards

### Card 01: Pre-Stage-0 Demux & Stage 0 Whitelisted/Mutation Check

* **What It Is:** Frame subtype demultiplexer and `0.002 ms` in-memory `ram_bssids` cache lookup (LRU-capped at 4,096 BSSIDs).  
* **How It Works:**  
  1. **Deauth/Disassoc Ingress (`subtype 0x0C / 0x0A`):** Routes directly by `addr3` BSSID to Track 4A's sliding counter (`>= 15` frames in `10 s` or `>= 30` in `60 s` triggers `HIGH +75 pts`), because Deauth frames carry no SSID.  
  2. **Whitelisted BSSID Integrity Path:** If `is_whitelisted == 1` and `db_ssid == observed_ssid`, skips Group 1 AI (`Stage 1 & 2`) but still executes **Track 4A** (Seq/TSF collision and Tag 3/61 multi-channel clone checks) before exiting as `BENIGN`.  
  3. **BSSID Name Mutation (`Option M2`):** If `db_ssid != observed_ssid`, sets `is_mutated = True (+45 pts)`, populates `ssid_catalog` via Stage 1 & 2, and force-routes to `4A & 4B`.  
* **What It Fixes:** Catches Evil Twins that clone both a whitelisted BSSID and its SSID (Point 1\) and provides a dedicated ingress path for SSID-less Deauth floods (Point 2).

---

### Card 02: Stage 1 & 2 — Work-Conserving Adaptive AI Engine & Encryption-Agnostic Cache

* **What It Is:** XGBoost (`1.4 ms`) \+ `bge-small-en-v1.5` (`5.8 ms`) worker backed by `ram_ssids` and `ssid_catalog`.  
* **How It Works:**  
  * **Adaptive Batching (`Q1` Upgrade):** Evaluates single live SSIDs immediately (`0 ms` queue wait, `Type A` \$1 \\times M\$ dot product `v @ W.T`) when the worker is idle, and automatically switches to `Type B` (\$N \\times M\$ batching, up to 32 SSIDs) if a beacon flood fills the queue.  
  * **Encryption-Agnostic Cache (Point 3 Fix):** Stores `bge_cos_raw` and `bge_cos_clean` (stopwords stripped) in `ssid_catalog` purely by `ssid_text`, never zeroing the cached column on PSK beacons.  
* **What It Fixes:** Prevents `mdk4` random-SSID floods from saturating the Raspberry Pi 5 CPU (Point 8\) and stops attackers from poisoning `ssid_catalog` by sending one WPA2-PSK beacon before switching to Open (Point 3).

---

### Card 03: Stage 2.5 — Dynamic PSK-Weighted `Suspicious Name?` Gatekeeper

* **What It Is:** The boolean routing diamond connecting Group 1 to Group 2\.  
* **How It Works:** Computes effective semantic similarity using the **current beacon's live encryption**: \$\$\\text{eff\_bge} \= \\begin{cases} 0.5 \\times \\text{bge\_cos} & \\text{if current encryption is WPA2/3-PSK} \\ \\text{bge\_cos} & \\text{if OPEN or 802.1X} \\end{cases}\$\$ Routes to Parallel Tracks `4A & 4B` if `xgb_prob >= 0.50 OR eff_bge >= 0.60 OR is_mutated == True`.  
* **What It Fixes:** Evaluates encryption state dynamically per BSSID rather than per cached SSID text, suppressing home router false positives while still catching high-similarity PSK lures.

---

### Card 04: Track 4A — Active RF, 15s Tag 3/61 Channel Tracker & Offline-Reset Probation

* **What It Is:** Parallel stateful tracker monitoring Deauth floods, Seq/TSF collisions, multi-channel clones, and New AP probation.  
* **How It Works:**  
  * **15-Second Sliding IE Channel Map (Point 7 Fix):** Extracts the AP's declared channel from Beacon **IE Tag 3 (`DS Parameter Set`) or Tag 61 (`HT Operation`)** into `{channel: last_seen_ts}`. If a legitimate AP changes channels (`Ch 6 -> Ch 1`), the old channel expires after `15 s` and updates `primary_channel` (`0 pts`). If two channels remain active within `15 s` (`6 <-> 1` ping-pong), triggers **Type A Multi-Channel Clone (`+70 pts HIGH`)**.  
  * **New AP Probation & 1-Hour Offline Reset (Point 4 Assumption):** Legitimate campus ceiling APs are PoE-powered with continuous 24/7 uptime. If an un-whitelisted AP goes offline for **`> 1 hour` (`now - last_seen_ts > 3600s`)**, `first_seen_ts` resets to `now`. Departmental Sister SSIDs decay to `Watchlist` after 24h of continuous uptime; exact main whitelist SSIDs (`eduroam`) retain their `MEDIUM` floor until manually whitelisted via the UI.  
* **What It Fixes:** Eliminates 2.4 GHz bleed-over false positives on Type A clones, gracefully handles legitimate IT channel changes, and blocks "hit-and-run" 24h timer priming attacks.

---

### Card 05: Track 4B — Strict Un-Diluted Jitter & Deep Beacon IE Fingerprinting

* **What It Is:** Parallel Track 4B inspector checking RSSI volatility, strict timing jitter, and Campus IE Blueprint matching.  
* **How It Works:**  
  * **Strict Un-Diluted Jitter (`+20 pts`):** Standard 802.11 beacon interval is `100 TU = 102.4 ms` (dedicated ASIC APs hold `< 4 ms` TSF jitter and `< 8 ms` arrival jitter). Evaluates only when `1 <= seq_diff <= 6` and `60.0 <= delta_t_ms <= 245.0` (at most 1 lost beacon, `k in {1, 2}`, `expected_ms = k * 102.4`), taking `max(abs(delta_t_ms - expected_ms), abs(tsf_delta_ms - expected_ms))` with **zero division by `k`**.  
  * **Campus IE Blueprint (`+55` / `+15` / `-35`):** Compares `802.1X`, `Tag 54 MDID`, `Tag 221/133`, and `MIMO` streams against `campus_ie_profile`. (`-35 pts` applies only to Sister SSIDs, never overriding un-whitelisted exact main SSIDs).  
* **What It Fixes:** Prevents error dilution across missed frames so software Evil Twins (`hostapd` jitter `22–85 ms`) are reliably caught.

---

### Card 06: Stage 5 — Coalesced Instant-Bypass Flush (`250 ms` Cap) & Manual UI Whitelist

* **What It Is:** Final `0–100` risk engine paired with flood-safe SQLite WAL persistence.  
* **How It Works:**  
  * **First Alert (`0 ms` Wait):** Transitions into `MEDIUM` or `HIGH` flush immediately if `now - last_flush_ts >= 0.25s`.  
  * **Flood Coalescing (`250 ms` Cooldown):** During a beacon flood, subsequent forced flushes coalesce into `250 ms` windows (capping disk writes at 4 commits/sec).  
  * **Manual-Only Whitelisting (Point 5):** `--learn-baseline` locks `campus_ie_profile` only; `is_whitelisted = 1` requires an explicit admin click on the static UI `[+ Add to Whitelist]` button.  
* **What It Fixes:** Preserves `< 10 ms` real-time alerting for single threats while making SQLite immune to `mdk4` flush-storm DoS attacks.

---

## Master Hybrid Risk Scoring Reference (0–100 Scale, v2.1.2)

| Rank | Check Name | Track | Score / Floor | 24h Decay? | Condition (v2.1.2) |
| :---: | :---- | :---: | :---: | :---: | :---- |
| **1** | **Deauth Storm / Same-Ch Collision** | `4A` | **Floor `HIGH` (`+75`)** | No | `>=15` Deauth/10s (via pre-Stage-0 demux) OR backward Seq \+ TSF regression |
| **2** | **Channel Match Type A (Multi-Ch Clone)** | `4A` | **Floor `HIGH` (`+70`)** | No | `>=2` IE Tag 3/61 channels active within 15s window (`6 <-> 1` ping-pong) |
| **3** | **Severe `info mismatch`** | `4B` | **`+55 pts`** | No | Open vs 802.1X, WPS tag, `1x1` PHY, missing MDID/Tag 221 |
| **4** | **Channel Match Type B (DS Tag 3 Spoof)** | `4B` | **`+45 pts`** | No | Captured radio channel \!= IE Tag 3 (`>= 2` ch off in 2.4G / any in 5G) |
| **5** | **BSSID Name Mutation (`Option M2`)** | `0 -> 4A` | **`+45 pts`** | No | Known BSSID changes its broadcast SSID (`is_mutated = 1`) |
| **6** | **New AP (`age < 24h`, N2 \+ W2 \+ 4A)** | `4A` | **Floor `MED` (`30`) \+ `+20`** | **Sister Only (`24h`)** | Resets `first_seen_ts` if offline `> 1h`; exact whitelist SSIDs keep `MED` floor until manual UI whitelist |
| **7** | **Strict Beacon Timing / TSF Jitter** | `4B` | **`+20 pts`** | Rolling | `max(arr_err, tsf_err)` std dev `> 20 ms` (`1<=seq_diff<=6`, `k in {1,2}`) |
| **8** | **RSSI Range Volatility** | `4B` | **`+20 pts`** | Rolling | Sudden jump \$\\Delta\\text{RSSI} \> 15\\text{ dB}\$ on same BSSID |
| **9** | **Partial `info mismatch` / Non-Std Ch** | `4B` | **`+15 pts` each** | No | Minor IE tag order variance OR 2.4G Ch outside `1, 6, 11` |
| **10** | **100% Campus IE Blueprint Match** | `4B` | **`-35 pts` (Sister Only)** | No | Matches locked Campus `802.1X` \+ `MDID` \+ `Tag 221` \+ `4x4` PHY on Sister SSIDs |
| **11** | **Static Strong RSSI (`>= -70 dBm`)** | `4B` | **`0 pts` (Gate only)** | N/A | Switches between full-frame logging (`1/s`) and infrequent monitoring (`1/10s`) |

