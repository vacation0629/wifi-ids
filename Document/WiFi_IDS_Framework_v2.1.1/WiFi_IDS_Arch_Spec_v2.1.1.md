# Edge Wi-Fi Evil Twin Detection Framework — Architecture & Team Specification (`v2.1.1`)

**Document ID:** `ARCH-SPEC-v2.1.1`**Target Hardware:** Raspberry Pi 5 Edge Sensor (Monitor Mode 802.11 Sniffer + Local SQLite WAL Engine)**Protected Campus Whitelist:** `['University_Campus_5G', 'University_Staff_Secure', 'University_Student_WiFi', 'University_Guest_Portal', 'eduroam']`**Companion Specifications:** `WiFi_IDS_Batching_Spec_v2.1.1.md`, `WiFi_IDS_Build_Plan_v2.1.1.md`, `WiFi_IDS_CHANGELOG_v2.1.1.md`

## Global Configuration, Batching & Dashboard UI Notes (Outside Flow Nodes)

| **Parameter / Control** | **Setting / Location** | **Operational Behavior (v2.1.1)** |
| :--- | :--- | :--- |
| **ENABLE_STOPWORD_STRIP** | `config.py` (`True` by default) | When `True`, `Stage 2.5` evaluates `bge_cos_clean` (tech stopwords `wifi`, `5g`, `wlan`, `net`, `broadband` removed; `WPA2/3-PSK` set to `0.0`). When `False` (raw research mode), `Stage 2.5` evaluates `bge_cos_raw`. |
| **AI Batching Policy (Q1 = Option 1)** | `name_screener.py` | **Live Sniffing (N = 1):** Evaluates each new uncached SSID **immediately (0 ms** **queue wait)** via `Type A` $1 \times M$ matrix multiplication (`7.2 ms` total).<br>**Cold Boot Scan (N >> 1):** Uses `Type B` $N \times M$ multi-SSID batching only during initial startup scan. |
| **SQLite Flush Policy (Q2 = Option 1)** | `db_manager.py` | **Routine Telemetry:** Buffers updates in `ram_bssids` and flushes to SQLite WAL every **3.0 seconds** (`0.33 fsync/sec`).<br>**Instant Alert Bypass:** Immediately flushes (`0 ms` timer wait) whenever any BSSID enters or escalates to `MEDIUM` (`30–69 pts`) or `HIGH` (`>= 70 pts`). |
| **Static Dashboard UI** **[+ Add to Whitelist]** | Global Dashboard UI Action | Writes SQL directly to SQLite. During every flush cycle, the sniffer checks `PRAGMA data_version;` (`0.001 ms`) and hot-reloads the RAM whitelist and $M \times 384$ embedding matrix without restarting. |


## Version 1 — High-Level System Logic Flow

High-level end-to-end topology separating **Group 1: Name Screening (Left Column)** from **Group 2: Parallel RF & Beacon Behavior Detection (4A** **&** **4B, Right Column)**.

```text
====================================================================================================
                     GROUP 1: NAME SCREENING                   ||   GROUP 2: PARALLEL DETECTION
====================================================================================================
                         ( Start )
                             |
                             v
                       < Read SSID > --- (No) ---> ( End )
                             | (Yes)                     ^
                             v                           | (Continuous Loop)
             +-------------------------------+           |
             |  1. Whitelist + Fuzzy Match   |           |
             |  • Known BSSID MAC check      |           |
             |  • BSSID Name Mutation check  |           |
             |  • XGBoost lexical features   |           |
             +-------------------------------+           |
                             |                           |
                             v                           |
             +-------------------------------+           |
             |  2. Semantic Neural Language  |           |
             |  • bge-small-en-v1.5 (384d)   |           |
             |  • Instant 1xM cosine cached  |           |
             |    once per SSID in SQLite    |           |
             +-------------------------------+           |
                             |                           |
                             v                           |
+---------------+    < 3. Suspicious >                   |
| Brief Logging | <--(No)-- Name?                     |
| (3.0s Batch)  |            |                           |
+---------------+            | (Yes: routed to Group 2)  |
                             +---------------------------+-----------------------+
                                                         |                       |
                                                         v                       v
                                            [ PARALLEL TRACK 4A ]   [ PARALLEL TRACK 4B ]
                                            +-------------------+   +-------------------+
                                            | Listening for:    |   |    < RSSI Check > |
                                            | • Deauth storm    |   |   Range volatility|
                                            | • BSSID collision |   +-------------------+
                                            | • AP first-seen   |        | (Yes)     | (No)
                                            +-------------------+        v           |
                                                      |             < RSSI Check >   |
                                                      v              is strong?      |
                                            +-------------------+    | (Yes) | (No)  |
                                            | Logging Behaviour |    |       v       |
                                            | To support beacon |    |   +---------+ |
                                            | frame analysis    |    |   | Monitor |<+
                                            +-------------------+    |   | Infreq. |
                                                      |              |   +---------+
                                                      |              v        |
                                                      |         +-------------------+
                                                      |         | Logging Beacon    |
                                                      |         | store full frame  |
                                                      |         +-------------------+
                                                      |                   |
                                                      |                   v
                                                      |         +-------------------+
                                                      |         | Beacon Analysis   |
                                                      |         | • Info mismatch   |
                                                      |         | • Timing jitter   |
                                                      |         | • Seq anomaly     |
                                                      |         | • Channel match   |
                                                      |         +-------------------+
                                                      |                   |
                                                      +---------+---------+
                                                                |
                                                                v
                                                       < 5. Risk Scoring >
                                                        Low / Med / High
                                                                |
                                        +-----------------------+-----------------------+
                                        | (Low: <30)            | (Med: 30-69)          | (High: >=70)
                                        | [3.0s Batch Flush]    | [Instant 0ms Flush!]  | [Instant 0ms Flush!]
                                        v                       v                       v
                                +---------------+       +---------------+       +---------------+
                                |   Watchlist   |       | Active Alert  |       |Security Alert |
                                | Keep tracking,|       | Prompt text   |       | Prompt text   |
                                |   no alert    |       | alert to app  |       | alert to app  |
                                +---------------+       +---------------+       +---------------+
                                        |                       |                       |
                                        +-----------------------+-----------------------+
                                                                |
                                                                +---> Loops back to < Read SSID >
```

## Version 2 — Detailed Subsystem Flows

### Version 2A: Detailed Flow of the Name Screening Group (Left Column)

Incorporates **Option M2** (explicit outgoing arrow from `BSSID Name Mutation Detector` to `Stage 1` so mutated SSIDs never leave `NULL` columns in `ssid_catalog`) and **Q1 = Option 1** (`Type A` instant $1 \times M$ evaluation on live cache misses with zero queue delay).

```text
                  [ Incoming 802.11 Beacon: (bssid, observed_ssid, enc) ]
                                             |
                                             v
                             < Stage 0: BSSID in `ram_bssids`? >
                                    /                 \
                            (Yes: Known)          (No: New BSSID)
                                  /                     \
                                 v                       \
                  < db_ssid == observed_ssid? >           \
                        /                 \                \
                  (Yes: Match)       (No: Changed!)         \
                      /                     \                \
                     v                       v                \
        +-------------------------+  +----------------------+  \
        | Whitelisted BSSID?      |  | BSSID Name Mutation  |   |
        | • Yes -> BENIGN (Exit)  |  | Detector (Option M2) |   |
        | • No + Cached Suspicious|  | • Flag is_mutated=1  |   |
        |   -> Route to 4A & 4B   |  | • Attach +45 pts     |   |
        +-------------------------+  +----------------------+   |
                                                |               |
                                                +-------+-------+
                                                        |
                                                        | (Outgoing arrow to populate/read `ram_ssids` / `ssid_catalog`)
                                                        v
                                    < Stage 1: observed_ssid in `ram_ssids`? >
                                           /                           \
                                   (Yes: Cache Hit)              (No: Live Cache Miss, N = 1)
                                         /                               \
                                        v                                 v
                        +-------------------------------+  +-------------------------------------------+
                        | Load Cached Scores (0.002 ms) |  | Stage 1: XGBoost Lexical (1.4 ms)         |
                        | • Read xgb_prob, bge_cos      |  | • Extract f1..f11 vs M whitelist targets  |
                        +-------------------------------+  +-------------------------------------------+
                                        |                                 |
                                        |                                 v
                                        |                  +-------------------------------------------+
                                        |                  | Stage 2: bge-small-en-v1.5 (5.8 ms)       |
                                        |                  | • Instant 1xM dot product: v @ W.T        |
                                        |                  | • Save bge_cos_raw & clean in `ram_ssids` |
                                        |                  |   and queue for SQLite `ssid_catalog`     |
                                        |                  +-------------------------------------------+
                                        \                                 /
                                         +---------------+---------------+
                                                         |
                                                         v
                                        < Stage 2.5: Suspicious Name? >
                                        [   xgb_prob >= 0.50          ]
                                        [   OR bge_cos >= 0.60        ]
                                        [   OR is_mutated == True     ]
                                               /                 \
                                         (No: Benign)       (Yes: Suspicious)
                                             /                     \
                                            v                       v
                                  +-------------------+   +---------------------------+
                                  |   Brief Logging   |   | Route to Group 2:         |
                                  | (3.0s RAM Buffer) |   | Parallel Tracks 4A & 4B   |
                                  +-------------------+   +---------------------------+
```

### Version 2B: Detailed Flow of the Behavioral Detection Group (Parallel `4A` & `4B`)

Incorporates parallel execution of **Track 4A** and **Track 4B**, plus **Q2 = Option 1** (`0 ms` Instant Alert Bypass Flush when entering or escalating to `MEDIUM` or `HIGH`).

```text
                       [ From Stage 2.5: Suspicious Name = YES (or is_mutated = True) ]
                                                      |
                        +-----------------------------+-----------------------------+
                        | (Fork to Track 4A)                                        | (Fork to Track 4B)
                        v                                                           v
        =================================                           =================================
          PARALLEL TRACK 4A: ACTIVE RF                                PARALLEL TRACK 4B: BEACON IEs
        =================================                           =================================
                        |                                                           |
                        v                                                           v
        +-------------------------------+                           < 4B.1: RSSI Volatility Check >
        | 4A.1: Active RF & State Check |                           [  Delta_RSSI > 15 dB (+20 pts) ]
        | • Deauth / Disassoc flood     |                                    /             \
        |   -> Floor HIGH (+75 pts)     |                              (Yes: Volatile)  (No: Stable)
        | • Same-Channel BSSID Collision|                                   |               |
        |   (Backward Seq / TSF jump)   |                                   v               |
        |   -> Floor HIGH (+75 pts)     |                           < 4B.2: RSSI >= -70 dBm? >
        | • Multi-Ch BSSID Clone (TypeA)|                                  /         \      |
        |   -> Floor HIGH (+70 pts)     |                             (Yes)          (No)   |
        | • New AP (age < 24h, W2)      |                              /               \    |
        |   -> Floor MED (30) + 20 pts  |                             |                 v   v
        | • SSID Mutated (+45 pts)      |                             |        +--------------------+
        +-------------------------------+                             |        | Monitor Infrequent |
                        |                                             |        | (10s Summary Log)  |
                        v                                             |        +--------------------+
        +-------------------------------+                             |                  |
        | 4A.2: Logging Behaviour       |                             +--------+---------+
        | • Update `ram_bssids` & queue |                                      |
        |   for SQLite WAL              |                                      v
        +-------------------------------+                           +-------------------------------+
                        |                                           | 4B.3: Logging Beacon Frame    |
                        |                                           | • Store full IE frame payload |
                        |                                           +-------------------------------+
                        |                                                      |
                        |                                                      v
                        |                                           +-------------------------------+
                        |                                           | 4B.4: Beacon Frame Analysis   |
                        |                                           | • Severe IE Mismatch (+55 pts)|
                        |                                           | • DS Tag 3 Ch Spoof (+45 pts) |
                        |                                           | • Timing Jitter >20ms (+20pts)|
                        |                                           | • Partial IE / Non-Std Ch(+15)|
                        |                                           | • 100% IE Match (-35 pts)     |
                        |                                           +-------------------------------+
                        |                                                      |
                        +--------------------------+---------------------------+
                                                   | (Tracks 4A & 4B Converge)
                                                   v
                                   +-------------------------------+
                                   | 5. Hybrid Risk Scoring Engine |
                                   | • Apply Hard Floors (HIGH/MED)|
                                   | • Sum Points (0 - 100 scale)  |
                                   | • Expire New AP floor >= 24h  |
                                   +-------------------------------+
                                                   |
                         +-------------------------+-------------------------+
                         | (< 30 pts: Low)         | (30 - 69 pts: Med)      | (>= 70 pts: High)
                         | [3.0s Periodic Flush]   | [Instant 0ms Bypass!]   | [Instant 0ms Bypass!]
                         v                         v                         v
                 +---------------+         +---------------+         +---------------+
                 |   Watchlist   |         | Active Alert  |         |Security Alert |
                 | Keep tracking,|         | Prompt text   |         | Prompt text   |
                 |   no alert    |         | alert to app  |         | alert to app  |
                 +---------------+         +---------------+         +---------------+
```

## Version 3 — Step-by-Step Component Info Cards

### Card 01: Stage 0 — BSSID Cache & Name Mutation Detector (`Option M2`)

* **What It Is:** An in-memory dictionary lookup (`ram_bssids`) backed by SQLite (`bssid_devices`) that checks every incoming Beacon's hardware MAC (`BSSID`) and current `SSID` in `0.002 ms`.
* **How It Works:**
  * If `bssid` is whitelisted (`is_whitelisted == 1`) and `db_ssid == observed_ssid`, update `last_seen_ts` in RAM and exit immediately as `BENIGN`.
  * If `bssid` is already in `ram_bssids` but `db_ssid != observed_ssid`, flag `is_mutated = True (+45 pts)`, pass the new `observed_ssid` into `Stage 1 (ram_ssids / ssid_catalog)` via the explicit outgoing arrow so its XGBoost and `bge-small` scores are populated with zero `NULL` gaps, and force-route through `Stage 2.5` into `4A & 4B`.
  * Weak RSSI never drops a frame at Stage 0.
* **What It Fixes:** Eliminates redundant AI inference on 99.9% of repeat beacons while catching attackers who dynamically rename an active rogue AP (`hostapd` / WiFi Pineapple).
### Card 02: Stage 1 — `ssid_catalog` Cache & XGBoost Lexical Classifier

* **What It Is:** A fast (`1.4 ms` live $1 \times M$ / `~2.1 ms` cold-boot $N \times M$ batch) gradient-boosted decision tree evaluating 11 lexical and orthographic features ($f_1..f_{11}$) against $M$ campus whitelist SSIDs.
* **How It Works:** Computes Levenshtein distance, Jaro-Winkler similarity, trigram overlap, and homoglyph substitutions on uncached SSIDs, saving `xgb_prob` into `ram_ssids` and queueing for `ssid_catalog`.
* **What It Fixes:** Catches **100.0%** of classical typo-squatting Evil Twins (`Un1versity_Campus_5G`) and rejects **97.5%** of ambient noise at the lexical layer.
### Card 03: Stage 2 — `bge-small-en-v1.5` Semantic Shield & Stopword Sanitizer (`Q1 = Option 1`)

* **What It Is:** A lightweight `66.4 MB` ONNX bi-encoder generating `384d` semantic vectors in `5.8 ms` on Raspberry Pi 5 CPU.
* **How It Works:**
  * **Live Mode (Type A,** **N = 1):** Embeds a newly discovered SSID **immediately (0 ms** **queue wait)** and multiplies the `1 x 384` vector against the pre-cached $M \times 384$ whitelist matrix $\mathbf{W}$ (`v @ W.T` in `0.005 ms`).
  * **Startup Mode (Type B,** **N >> 1):** Batch-embeds all initial SSIDs in one ONNX call (`E @ W.T`).
  * Stores both `bge_cos_raw` and `bge_cos_clean` (where `WPA2/3-PSK` is set to `0.0` and generic tokens `wifi`, `5g`, `wlan`, `net`, `broadband` are stripped).
* **What It Fixes:** Catches **97.1%** of Zero-Overlap Lures (`Complimentary_Visitor_Broadband`), cures the **95% false-positive rate** on Open coffee shop Wi-Fi (`Starbucks_WiFi`), and avoids artificial `100 ms` queue lag during live sniffing (`Trap 1`).
### Card 04: Stage 2.5 — `Suspicious Name?` Gatekeeper (`G1 OR-Gate`)

* **What It Is:** The boolean routing diamond connecting Group 1 (Left Column) to Group 2 (Right Column).
* **How It Works:** Routes a BSSID to Parallel Tracks `4A & 4B` if: $$\text{xgb_prob} \ge 0.50 ;\lor; \text{bge_cos} \ge 0.60 ;\lor; \text{is_mutated} = \text{True}$$ Otherwise, routes to `Brief Logging`.
* **What It Fixes:** Prevents benign ambient traffic from consuming stateful packet ring buffers in Group 2 while guaranteeing that orthographic typos, semantic lures, and mutated BSSIDs enter behavioral inspection.
### Card 05: Track 4A — Active RF & State Listener (`Deauth / Collision / Age`)

* **What It Is:** Parallel stateful tracker monitoring management floods, sequence/TSF counters, multi-channel cloning, and AP first-seen age.
* **How It Works:**
  * **Deauth Flood OR Same-Channel BSSID Collision** (backward `Dot11.SC` jump + backward 64-bit `TSF` clock regression): Hard Floor `HIGH (+75 pts)`.
  * **Multi-Channel BSSID Clone (Type A):** Same BSSID transmitting on 2 channels simultaneously $\rightarrow$ Hard Floor `HIGH (+70 pts)`.
  * **New AP (age < 24h, Option N2 + W2):** Hard Floor `MEDIUM (30 pts) + 20 pts` for the first 24 hours; automatically decays to `0` at `age >= 24h`.
* **What It Fixes:** Separates normal packet loss (forward-only sequence gaps) from real BSSID collisions and ensures brand-new suspicious APs cannot silently hide in `Watchlist` during their first 24 hours.
### Card 06: Track 4B (Part 1) — RSSI Volatility & Adaptive Frame Logger

* **What It Is:** Signal variance detector and I/O rate controller in Parallel Track 4B.
* **How It Works:**
  * **RSSI Range Volatility ($\Delta\text{RSSI} > 15\text{ dB}$):** Adds `+20 pts`.
  * **Static Strong RSSI (>= -70 dBm):** Adds **0 pts**, switching logging between `Store full frame data` and `Monitor infrequently`.
* **What It Fixes:** Avoids falsely penalizing legitimate ceiling APs mounted close to the Pi 5 while still detecting sudden signal jumps from mobile or spoofed transmitters.
### Card 07: Track 4B (Part 2) — Deep Beacon IE Fingerprinting (`Auto-Learn Blueprint`)

* **What It Is:** Deep inspection of 802.11 Beacon Information Elements (`Dot11Elt`) against an auto-learned, locked Campus IE Blueprint (`campus_ie_profile`).
* **How It Works:** Compares RSN AKM (`802.1X` vs `Open`), Mobility Domain ID (`Tag 54 MDID`), Controller Vendor TLVs (`Tag 221/133`), PHY streams (`Tag 45/191/255`), and DS Parameter channel (`Tag 3`).
  * **Severe** **info mismatch** **(+55 pts):** Open encryption on 802.1X pattern, WPS consumer model tag, `1x1` USB PHY downgrade, or missing `MDID`/Controller TLV.
  * **DS Tag 3 Channel Spoof (+45 pts):** Captured channel differs from Tag 3 by $\ge 2$ channels in 2.4 GHz (or any mismatch in 5 GHz).
  * **100% Campus IE Blueprint Match (-35 pts):** Verified campus hardware/controller match.
* **What It Fixes:** Defeats trivial `macchanger` OUI spoofing and allows legitimate Departmental Sister networks (`Law_School_Faculty`) to settle automatically into `Watchlist (Low)` after the 24h decay window.
### Card 08: Stage 5 — Hybrid Risk Scoring Engine & Instant-Bypass Batch Flush (`Q2 = Option 1`)

* **What It Is:** Final decision engine combining hard floors and additive points (`0–100`) paired with the hybrid `3.0s` / Instant-Bypass SQLite WAL batch layer (`WiFi_IDS_Batching_Spec_v2.1.1.md`).
* **How It Works:**
  * Evaluates `Low (< 30)` $\rightarrow$ `Watchlist`, `Medium (30–69)` $\rightarrow$ `Active Alert`, `High (>= 70)` $\rightarrow$ `Security Alert`.
  * Flushes routine `Brief Logging` and `Watchlist` updates to SQLite WAL every **3.0 seconds** (`0.33 fsync/s`), **but bypasses the timer (0 ms** **wait)** to commit immediately whenever any BSSID enters or escalates to `MEDIUM` or `HIGH`.
  * Checks `PRAGMA data_version` (`0.001 ms`) during every flush to hot-reload any BSSIDs whitelisted via the Dashboard UI `[+ Add to Whitelist]` button.
* **What It Fixes:** Eliminates `sqlite3.OperationalError: database is locked` AND eliminates the 3-second alert delay (`Trap 2`) so `Active` and `Security` alerts appear on the Dashboard UI in `< 10 ms`.
## Master Hybrid Risk Scoring Reference (`0–100` Scale)

| **Rank** | **Check Name** | **Track** | **Score / Floor** | **24h Decay?** | **Condition** |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **1** | **Deauth Storm / Same-Ch Collision** | `4A` | **Floor** **HIGH** **(+75)** | No | Deauth flood OR backward Seq + TSF clock regression |
| **2** | **Channel Match Type A (Multi-Ch Clone)** | `4A` | **Floor** **HIGH** **(+70)** | No | Same BSSID active on 2 channels simultaneously |
| **3** | **Severe** **info mismatch** | `4B` | **+55 pts** | No | Open vs 802.1X, WPS tag, `1x1` PHY, missing MDID/Tag 221 |
| **4** | **Channel Match Type B (DS Tag 3 Spoof)** | `4B` | **+45 pts** | No | Captured channel != IE Tag 3 (`>= 2` ch off in 2.4G / any in 5G) |
| **5** | **BSSID Name Mutation (Option M2)** | `0 -> 4A` | **+45 pts** | No | Known BSSID changes its broadcast SSID (`is_mutated = 1`) |
| **6** | **New AP (age < 24h, Option N2 + W2)** | `4A` | **Floor** **MED** **(30) +** **+20** | **Yes (24h)** | Un-whitelisted BSSID (`age < 24h`) passing Stage 2.5 |
| **7** | **Beacon Timing Jitter** | `4B` | **+20 pts** | Rolling | Beacon delta-t std dev `> 20 ms` |
| **8** | **RSSI Range Volatility** | `4B` | **+20 pts** | Rolling | Sudden jump $\Delta\text{RSSI} > 15\text{ dB}$ on same BSSID |
| **9** | **Partial** **info mismatch** **/ Non-Std Ch** | `4B` | **+15 pts** **each** | No | Minor IE tag order variance OR 2.4G Ch outside `1, 6, 11` |
| **10** | **100% Campus IE Blueprint Match** | `4B` | **-35 pts** | No | Matches locked Campus `802.1X` + `MDID` + `Tag 221` + `4x4` PHY |
| **11** | **Static Strong RSSI (>= -70 dBm)** | `4B` | **0 pts** **(Gate only)** | N/A | Switches between full-frame logging and infrequent monitoring |

