# Edge Wi-Fi Evil Twin Detection Framework — Overview & Build Plan (`v2.1.1`)

**Document ID:** `BUILD-PLAN-v2.1.1`**Target Environment:** Raspberry Pi 5 Edge Sensor (Monitor Mode 802.11 Sniffer + SQLite WAL Database)**Protected Campus Whitelist:** `['University_Campus_5G', 'University_Staff_Secure', 'University_Student_WiFi', 'University_Guest_Portal', 'eduroam']`**Companion Specifications:** `WiFi_IDS_Arch_Spec_v2.1.1.md`, `WiFi_IDS_Batching_Spec_v2.1.1.md`, `WiFi_IDS_CHANGELOG_v2.1.1.md`

## Part 1: System Overview (For Human Developers)

### 1.1 The Core Problem & Two-Group Solution

A standalone decision tree (XGBoost) catches **100%** of spelling typos (`Un1versity_Campus_5G`) in `1.4 ms`, but misses **97.1%** of Zero-Overlap Semantic Lures (`Complimentary_Visitor_Broadband`). Conversely, a lightweight embedding model (`BAAI/bge-small-en-v1.5`, `66.4 MB` ONNX) catches **97.1%** of Zero-Overlap Lures in `5.8 ms`, but suffers a **95% false-positive rate** on ambient coffee shop Wi-Fi (`Starbucks_WiFi`) due to shared generic words like `"WiFi"` and `"5G"`.

To solve both problems without overloading the Raspberry Pi 5, the framework splits detection into two groups backed by an in-memory + SQLite WAL batch engine (`WiFi_IDS_Batching_Spec_v2.1.1.md`):

* **Group 1 — Name Screening (Left Column):**
  * **Stage 0 (BSSID Cache & Mutation Check):** Checks `ram_bssids` (`0.002 ms`). If a known `BSSID` changes its `SSID` (`db_ssid != observed_ssid`), **Option M2** flags `is_mutated = True (+45 pts)`, routes via an explicit outgoing arrow into `Stage 1 & 2` so `ssid_catalog` has zero `NULL` gaps, and force-routes through `Stage 2.5` to Group 2 (`4A & 4B`).
  * **Stage 1 & 2 (ssid_catalog** **Cache +** **Q1 = Option 1** **Vectorized Inference):**
    * **Live Sniffing (Type A, $1 \times M$):** Evaluates each newly discovered SSID **immediately (0 ms** **queue wait)** in `7.2 ms` (`1.4 ms` XGBoost + `5.8 ms` `bge-small` + `0.005 ms` dot product `v @ W.T` against the pre-cached $M \times 384$ whitelist matrix $\mathbf{W}$), avoiding artificial `100 ms` queue latency (`Trap 1`).
    * **Startup Scan (Type B, $N \times M$):** Uses multi-SSID batching (`E @ W.T`) only during cold boot when $N$ unknown SSIDs arrive together.
  * **Stage 2.5 (Suspicious Name?** **G1 OR-Gate):** Routes to Group 2 if `xgb_prob >= 0.50 OR bge_cos >= 0.60 OR is_mutated == True`.
* **Group 2 — Parallel RF & Beacon Behavior Detection (Right Column):**
  * **Parallel Track 4A (Active RF & State Listener):** Monitors Deauth floods, Same-Channel BSSID Collisions (backward sequence jumps + TSF clock regressions), Multi-Channel BSSID Clones, and the 24-hour New AP floor (`Option N2 + W2`).
  * **Parallel Track 4B (RSSI Volatility & Deep Beacon IE Inspector):** Checks RSSI range volatility (`> 15 dB`), uses static RSSI (`>= -70 dBm`, `0 pts`) strictly to control logging frequency, and compares Beacon Information Elements (`Dot11Elt`) against an auto-learned Campus IE Blueprint (`campus_ie_profile`).
* **Hybrid 3.0s Batch Flush + Instant Alert Bypass (Q2 = Option 1) & UI Hot-Reload:**
  * Routine telemetry (`Brief Logging` & `Watchlist`) buffers in `ram_bssids` and flushes to SQLite WAL every **3.0 seconds** (`0.33 fsync/sec`).
  * **Instant Alert Bypass (Trap 2** **Fix):** Whenever any BSSID enters or escalates to `MEDIUM (30–69 pts)` or `HIGH (>= 70 pts)`, the batch manager bypasses the 3.0s timer (`0 ms` wait) and commits immediately (`< 10 ms` to Dashboard UI).
  * Every flush checks `PRAGMA data_version;` (`0.001 ms`) to detect when the static Dashboard UI `[+ Add to Whitelist]` button inserts a BSSID into SQLite, hot-reloading the RAM whitelist automatically.
## Part 2: AI Coding Assistant Specification & Ruleset

### 2.1 Hard Architectural Rules (DO NOT Violate)

* **Never drop a packet at Stage 0 due to weak RSSI.** Weak RSSI (`< -70 dBm`) is evaluated only in Track 4B (`0 pts`) to switch between full-frame logging and infrequent summary logging.
* **Never leave** **NULL** **columns in** **ssid_catalog** **on BSSID Mutation (Option M2).** If a known BSSID changes its SSID to an unseen string, compute `xgb_prob`, `bge_cos_raw`, `bge_cos_clean`, and `bge_vector_blob` in `ssid_catalog` first, then force-route through `Stage 2.5` to `4A & 4B` with `+45 pts`.
* **Keep** **Stage 2.5** **clean.** The decision expression is strictly:
```python
bge_cos = row.bge_cos_clean if config.ENABLE_STOPWORD_STRIP else row.bge_cos_raw
```

is_suspicious_name = (row.xgb_prob >= 0.50) or (bge_cos >= 0.60) or bssid_state.is_mutated

* **Enforce** **Q1 = Option 1** **(No** **100 ms** **Queue in Live Mode).** Use $N \times M$ batching (`Type B`) *only* during startup/cold-boot scans. During live packet capture, evaluate any uncached SSID immediately ($N = 1$, `Type A`) against the pre-cached $M \times 384$ whitelist matrix $\mathbf{W}$.
* **Enforce** **Q2 = Option 1** **(Hybrid 3.0s Flush + Instant Alert Bypass).** Buffer routine telemetry in `ram_bssids` and flush every `3.0` seconds, **except** when `new_tier in ('MEDIUM', 'HIGH') and new_tier > old_tier`, which must call `flush_to_sqlite(force=True)` immediately (`0 ms` wait).
* **Check** **PRAGMA data_version** **on every flush.** When the Dashboard UI `[+ Add to Whitelist]` button writes to SQLite, `PRAGMA data_version` increments and triggers `reload_whitelist_into_ram()`.
### 2.2 SQLite 4-Table Schema (`PRAGMA journal_mode=WAL;`)

```sql
PRAGMA journal_mode=WAL;
PRAGMA synchronous=NORMAL;
PRAGMA busy_timeout=5000;
CREATE TABLE IF NOT EXISTS campus_ie_profile (
    profile_id INTEGER PRIMARY KEY AUTOINCREMENT,
    ssid_pattern TEXT NOT NULL UNIQUE,
    expected_akm TEXT NOT NULL,          -- '802.1X' or 'OPEN'
    mdid_hex TEXT,                       -- Tag 54 Mobility Domain ID (2-byte hex)
    vendor_oui_json TEXT,                -- JSON list of Tag 221/133 OUI/TLV signatures
    min_spatial_streams INTEGER,         -- Minimum MIMO streams from Tag 45/191/255
    ie_tag_sequence_json TEXT,           -- Ordered list of IE tag IDs
    locked_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS ssid_catalog (
    ssid_text TEXT PRIMARY KEY,
    matched_whitelist_ssid TEXT NOT NULL,
    xgb_prob REAL NOT NULL,
    bge_cos_raw REAL NOT NULL,
    bge_cos_clean REAL NOT NULL,
    bge_vector_blob BLOB NOT NULL,       -- 384 float32 bytes (1536 bytes)
    is_suspicious_name INTEGER NOT NULL, -- 0 or 1
    first_computed_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS bssid_devices (
    bssid TEXT PRIMARY KEY,
    current_ssid TEXT NOT NULL,
    is_whitelisted INTEGER NOT NULL DEFAULT 0,
    is_mutated INTEGER NOT NULL DEFAULT 0,
    active_channels_json TEXT NOT NULL,  -- Tracks simultaneous channels for Type A clone check
    first_seen_ts REAL NOT NULL,
    last_seen_ts REAL NOT NULL,
    last_rssi INTEGER NOT NULL,
    rssi_volatility_db REAL NOT NULL DEFAULT 0.0,
    primary_channel INTEGER NOT NULL,
    encryption_type TEXT NOT NULL,       -- 'OPEN', '802.1X', 'PSK'
    ie_match_status TEXT NOT NULL,       -- 'EXACT', 'PARTIAL', 'SEVERE_MISMATCH'
    current_risk_score INTEGER NOT NULL DEFAULT 0,
    risk_tier TEXT NOT NULL DEFAULT 'LOW',
    FOREIGN KEY (current_ssid) REFERENCES ssid_catalog(ssid_text)
);
CREATE TABLE IF NOT EXISTS beacon_behavior_logs (
    log_id INTEGER PRIMARY KEY AUTOINCREMENT,
    bssid TEXT NOT NULL,
    timestamp REAL NOT NULL,
    seq_num INTEGER NOT NULL,
    tsf_timestamp INTEGER NOT NULL,
    jitter_ms REAL NOT NULL,
    deauth_count_1m INTEGER NOT NULL,
    channel_anomaly_type TEXT,           -- 'NONE', 'TYPE_A_CLONE', 'TYPE_B_TAG3', 'TYPE_C_NONSTD'
    ssid_mutated INTEGER NOT NULL,
    raw_ie_fingerprint TEXT,             -- Full hex/JSON when RSSI >= -70 dBm; NULL when < -70 dBm
    FOREIGN KEY (bssid) REFERENCES bssid_devices(bssid)
);
```

## Part 3: Technical Rationale, Benchmark Dump & Batching Math

### 3.1 Master 9-Model Benchmark Summary (210 Operational Samples)

* **XGBoost Classifier (< 5 MB,** **1.4 ms):** `100.0%` on Classical Orthographic (40), `93.3%` on Departmental Sister (60), `97.5%` on Ambient Noise (40), but **2.9%** **on Zero-Overlap Lures (70)**.
* **BAAI/bge-small-en-v1.5** **(66.4 MB** **ONNX,** **5.8 ms):** **97.1%** **on Zero-Overlap Lures (70)** and `100.0%` on Classical Orthographic (40), but `13.3%` on Departmental Sister (60) and **5.0%** **on Raw Ambient Noise (40)** before stopword stripping.
### 3.2 Solving Trap 1 & Trap 2 in the Batching Engine (`v2.1.1`)

* **Why** **Type A** **($1 \times M$) Replaces** **Type B** **($N \times M$) After Boot (Trap 1** **Resolution):**
  * At cold boot, 25+ unknown SSIDs are discovered simultaneously (`Type B` embeds all 25 in `~38 ms` + `E @ W.T` in `0.04 ms`).
  * Once running, all ambient APs are cached in `ram_ssids`. New SSIDs appear one at a time ($N=1$). Holding a `100 ms` batch window for $N=1$ wastes `100 ms`. Instead, `Type A` embeds the 1 SSID immediately (`5.8 ms`) and computes `v @ W.T` in `0.005 ms`.
* **Why Hybrid 3.0s Flush + Instant Alert Bypass Solves** **Trap 2:**
  * 50 APs $\times$ 10 beacons/sec = `1,500 beacons` per 3.0s window. In-memory deduplication in `ram_bssids` collapses 1,500 frames into **50 unique BSSID state rows**, committed in 1 SQLite WAL transaction (`0.33 fsync/sec`).
  * When an attack occurs (`risk_tier` escalates to `MEDIUM` or `HIGH`), `flush_to_sqlite(force=True)` bypasses the 3.0s timer so the Dashboard UI receives the alert in `< 10 ms`.
## Part 4: Step-by-Step Build Plan & Verification Criteria

| **Step** | **Module** | **Implementation Task** | **Verification Criteria (Pass/Fail Check)** |
| :--- | :--- | :--- | :--- |
| **1** | `config.py` & `db_manager.py` | Create 4-table SQLite WAL database, `ram_bssids` / `ram_ssids` caches, 3.0s batch commit loop, Instant Alert Bypass (`Q2 = Option 1`), and `PRAGMA data_version` hot-reload watcher. | **Check 1.1:** Simulate 500 beacon updates/sec for 10s (`LOW` tier); verify `0` lock errors and `<= 4` disk commits.<br>**Check 1.2:** Run external SQL `UPDATE` whitelisting a BSSID; verify `PRAGMA data_version` triggers RAM reload within `3.0s`.<br>**Check 1.3:** Trigger a `LOW -> HIGH` risk escalation mid-window; verify `flush_to_sqlite(force=True)` commits to SQLite in `< 10 ms` without waiting for the 3.0s timer. |
| **2** | `name_screener.py` | Load `xgb_model` and `bge-small-en-v1.5` ONNX; implement cold-boot $N \times M$ batching (`Type B`), live $1 \times M$ instant inference (`Type A`, `Q1 = Option 1`), stopword stripper, `Stage 2.5` G1 OR-Gate, and `Option M2` mutation population. | **Check 2.1:** Verify `Starbucks_WiFi` (Open) scores `bge_cos_raw > 0.60` and `bge_cos_clean < 0.40`.<br>**Check 2.2:** Mutate a known BSSID's SSID to a new string; verify `ssid_catalog` has zero `NULL` fields and routes to Group 2 with `+45 pts`.<br>**Check 2.3:** Verify a single new SSID in live mode completes Stage 1 + Stage 2 in `< 10 ms` (`0 ms` queue wait). |
| **3** | `track_4a_state.py` | Implement Deauth counter (`+75`), backward Seq/TSF collision detector (`+75`), Multi-Channel BSSID clone check (`+70`), and 24h W2 New AP timer (`Floor 30 + 20`). | **Check 3.1:** Feed forward gap `Seq 100 -> 104` (`0 pts`) vs backward oscillation `2400 -> 85 -> 2401` + TSF regression (`+75 pts HIGH`).<br>**Check 3.2:** Verify New AP floor drops from `30` to `0` when `now - first_seen_ts >= 86400`. |
| **4** | `track_4b_beacon.py` | Implement `--learn-baseline` snapshot into `campus_ie_profile`, IE mismatch scorer (`+55` / `+15` / `-35`), Tag 3 channel spoof check (`+45`), and RSSI gate (`0 pts`). | **Check 4.1:** Verify strong RSSI (`-45 dBm`) adds `0 pts` and sets full-frame logging.<br>**Check 4.2:** Verify `Ch 6` frame with `Tag 3 = Ch 1` scores `+45 pts`, while `Ch 6` with `Tag 3 = Ch 5` scores `0 pts`. |
| **5** | `risk_engine.py` | Combine Track 4A & 4B floors and points into `Low (<30)`, `Medium (30-69)`, and `High (>=70)`. | **Check 5.1:** Replay 210 benchmark samples; verify `>= 97%` recall on Zero-Overlap Lures, `100%` on Classical Ortho, and `0` false alerts on established Departmental Sisters (`>24h`). |

