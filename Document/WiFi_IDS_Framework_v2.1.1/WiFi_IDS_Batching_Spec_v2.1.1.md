# Edge Wi-Fi Evil Twin Detection Framework — Batching, Caching & I/O Engine Specification (`v2.1.1`)

**Document ID:** `BATCH-SPEC-v2.1.1`**Target Hardware:** Raspberry Pi 5 Edge Sensor (ARM Cortex-A76 Quad-Core, Monitor Mode 802.11 Sniffer, Local SQLite WAL Storage)**Companion Documents:** `WiFi_IDS_Arch_Spec_v2.1.1.md`, `WiFi_IDS_Build_Plan_v2.1.1.md`, `WiFi_IDS_CHANGELOG_v2.1.1.md`

## 1. Executive Summary: Why a Dedicated Batching Architecture Is Required

In an operational campus environment with $50$ nearby Access Points broadcasting $10$ beacons/second ($500\text{ packets/sec}$) against $M$ protected whitelist SSIDs, a naive per-packet pipeline fails in two ways:

* **Storage I/O Collapse (500 fsync/sec):** Executing `INSERT`/`UPDATE` + `conn.commit()` on every captured beacon frame saturates Raspberry Pi microSD/NVMe I/O, triggers `sqlite3.OperationalError: database is locked` when the Dashboard UI queries the database, and causes kernel packet drops.
* **Redundant $N \times M$ AI Compute:** Re-running lexical feature extraction, XGBoost (`1.4 ms`), and `bge-small-en-v1.5` ONNX embedding (`5.8 ms`) across $M$ whitelist targets on every beacon wastes CPU on strings that were already evaluated milliseconds earlier.
At the same time, **naive batching introduces two operational traps** that `v2.1.1` explicitly eliminates:

* **Trap 1 (The** **100 ms** **Live Queue Delay):** Holding newly discovered SSIDs in a `100 ms` collection window (`Type B` batching) makes sense *only* during the first second of cold boot when $N=25+$ networks appear simultaneously. Once running, new SSIDs appear one by one ($N=1$). Forcing live beacons to wait in a `100 ms` queue adds artificial lag for zero batching gain.
* **Trap 2 (The** **3.0 s** **Alert Blind Spot):** Buffering database writes in RAM for `3.0 seconds` (`Type C` batching) reduces disk writes by `1,500x`, *but* if a newly detected Evil Twin or Deauth Storm waits `3.0 seconds` in RAM before flushing to SQLite, the Dashboard UI alert is delayed by up to `3.0 seconds`.
## 2. Summary Comparison of the 4 Batching & Caching Mechanisms (`v2.1.1`)

| **Mechanism** | **Scope** | **Operational Mode** | **Unbatched Cost** | **Batched / Cached Cost (v2.1.1)** | **Engineering Rule Locked In** |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **1.** **Type A: $1 \times M$ Whitelist Matrix Vectorization** | Single new SSID vs $M$ Whitelist SSIDs | **Live Sniffing (N = 1)** | $M \times 5.8\text{ ms} = 58\text{ ms}$ (for $M=10$) | **5.8 ms** **embed +** **0.005 ms** **dot product (v @ W.T)** | **Q1 = Option 1:** Every new live SSID is evaluated immediately (`0 ms` queue wait) against the pre-embedded $M \times 384$ RAM matrix $\mathbf{W}$. |
| **2.** **Type B: $N \times M$ Multi-SSID Burst Batching** | $N$ unknown SSIDs vs $M$ Whitelist SSIDs | **Cold Boot / Startup Scan Only (N >> 1)** | $25 \times 7.2\text{ ms} = 180\text{ ms}$ + $25$ commits (`~317 ms`) | **~38 ms** **ONNX +** **0.04 ms** **E @ W.T** **+** **2.1 ms** **XGB =** **~43 ms** | Used strictly during startup / baseline scan when $N$ uncached SSIDs are collected together. Disabled during steady-state live sniffing. |
| **3.** **Type C: Hybrid RAM-to-SQLite WAL Flush** | High-frequency packet telemetry (`500 pkt/s`) | **Continuous Background + Event-Driven Bypass** | `500 commits/sec` (`500 fsync/sec`) | **0.33 fsync/sec** **(3.0s** **timer) OR** **< 10 ms** **on Alert Bypass** | **Q2 = Option 1:** Routine telemetry (`Brief Logging` & `Watchlist`) flushes every `3.0s`; any escalation to `MEDIUM` or `HIGH` flushes **instantly (0 ms** **wait)**. |
| **4.** **PRAGMA data_version** **Hot-Reload** | Static Dashboard UI `[+ Add to Whitelist]` | **Checked Every Flush Cycle (0.001 ms)** | Requires full sniffer restart or HTTP API server | **0.001 ms** **integer check; reloads RAM only on change** | UI writes standard SQL directly to SQLite; sniffer detects `data_version` change and rebuilds $\mathbf{W}_{(M \times 384)}$ in RAM automatically. |


## 3. Master Logical Flow Diagram (Large Format)

### Figure 1.1: End-to-End Batching, RAM Caching, Instant Alert Bypass & UI Hot-Reload Flow

```text
========================================================================================================================
                         PHASE A: STARTUP / COLD-BOOT INITIALIZATION (RUNS ONCE AT PROCESS START)
========================================================================================================================
  +------------------------------------------------------------------------------------------------------------------+
  | 1. SQLite WAL Init & RAM Mirror Load                                                                             |
  |    • Execute: PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL; PRAGMA busy_timeout=5000;                      |
  |    • Load `ssid_catalog` -------------> into `ram_ssids` dict: { ssid_text: SSIDRecord }                         |
  |    • Load `bssid_devices` ------------> into `ram_bssids` dict: { bssid: BSSIDState }                            |
  |    • Load `campus_ie_profile` --------> into `ram_ie_blueprint` object                                           |
  |    • Load `known_whitelist_bssids` ---> into `ram_whitelist_bssids` set                                          |
  |    • Pre-compute Whitelist Embeddings -> L2-normalized NumPy Matrix W of shape (M x 384), dtype=float32          |
  |    • Record initial SQLite state ------> `last_data_version = cursor.execute("PRAGMA data_version").fetchone()`  |
  +------------------------------------------------------------------------------------------------------------------+
                                                           |
                                                           v
  +------------------------------------------------------------------------------------------------------------------+
  | 2. Optional Cold-Boot Burst Scan (Type B: N x M Vectorized Batching — Only If N Uncached SSIDs Queued at Boot)   |
  |    • Batch-embed all N unknown SSIDs in one SIMD ONNX call: E_(N x 384) = bge_small.embed(list_of_N_ssids)       |
  |    • Compute all N x M cosine scores in one matrix multiply: cos_scores = np.max(E @ W.T, axis=1) (0.04 ms)      |
  |    • Compute all N lexical feature rows and run single batch prediction: xgb_probs = xgb.predict_proba(X_Nx11)   |
  |    • Single transactional write: BEGIN -> cursor.executemany("INSERT INTO ssid_catalog...") -> COMMIT            |
  +------------------------------------------------------------------------------------------------------------------+
                                                           |
                                                           v
========================================================================================================================
                   PHASE B: LIVE PACKET CAPTURE LOOP (500 PACKETS/SEC — ZERO DISK I/O ON HOT PATH)
========================================================================================================================
                       [ Incoming 802.11 Frame Captured from Monitor-Mode Socket (scapy/libpcap) ]
                                                           |
                                                           v
                                        < Stage 0: Is BSSID in `ram_bssids`? >
                                              /                        \
                                      (Yes: Cache Hit)            (No: New BSSID)
                                            /                            \
                                           v                              v
                        < ram_bssids[bssid].ssid == obs_ssid? >    +-------------------------------------+
                              /                         \          | Create new `BSSIDState` in RAM      |
                      (Yes: Unchanged)            (No: Mutated!)   | • Set `first_seen_ts = now`         |
                            /                             \        | • Mark `bssid` in `dirty_bssids`    |
                           v                               v       +-------------------------------------+
            +-----------------------------+   +-----------------------------------+       |
            | Fast Path Check:            |   | Option M2 Mutation Handler:       |       |
            | • If `is_whitelisted == 1`: |   | • Set `is_mutated = True` (+45pt) |       |
            |   Update `last_seen_ts` in  |   | • Update `current_ssid = obs_ssid`|       |
            |   RAM, mark dirty, & EXIT.  |   | • Mark `bssid` in `dirty_bssids`  |       |
            +-----------------------------+   +-----------------------------------+       |
                           |                                   |                          |
                           +-----------------+-----------------+--------------------------+
                                             | (Non-whitelisted BSSID continues)
                                             v
                              < Stage 1: Is `obs_ssid` in `ram_ssids`? >
                                    /                            \
                            (Yes: 0.002 ms)                 (No: Live Cache Miss, N = 1)
                                  /                                \
                                 v                                  v
              +-------------------------------------+   +------------------------------------------------------------+
              | Reuse Cached Naming Scores from RAM |   | Type A: Instant 1 x M Vectorized Compute (Q1 = Option 1)   |
              | • Read `xgb_prob`                   |   | • NO 100 ms queue wait! Evaluates immediately in 7.2 ms:   |
              | • Read `bge_cos_clean` / `raw`      |   |   1. Extract f1..f11 vs M targets -> `xgb_prob` (1.4 ms)   |
              | • Read `is_suspicious_name`         |   |   2. Embed `obs_ssid` -> `v_raw` (1 x 384) (5.8 ms)        |
              +-------------------------------------+   |   3. Dot product: `cos_raw = max(v_raw @ W.T)` (0.005 ms)  |
                                 \                      |   4. If OPEN/802.1X: strip stopwords -> `cos_clean`        |
                                  \                     |      Else (WPA2/3-PSK): `cos_clean = 0.0`                  |
                                   \                    |   5. Save in `ram_ssids[obs_ssid]` & queue for SQLite      |
                                    \                   +------------------------------------------------------------+
                                     \                                      /
                                      +------------------+-----------------+
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
                  +-----------------------------------+   +----------------------------------------------------------+
                  | Brief Logging (In-Memory Dedupe)  |   | Parallel Tracks 4A & 4B + Stage 5 Risk Engine (In RAM)   |
                  | • Update `last_seen_ts`, `rssi`   |   | • Track 4A: Update Deauth count, Seq/TSF collision,      |
                  |   inside `ram_bssids[bssid]`      |   |   active channel set, & 24h W2 New AP floor in RAM       |
                  | • Add `bssid` to `dirty_bssids`   |   | • Track 4B: Update RSSI volatility, beacon jitter,       |
                  | • DO NOT write to disk yet!       |   |   and IE Blueprint match status in RAM                   |
                  +-----------------------------------+   | • Stage 5: Compute `new_score` (0-100) & `new_tier`      |
                                    |                     |   (`LOW < 30`, `MEDIUM 30-69`, `HIGH >= 70`)             |
                                    |                     +----------------------------------------------------------+
                                    |                                                   |
                                    |                                                   v
                                    |                     < Q2 = Option 1: Did Risk Tier Escalate to MED or HIGH? >
                                    |                     [  (new_tier in {'MEDIUM','HIGH'} and new_tier > old_tier) ]
                                    |                     [   OR (first_alert_for_bssid and new_tier >= 'MEDIUM')    ]
                                    |                                    /                              \
                                    |                        (No: Routine Watchlist)          (Yes: ALERT TRIGGERED!)
                                    |                                  /                                  \
                                    +-----------------+---------------+                                    v
                                                      |                                  +---------------------------+
                                                      v                                  | INSTANT BYPASS FLUSH      |
                                    +-----------------------------------+                | (0 ms Timer Wait!)        |
                                    | Wait in RAM Buffer Until:         |                | • Immediately execute     |
                                    | `now - last_flush_ts >= 3.0 sec`  |                |   Phase C Transaction     |
                                    +-----------------------------------+                | • Alert visible to UI in  |
                                                      |                                  |   < 10 ms!                |
                                                      +-----------------+----------------+---------------------------+
                                                                        |
                                                                        v
========================================================================================================================
              PHASE C: TRANSACTIONAL SQLITE WAL FLUSH & PRAGMA data_version SYNC (RUNS EVERY 3.0s OR ON BYPASS)
========================================================================================================================
  +------------------------------------------------------------------------------------------------------------------+
  | Step C1: Check External Dashboard UI Edits via `PRAGMA data_version` (0.001 ms)                                  |
  |   • Query: `curr_ver = conn.execute("PRAGMA data_version;").fetchone()[0]`                                       |
  |   • If `curr_ver != last_data_version`:                                                                          |
  |       -> Dashboard UI clicked `[+ Add to Whitelist]`!                                                            |
  |       -> Reload `known_whitelist_bssids` & `whitelist_ssids` from SQLite into RAM                                |
  |       -> Rebuild `W_(M x 384)` matrix using cached `bge_vector_blob` from `ssid_catalog`                         |
  +------------------------------------------------------------------------------------------------------------------+
                                                           |
                                                           v
  +------------------------------------------------------------------------------------------------------------------+
  | Step C2: Single Atomic SQLite WAL Batch Commit (~5 - 12 ms Total for All Dirty Records)                          |
  |   • `with conn:` (Opens single `BEGIN IMMEDIATE` transaction)                                                    |
  |       1. If `new_ssid_queue` non-empty:                                                                          |
  |          `cursor.executemany("INSERT OR IGNORE INTO ssid_catalog VALUES (?,?,?,?,?,?,?,?)", new_ssid_queue)`     |
  |       2. If `dirty_bssids` non-empty (Deduplicated: 1 row per BSSID, NOT 30 rows per 3s!):                       |
  |          `cursor.executemany("INSERT INTO bssid_devices ... ON CONFLICT(bssid) DO UPDATE ...", dirty_bssid_rows)`|
  |       3. If `pending_behavior_logs` non-empty:                                                                   |
  |          `cursor.executemany("INSERT INTO beacon_behavior_logs VALUES (...)", pending_behavior_logs)`            |
  |   • `COMMIT` (Executes exactly 1 `fsync` to disk)                                                                |
  |   • Clear `new_ssid_queue`, `dirty_bssids`, `pending_behavior_logs`; update `last_flush_ts = time.monotonic()`   |
  |   • Refresh `last_data_version = conn.execute("PRAGMA data_version;").fetchone()[0]` (ignores own commit!)       |
  +------------------------------------------------------------------------------------------------------------------+
```

## 4. Detailed Subsystem Design Specification

### 4.1 In-Memory Data Structures (`ram_ssids` & `ram_bssids`)

To guarantee `0.002 ms` packet processing without touching SQLite on the hot path, the sniffer maintains four structures in RAM:

| **RAM Structure** | **Python Type** | **Key** | **Value / Shape** | **Memory Footprint (500 APs)** |
| :--- | :--- | :--- | :--- | :--- |
| **W_matrix** | `np.ndarray` (`float32`) | Row index $0..M-1$ | L2-normalized `(M, 384)` matrix of protected campus whitelist SSIDs | `~15 KB` ($M=10$) |
| **ram_ssids** | `dict[str, SSIDRecord]` | `ssid_text` (`str`) | `matched_wl`, `xgb_prob`, `bge_cos_raw`, `bge_cos_clean`, `is_suspicious_name` | `~120 KB` (500 SSIDs) |
| **ram_bssids** | `dict[str, BSSIDState]` | `bssid` (`str`) | Rolling window deque of last 20 RSSI/TSF/Seq samples, `current_ssid`, `is_whitelisted`, `is_mutated`, `active_channels`, `first_seen_ts`, `last_seen_ts`, `current_risk_score`, `risk_tier` | `~650 KB` (500 BSSIDs) |
| **dirty_bssids** | `set[str]` | `bssid` (`str`) | Set of `bssid` keys modified since the last SQLite flush | `< 20 KB` |


### 4.2 Why In-Memory Deduplication Cuts Write Volume by `30x` Within Each `3.0s` Window

Suppose 50 APs each broadcast 10 beacons/sec:

* Over a `3.0-second` window, the sniffer receives **$50 \times 10 \times 3 = 1,500\text{ beacon frames}$**.
* Because `ram_bssids[bssid]` updates in place inside Python RAM (`last_seen_ts`, `last_rssi`, `rssi_volatility_db`, `current_risk_score`), `dirty_bssids` contains **at most 50 unique BSSID keys** at the end of the 3.0-second window.
* When Step C2 runs `cursor.executemany()` on `bssid_devices`, it writes **50 deduplicated rows** in a single transaction instead of 1,500 individual packet updates.
### 4.3 Avoiding False Self-Triggers on `PRAGMA data_version`

A critical SQLite implementation detail: **PRAGMA data_version** **increments only when** ***another*** **database connection modifies the database, NOT when the current connection commits.**

* Even so, to be 100% immune to driver differences, our flush loop checks `PRAGMA data_version` in **Step C1 (before** **COMMIT)** to detect external Dashboard UI writes, and then re-reads `last_data_version = conn.execute("PRAGMA data_version").fetchone()[0]` at the end of **Step C2 (after** **COMMIT)**.
* Meanwhile, the Dashboard UI opens its own SQLite connection (`PRAGMA journal_mode=WAL;`) and executes:
UPDATE bssid_devices SET is_whitelisted = 1, risk_tier = 'LOW', current_risk_score = 0 WHERE bssid = ?;

* Because SQLite WAL allows concurrent readers and non-blocking writers when the sniffer is only committing for `~8 ms` every `3.0 seconds`, the UI query succeeds instantaneously and increments `PRAGMA data_version` for the sniffer's next cycle.
### 4.4 Ring-Buffer Pruning for `beacon_behavior_logs`

While `ssid_catalog` and `bssid_devices` grow only with unique SSIDs and BSSIDs (a few megabytes per month), `beacon_behavior_logs` stores time-series behavioral snapshots. To prevent SD card exhaustion during multi-week deployments:

* **Adaptive Rate Control (Track 4B.2):**
  * Strong signal (`RSSI >= -70 dBm`): Logs at most **1 behavioral snapshot per second per suspicious BSSID** (not 10 raw frames/sec) unless an active anomaly (`Deauth`, `Seq/TSF jump`, or `Channel spoof`) occurs.
  * Weak signal (`RSSI < -70 dBm`): Logs **1 summary snapshot every 10 seconds** (`Monitor infrequently`).
* **Periodic Retention Pruning:**
  * Once every hour, the batch manager runs `DELETE FROM beacon_behavior_logs WHERE timestamp < (strftime('%s','now') - 604800);` to retain a rolling 7-day forensic window.
## 5. Reference Python Implementation Skeleton (`BatchDatabaseManager`)

```python
import sqlite3
import time
import numpy as np
from dataclasses import dataclass, field
from typing import Dict, Set, List, Tuple
@dataclass
class SSIDRecord:
    ssid_text: str
    matched_whitelist_ssid: str
    xgb_prob: float
    bge_cos_raw: float
    bge_cos_clean: float
    bge_vector_blob: bytes
    is_suspicious_name: int
    first_computed_at: float
@dataclass
class BSSIDState:
    bssid: str
    current_ssid: str
    is_whitelisted: int = 0
    is_mutated: int = 0
    active_channels_json: str = "[]"
    first_seen_ts: float = 0.0
    last_seen_ts: float = 0.0
    last_rssi: int = -100
    rssi_volatility_db: float = 0.0
    primary_channel: int = 1
    encryption_type: str = "OPEN"
    ie_match_status: str = "SEVERE_MISMATCH"
    current_risk_score: int = 0
    risk_tier: str = "LOW"
class BatchDatabaseManager:
    FLUSH_INTERVAL_SEC = 3.0
    TIER_RANK = {"LOW": 0, "MEDIUM": 1, "HIGH": 2}
    def __init__(self, db_path: str):
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self.conn.execute("PRAGMA journal_mode=WAL;")
        self.conn.execute("PRAGMA synchronous=NORMAL;")
        self.conn.execute("PRAGMA busy_timeout=5000;")
        self.ram_ssids: Dict[str, SSIDRecord] = {}
        self.ram_bssids: Dict[str, BSSIDState] = {}
        self.new_ssid_queue: List[Tuple] = []
        self.dirty_bssids: Set[str] = set()
        self.pending_behavior_logs: List[Tuple] = []
        self.last_flush_ts = time.monotonic()
        self.last_data_version = self._get_data_version()
    def _get_data_version(self) -> int:
        return self.conn.execute("PRAGMA data_version;").fetchone()[0]
    def record_bssid_update(self, state: BSSIDState, prev_tier: str) -> None:
        """Updates RAM state and triggers Instant Alert Bypass if risk_tier escalated."""
        self.ram_bssids[state.bssid] = state
        self.dirty_bssids.add(state.bssid)
        # Q2 = Option 1: Instant Flush Bypass on Alert Trigger/Escalation
        new_rank = self.TIER_RANK.get(state.risk_tier, 0)
        old_rank = self.TIER_RANK.get(prev_tier, 0)
        if new_rank >= 1 and new_rank > old_rank:
            self.flush_to_sqlite(force=True)
        elif (time.monotonic() - self.last_flush_ts) >= self.FLUSH_INTERVAL_SEC:
            self.flush_to_sqlite(force=False)
    def flush_to_sqlite(self, force: bool = False) -> None:
        """Executes Step C1 (PRAGMA data_version check) and Step C2 (Atomic Batch Commit)."""
        curr_ver = self._get_data_version()
        if curr_ver != self.last_data_version:
            self.reload_whitelist_into_ram()
        if not (force or self.new_ssid_queue or self.dirty_bssids or self.pending_behavior_logs):
            self.last_flush_ts = time.monotonic()
            return
        with self.conn:
            if self.new_ssid_queue:
                self.conn.executemany(
                    """INSERT OR IGNORE INTO ssid_catalog
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                    self.new_ssid_queue,
                )
                self.new_ssid_queue.clear()
            if self.dirty_bssids:
                rows = [
                    (
                        s.bssid, s.current_ssid, s.is_whitelisted, s.is_mutated,
                        s.active_channels_json, s.first_seen_ts, s.last_seen_ts,
                        s.last_rssi, s.rssi_volatility_db, s.primary_channel,
                        s.encryption_type, s.ie_match_status, s.current_risk_score, s.risk_tier
                    )
                    for b in self.dirty_bssids if (s := self.ram_bssids.get(b)) is not None
                ]
                self.conn.executemany(
                    """INSERT INTO bssid_devices VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                       ON CONFLICT(bssid) DO UPDATE SET
                           current_ssid=excluded.current_ssid,
                           is_whitelisted=excluded.is_whitelisted,
                           is_mutated=excluded.is_mutated,
                           active_channels_json=excluded.active_channels_json,
                           last_seen_ts=excluded.last_seen_ts,
                           last_rssi=excluded.last_rssi,
                           rssi_volatility_db=excluded.rssi_volatility_db,
                           primary_channel=excluded.primary_channel,
                           encryption_type=excluded.encryption_type,
                           ie_match_status=excluded.ie_match_status,
                           current_risk_score=excluded.current_risk_score,
                           risk_tier=excluded.risk_tier""",
                    rows,
                )
                self.dirty_bssids.clear()
            if self.pending_behavior_logs:
                self.conn.executemany(
                    """INSERT INTO beacon_behavior_logs
                       (bssid, timestamp, seq_num, tsf_timestamp, jitter_ms,
                        deauth_count_1m, channel_anomaly_type, ssid_mutated, raw_ie_fingerprint)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    self.pending_behavior_logs,
                )
                self.pending_behavior_logs.clear()
        self.last_data_version = self._get_data_version()
        self.last_flush_ts = time.monotonic()
    def reload_whitelist_into_ram(self) -> None:
        """Hot-reloads whitelisted BSSIDs/SSIDs after Dashboard UI edits."""
        for row in self.conn.execute("SELECT bssid, is_whitelisted FROM bssid_devices WHERE is_whitelisted = 1"):
            if row[0] in self.ram_bssids:
                self.ram_bssids[row[0]].is_whitelisted = 1
                self.ram_bssids[row[0]].risk_tier = "LOW"
                self.ram_bssids[row[0]].current_risk_score = 0
```
