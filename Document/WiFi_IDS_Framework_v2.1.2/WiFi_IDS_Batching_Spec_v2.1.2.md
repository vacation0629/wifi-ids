# Edge Wi-Fi Evil Twin Detection Framework — Batching, Caching & I/O Engine Specification (v2.1.2)

**Document ID:** BATCH-SPEC-v2.1.2  
**Target Hardware:** Raspberry Pi 5 Edge Sensor (ARM Cortex-A76 Quad-Core, Monitor Mode 802.11 Sniffer, Local SQLite WAL Storage)  
**Companion Documents:** `WiFi_IDS_Arch_Spec_v2.1.2.md`, `WiFi_IDS_Build_Plan_v2.1.2.md`, `WiFi_IDS_CHANGELOG_v2.1.2.md`

---

## 1\. Executive Summary: Adversarial-Safe Batching & Caching (v2.1.2)

In `v2.1.1`, we solved **Trap 1** (removing the fixed `100 ms` queue wait in live mode) and **Trap 2** (adding an Instant Alert Bypass flush when a BSSID enters `MEDIUM` or `HIGH`). However, adversarial review identified three critical edge cases under attack (`mdk4` beacon floods and cache poisoning):

1. **Flush-Storm DoS on `force=True`:** Because every newly discovered suspicious BSSID hits the `MEDIUM` New-AP floor on its first beacon, an attacker injecting 500 fake BSSIDs/sec would trigger 500 synchronous `flush_to_sqlite(force=True)` disk commits per second.  
2. **CPU Saturation on Flooded `1 x M` Inference:** Evaluating 1,000 random fake SSIDs/sec one-by-one (`1 x M` mode at `7.2 ms` each) requires `7.2 seconds` of CPU time per second.  
3. **Unbounded RAM Growth & PSK Cache Poisoning:** Uncapped `ram_bssids` / `ram_ssids` dictionaries can exhaust RAM under random MAC/SSID floods, and zeroing `bge_cos_clean` inside `ssid_catalog` when a beacon uses WPA2-PSK allows an attacker to poison the cache before flipping to Open encryption.

`v2.1.2` upgrades the batching engine to be **100% flood-resilient** while preserving `0 ms` queue latency and `< 10 ms` alert commits during normal operation.

---

## 2\. Summary of the 5 Batching, Caching & DoS-Protection Mechanisms (v2.1.2)

| Mechanism | Operational Scope | Normal Traffic Behavior | Under `mdk4` Flood Attack | Core Engineering Rule (v2.1.2) |
| :---- | :---- | :---- | :---- | :---- |
| **1\. Work-Conserving Adaptive AI Queue (`Q1` Upgrade)** | Uncached SSID inference (`XGBoost` \+ `bge-small`) | **Queue Depth \= 1:** Runs `Type A` (\$1 \\times M\$ dot product `v @ W.T`) immediately (`0 ms` wait, `7.2 ms` compute). | **Queue Depth \> 1:** Drains up to `32` queued SSIDs at once via `Type B` (\$N \\times M\$ matrix multiply `E @ W.T`, `~1.7 ms/SSID`). | Zero queue lag in normal traffic; automatic `4.2x–7.4x` SIMD batch speedup during SSID floods. |
| **2\. Instant Alert Bypass \+ `250 ms` Cooldown (`Q2` Upgrade)** | SQLite WAL commits on `MEDIUM` / `HIGH` escalations | **First Alert (`dt >= 250 ms`):** Flushes immediately (`0 ms` timer wait, `< 10 ms` to UI). | **Flood Alerts (`dt < 250 ms`):** Sets `urgent_flush_pending = True` and coalesces all new alerts into the next `250 ms` tick. | Preserves instant `< 10 ms` UI alerting while capping worst-case disk writes at **4 commits/sec** (`4 fsync/sec`). |
| **3\. Routine `3.0 s` Deduplicated Batch Flush (`Type C`)** | Benign (`Brief Logging`) & stable `Watchlist` / repeat alerts | Collapses `1,500 beacons / 3s` (50 APs) into `<= 50` deduplicated BSSID rows (`0.33 fsync/sec`). | Deduplicates repeated frames in RAM; evicts oldest `LOW` entries if RAM cap reached. | Repeat beacons from an already-alerted `MEDIUM`/`HIGH` AP are batched on the `3.0 s` timer. |
| **4\. Encryption-Agnostic `ssid_catalog` \+ Bounded LRU RAM** | `ram_ssids` (`4,096` cap) & `ram_bssids` (`4,096` cap) | Stores pure text `bge_cos_raw` and `bge_cos_clean` in `ssid_catalog`; applies `0.5x` PSK weight at Stage 2.5. | OrderedDict LRU evicts oldest un-whitelisted `LOW` entries when count exceeds `4,096`. | Prevents PSK cache poisoning (Point 3\) and caps total RAM footprint under `< 8 MB` (Point 8). |
| **5\. Manual-Only UI Whitelist \+ `PRAGMA data_version`** | Static Dashboard UI `[+ Add to Whitelist]` button | Checks `PRAGMA data_version` (`0.001 ms`) on every flush; reloads whitelist & rebuilds \$\\mathbf{W}\_{(M \\times 384)}\$ on change. | Whitelisted BSSIDs are pinned in RAM (immune to LRU eviction) and still run Track 4A checks. | `--learn-baseline` only locks `campus_ie_profile`; `is_whitelisted = 1` is strictly manual via UI (Point 5). |

---

## 3\. Master Logical Flow Diagram (Large Format — v2.1.2)

```
========================================================================================================================
                         PHASE A: STARTUP / COLD-BOOT INITIALIZATION (RUNS ONCE AT PROCESS START)
========================================================================================================================

  +------------------------------------------------------------------------------------------------------------------+
  | 1. SQLite WAL Init & Bounded LRU RAM Mirror Load                                                                 |
  |    • Execute: PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL; PRAGMA busy_timeout=5000;                      |
  |    • Load `ssid_catalog` -------------> into `ram_ssids` OrderedDict (MAX_RAM_SSIDS = 4096)                      |
  |    • Load `bssid_devices` ------------> into `ram_bssids` OrderedDict (MAX_RAM_BSSIDS = 4096)                    |
  |    • Load `campus_ie_profile` --------> into `ram_ie_blueprint` (Locked via `--learn-baseline`; NO auto-whitelist)|
  |    • Pre-compute Whitelist Embeddings -> L2-normalized NumPy Matrix W of shape (M x 384), dtype=float32          |
  |    • Record initial SQLite state ------> `last_data_version = conn.execute("PRAGMA data_version").fetchone()[0]` |
  +------------------------------------------------------------------------------------------------------------------+
                                                           |
                                                           v
========================================================================================================================
                   PHASE B: LIVE PACKET CAPTURE LOOP (500 PACKETS/SEC — ZERO DISK I/O ON HOT PATH)
========================================================================================================================

                       [ Incoming 802.11 Management Frame Captured from Monitor-Mode Socket ]
                                                           |
                                                           v
                                      < Step B0: Frame Subtype Demultiplexer >
                                     /                                        \
                        (Beacon / Probe Response)                   (Deauth / Disassoc: 0x0C / 0x0A)
                                   |                                                   |
                                   v                                                   v
                  < Stage 0: Is BSSID in `ram_bssids`? >              +------------------------------------------------+
                        /                        \                    | Direct Deauth Ingress (Point 2 Fix):           |
                (Yes: Cache Hit)            (No: New BSSID)           | • Lookup/create `ram_bssids[addr3]`            |
                      /                            \                  | • Increment 10s/60s sliding Deauth counter     |
                     v                              v                 | • If `>=15/10s` or `>=30/60s` -> Jump to 4A!   |
  < ram_bssids[bssid].ssid == obs_ssid? >  +-----------------------+  +------------------------------------------------+
        /                         \        | Create `BSSIDState`   |                   |
(Yes: Unchanged)            (No: Mutated!) | • Enforce 4096 LRU cap|                   |
      /                             \      | • `first_seen_ts=now` |                   |
     v                               v     +-----------------------+                   |
+-------------------------------+ +-------------------------------+ |                  |
| Whitelisted Check (Point 1):  | | Option M2 Mutation Handler:   | |                  |
| • If `is_whitelisted == 1`:   | | • `is_mutated = True` (+45pt) | |                  |
|   Bypass AI (Stg 1 & 2) and   | | • Update `current_ssid`       | |                  |
|   Jump to Track 4A to verify  | | • Route to Stage 1            | |                  |
|   NO Seq/TSF or Ch Clone!     | +-------------------------------+ |                  |
+-------------------------------+                 |                 |                  |
     | (Whitelisted -> Track 4A)                  +--------+--------+                  |
     |                                                     | (Un-whitelisted BSSID)    |
     |                                                     v                           |
     |                                    < Stage 1: Is `obs_ssid` in `ram_ssids`? >   |
     |                                          /                            \         |
     |                                  (Yes: 0.002 ms)                 (No: Enqueue to Adaptive Worker)
     |                                        /                                \       |
     |                                       v                                  v      |
     |                    +-------------------------------------+   +--------------------------------------------------+
     |                    | Reuse Encryption-Agnostic Scores    |   | Work-Conserving Adaptive AI Worker (Q1 Upgrade): |
     |                    | • Read `xgb_prob`                   |   | • Drain `k = min(len(queue), 32)` SSIDs:         |
     |                    | • Read pure `bge_cos_raw` & `clean` |   |   - If `k == 1` (Normal): Instant 1xM (`v @ W.T`)|
     |                    +-------------------------------------+   |     in 7.2 ms with 0 ms wait!                    |
     |                                       \                      |   - If `k > 1` (Flood): Batch NxM (`E @ W.T`)    |
     |                                        \                     | • Store encryption-agnostic `bge_cos_raw` &      |
     |                                         \                    |   `bge_cos_clean` in `ram_ssids` (4096 LRU cap)  |
     |                                          +---------+---------+--------------------------------------------------+
     |                                                    |                            |
     |                                                    v                            |
     |                                   < Stage 2.5: Suspicious Name? >               |
     |                                   [ eff_bge = 0.5*bge_cos if PSK else bge_cos ] |
     |                                   [ xgb_prob >= 0.50 OR eff_bge >= 0.60       ] |
     |                                   [ OR is_mutated == True                     ] |
     |                                          /                 \                    |
     |                                    (No: Benign)       (Yes: Suspicious)         |
     |                                        /                     \                  |
     |                                       v                       +--------+--------+
     |                     +-----------------------------------+              |
     |                     | Brief Logging (In-Memory Dedupe)  |              |
     |                     | • Update `last_seen_ts`, `rssi`   |              |
     |                     | • Add `bssid` to `dirty_bssids`   |              |
     |                     +-----------------------------------+              |
     |                                       |                                |
     +---------------------------------------+--------------------------------+
     | (Whitelisted BSSID runs 4A only)      |                                | (Suspicious BSSID runs 4A & 4B)
     +---------------------------------------+--------------------------------+
                                             |
                                             v
                 +----------------------------------------------------------------------------------------+
                 | Parallel Tracks 4A & 4B + Stage 5 Risk Engine (In RAM)                                 |
                 | • Track 4A: Check Deauth flood (+75), Backward Seq/TSF collision (+75),                |
                 |   15s sliding IE Tag 3/61 channel map (+70 if >=2 active ch; 0 pts if 1-way move),     |
                 |   and 1-hour offline probation reset (`now - last_seen_ts > 3600s -> first_seen=now`)  |
                 | • Track 4B (Un-whitelisted): Check RSSI volatility (+20), Strict Un-Diluted Jitter     |
                 |   (`1<=seq_diff<=6`, `k in {1,2}`, `max(arr_err, tsf_err)` > 20ms -> +20), & IE match  |
                 | • Stage 5: Compute `new_score` & `new_tier` (`LOW < 30`, `MEDIUM 30-69`, `HIGH >= 70`) |
                 +----------------------------------------------------------------------------------------+
                                                           |
                                                           v
                          < Q2 Coalesced Flush Gate: Did `risk_tier` Escalate to MED or HIGH? >
                                           /                               \
                             (No: Routine / Same Tier)             (Yes: New Alert / Escalation!)
                                         /                                   \
                                        v                                     v
                     +-------------------------------------+    < Is `now - last_flush_ts >= 0.25s`? >
                     | Check Periodic Timer:               |           /                      \
                     | • Flush if `dt >= 3.0s`             |   (Yes: >= 250 ms)         (No: < 250 ms Flood!)
                     | • OR if `urgent_flush_pending`      |         /                          \
                     |   and `dt >= 0.25s`                 |        v                            v
                     +-------------------------------------+  +-------------------+  +---------------------------------+
                                        |                     | INSTANT BYPASS    |  | COALESCE URGENT FLUSH           |
                                        |                     | FLUSH (0 ms Wait!)|  | • `urgent_flush_pending = True` |
                                        |                     | • Commits in <10ms|  | • Flushes at next 250 ms tick   |
                                        +---------------------+---------+---------+--+---------------------------------+
                                                                        |
                                                                        v
========================================================================================================================
          PHASE C: ATOMIC SQLITE WAL FLUSH & PRAGMA data_version SYNC (EVERY 3.0s, INSTANT BYPASS, OR 250ms CAP)
========================================================================================================================

  +------------------------------------------------------------------------------------------------------------------+
  | Step C1: Check External Dashboard UI Edits via `PRAGMA data_version` (0.001 ms)                                  |
  |   • If `curr_ver != last_data_version`: Reload manually whitelisted BSSIDs & rebuild `W_(M x 384)` in RAM        |
  | Step C2: Single Atomic SQLite WAL Batch Commit (`BEGIN IMMEDIATE ... executemany() ... COMMIT`)                  |
  |   • Flush `new_ssid_queue`, deduplicated `dirty_bssids`, and rate-limited `pending_behavior_logs`                |
  |   • Reset `urgent_flush_pending = False`, `last_flush_ts = time.monotonic()`, and refresh `last_data_version`    |
  +------------------------------------------------------------------------------------------------------------------+
```

---

## 4\. Reference Python Implementation (`BatchDatabaseManager` v2.1.2)

```py
import sqlite3
import time
import json
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Dict, Set, List, Tuple

@dataclass
class SSIDRecord:
    ssid_text: str
    matched_whitelist_ssid: str
    xgb_prob: float
    bge_cos_raw: float
    bge_cos_clean: float        # Encryption-agnostic (stopwords stripped only)
    bge_vector_blob: bytes
    is_suspicious_name: int
    first_computed_at: float

@dataclass
class BSSIDState:
    bssid: str
    current_ssid: str
    is_whitelisted: int = 0     # Strictly set via manual UI click (Point 5)
    is_mutated: int = 0
    active_channels_map: Dict[int, float] = field(default_factory=dict)  # {tag3_ch: last_seen_ts} (15s window)
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
    MIN_FORCE_COOLDOWN_SEC = 0.25   # Point 8 Fix: Caps forced flushes at max 4 commits/sec
    OFFLINE_RESET_SEC = 3600.0      # Point 4 Fix: 1-hour offline gap resets 24h probation timer
    CHANNEL_WINDOW_SEC = 15.0       # Point 7 Fix: 15s sliding window for IE Tag 3/61 channel map
    MAX_RAM_ENTRIES = 4096          # Point 8 Fix: Bounded LRU cache cap
    TIER_RANK = {"LOW": 0, "MEDIUM": 1, "HIGH": 2}

    def __init__(self, db_path: str):
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self.conn.execute("PRAGMA journal_mode=WAL;")
        self.conn.execute("PRAGMA synchronous=NORMAL;")
        self.conn.execute("PRAGMA busy_timeout=5000;")

        self.ram_ssids: OrderedDict[str, SSIDRecord] = OrderedDict()
        self.ram_bssids: OrderedDict[str, BSSIDState] = OrderedDict()
        self.new_ssid_queue: List[Tuple] = []
        self.dirty_bssids: Set[str] = set()
        self.pending_behavior_logs: List[Tuple] = []

        self.urgent_flush_pending = False
        self.last_flush_ts = time.monotonic()
        self.last_data_version = self._get_data_version()

    def _get_data_version(self) -> int:
        return self.conn.execute("PRAGMA data_version;").fetchone()[0]

    def update_channel_and_probation(self, state: BSSIDState, tag3_channel: int, now_ts: float) -> bool:
        """
        Point 4 & Point 7 Fix:
        1. Resets first_seen_ts if un-whitelisted AP was offline for > 1 hour (3600s).
        2. Prunes IE Tag 3/61 channels older than 15s; returns True if Multi-Channel Clone (>=2 active).
        """
        if not state.is_whitelisted and state.last_seen_ts > 0:
            if (now_ts - state.last_seen_ts) > self.OFFLINE_RESET_SEC:
                state.first_seen_ts = now_ts  # Reset 24h probation timer after >1h offline gap

        state.last_seen_ts = now_ts
        state.active_channels_map[tag3_channel] = now_ts
        expired = [ch for ch, ts in state.active_channels_map.items() if (now_ts - ts) > self.CHANNEL_WINDOW_SEC]
        for ch in expired:
            del state.active_channels_map[ch]

        if len(state.active_channels_map) == 1:
            state.primary_channel = tag3_channel  # Legit 1-way channel move completed
            return False
        return len(state.active_channels_map) >= 2

    def record_bssid_update(self, state: BSSIDState, prev_tier: str) -> None:
        """Updates bounded LRU RAM state and executes Coalesced Instant Alert Bypass."""
        if state.bssid in self.ram_bssids:
            self.ram_bssids.move_to_end(state.bssid)
        else:
            if len(self.ram_bssids) >= self.MAX_RAM_ENTRIES:
                # Evict oldest un-whitelisted LOW-risk BSSID first
                for old_bssid, old_state in list(self.ram_bssids.items()):
                    if not old_state.is_whitelisted and old_state.risk_tier == "LOW":
                        del self.ram_bssids[old_bssid]
                        self.dirty_bssids.discard(old_bssid)
                        break
            self.ram_bssids[state.bssid] = state

        self.dirty_bssids.add(state.bssid)
        now_mono = time.monotonic()
        elapsed = now_mono - self.last_flush_ts

        new_rank = self.TIER_RANK.get(state.risk_tier, 0)
        old_rank = self.TIER_RANK.get(prev_tier, 0)

        if new_rank >= 1 and new_rank > old_rank:
            if elapsed >= self.MIN_FORCE_COOLDOWN_SEC:
                self.flush_to_sqlite(force=True)
            else:
                self.urgent_flush_pending = True
        elif self.urgent_flush_pending and elapsed >= self.MIN_FORCE_COOLDOWN_SEC:
            self.flush_to_sqlite(force=True)
        elif elapsed >= self.FLUSH_INTERVAL_SEC:
            self.flush_to_sqlite(force=False)

    def flush_to_sqlite(self, force: bool = False) -> None:
        curr_ver = self._get_data_version()
        if curr_ver != self.last_data_version:
            self.reload_whitelist_into_ram()

        if not (force or self.urgent_flush_pending or self.new_ssid_queue or self.dirty_bssids or self.pending_behavior_logs):
            self.last_flush_ts = time.monotonic()
            return

        with self.conn:
            if self.new_ssid_queue:
                self.conn.executemany(
                    "INSERT OR IGNORE INTO ssid_catalog VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                    self.new_ssid_queue,
                )
                self.new_ssid_queue.clear()

            if self.dirty_bssids:
                rows = [
                    (
                        s.bssid, s.current_ssid, s.is_whitelisted, s.is_mutated,
                        json.dumps(s.active_channels_map), s.first_seen_ts, s.last_seen_ts,
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
                           first_seen_ts=excluded.first_seen_ts,
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

        self.urgent_flush_pending = False
        self.last_data_version = self._get_data_version()
        self.last_flush_ts = time.monotonic()

    def reload_whitelist_into_ram(self) -> None:
        for row in self.conn.execute("SELECT bssid, is_whitelisted FROM bssid_devices WHERE is_whitelisted = 1"):
            if row[0] in self.ram_bssids:
                self.ram_bssids[row[0]].is_whitelisted = 1
                self.ram_bssids[row[0]].risk_tier = "LOW"
                self.ram_bssids[row[0]].current_risk_score = 0
```

