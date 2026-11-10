"""
Edge Wi-Fi Evil Twin Detection Framework (v2.1.2)
Database & In-Memory Batch/Cache Manager
"""

import json
import os
import sqlite3
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

from detector.ids_v2.config import (
    DEFAULT_DB_PATH,
    FLUSH_INTERVAL_SEC,
    MIN_FORCE_COOLDOWN_SEC,
    OFFLINE_RESET_SEC,
    CHANNEL_WINDOW_SEC,
    MAX_RAM_ENTRIES,
    TIER_RANK,
)


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


@dataclass
class CampusIEProfile:
    profile_name: str
    locked_at: float = 0.0
    akm_suites: List[str] = field(default_factory=list)
    pairwise_ciphers: List[str] = field(default_factory=list)
    has_mdid: int = 0
    has_vendor_221: int = 0
    mimo_streams: int = 1
    raw_ies_hash: str = ""


@dataclass
class BeaconBehaviorLog:
    bssid: str
    timestamp: float
    seq_num: int = 0
    tsf_timestamp: int = 0
    jitter_ms: float = 0.0
    deauth_count_1m: int = 0
    channel_anomaly_type: str = "NONE"
    ssid_mutated: int = 0
    raw_ie_fingerprint: str = ""


class BatchDatabaseManager:
    """
    Adversarial-Safe In-Memory LRU Cache & SQLite WAL Batch Persistence Manager.
    - Caps RAM at MAX_RAM_ENTRIES (4,096) for BSSIDs and SSIDs.
    - Routine deduplicated batch flush every FLUSH_INTERVAL_SEC (3.0s).
    - Coalesced Instant Alert Bypass with MIN_FORCE_COOLDOWN_SEC (0.25s / max 4 commits/s).
    - PRAGMA data_version hot-reloads manually updated whitelists.
    """

    FLUSH_INTERVAL_SEC = FLUSH_INTERVAL_SEC
    MIN_FORCE_COOLDOWN_SEC = MIN_FORCE_COOLDOWN_SEC
    OFFLINE_RESET_SEC = OFFLINE_RESET_SEC
    CHANNEL_WINDOW_SEC = CHANNEL_WINDOW_SEC
    MAX_RAM_ENTRIES = MAX_RAM_ENTRIES
    TIER_RANK = TIER_RANK

    def __init__(self, db_path: str = DEFAULT_DB_PATH):
        self.db_path = db_path
        if db_path != ":memory:":
            os.makedirs(os.path.dirname(os.path.abspath(db_path)), exist_ok=True)

        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self._init_db()

        self.ram_ssids: OrderedDict[str, SSIDRecord] = OrderedDict()
        self.ram_bssids: OrderedDict[str, BSSIDState] = OrderedDict()
        self.whitelisted_bssids: Set[str] = set()

        self.new_ssid_queue: Dict[str, Tuple] = {}
        self.dirty_bssids: Set[str] = set()
        self.pending_behavior_logs: List[Tuple] = []

        self.urgent_flush_pending: bool = False
        # Allow immediate first alert flush on startup by subtracting cooldown
        self.last_flush_ts: float = time.monotonic() - self.MIN_FORCE_COOLDOWN_SEC
        self.last_data_version: int = self._get_data_version()
        self.commit_count: int = 0
        self._lock: threading.RLock = threading.RLock()

        self.load_from_db()

    def _init_db(self) -> None:
        """Initializes WAL mode and creates the 4-table schema with indexes."""
        self.conn.execute("PRAGMA journal_mode=WAL;")
        self.conn.execute("PRAGMA synchronous=NORMAL;")
        self.conn.execute("PRAGMA busy_timeout=5000;")

        with self.conn:
            # 1. ssid_catalog
            self.conn.execute(
                """CREATE TABLE IF NOT EXISTS ssid_catalog (
                    ssid_text TEXT PRIMARY KEY,
                    matched_whitelist_ssid TEXT,
                    xgb_prob REAL,
                    bge_cos_raw REAL,
                    bge_cos_clean REAL,
                    bge_vector_blob BLOB,
                    is_suspicious_name INTEGER,
                    first_computed_at REAL
                );"""
            )

            # 2. bssid_devices
            self.conn.execute(
                """CREATE TABLE IF NOT EXISTS bssid_devices (
                    bssid TEXT PRIMARY KEY,
                    current_ssid TEXT,
                    is_whitelisted INTEGER DEFAULT 0,
                    is_mutated INTEGER DEFAULT 0,
                    active_channels_json TEXT,
                    first_seen_ts REAL,
                    last_seen_ts REAL,
                    last_rssi INTEGER,
                    rssi_volatility_db REAL,
                    primary_channel INTEGER,
                    encryption_type TEXT,
                    ie_match_status TEXT,
                    current_risk_score INTEGER,
                    risk_tier TEXT
                );"""
            )
            self.conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_bssid_devices_whitelisted ON bssid_devices(is_whitelisted);"
            )

            # 3. campus_ie_profile
            self.conn.execute(
                """CREATE TABLE IF NOT EXISTS campus_ie_profile (
                    profile_name TEXT PRIMARY KEY,
                    locked_at REAL,
                    akm_suites_json TEXT,
                    pairwise_ciphers_json TEXT,
                    has_mdid INTEGER,
                    has_vendor_221 INTEGER,
                    mimo_streams INTEGER,
                    raw_ies_hash TEXT
                );"""
            )

            # 4. beacon_behavior_logs
            self.conn.execute(
                """CREATE TABLE IF NOT EXISTS beacon_behavior_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    bssid TEXT,
                    timestamp REAL,
                    seq_num INTEGER,
                    tsf_timestamp INTEGER,
                    jitter_ms REAL,
                    deauth_count_1m INTEGER,
                    channel_anomaly_type TEXT,
                    ssid_mutated INTEGER,
                    raw_ie_fingerprint TEXT
                );"""
            )
            self.conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_beacon_logs_bssid_ts ON beacon_behavior_logs(bssid, timestamp);"
            )

    def _get_data_version(self) -> int:
        return self.conn.execute("PRAGMA data_version;").fetchone()[0]

    def _evict_one_bssid_if_needed(self) -> None:
        """Evicts oldest un-whitelisted LOW risk BSSID first, then oldest un-whitelisted BSSID."""
        if len(self.ram_bssids) < self.MAX_RAM_ENTRIES:
            return

        # 1. Evict oldest un-whitelisted LOW-risk BSSID first (generator iteration)
        victim_bssid = next(
            (b for b, s in self.ram_bssids.items() if not s.is_whitelisted and b not in self.whitelisted_bssids and s.risk_tier == "LOW"),
            None
        )
        if victim_bssid is not None:
            del self.ram_bssids[victim_bssid]
            self.dirty_bssids.discard(victim_bssid)
            return

        # 2. If no LOW-risk un-whitelisted found, evict oldest un-whitelisted
        victim_bssid = next(
            (b for b, s in self.ram_bssids.items() if not s.is_whitelisted and b not in self.whitelisted_bssids),
            None
        )
        if victim_bssid is not None:
            del self.ram_bssids[victim_bssid]
            self.dirty_bssids.discard(victim_bssid)
            return

    def load_from_db(self) -> None:
        """Loads cached SSIDs and BSSID devices from SQLite into bounded LRU RAM."""
        cursor = self.conn.cursor()

        # 1. First, load ALL whitelisted BSSIDs (they are immune to eviction and must be known)
        cursor.execute("SELECT bssid FROM bssid_devices WHERE is_whitelisted = 1")
        self.whitelisted_bssids = {row[0] for row in cursor.fetchall()}

        # 2. Load most recent bssid_devices up to MAX_RAM_ENTRIES
        # Whitelisted devices first, then most recently seen devices
        cursor.execute(
            """SELECT bssid, current_ssid, is_whitelisted, is_mutated, active_channels_json,
                      first_seen_ts, last_seen_ts, last_rssi, rssi_volatility_db,
                      primary_channel, encryption_type, ie_match_status, current_risk_score, risk_tier
               FROM bssid_devices
               ORDER BY is_whitelisted DESC, last_seen_ts DESC
               LIMIT ?""",
            (self.MAX_RAM_ENTRIES,)
        )
        bssid_rows = cursor.fetchall()
        for row in reversed(bssid_rows):
            active_ch = {}
            if row[4]:
                try:
                    active_ch = {int(k): float(v) for k, v in json.loads(row[4]).items()}
                except Exception:
                    active_ch = {}
            self.ram_bssids[row[0]] = BSSIDState(
                bssid=row[0],
                current_ssid=row[1],
                is_whitelisted=row[2],
                is_mutated=row[3],
                active_channels_map=active_ch,
                first_seen_ts=row[5],
                last_seen_ts=row[6],
                last_rssi=row[7],
                rssi_volatility_db=row[8],
                primary_channel=row[9],
                encryption_type=row[10],
                ie_match_status=row[11],
                current_risk_score=row[12],
                risk_tier=row[13]
            )

        # 3. Load most recent ssid_catalog up to MAX_RAM_ENTRIES
        cursor.execute(
            """SELECT ssid_text, matched_whitelist_ssid, xgb_prob, bge_cos_raw,
                      bge_cos_clean, bge_vector_blob, is_suspicious_name, first_computed_at
               FROM ssid_catalog
               ORDER BY first_computed_at DESC
               LIMIT ?""",
            (self.MAX_RAM_ENTRIES,)
        )
        ssid_rows = cursor.fetchall()
        for row in reversed(ssid_rows):
            self.ram_ssids[row[0]] = SSIDRecord(
                ssid_text=row[0],
                matched_whitelist_ssid=row[1],
                xgb_prob=row[2],
                bge_cos_raw=row[3],
                bge_cos_clean=row[4],
                bge_vector_blob=row[5],
                is_suspicious_name=row[6],
                first_computed_at=row[7]
            )

    def update_channel_and_probation(self, state: BSSIDState, tag3_channel: int, now_ts: float) -> bool:
        """
        Point 4 & Point 7 Fix:
        1. Resets first_seen_ts if un-whitelisted AP was offline for > 1 hour (3600s).
        2. Prunes IE Tag 3/61 channels older than 15s; returns True if Multi-Channel Clone (>=2 active).
        """
        with self._lock:
            if tag3_channel is None:
                return False
            try:
                tag3_channel = int(float(tag3_channel))
            except (ValueError, TypeError):
                return False

            if state.bssid in self.whitelisted_bssids:
                state.is_whitelisted = 1

            if not state.is_whitelisted and state.last_seen_ts > 0:
                if (now_ts - state.last_seen_ts) > self.OFFLINE_RESET_SEC:
                    state.first_seen_ts = now_ts  # Reset 24h probation timer after >1h offline gap

            if state.first_seen_ts == 0.0:
                state.first_seen_ts = now_ts

            state.last_seen_ts = max(state.last_seen_ts, now_ts)
            state.active_channels_map[tag3_channel] = max(state.active_channels_map.get(tag3_channel, 0.0), now_ts)
            expired = [ch for ch, ts in state.active_channels_map.items() if (now_ts - ts) > self.CHANNEL_WINDOW_SEC]
            for ch in expired:
                del state.active_channels_map[ch]

            if len(state.active_channels_map) == 1:
                state.primary_channel = tag3_channel  # Legit 1-way channel move completed
                return False
            return len(state.active_channels_map) >= 2

    def put_bssid(self, state: BSSIDState) -> None:
        """Stores or updates a BSSIDState in bounded LRU RAM cache (cap 4096) and marks it dirty."""
        with self._lock:
            if state.bssid in self.ram_bssids:
                self.ram_bssids[state.bssid] = state
                self.ram_bssids.move_to_end(state.bssid)
            else:
                self._evict_one_bssid_if_needed()
                self.ram_bssids[state.bssid] = state

            if state.is_whitelisted:
                self.whitelisted_bssids.add(state.bssid)
            else:
                self.whitelisted_bssids.discard(state.bssid)

            self.dirty_bssids.add(state.bssid)

    def record_bssid_update(self, state: BSSIDState, prev_tier: str, now_mono: Optional[float] = None) -> None:
        """
        Updates bounded LRU RAM state and executes Coalesced Instant Alert Bypass.
        - Evicts oldest un-whitelisted LOW-risk BSSID when reaching MAX_RAM_ENTRIES.
        - If escalating to MEDIUM or HIGH:
          - If elapsed >= 0.25s: flushes immediately (force=True).
          - If elapsed < 0.25s: sets urgent_flush_pending = True.
        - If urgent_flush_pending and elapsed >= 0.25s: flushes immediately.
        - If elapsed >= 3.0s: routine batch flush.
        """
        with self._lock:
            self.put_bssid(state)

            if now_mono is None:
                now_mono = time.monotonic()
            if self.last_flush_ts > now_mono:
                self.last_flush_ts = now_mono - self.MIN_FORCE_COOLDOWN_SEC
            elapsed = now_mono - self.last_flush_ts

            new_rank = self.TIER_RANK.get(state.risk_tier, 0)
            old_rank = self.TIER_RANK.get(prev_tier, 0)

            if new_rank >= 1 and new_rank > old_rank:
                if elapsed >= self.MIN_FORCE_COOLDOWN_SEC:
                    self.flush_to_sqlite(force=True, now_mono=now_mono)
                else:
                    self.urgent_flush_pending = True
            elif self.urgent_flush_pending and elapsed >= self.MIN_FORCE_COOLDOWN_SEC:
                self.flush_to_sqlite(force=True, now_mono=now_mono)
            elif elapsed >= self.FLUSH_INTERVAL_SEC:
                self.flush_to_sqlite(force=False, now_mono=now_mono)

    def check_and_sync_data_version(self) -> bool:
        """Checks PRAGMA data_version (0.001 ms) and hot-reloads whitelists if modified externally."""
        with self._lock:
            curr_ver = self._get_data_version()
            if curr_ver != self.last_data_version:
                self.reload_whitelist_into_ram()
                self.last_data_version = curr_ver
                return True
            return False

    def flush_to_sqlite(self, force: bool = False, now_mono: Optional[float] = None) -> bool:
        """
        Executes atomic WAL transaction:
        1. Checks PRAGMA data_version; reloads whitelist if modified externally.
        2. Inserts new_ssid_queue.
        3. Upserts dirty_bssids via ON CONFLICT DO UPDATE.
        4. Inserts pending_behavior_logs.
        Returns True if an actual commit to SQLite took place.
        """
        with self._lock:
            curr_ver = self._get_data_version()
            if curr_ver != self.last_data_version:
                self.reload_whitelist_into_ram()
                self.last_data_version = curr_ver

            if not (force or self.urgent_flush_pending or self.new_ssid_queue or self.dirty_bssids or self.pending_behavior_logs):
                if now_mono is None:
                    now_mono = time.monotonic()
                self.last_flush_ts = now_mono
                return False

            with self.conn:
                if self.new_ssid_queue:
                    self.conn.executemany(
                        """INSERT INTO ssid_catalog VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                           ON CONFLICT(ssid_text) DO UPDATE SET
                               matched_whitelist_ssid=excluded.matched_whitelist_ssid,
                               xgb_prob=excluded.xgb_prob,
                               bge_cos_raw=excluded.bge_cos_raw,
                               bge_cos_clean=excluded.bge_cos_clean,
                               bge_vector_blob=excluded.bge_vector_blob,
                               is_suspicious_name=excluded.is_suspicious_name,
                               first_computed_at=excluded.first_computed_at""",
                        list(self.new_ssid_queue.values()),
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
                    if rows:
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

                self.commit_count += 1

            self.urgent_flush_pending = False
            self.last_data_version = self._get_data_version()
            if now_mono is None:
                now_mono = time.monotonic()
            self.last_flush_ts = now_mono
            return True

    def reload_whitelist_into_ram(self) -> None:
        """Hot-reloads manually whitelisted BSSIDs after PRAGMA data_version change."""
        with self._lock:
            self.whitelisted_bssids.clear()
            for row in self.conn.execute("SELECT bssid FROM bssid_devices WHERE is_whitelisted = 1"):
                self.whitelisted_bssids.add(row[0])
                if row[0] in self.ram_bssids:
                    self.ram_bssids[row[0]].is_whitelisted = 1
                    self.ram_bssids[row[0]].risk_tier = "LOW"
                    self.ram_bssids[row[0]].current_risk_score = 0

            # Demote in RAM any BSSIDs that were un-whitelisted externally
            for bssid, state in self.ram_bssids.items():
                if state.is_whitelisted and bssid not in self.whitelisted_bssids:
                    state.is_whitelisted = 0

    def put_ssid(self, record: SSIDRecord) -> None:
        """Stores SSIDRecord in bounded LRU RAM and enqueues for SQLite persistence."""
        with self._lock:
            if record.ssid_text not in self.ram_ssids:
                if len(self.ram_ssids) >= self.MAX_RAM_ENTRIES:
                    self.ram_ssids.popitem(last=False)
            self.ram_ssids[record.ssid_text] = record
            self.ram_ssids.move_to_end(record.ssid_text)

            self.new_ssid_queue[record.ssid_text] = (
                record.ssid_text,
                record.matched_whitelist_ssid,
                record.xgb_prob,
                record.bge_cos_raw,
                record.bge_cos_clean,
                record.bge_vector_blob,
                record.is_suspicious_name,
                record.first_computed_at
            )

    def get_ssid(self, ssid_text: str) -> Optional[SSIDRecord]:
        """Retrieves SSIDRecord from RAM cache or SQLite catalog."""
        with self._lock:
            if ssid_text in self.ram_ssids:
                self.ram_ssids.move_to_end(ssid_text)
                return self.ram_ssids[ssid_text]

            cursor = self.conn.cursor()
            cursor.execute(
                """SELECT ssid_text, matched_whitelist_ssid, xgb_prob, bge_cos_raw,
                          bge_cos_clean, bge_vector_blob, is_suspicious_name, first_computed_at
                   FROM ssid_catalog WHERE ssid_text = ?""",
                (ssid_text,)
            )
            row = cursor.fetchone()
            if not row:
                return None

            record = SSIDRecord(
                ssid_text=row[0],
                matched_whitelist_ssid=row[1],
                xgb_prob=row[2],
                bge_cos_raw=row[3],
                bge_cos_clean=row[4],
                bge_vector_blob=row[5],
                is_suspicious_name=row[6],
                first_computed_at=row[7]
            )
            if len(self.ram_ssids) >= self.MAX_RAM_ENTRIES:
                self.ram_ssids.popitem(last=False)
            self.ram_ssids[ssid_text] = record
            return record

    def get_bssid(self, bssid: str) -> Optional[BSSIDState]:
        """Retrieves BSSIDState from RAM cache or SQLite devices."""
        with self._lock:
            if bssid in self.ram_bssids:
                self.ram_bssids.move_to_end(bssid)
                return self.ram_bssids[bssid]

            cursor = self.conn.cursor()
            cursor.execute(
                """SELECT bssid, current_ssid, is_whitelisted, is_mutated, active_channels_json,
                          first_seen_ts, last_seen_ts, last_rssi, rssi_volatility_db,
                          primary_channel, encryption_type, ie_match_status, current_risk_score, risk_tier
                   FROM bssid_devices WHERE bssid = ?""",
                (bssid,)
            )
            row = cursor.fetchone()
            if not row:
                return None

            active_ch = {}
            if row[4]:
                try:
                    active_ch = {int(k): float(v) for k, v in json.loads(row[4]).items()}
                except Exception:
                    active_ch = {}

            state = BSSIDState(
                bssid=row[0],
                current_ssid=row[1],
                is_whitelisted=row[2],
                is_mutated=row[3],
                active_channels_map=active_ch,
                first_seen_ts=row[5],
                last_seen_ts=row[6],
                last_rssi=row[7],
                rssi_volatility_db=row[8],
                primary_channel=row[9],
                encryption_type=row[10],
                ie_match_status=row[11],
                current_risk_score=row[12],
                risk_tier=row[13]
            )
            if row[2] == 1:
                self.whitelisted_bssids.add(row[0])

            self._evict_one_bssid_if_needed()
            self.ram_bssids[bssid] = state
            return state

    def add_behavior_log(
        self,
        bssid: str,
        timestamp: float,
        seq_num: int = 0,
        tsf_timestamp: int = 0,
        jitter_ms: float = 0.0,
        deauth_count_1m: int = 0,
        channel_anomaly_type: str = "NONE",
        ssid_mutated: int = 0,
        raw_ie_fingerprint: str = ""
    ) -> None:
        """Enqueues a beacon behavior log entry to be flushed in the next batch."""
        with self._lock:
            self.pending_behavior_logs.append((
                bssid,
                timestamp,
                seq_num,
                tsf_timestamp,
                jitter_ms,
                deauth_count_1m,
                channel_anomaly_type,
                ssid_mutated,
                raw_ie_fingerprint
            ))

    def save_campus_ie_profile(self, profile: CampusIEProfile) -> None:
        """Persists or updates the campus IE blueprint profile."""
        with self._lock:
            with self.conn:
                self.conn.execute(
                    """INSERT INTO campus_ie_profile
                       (profile_name, locked_at, akm_suites_json, pairwise_ciphers_json,
                        has_mdid, has_vendor_221, mimo_streams, raw_ies_hash)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                       ON CONFLICT(profile_name) DO UPDATE SET
                           locked_at=excluded.locked_at,
                           akm_suites_json=excluded.akm_suites_json,
                           pairwise_ciphers_json=excluded.pairwise_ciphers_json,
                           has_mdid=excluded.has_mdid,
                           has_vendor_221=excluded.has_vendor_221,
                           mimo_streams=excluded.mimo_streams,
                           raw_ies_hash=excluded.raw_ies_hash""",
                    (
                        profile.profile_name,
                        profile.locked_at,
                        json.dumps(profile.akm_suites),
                        json.dumps(profile.pairwise_ciphers),
                        profile.has_mdid,
                        profile.has_vendor_221,
                        profile.mimo_streams,
                        profile.raw_ies_hash
                    )
                )
                self.commit_count += 1

    def get_campus_ie_profile(self, profile_name: str = "campus_default") -> Optional[CampusIEProfile]:
        """Retrieves a locked campus IE blueprint profile."""
        with self._lock:
            cursor = self.conn.cursor()
            cursor.execute(
                """SELECT profile_name, locked_at, akm_suites_json, pairwise_ciphers_json,
                          has_mdid, has_vendor_221, mimo_streams, raw_ies_hash
                   FROM campus_ie_profile WHERE profile_name = ?""",
                (profile_name,)
            )
            row = cursor.fetchone()
            if not row:
                return None
            return CampusIEProfile(
                profile_name=row[0],
                locked_at=row[1],
                akm_suites=json.loads(row[2]) if row[2] else [],
                pairwise_ciphers=json.loads(row[3]) if row[3] else [],
                has_mdid=row[4],
                has_vendor_221=row[5],
                mimo_streams=row[6],
                raw_ies_hash=row[7]
            )

    def close(self) -> None:
        """Flushes remaining pending dirty records and closes the database connection."""
        with self._lock:
            self.flush_to_sqlite(force=True)
            self.conn.close()
