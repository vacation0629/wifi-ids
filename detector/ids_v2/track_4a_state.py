"""
Edge Wi-Fi Evil Twin Detection Framework (v2.1.2)
Track 4A: Pre-Stage-0 Frame Demultiplexer & Stateful Active RF State Tracker
"""

import collections
import logging
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple, Union

from detector.ids_v2.config import (
    CHANNEL_WINDOW_SEC,
    DEAUTH_THRESHOLD_10S,
    DEAUTH_THRESHOLD_60S,
    OFFLINE_RESET_SEC,
    SCORE_THRESHOLD_HIGH,
    SCORE_THRESHOLD_MEDIUM,
    TIER_RANK,
)
from detector.ids_v2.db_manager import (
    BatchDatabaseManager,
    BSSIDState,
)

logger = logging.getLogger(__name__)

# Scoring & Threshold Constants for Track 4A
SCORE_FLOOR_DEAUTH_FLOOD: int = 75
SCORE_FLOOR_SAME_CHANNEL_COLLISION: int = 75
SCORE_FLOOR_MULTI_CHANNEL_CLONE: int = 70
TSF_BACKWARD_TOLERANCE_US: int = 1_000_000   # 1 second regression in microseconds
SEQ_BACKWARD_TOLERANCE: int = 5              # Up to 5 reordered frames tolerated
SEQ_MODULO: int = 4096


def extract_tag3_or_61_channel(frame: Any) -> Optional[int]:
    """
    Extracts the AP's operating channel from 802.11 Beacon Information Elements:
    - IE Tag 3: DS Parameter Set (byte 0 is channel 1..14)
    - IE Tag 61: HT Operation (byte 0 is primary channel 1..165+)
    NEVER uses receiver Radiotap frequency (Point 7 Architectural Rule).
    Supports Scapy Dot11 packets, dicts, or objects with tag attributes.
    """
    if frame is None:
        return None

    # 1. If frame is a dictionary
    if isinstance(frame, dict):
        for attr in ("tag3_channel", "channel", "tag61_channel", "operating_channel"):
            if attr in frame and frame[attr] is not None:
                try:
                    return int(frame[attr])
                except (ValueError, TypeError):
                    pass
        # Check raw_elements in dict
        raw_elts = frame.get("elements", [])
        for elt_id, elt_data in raw_elts:
            if elt_id in (3, 61) and elt_data is not None:
                if isinstance(elt_data, (bytes, bytearray)):
                    if len(elt_data) >= 1:
                        return elt_data[0]
                else:
                    try:
                        return int(elt_data)
                    except (ValueError, TypeError):
                        pass

    # 2. If frame is a Scapy Dot11 packet
    # Scan Dot11Elt layers
    try:
        cur = frame
        while cur is not None and hasattr(cur, "haslayer"):
            # Check if current or sublayer has Dot11Elt
            from scapy.layers.dot11 import Dot11Elt  # type: ignore
            if not cur.haslayer(Dot11Elt):
                break
            elt = cur.getlayer(Dot11Elt)
            while elt is not None:
                if elt.ID == 3 and elt.info and len(elt.info) >= 1:
                    ch = elt.info[0] if isinstance(elt.info, (bytes, bytearray)) else ord(elt.info[0])
                    return int(ch)
                if elt.ID == 61 and elt.info and len(elt.info) >= 1:
                    ch = elt.info[0] if isinstance(elt.info, (bytes, bytearray)) else ord(elt.info[0])
                    return int(ch)
                elt = elt.payload.getlayer(Dot11Elt) if elt.payload else None
            break
    except ImportError:
        pass
    except Exception as e:
        logger.debug(f"Could not parse Dot11Elt from frame: {e}")

    # 3. Direct attribute check
    for attr in ("tag3_channel", "channel", "tag61_channel", "operating_channel"):
        if hasattr(frame, attr):
            val = getattr(frame, attr)
            if val is not None:
                try:
                    return int(val)
                except (ValueError, TypeError):
                    pass

    return None


@dataclass
class Track4AResult:
    """Detailed evaluation result from Track 4A State Tracker."""
    bssid: str
    is_anomaly: bool = False
    anomaly_type: str = "NONE"          # "NONE", "DEAUTH_FLOOD", "SAME_CHANNEL_COLLISION", "MULTI_CHANNEL_CLONE"
    score_delta: int = 0
    risk_score: int = 0
    risk_tier: str = "LOW"
    is_whitelisted: bool = False
    deauth_count_10s: int = 0
    deauth_count_60s: int = 0
    active_channels: List[int] = field(default_factory=list)
    primary_channel: int = 1
    bssid_state: Optional[BSSIDState] = None
    details: Dict[str, Any] = field(default_factory=dict)

    @property
    def added_score(self) -> int:
        return self.score_delta

    @property
    def current_risk_score(self) -> int:
        return self.risk_score

    @property
    def hard_floor_tier(self) -> Optional[str]:
        return "HIGH" if self.is_anomaly else None


class Track4AStateTracker:
    """
    Track 4A: Pre-Stage-0 Ingress Router & Stateful Active RF State Tracker (v2.1.2).

    Core Capabilities:
    1. Pre-Stage-0 Management Demultiplexer & Deauth Counter:
       - Subtypes 0x0C (Deauth) and 0x0A (Disassoc) carry NO SSID. Route directly by bssid = frame.addr3.
       - Sliding window per BSSID (10s and 60s).
       - Thresholds: >=15 in 10s OR >=30 in 60s triggers Hard Floor HIGH (+75 pts).
    2. Whitelisted BSSID Track 4A Integrity Verification Path (Point 1 Fix):
       - Whitelisted BSSIDs (is_whitelisted == 1) with unchanged SSID bypass Stage 1 & 2 AI to save CPU,
         but MUST route through Track 4A to verify no collision or multi-channel clone occurs.
       - If no anomaly detected: exits as BENIGN / LOW (current_risk_score = 0).
       - If anomaly detected: escalates to HIGH (+70 / +75 pts).
    3. 15-Second Sliding Tag 3/61 Channel Tracker (Point 7 Fix):
       - Extracts declared channel from Beacon IE Tag 3 (DS Parameter Set) or Tag 61 (HT Operation).
       - Maintains {channel: last_seen_ts} with 15.0s window.
       - Legitimate 1-way channel move (Ch 6 -> Ch 1) expires old channel in 15s, updating primary_channel (0 pts).
       - >=2 channels active within 15s triggers Type A Multi-Channel Clone (+70 pts HIGH).
    4. 1-Hour Offline Probation Reset (Point 4 Fix):
       - Legitimate campus ceiling APs stay online 24/7.
       - If an un-whitelisted AP goes dark for > 1 hour (3600s), resets first_seen_ts = now.
    5. Same-Channel Backward Seq / TSF Collision Detector:
       - On the same channel:
         - Sequence jumps backwards: (prev_seq - curr_seq) % 4096 between 6 and 2047 (+75 pts).
         - Normal forward rollover (e.g. 4095 -> 0, 1, 2) is NOT a collision.
         - TSF regression: curr_tsf < prev_tsf - 1,000,000 us (+75 pts).
    """

    CHANNEL_WINDOW_SEC = CHANNEL_WINDOW_SEC
    OFFLINE_RESET_SEC = OFFLINE_RESET_SEC
    DEAUTH_THRESHOLD_10S = DEAUTH_THRESHOLD_10S
    DEAUTH_THRESHOLD_60S = DEAUTH_THRESHOLD_60S
    SCORE_FLOOR_DEAUTH_FLOOD = SCORE_FLOOR_DEAUTH_FLOOD
    SCORE_FLOOR_SAME_CHANNEL_COLLISION = SCORE_FLOOR_SAME_CHANNEL_COLLISION
    SCORE_FLOOR_MULTI_CHANNEL_CLONE = SCORE_FLOOR_MULTI_CHANNEL_CLONE

    def __init__(
        self,
        db_manager: BatchDatabaseManager,
        screener: Optional[Any] = None,
    ):
        self.db_manager = db_manager
        self.screener = screener
        self._lock = threading.RLock()

        # In-memory sliding deauth timestamps: {bssid: deque([timestamp1, timestamp2, ...])}
        self._deauth_windows: Dict[str, collections.deque[float]] = {}

        # In-memory RF history per channel for same-channel backward Seq / TSF detection:
        # {bssid: {channel: {"last_seq": int, "last_tsf": int, "last_ts": float}}}
        self._rf_history: Dict[str, Dict[int, Dict[str, Any]]] = {}

        # In-memory collision timestamps: {bssid: last_collision_timestamp}
        self._collision_windows: Dict[str, float] = {}

        # Attach tracker to screener if screener provided
        if self.screener is not None and hasattr(self.screener, "set_track_4a"):
            self.screener.set_track_4a(self)

    def _normalize_bssid(self, bssid: str) -> str:
        """Returns standard case-normalized BSSID string."""
        return bssid.strip().lower()

    def _is_bssid_whitelisted(self, bssid: str, state: Optional[BSSIDState] = None) -> bool:
        """Checks if BSSID is in the manual whitelist (case-insensitive)."""
        if state is not None and state.is_whitelisted == 1:
            return True
        b_norm = self._normalize_bssid(bssid)
        with self.db_manager._lock:
            for w in self.db_manager.whitelisted_bssids:
                if self._normalize_bssid(w) == b_norm:
                    return True
        return False

    def process_deauth_frame(
        self,
        bssid: str,
        now_ts: Optional[float] = None,
    ) -> Track4AResult:
        """
        Pre-Stage-0 Deauthentication / Disassociation Ingress Router.
        Subtype 0x0C (Deauth) & 0x0A (Disassoc) carry NO SSID and route directly by bssid = frame.addr3.
        Maintains sliding window deques per BSSID in 10s and 60s windows.
        Threshold: >= 15 deauth frames in 10s OR >= 30 deauth frames in 60s triggers Hard Floor HIGH (+75 pts).
        """
        if now_ts is None:
            now_ts = time.time()

        with self._lock:
            b_norm = self._normalize_bssid(bssid)
            state = self.db_manager.get_bssid(bssid)
            is_wl = self._is_bssid_whitelisted(bssid, state)

            if state is None:
                state = BSSIDState(
                    bssid=bssid,
                    current_ssid="",
                    is_whitelisted=1 if is_wl else 0,
                    first_seen_ts=now_ts,
                    last_seen_ts=now_ts,
                )
                self.db_manager.put_bssid(state)
            else:
                # 1-Hour Offline Probation Reset on un-whitelisted AP (PoE Uptime Assumption)
                if not state.is_whitelisted and state.last_seen_ts > 0:
                    if (now_ts - state.last_seen_ts) > self.OFFLINE_RESET_SEC:
                        state.first_seen_ts = now_ts
                        self._rf_history.pop(b_norm, None)
                        self._collision_windows.pop(b_norm, None)

                state.last_seen_ts = max(state.last_seen_ts, now_ts)
                if is_wl:
                    state.is_whitelisted = 1
                self.db_manager.put_bssid(state)

            # Update sliding deque of deauth timestamps
            deq = self._deauth_windows.setdefault(b_norm, collections.deque())
            deq.append(now_ts)

            # Purge timestamps older than 60.0s
            cutoff_60 = now_ts - 60.0
            while deq and deq[0] < cutoff_60:
                deq.popleft()

            # Bound memory: if tracked BSSID windows exceed 512, prune fully expired entries
            if len(self._deauth_windows) > 512:
                self.clean_expired_deauth_windows(now_ts)

            # Count in 10s and 60s windows
            cutoff_10 = now_ts - 10.0
            count_10s = sum(1 for ts in deq if ts >= cutoff_10)
            count_60s = len(deq)

            is_flood = (count_10s >= self.DEAUTH_THRESHOLD_10S) or (count_60s >= self.DEAUTH_THRESHOLD_60S)
            prev_tier = state.risk_tier

            if is_flood:
                score_delta = self.SCORE_FLOOR_DEAUTH_FLOOD
                state.current_risk_score = max(state.current_risk_score, self.SCORE_FLOOR_DEAUTH_FLOOD)
                state.risk_tier = "HIGH"
                self.db_manager.record_bssid_update(state, prev_tier=prev_tier, now_mono=now_ts)
                self.db_manager.add_behavior_log(
                    bssid=bssid,
                    timestamp=now_ts,
                    jitter_ms=0.0,
                    deauth_count_1m=count_60s,
                    channel_anomaly_type="DEAUTH_FLOOD",
                )
                is_anomaly = True
                anomaly_type = "DEAUTH_FLOOD"
            else:
                score_delta = 0
                is_anomaly = False
                anomaly_type = "NONE"
                self.db_manager.put_bssid(state)

            return Track4AResult(
                bssid=bssid,
                is_anomaly=is_anomaly,
                anomaly_type=anomaly_type,
                score_delta=score_delta,
                risk_score=state.current_risk_score,
                risk_tier=state.risk_tier,
                is_whitelisted=bool(state.is_whitelisted),
                deauth_count_10s=count_10s,
                deauth_count_60s=count_60s,
                active_channels=list(state.active_channels_map.keys()),
                primary_channel=state.primary_channel,
                bssid_state=state,
                details={
                    "count_10s": count_10s,
                    "count_60s": count_60s,
                    "threshold_10s": self.DEAUTH_THRESHOLD_10S,
                    "threshold_60s": self.DEAUTH_THRESHOLD_60S,
                },
            )

    def process_beacon_frame(
        self,
        bssid: str,
        observed_ssid: str,
        tag3_channel: int,
        seq_num: int,
        tsf_timestamp: int,
        now_ts: Optional[float] = None,
    ) -> Track4AResult:
        """
        Track 4A Ingress for 802.11 Beacon Frames.
        - Whitelisted BSSIDs execute Track 4A integrity verification (Seq/TSF collision & Tag 3/61 clone).
        - 15s sliding Tag 3/61 channel tracker:
            1-way channel move (Ch 6 -> Ch 1) expires old channel in 15s with 0 pts.
            >= 2 channels active within 15s triggers Type A Multi-Channel Clone (+70 pts HIGH).
        - 1-hour offline gap on un-whitelisted AP resets first_seen_ts = now.
        - Same-channel backward Seq / TSF regression triggers Same-Channel Collision (+75 pts HIGH).
        """
        if now_ts is None:
            now_ts = time.time()

        try:
            tag3_channel = int(float(tag3_channel))
        except (ValueError, TypeError):
            tag3_channel = 1

        seq_num = int(seq_num) & 0x0FFF
        try:
            tsf_timestamp = int(tsf_timestamp)
        except (ValueError, TypeError):
            tsf_timestamp = 0

        with self._lock:
            b_norm = self._normalize_bssid(bssid)
            state = self.db_manager.get_bssid(bssid)
            is_wl = self._is_bssid_whitelisted(bssid, state)

            if state is None:
                # Stage 0: Brand new BSSID
                state = BSSIDState(
                    bssid=bssid,
                    current_ssid=observed_ssid,
                    is_whitelisted=1 if is_wl else 0,
                    first_seen_ts=now_ts,
                    last_seen_ts=now_ts,
                    primary_channel=tag3_channel,
                    active_channels_map={tag3_channel: now_ts},
                )
                self.db_manager.put_bssid(state)
            else:
                if is_wl:
                    state.is_whitelisted = 1

            # -------------------------------------------------------------
            # Check 4: 1-Hour Offline Probation Reset (Point 4 Fix)
            # -------------------------------------------------------------
            # PoE ceiling APs stay online 24/7. If an un-whitelisted AP went dark for > 1 hour,
            # reset its probation timer (first_seen_ts = now) to defeat hit-and-run timer priming.
            was_offline_over_1h = False
            if not state.is_whitelisted and state.last_seen_ts > 0:
                gap = now_ts - state.last_seen_ts
                if gap > self.OFFLINE_RESET_SEC:
                    state.first_seen_ts = now_ts
                    was_offline_over_1h = True
                    # Reset RF history and collision window for this BSSID since AP may have rebooted after >1 hour
                    self._rf_history.pop(b_norm, None)
                    self._collision_windows.pop(b_norm, None)

            if state.first_seen_ts == 0.0:
                state.first_seen_ts = now_ts

            # Update last_seen_ts
            state.last_seen_ts = max(state.last_seen_ts, now_ts)
            state.current_ssid = observed_ssid

            # -------------------------------------------------------------
            # Check 3: 15-Second Sliding Tag 3/61 Channel Tracker (Point 7 Fix)
            # -------------------------------------------------------------
            # Update timestamp for current declared channel
            state.active_channels_map[tag3_channel] = max(
                state.active_channels_map.get(tag3_channel, 0.0), now_ts
            )

            # Expire channels not seen within CHANNEL_WINDOW_SEC (15.0s)
            expired_channels = [
                ch for ch, ts in list(state.active_channels_map.items())
                if (now_ts - ts) > self.CHANNEL_WINDOW_SEC
            ]
            for ch in expired_channels:
                del state.active_channels_map[ch]

            active_channels = sorted(state.active_channels_map.keys())
            is_multi_channel_clone = len(active_channels) >= 2

            if len(active_channels) == 1:
                state.primary_channel = active_channels[0]

            # -------------------------------------------------------------
            # Check 5: Same-Channel Backward Seq / TSF Collision Detector
            # -------------------------------------------------------------
            ch_history = self._rf_history.setdefault(b_norm, {})
            rf_entry = ch_history.get(tag3_channel)
            is_seq_collision = False
            is_tsf_collision = False

            if rf_entry is not None and not was_offline_over_1h:
                prev_seq = rf_entry.get("last_seq", 0)
                prev_tsf = rf_entry.get("last_tsf", 0)

                # 1. Backward TSF check:
                # TSF drops backwards by > 1,000,000 microseconds (1.0 second regression)
                if prev_tsf > 0 and tsf_timestamp > 0:
                    if tsf_timestamp < (prev_tsf - TSF_BACKWARD_TOLERANCE_US):
                        is_tsf_collision = True

                # 2. Backward sequence check:
                # In 12-bit arithmetic modulo 4096:
                # If sequence jumps backwards (prev_seq > curr_seq + 5 without rollover)
                backward_diff = (prev_seq - seq_num) % SEQ_MODULO
                if SEQ_BACKWARD_TOLERANCE < backward_diff < (SEQ_MODULO // 2):
                    time_gap = now_ts - rf_entry.get("last_ts", 0.0)
                    if not (time_gap >= 10.0 and not is_tsf_collision):
                        is_seq_collision = True

            # Update RF history for this specific channel
            ch_history[tag3_channel] = {
                "last_channel": tag3_channel,
                "last_seq": seq_num,
                "last_tsf": tsf_timestamp,
                "last_ts": now_ts,
            }

            # -------------------------------------------------------------
            # Sliding Active Collision Window Check
            # -------------------------------------------------------------
            is_current_collision = (is_seq_collision or is_tsf_collision)
            if is_current_collision:
                self._collision_windows[b_norm] = now_ts

            is_collision_active = is_current_collision or (
                b_norm in self._collision_windows
                and (now_ts - self._collision_windows[b_norm]) <= self.CHANNEL_WINDOW_SEC
            )
            # Expire old collision window if window exceeded
            if not is_current_collision and b_norm in self._collision_windows and (now_ts - self._collision_windows[b_norm]) > self.CHANNEL_WINDOW_SEC:
                self._collision_windows.pop(b_norm, None)

            # Deauth flood active check
            deauth_10s = self.get_deauth_count(bssid, 10.0, now_ts)
            deauth_60s = self.get_deauth_count(bssid, 60.0, now_ts)
            is_deauth_flood_active = (deauth_10s >= self.DEAUTH_THRESHOLD_10S) or (deauth_60s >= self.DEAUTH_THRESHOLD_60S)

            # -------------------------------------------------------------
            # Determine Anomaly Type & Hard Floors
            # -------------------------------------------------------------
            prev_tier = state.risk_tier

            if is_collision_active:
                is_anomaly = True
                anomaly_type = "SAME_CHANNEL_COLLISION"
                score_delta = self.SCORE_FLOOR_SAME_CHANNEL_COLLISION
                state.current_risk_score = max(state.current_risk_score, self.SCORE_FLOOR_SAME_CHANNEL_COLLISION)
                state.risk_tier = "HIGH"
                if is_current_collision:
                    self.db_manager.record_bssid_update(state, prev_tier=prev_tier, now_mono=now_ts)
                    self.db_manager.add_behavior_log(
                        bssid=bssid,
                        timestamp=now_ts,
                        seq_num=seq_num,
                        tsf_timestamp=tsf_timestamp,
                        channel_anomaly_type="SAME_CHANNEL_COLLISION",
                        deauth_count_1m=deauth_60s,
                    )
                else:
                    self.db_manager.put_bssid(state)
            elif is_multi_channel_clone:
                is_anomaly = True
                anomaly_type = "MULTI_CHANNEL_CLONE"
                score_delta = self.SCORE_FLOOR_MULTI_CHANNEL_CLONE
                state.current_risk_score = max(state.current_risk_score, self.SCORE_FLOOR_MULTI_CHANNEL_CLONE)
                state.risk_tier = "HIGH"
                self.db_manager.record_bssid_update(state, prev_tier=prev_tier, now_mono=now_ts)
                self.db_manager.add_behavior_log(
                    bssid=bssid,
                    timestamp=now_ts,
                    seq_num=seq_num,
                    tsf_timestamp=tsf_timestamp,
                    channel_anomaly_type="MULTI_CHANNEL_CLONE",
                    deauth_count_1m=deauth_60s,
                )
            elif is_deauth_flood_active:
                is_anomaly = True
                anomaly_type = "DEAUTH_FLOOD"
                score_delta = self.SCORE_FLOOR_DEAUTH_FLOOD
                state.current_risk_score = max(state.current_risk_score, self.SCORE_FLOOR_DEAUTH_FLOOD)
                state.risk_tier = "HIGH"
                self.db_manager.put_bssid(state)
            else:
                is_anomaly = False
                anomaly_type = "NONE"
                score_delta = 0

                # Check 2: Whitelisted AP Integrity Path
                # Only clear score to BENIGN if the whitelisted AP has NOT mutated its SSID!
                if state.is_whitelisted == 1 and not state.is_mutated:
                    state.current_risk_score = 0
                    state.risk_tier = "LOW"
                    self.db_manager.record_bssid_update(state, prev_tier=prev_tier, now_mono=now_ts)
                else:
                    self.db_manager.put_bssid(state)

            deauth_10s = self.get_deauth_count(bssid, 10.0, now_ts)
            deauth_60s = self.get_deauth_count(bssid, 60.0, now_ts)

            return Track4AResult(
                bssid=bssid,
                is_anomaly=is_anomaly,
                anomaly_type=anomaly_type,
                score_delta=score_delta,
                risk_score=state.current_risk_score,
                risk_tier=state.risk_tier,
                is_whitelisted=bool(state.is_whitelisted),
                deauth_count_10s=deauth_10s,
                deauth_count_60s=deauth_60s,
                active_channels=active_channels,
                primary_channel=state.primary_channel,
                bssid_state=state,
                details={
                    "is_seq_collision": is_seq_collision,
                    "is_tsf_collision": is_tsf_collision,
                    "is_multi_channel_clone": is_multi_channel_clone,
                    "was_offline_over_1h": was_offline_over_1h,
                    "first_seen_ts": state.first_seen_ts,
                    "last_seen_ts": state.last_seen_ts,
                    "primary_channel": state.primary_channel,
                },
            )

    def route_management_frame(
        self,
        subtype: int,
        bssid: str,
        observed_ssid: str = "",
        tag3_channel: int = 1,
        seq_num: int = 0,
        tsf_timestamp: int = 0,
        now_ts: Optional[float] = None,
    ) -> Optional[Track4AResult]:
        """
        Pre-Stage-0 Ingress router for 802.11 management frames:
        - Subtype 0x0C (Deauth) & 0x0A (Disassoc): routes directly to Track 4A deauth counter.
        - Subtype 0x08 (Beacon): routes to Track 4A beacon processor.
        """
        if subtype in (0x0C, 0x0A, 12, 10):
            return self.process_deauth_frame(bssid, now_ts=now_ts)
        elif subtype in (0x08, 8):
            return self.process_beacon_frame(
                bssid=bssid,
                observed_ssid=observed_ssid,
                tag3_channel=tag3_channel,
                seq_num=seq_num,
                tsf_timestamp=tsf_timestamp,
                now_ts=now_ts,
            )
        return None

    def demux_frame(
        self,
        frame: Any,
        now_ts: Optional[float] = None,
    ) -> Optional[Track4AResult]:
        """
        Demultiplexes a raw 802.11 frame (Scapy packet, dict, or object):
        - Inspects frame subtype:
          - 0x0C (Deauth) / 0x0A (Disassoc) -> process_deauth_frame(frame.addr3)
          - 0x08 (Beacon) -> extracts tag3/61 channel, seq_num, tsf -> process_beacon_frame(...)
        """
        if frame is None:
            return None

        # 1. If frame is a dictionary
        if isinstance(frame, dict):
            subtype = frame.get("subtype", 0)
            bssid = frame.get("bssid") or frame.get("addr3") or frame.get("addr2", "")
            if not bssid:
                return None
            if subtype in (0x0C, 0x0A, 12, 10):
                return self.process_deauth_frame(bssid, now_ts=now_ts)
            elif subtype in (0x08, 8):
                ssid = frame.get("ssid", "")
                ch = extract_tag3_or_61_channel(frame) or 1
                seq = frame.get("seq_num") or frame.get("seq", 0)
                tsf = frame.get("tsf_timestamp") or frame.get("tsf", 0)
                return self.process_beacon_frame(bssid, ssid, ch, seq, tsf, now_ts=now_ts)
            return None

        # 2. If frame is a Scapy packet (or wrapped in RadioTap)
        target = frame
        if hasattr(frame, "haslayer"):
            try:
                from scapy.layers.dot11 import Dot11  # type: ignore
                if frame.haslayer(Dot11):
                    target = frame.getlayer(Dot11)
            except Exception:
                if hasattr(frame, "_dot11"):
                    target = getattr(frame, "_dot11")
                elif hasattr(frame, "getlayer"):
                    try:
                        target = frame.getlayer("Dot11") or frame
                    except Exception:
                        pass
        elif hasattr(frame, "_dot11"):
            target = getattr(frame, "_dot11")

        subtype = getattr(target, "subtype", None)
        if subtype is None and hasattr(target, "type") and target.type == 0:
            subtype = getattr(target, "subtype", None)

        if subtype in (0x0C, 0x0A, 12, 10):
            bssid = getattr(target, "addr3", None) or getattr(target, "addr2", None)
            if bssid:
                return self.process_deauth_frame(str(bssid), now_ts=now_ts)

        if subtype in (0x08, 8):
            bssid = getattr(target, "addr3", None) or getattr(target, "addr2", None)
            if not bssid:
                return None
            bssid_str = str(bssid)

            # Extract SSID
            ssid = ""
            try:
                from scapy.layers.dot11 import Dot11Elt  # type: ignore
                if frame.haslayer(Dot11Elt):
                    elt = frame.getlayer(Dot11Elt)
                    while elt is not None:
                        if elt.ID == 0:
                            raw_info = elt.info
                            ssid = raw_info.decode("utf-8", errors="ignore") if isinstance(raw_info, bytes) else str(raw_info)
                            break
                        elt = elt.payload.getlayer(Dot11Elt) if elt.payload else None
            except Exception:
                pass
            if not ssid:
                raw_info = getattr(target, "info", "")
                if isinstance(raw_info, bytes):
                    ssid = raw_info.decode("utf-8", errors="ignore")
                else:
                    ssid = str(raw_info) if raw_info else ""

            # Extract Channel from Tag 3 or Tag 61
            ch = extract_tag3_or_61_channel(target) or extract_tag3_or_61_channel(frame) or 1

            # Extract Sequence Number
            seq_num = 0
            if hasattr(target, "SC"):
                seq_num = (target.SC >> 4) & 0x0FFF
            elif hasattr(target, "seq"):
                seq_num = int(target.seq) & 0x0FFF

            # Extract TSF Timestamp
            tsf_ts = getattr(target, "timestamp", 0)

            return self.process_beacon_frame(
                bssid=bssid_str,
                observed_ssid=ssid,
                tag3_channel=ch,
                seq_num=seq_num,
                tsf_timestamp=tsf_ts,
                now_ts=now_ts,
            )

        return None

    def get_deauth_count(
        self,
        bssid: str,
        window_sec: float = 60.0,
        now_ts: Optional[float] = None,
    ) -> int:
        """Returns the number of deauth/disassoc frames observed for BSSID within window_sec."""
        if now_ts is None:
            now_ts = time.time()
        b_norm = self._normalize_bssid(bssid)
        with self._lock:
            deq = self._deauth_windows.get(b_norm)
            if not deq:
                return 0
            cutoff_60 = now_ts - 60.0
            while deq and deq[0] < cutoff_60:
                deq.popleft()
            if not deq:
                self._deauth_windows.pop(b_norm, None)
                return 0
            cutoff = now_ts - window_sec
            return sum(1 for ts in deq if ts >= cutoff)

    def clean_expired_deauth_windows(self, now_ts: Optional[float] = None) -> None:
        """Purges expired deauth sliding windows from memory to bound RAM."""
        if now_ts is None:
            now_ts = time.time()
        cutoff_60 = now_ts - 60.0
        with self._lock:
            to_remove = []
            for b_norm, deq in self._deauth_windows.items():
                while deq and deq[0] < cutoff_60:
                    deq.popleft()
                if not deq:
                    to_remove.append(b_norm)
            for b_norm in to_remove:
                self._deauth_windows.pop(b_norm, None)

    def get_active_channels(
        self,
        bssid: str,
        now_ts: Optional[float] = None,
    ) -> List[int]:
        """Returns currently active Tag 3/61 operating channels for BSSID (15.0s window)."""
        if now_ts is None:
            now_ts = time.time()
        state = self.db_manager.get_bssid(bssid)
        if state is None:
            return []
        with self._lock:
            return sorted([
                ch for ch, ts in state.active_channels_map.items()
                if (now_ts - ts) <= self.CHANNEL_WINDOW_SEC
            ])

    def get_rf_history(self, bssid: str, channel: Optional[int] = None) -> Optional[Dict[str, Any]]:
        """Returns cached RF state for BSSID (last channel, seq, tsf)."""
        b_norm = self._normalize_bssid(bssid)
        with self._lock:
            ch_map = self._rf_history.get(b_norm)
            if not ch_map:
                return None
            if channel is not None:
                entry = ch_map.get(channel)
                return dict(entry) if entry else None
            # Return entry with most recent timestamp
            latest_entry = max(ch_map.values(), key=lambda e: e.get("last_ts", 0.0))
            return dict(latest_entry)

    def is_probation_active(
        self,
        bssid: str,
        now_ts: Optional[float] = None,
    ) -> bool:
        """
        Returns True if un-whitelisted AP is currently within its 24-hour probation period (age < 86,400s).
        Returns False if AP is whitelisted or uptime >= 24 hours.
        Also returns True if un-whitelisted AP has been offline for > 1 hour (continuous uptime broken).
        """
        if now_ts is None:
            now_ts = time.time()
        state = self.db_manager.get_bssid(bssid)
        if state is None or (state.first_seen_ts == 0.0 and state.last_seen_ts == 0.0 and not state.active_channels_map):
            return True
        if state.is_whitelisted == 1:
            return False
        # If un-whitelisted AP was offline for > 1 hour, continuous uptime was broken
        if state.last_seen_ts > 0 and (now_ts - state.last_seen_ts) > self.OFFLINE_RESET_SEC:
            return True
        uptime = now_ts - state.first_seen_ts
        return uptime < 86400.0

    def get_probation_age(
        self,
        bssid: str,
        now_ts: Optional[float] = None,
    ) -> float:
        """Returns continuous uptime age in seconds since first_seen_ts."""
        if now_ts is None:
            now_ts = time.time()
        state = self.db_manager.get_bssid(bssid)
        if state is None or (state.first_seen_ts == 0.0 and state.last_seen_ts == 0.0 and not state.active_channels_map):
            return 0.0
        # If un-whitelisted AP was offline for > 1 hour, continuous uptime was broken
        if not state.is_whitelisted and state.last_seen_ts > 0 and (now_ts - state.last_seen_ts) > self.OFFLINE_RESET_SEC:
            return 0.0
        return max(0.0, now_ts - state.first_seen_ts)

    def reset(self) -> None:
        """Clears all in-memory deauth sliding windows, collision windows, and RF history (useful for test resets)."""
        with self._lock:
            self._deauth_windows.clear()
            self._rf_history.clear()
            self._collision_windows.clear()
