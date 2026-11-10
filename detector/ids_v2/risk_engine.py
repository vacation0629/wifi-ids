"""
Edge Wi-Fi Evil Twin Detection Framework (v2.1.2)
Stage 5: Master Hybrid Risk Scoring Engine (0–100 Scale) & Alert Gatekeeper
"""

import logging
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

from detector.ids_v2.config import (
    DEFAULT_CAMPUS_WHITELIST,
    MIN_FORCE_COOLDOWN_SEC,
    OFFLINE_RESET_SEC,
    SCORE_THRESHOLD_HIGH,
    SCORE_THRESHOLD_MEDIUM,
    TIER_RANK,
    WHITELISTED_SSIDS,
)
from detector.ids_v2.db_manager import (
    BatchDatabaseManager,
    BSSIDState,
)
from detector.ids_v2.track_4a_state import (
    SCORE_FLOOR_DEAUTH_FLOOD,
    SCORE_FLOOR_MULTI_CHANNEL_CLONE,
    SCORE_FLOOR_SAME_CHANNEL_COLLISION,
    Track4AResult,
)
from detector.ids_v2.track_4b_beacon import (
    SCORE_CAMPUS_BLUEPRINT_MATCH,
    SCORE_CHANNEL_MATCH_TYPE_B,
    SCORE_JITTER_ANOMALY,
    SCORE_PARTIAL_IE_MISMATCH,
    SCORE_RSSI_VOLATILITY,
    SCORE_SEVERE_IE_MISMATCH,
    Track4BResult,
)

logger = logging.getLogger(__name__)

# Master Risk Scoring Table Constants (v2.1.2)
FLOOR_DEAUTH_STORM: int = SCORE_FLOOR_DEAUTH_FLOOD               # 75 pts (Rank 1: Floor HIGH)
FLOOR_SAME_CHANNEL_COLLISION: int = SCORE_FLOOR_SAME_CHANNEL_COLLISION # 75 pts (Rank 1: Floor HIGH)
FLOOR_MULTI_CHANNEL_CLONE: int = SCORE_FLOOR_MULTI_CHANNEL_CLONE     # 70 pts (Rank 2: Floor HIGH)
FLOOR_NEW_AP_PROBATION: int = 30                                 # 30 pts (Rank 6: Floor MEDIUM)
FLOOR_EXACT_WHITELIST_UNAPPROVED: int = 30                       # 30 pts (Rank 6: Exact Whitelist retention)

POINTS_DEAUTH_STORM: int = 75
POINTS_SAME_CHANNEL_COLLISION: int = 75
POINTS_MULTI_CHANNEL_CLONE: int = 70
POINTS_SEVERE_IE_MISMATCH: int = SCORE_SEVERE_IE_MISMATCH        # +55 pts (Rank 3)
POINTS_CHANNEL_MATCH_TYPE_B: int = SCORE_CHANNEL_MATCH_TYPE_B    # +45 pts (Rank 4)
POINTS_BSSID_NAME_MUTATION: int = 45                             # +45 pts (Rank 5: Option M2)
POINTS_NEW_AP_PROBATION: int = 20                                # +20 pts (Rank 6)
POINTS_STRICT_JITTER: int = SCORE_JITTER_ANOMALY                 # +20 pts (Rank 7)
POINTS_RSSI_VOLATILITY: int = SCORE_RSSI_VOLATILITY              # +20 pts (Rank 8)
POINTS_PARTIAL_IE_MISMATCH: int = SCORE_PARTIAL_IE_MISMATCH      # +15 pts (Rank 9)
POINTS_NON_STANDARD_CHANNEL: int = 15                            # +15 pts (Rank 9)
POINTS_CAMPUS_BLUEPRINT_MATCH: int = SCORE_CAMPUS_BLUEPRINT_MATCH # -35 pts (Rank 10: Sister only)

PROBATION_PERIOD_SEC: float = 86400.0                            # 24 hours uptime


@dataclass
class RiskAssessment:
    """Detailed risk assessment outcome produced by HybridRiskEngine."""
    bssid: str
    ssid: str
    risk_score: int
    risk_tier: str                                               # "LOW", "MEDIUM", "HIGH"
    prev_risk_tier: str = "LOW"
    is_escalation: bool = False
    triggered_instant_flush: bool = False
    effective_floor: int = 0
    raw_accumulated_score: int = 0
    applied_floors: List[Tuple[str, int]] = field(default_factory=list)
    applied_points: List[Tuple[str, int]] = field(default_factory=list)
    is_whitelisted: bool = False
    is_sister_ssid: bool = False
    is_exact_whitelist: bool = False
    uptime_seconds: float = 0.0
    reasons: List[str] = field(default_factory=list)
    bssid_state: Optional[BSSIDState] = None

    @property
    def current_risk_score(self) -> int:
        return self.risk_score


class HybridRiskEngine:
    """
    Master Hybrid Risk Scoring Engine (0–100 Scale, v2.1.2).

    Ranks and Floors from Master Risk Scoring Table:
      1. Deauth Storm (>=15/10s or >=30/60s) / Same-Ch Collision: Floor HIGH (75 pts)
      2. Type A Multi-Ch Clone (>=2 active Tag 3/61 channels in 15s): Floor HIGH (70 pts)
      3. Severe IE Mismatch: +55 pts
      4. Channel Match Type B (DS Tag 3 Spoof): +45 pts
      5. BSSID Name Mutation (Option M2): +45 pts
      6. New AP Probation (age < 24h): Floor MEDIUM (30 pts) + 20 pts
         - Sister SSID Rule (Check 5.1): Un-whitelisted Sister SSID (e.g. Law_School_Faculty)
           with 100% IE match (-35 pts) decays to LOW (< 30 pts, Watchlist) after 24h continuous uptime.
         - Exact Main Whitelist Rule (Check 5.1): Un-whitelisted exact whitelist SSID (e.g. eduroam,
           University_Campus_5G) retains its MEDIUM floor (>= 30 pts) indefinitely until an admin
           explicitly marks is_whitelisted = 1 in the database / UI.
      7. Strict Beacon Timing / TSF Jitter > 20ms: +20 pts
      8. RSSI Volatility (> 15 dB jump): +20 pts
      9. Partial IE Mismatch / Non-standard channel: +15 pts each
      10. 100% Campus IE Blueprint Match: -35 pts (Sister only, never exact whitelist)
      11. Static Strong RSSI (>= -70 dBm): 0 pts (Gate only)

    Score accumulation is clamped to [0, 100].
    Tiers: LOW (< 30), MEDIUM (30–69), HIGH (>= 70).
    Escalations to MEDIUM or HIGH trigger Coalesced Instant Alert Bypass (MIN_FORCE_COOLDOWN_SEC = 0.25s).
    """

    FLOOR_DEAUTH_STORM = FLOOR_DEAUTH_STORM
    FLOOR_SAME_CHANNEL_COLLISION = FLOOR_SAME_CHANNEL_COLLISION
    FLOOR_MULTI_CHANNEL_CLONE = FLOOR_MULTI_CHANNEL_CLONE
    FLOOR_NEW_AP_PROBATION = FLOOR_NEW_AP_PROBATION
    FLOOR_EXACT_WHITELIST_UNAPPROVED = FLOOR_EXACT_WHITELIST_UNAPPROVED

    POINTS_SEVERE_IE_MISMATCH = POINTS_SEVERE_IE_MISMATCH
    POINTS_CHANNEL_MATCH_TYPE_B = POINTS_CHANNEL_MATCH_TYPE_B
    POINTS_BSSID_NAME_MUTATION = POINTS_BSSID_NAME_MUTATION
    POINTS_NEW_AP_PROBATION = POINTS_NEW_AP_PROBATION
    POINTS_STRICT_JITTER = POINTS_STRICT_JITTER
    POINTS_RSSI_VOLATILITY = POINTS_RSSI_VOLATILITY
    POINTS_PARTIAL_IE_MISMATCH = POINTS_PARTIAL_IE_MISMATCH
    POINTS_NON_STANDARD_CHANNEL = POINTS_NON_STANDARD_CHANNEL
    POINTS_CAMPUS_BLUEPRINT_MATCH = POINTS_CAMPUS_BLUEPRINT_MATCH

    SCORE_THRESHOLD_MEDIUM = SCORE_THRESHOLD_MEDIUM
    SCORE_THRESHOLD_HIGH = SCORE_THRESHOLD_HIGH
    PROBATION_PERIOD_SEC = PROBATION_PERIOD_SEC
    OFFLINE_RESET_SEC = OFFLINE_RESET_SEC
    MIN_FORCE_COOLDOWN_SEC = MIN_FORCE_COOLDOWN_SEC

    def __init__(
        self,
        db_manager: BatchDatabaseManager,
        campus_whitelist: Optional[List[str]] = None,
    ):
        self.db_manager = db_manager
        self.campus_whitelist: List[str] = (
            list(campus_whitelist) if campus_whitelist is not None else list(DEFAULT_CAMPUS_WHITELIST)
        )
        self._lock = threading.RLock()

    def _normalize_bssid(self, bssid: str) -> str:
        return bssid.strip().lower()

    def is_exact_whitelist_ssid(self, ssid: str) -> bool:
        """Checks if SSID exactly matches one of the protected campus baseline whitelist SSIDs."""
        clean = ssid.strip().lower()
        if not clean:
            return False
        # Check against campus_whitelist and global WHITELISTED_SSIDS
        for w in self.campus_whitelist:
            if clean == w.strip().lower():
                return True
        for w in WHITELISTED_SSIDS:
            if clean == w.strip().lower():
                return True
        return False

    def is_sister_ssid(self, ssid: str) -> bool:
        """
        Sister SSIDs are un-whitelisted SSIDs that share campus affiliation or blueprint profile
        (e.g. 'Law_School_Faculty'), but do NOT match the exact primary campus whitelist names.
        """
        if not ssid or not ssid.strip():
            return False
        return not self.is_exact_whitelist_ssid(ssid)

    def determine_tier(self, score: int) -> str:
        """Maps risk score (0–100) to standard tier: LOW (<30), MEDIUM (30–69), HIGH (>=70)."""
        if score >= self.SCORE_THRESHOLD_HIGH:
            return "HIGH"
        if score >= self.SCORE_THRESHOLD_MEDIUM:
            return "MEDIUM"
        return "LOW"

    def compute_risk(
        self,
        bssid: str,
        ssid: str,
        bssid_state: Optional[BSSIDState] = None,
        track_4a_result: Optional[Track4AResult] = None,
        track_4b_result: Optional[Track4BResult] = None,
        is_mutated: bool = False,
        now_ts: Optional[float] = None,
        is_whitelisted: Optional[bool] = None,
        is_suspicious_name: bool = True,
        prev_tier: Optional[str] = None,
    ) -> RiskAssessment:
        """
        Pure calculation of Master Hybrid Risk Score (0–100 scale) and Floors/Points aggregation.
        Evaluates Ranks 1 through 10 and produces a comprehensive RiskAssessment.
        """
        if now_ts is None:
            now_ts = time.time()

        b_norm = self._normalize_bssid(bssid)

        # Determine whitelist status
        if is_whitelisted is None:
            if bssid_state is not None and bssid_state.is_whitelisted == 1:
                is_wl = True
            elif b_norm in self.db_manager.whitelisted_bssids:
                is_wl = True
            else:
                is_wl = False
        else:
            is_wl = bool(is_whitelisted)

        # Check mutation status
        mutated = bool(is_mutated or (bssid_state is not None and bssid_state.is_mutated))

        # Check SSID type
        is_exact_wl = self.is_exact_whitelist_ssid(ssid)
        is_sister = self.is_sister_ssid(ssid) if not is_wl else False

        applied_floors: List[Tuple[str, int]] = []
        applied_points: List[Tuple[str, int]] = []
        reasons: List[str] = []

        # Calculate continuous uptime / age
        first_seen = bssid_state.first_seen_ts if bssid_state and bssid_state.first_seen_ts > 0 else now_ts
        last_seen = bssid_state.last_seen_ts if bssid_state and bssid_state.last_seen_ts > 0 else now_ts

        # 1-Hour Offline Probation Reset (Point 4): if offline > 3600s, uptime resets
        if not is_wl and last_seen > 0 and (now_ts - last_seen) > self.OFFLINE_RESET_SEC:
            uptime = 0.0
            first_seen = now_ts
            if bssid_state is not None:
                bssid_state.first_seen_ts = now_ts
        else:
            uptime = max(0.0, now_ts - first_seen)

        # ---------------------------------------------------------------------
        # Rank 1: Deauth Storm / Same-Ch Collision (Floor HIGH 75 pts)
        # ---------------------------------------------------------------------
        has_deauth_storm = False
        has_same_ch_collision = False

        if track_4a_result is not None:
            if track_4a_result.anomaly_type == "DEAUTH_FLOOD" or (
                track_4a_result.deauth_count_10s >= 15 or track_4a_result.deauth_count_60s >= 30
            ):
                has_deauth_storm = True
            if track_4a_result.anomaly_type == "SAME_CHANNEL_COLLISION":
                has_same_ch_collision = True

        if has_deauth_storm:
            applied_floors.append(("DEAUTH_STORM_FLOOR", self.FLOOR_DEAUTH_STORM))
            applied_points.append(("DEAUTH_STORM", POINTS_DEAUTH_STORM))
            reasons.append("Deauth Storm (>=15/10s or >=30/60s) -> Floor HIGH (75 pts)")
        elif has_same_ch_collision:
            applied_floors.append(("SAME_CHANNEL_COLLISION_FLOOR", self.FLOOR_SAME_CHANNEL_COLLISION))
            applied_points.append(("SAME_CHANNEL_COLLISION", POINTS_SAME_CHANNEL_COLLISION))
            reasons.append("Same-Channel Backward Seq / TSF Collision -> Floor HIGH (75 pts)")

        # ---------------------------------------------------------------------
        # Rank 2: Channel Match Type A: Multi-Channel Clone (Floor HIGH 70 pts)
        # ---------------------------------------------------------------------
        has_multi_ch_clone = False
        if track_4a_result is not None:
            if track_4a_result.anomaly_type == "MULTI_CHANNEL_CLONE" or len(track_4a_result.active_channels) >= 2:
                has_multi_ch_clone = True

        if has_multi_ch_clone:
            applied_floors.append(("MULTI_CHANNEL_CLONE_FLOOR", self.FLOOR_MULTI_CHANNEL_CLONE))
            applied_points.append(("MULTI_CHANNEL_CLONE", POINTS_MULTI_CHANNEL_CLONE))
            reasons.append("Channel Match Type A: Multi-Channel Clone (>=2 channels active in 15s) -> Floor HIGH (70 pts)")

        # ---------------------------------------------------------------------
        # Rank 3: Severe IE Mismatch (+55 pts)
        # ---------------------------------------------------------------------
        if track_4b_result is not None and track_4b_result.ie_match_status == "SEVERE_MISMATCH":
            applied_points.append(("SEVERE_IE_MISMATCH", self.POINTS_SEVERE_IE_MISMATCH))
            reasons.append("Severe IE Mismatch: Open on 802.1X, WPS present, 1x1 PHY, or missing MDID/Tag 221 (+55 pts)")

        # ---------------------------------------------------------------------
        # Rank 4: Channel Match Type B: DS Tag 3 Spoof (+45 pts)
        # ---------------------------------------------------------------------
        if track_4b_result is not None and (
            "CHANNEL_MATCH_TYPE_B" in track_4b_result.anomaly_types
            or (track_4b_result.score_delta >= self.POINTS_CHANNEL_MATCH_TYPE_B and "Tag 3" in str(track_4b_result.details))
        ):
            applied_points.append(("CHANNEL_MATCH_TYPE_B", self.POINTS_CHANNEL_MATCH_TYPE_B))
            reasons.append("Channel Match Type B: Captured radio channel != IE Tag 3 (+45 pts)")

        # ---------------------------------------------------------------------
        # Rank 5: BSSID Name Mutation (Option M2) (+45 pts)
        # ---------------------------------------------------------------------
        if mutated:
            applied_points.append(("BSSID_NAME_MUTATION", self.POINTS_BSSID_NAME_MUTATION))
            reasons.append("BSSID Name Mutation (Option M2): Known BSSID broadcast SSID changed (+45 pts)")

        # ---------------------------------------------------------------------
        # Rank 6: New AP Probation & Whitelist Floor Rules (Check 5.1)
        # ---------------------------------------------------------------------
        if not is_wl:
            if is_exact_wl:
                # Exact Main Whitelist Rule (Check 5.1):
                # Un-whitelisted exact whitelist SSID (eduroam, University_Campus_5G)
                # retains its MEDIUM floor (>= 30 pts) indefinitely until an admin marks is_whitelisted = 1.
                applied_floors.append(("UNWHITELISTED_EXACT_SSID_FLOOR", self.FLOOR_EXACT_WHITELIST_UNAPPROVED))
                reasons.append("Exact Whitelist SSID un-whitelisted: Retains MEDIUM floor (30 pts) until manual UI whitelist")

                # If age < 24h, also apply probation points
                if uptime < self.PROBATION_PERIOD_SEC:
                    applied_points.append(("NEW_AP_PROBATION", self.POINTS_NEW_AP_PROBATION))
                    applied_floors.append(("NEW_AP_PROBATION_FLOOR", self.FLOOR_NEW_AP_PROBATION))
                    reasons.append(f"New AP Probation (uptime {uptime:.0f}s < 24h) -> +20 pts")
            elif is_suspicious_name or mutated:
                # Sister SSID / Un-whitelisted suspicious SSID (passing Stage 2.5):
                # Probation applies strictly for the first 24h of continuous uptime
                if uptime < self.PROBATION_PERIOD_SEC:
                    applied_points.append(("NEW_AP_PROBATION", self.POINTS_NEW_AP_PROBATION))
                    applied_floors.append(("NEW_AP_PROBATION_FLOOR", self.FLOOR_NEW_AP_PROBATION))
                    reasons.append(f"New AP Probation (uptime {uptime:.0f}s < 24h) -> Floor MEDIUM (30 pts) + 20 pts")
                else:
                    # 24h Continuous Uptime Reached: Probation decayed!
                    reasons.append(f"New AP Probation Decayed (uptime {uptime:.0f}s >= 24h continuous uptime)")

        # ---------------------------------------------------------------------
        # Rank 7: Strict Beacon Timing / TSF Jitter > 20ms (+20 pts)
        # ---------------------------------------------------------------------
        if track_4b_result is not None and "JITTER_ANOMALY" in track_4b_result.anomaly_types:
            applied_points.append(("STRICT_TIMING_JITTER", self.POINTS_STRICT_JITTER))
            reasons.append(f"Strict Beacon Timing / TSF Jitter > 20ms (error {track_4b_result.sample_error_ms:.1f}ms) -> +20 pts")

        # ---------------------------------------------------------------------
        # Rank 8: RSSI Volatility (> 15 dB jump) (+20 pts)
        # ---------------------------------------------------------------------
        if track_4b_result is not None and "RSSI_VOLATILITY" in track_4b_result.anomaly_types:
            applied_points.append(("RSSI_VOLATILITY", self.POINTS_RSSI_VOLATILITY))
            reasons.append(f"RSSI Volatility: Sudden jump Delta_RSSI > 15 dB (jump {track_4b_result.rssi_delta:.1f} dB) -> +20 pts")

        # ---------------------------------------------------------------------
        # Rank 9: Partial IE Mismatch / Non-Standard Channel (+15 pts each)
        # ---------------------------------------------------------------------
        effective_ch = None
        if track_4a_result is not None and track_4a_result.primary_channel:
            effective_ch = track_4a_result.primary_channel
        elif bssid_state is not None and bssid_state.primary_channel:
            effective_ch = bssid_state.primary_channel
        elif track_4b_result is not None and "channel_type_b" in track_4b_result.details:
            effective_ch = track_4b_result.details["channel_type_b"].get("declared_channel")

        is_non_std_channel = False
        if effective_ch is not None and 1 <= effective_ch <= 14 and effective_ch not in (1, 6, 11):
            is_non_std_channel = True
        elif track_4b_result is not None and any(
            "Non-standard 2.4 GHz channel" in str(r)
            for r in track_4b_result.details.get("ie_blueprint", {}).get("reasons", [])
        ):
            is_non_std_channel = True

        is_partial_ie = False
        if track_4b_result is not None and track_4b_result.ie_match_status == "PARTIAL_MISMATCH":
            reasons_list = track_4b_result.details.get("ie_blueprint", {}).get("reasons", [])
            has_other_ie_reason = any("Non-standard 2.4 GHz channel" not in str(r) for r in reasons_list) if reasons_list else True
            if has_other_ie_reason or not is_non_std_channel:
                is_partial_ie = True

        if is_partial_ie:
            applied_points.append(("PARTIAL_IE_MISMATCH", self.POINTS_PARTIAL_IE_MISMATCH))
            reasons.append("Partial IE Mismatch: Minor tag sequence order or cipher variance (+15 pts)")

        if is_non_std_channel:
            applied_points.append(("NON_STANDARD_CHANNEL", self.POINTS_NON_STANDARD_CHANNEL))
            reasons.append(f"Non-Standard 2.4 GHz Channel ({effective_ch or 'outside {1, 6, 11}'}) (+15 pts)")

        # ---------------------------------------------------------------------
        # Rank 10: 100% Campus IE Blueprint Match (-35 pts Sister Only)
        # ---------------------------------------------------------------------
        if track_4b_result is not None and track_4b_result.ie_match_status == "100%_MATCH":
            if is_sister and not is_exact_wl:
                applied_points.append(("CAMPUS_BLUEPRINT_MATCH", self.POINTS_CAMPUS_BLUEPRINT_MATCH))
                reasons.append("100% Campus IE Blueprint Match: -35 pts discount applied to Departmental Sister SSID")
            elif is_exact_wl:
                reasons.append("100% Campus IE Blueprint Match on Exact Whitelist SSID: Preserves MEDIUM floor (0 pts discount)")

        # ---------------------------------------------------------------------
        # Score Accumulation, Floors, and Clamping [0, 100]
        # ---------------------------------------------------------------------
        effective_floor = max([fl for _, fl in applied_floors], default=0)

        # Sum of additive and subtractive points
        total_points = sum(pts for _, pts in applied_points)
        raw_accumulated_score = max(0, total_points)

        # The floor sets the minimum bound for the score
        final_score = max(effective_floor, raw_accumulated_score)
        final_score = min(100, max(0, final_score))

        tier = self.determine_tier(final_score)
        resolved_prev_tier = prev_tier if prev_tier is not None else (bssid_state.risk_tier if bssid_state else "LOW")

        prev_rank = TIER_RANK.get(resolved_prev_tier, 0)
        curr_rank = TIER_RANK.get(tier, 0)
        is_escalation = bool(curr_rank >= 1 and curr_rank > prev_rank)

        return RiskAssessment(
            bssid=bssid,
            ssid=ssid,
            risk_score=final_score,
            risk_tier=tier,
            prev_risk_tier=resolved_prev_tier,
            is_escalation=is_escalation,
            effective_floor=effective_floor,
            raw_accumulated_score=raw_accumulated_score,
            applied_floors=applied_floors,
            applied_points=applied_points,
            is_whitelisted=is_wl,
            is_sister_ssid=is_sister,
            is_exact_whitelist=is_exact_wl,
            uptime_seconds=uptime,
            reasons=reasons,
            bssid_state=bssid_state,
        )

    def evaluate_and_update(
        self,
        bssid: str,
        ssid: str,
        bssid_state: Optional[BSSIDState] = None,
        track_4a_result: Optional[Track4AResult] = None,
        track_4b_result: Optional[Track4BResult] = None,
        is_mutated: bool = False,
        now_ts: Optional[float] = None,
        is_whitelisted: Optional[bool] = None,
        is_suspicious_name: bool = True,
        force_flush: bool = False,
        prev_tier: Optional[str] = None,
    ) -> RiskAssessment:
        """
        Evaluates risk score, updates BSSIDState in SQLite LRU cache, and triggers
        Coalesced Instant Alert Bypass if escalating to MEDIUM or HIGH.
        """
        if now_ts is None:
            now_ts = time.time()

        with self._lock:
            if bssid_state is None:
                bssid_state = self.db_manager.get_bssid(bssid)

            resolved_prev_tier = prev_tier if prev_tier is not None else (bssid_state.risk_tier if bssid_state else "LOW")

            if bssid_state is None:
                is_wl_init = 1 if (is_whitelisted or self._normalize_bssid(bssid) in self.db_manager.whitelisted_bssids) else 0
                bssid_state = BSSIDState(
                    bssid=bssid,
                    current_ssid=ssid,
                    is_whitelisted=is_wl_init,
                    first_seen_ts=now_ts,
                    last_seen_ts=now_ts,
                    current_risk_score=0,
                    risk_tier="LOW",
                )
                self.db_manager.put_bssid(bssid_state)

            assessment = self.compute_risk(
                bssid=bssid,
                ssid=ssid,
                bssid_state=bssid_state,
                track_4a_result=track_4a_result,
                track_4b_result=track_4b_result,
                is_mutated=is_mutated,
                now_ts=now_ts,
                is_whitelisted=is_whitelisted,
                is_suspicious_name=is_suspicious_name,
                prev_tier=resolved_prev_tier,
            )

            # Update mutable state in RAM
            bssid_state.current_ssid = ssid
            bssid_state.current_risk_score = assessment.risk_score
            bssid_state.risk_tier = assessment.risk_tier
            bssid_state.last_seen_ts = max(bssid_state.last_seen_ts, now_ts)
            if assessment.is_whitelisted:
                bssid_state.is_whitelisted = 1

            if track_4b_result is not None:
                bssid_state.ie_match_status = track_4b_result.ie_match_status
                bssid_state.rssi_volatility_db = track_4b_result.rssi_delta
            if track_4a_result is not None:
                bssid_state.primary_channel = track_4a_result.primary_channel

            # Coalesced Instant Alert Bypass persistence
            commit_before = self.db_manager.commit_count
            self.db_manager.record_bssid_update(
                state=bssid_state,
                prev_tier=resolved_prev_tier,
                now_mono=now_ts,
            )
            if force_flush:
                self.db_manager.flush_to_sqlite(force=True, now_mono=now_ts)

            assessment.triggered_instant_flush = bool(self.db_manager.commit_count > commit_before)
            assessment.bssid_state = bssid_state
            return assessment
