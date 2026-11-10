"""
Step 5 Unit Test Harness: Master Hybrid Risk Scoring Engine & Unified Pipeline (v2.1.2)
Verifies:
- Check 5.1: Un-whitelisted Sister SSID ('Law_School_Faculty') with 100% IE match
  decays to LOW (< 30 pts, Watchlist) after 24h continuous uptime, while an un-whitelisted
  'eduroam' AP retains its MEDIUM floor (>= 30 pts) indefinitely until manually whitelisted.
- Check 5.1b: 1-hour offline gap (> 3600s) on Sister SSID resets probation timer back to MEDIUM.
- Check 5.1c: Admin manual whitelisting clears the MEDIUM floor on exact whitelist AP.
- Master Risk Scoring Table Floors & Points (Ranks 1 to 10):
  * Rank 1: Deauth Storm (>=15/10s) / Same-Ch Collision -> Floor HIGH (75 pts).
  * Rank 2: Type A Multi-Channel Clone (>=2 active channels in 15s) -> Floor HIGH (70 pts).
  * Rank 3: Severe IE Mismatch (+55 pts).
  * Rank 4: Channel Match Type B (DS Tag 3 Spoof) (+45 pts).
  * Rank 5: BSSID Name Mutation (Option M2) (+45 pts).
  * Rank 6: New AP Probation (age < 24h) (+20 pts, floor 30).
  * Rank 7: Strict Beacon Timing Jitter (+20 pts).
  * Rank 8: RSSI Volatility (+20 pts).
  * Rank 9: Partial IE Mismatch & Non-standard channel (+15 pts each).
  * Rank 10: 100% Campus IE Match (-35 pts Sister only).
  * Clamp bounds: Score clamped to [0, 100].
- Unified Two-Group Wi-Fi Evil Twin Sniffer Pipeline (WiFiIDSPipeline):
  * Pre-Stage-0 Ingress: Subtypes 0x0C / 0x0A route directly to Track 4A.
  * Stage 0 Whitelisted AP Integrity Path: Skips AI, verifies no clone/collision.
  * Stage 0 Whitelisted AP Clone Attack: Escalates to HIGH (+70 pts).
  * Stage 0 Mutation (Option M2): Flags is_mutated=1 (+45 pts).
  * Stage 2.5 Dynamic PSK Gate: eff_bge = 0.5 * bge_cos if PSK else bge_cos.
  * Coalesced Instant Alert Bypass vs Routine 3.0s Batch Flush.
  * Dictionary, Scapy Dot11, and Mock Frame Compatibility.
"""

import os
import tempfile
import time
import unittest

from detector.ids_v2.config import (
    DEFAULT_CAMPUS_WHITELIST,
    SCORE_THRESHOLD_HIGH,
    SCORE_THRESHOLD_MEDIUM,
)
from detector.ids_v2.db_manager import (
    BatchDatabaseManager,
    BSSIDState,
    CampusIEProfile,
)
from detector.ids_v2.pipeline import (
    PipelineResult,
    WiFiIDSPipeline,
)
from detector.ids_v2.risk_engine import (
    FLOOR_DEAUTH_STORM,
    FLOOR_EXACT_WHITELIST_UNAPPROVED,
    FLOOR_MULTI_CHANNEL_CLONE,
    FLOOR_NEW_AP_PROBATION,
    FLOOR_SAME_CHANNEL_COLLISION,
    HybridRiskEngine,
    POINTS_BSSID_NAME_MUTATION,
    POINTS_CAMPUS_BLUEPRINT_MATCH,
    POINTS_CHANNEL_MATCH_TYPE_B,
    POINTS_DEAUTH_STORM,
    POINTS_MULTI_CHANNEL_CLONE,
    POINTS_NEW_AP_PROBATION,
    POINTS_NON_STANDARD_CHANNEL,
    POINTS_PARTIAL_IE_MISMATCH,
    POINTS_RSSI_VOLATILITY,
    POINTS_SAME_CHANNEL_COLLISION,
    POINTS_SEVERE_IE_MISMATCH,
    POINTS_STRICT_JITTER,
    PROBATION_PERIOD_SEC,
    RiskAssessment,
)
from detector.ids_v2.track_4a_state import Track4AResult
from detector.ids_v2.track_4b_beacon import Track4BResult


class TestStep5RiskEngine(unittest.TestCase):

    def setUp(self):
        self.temp_db = tempfile.NamedTemporaryFile(delete=False, suffix=".db")
        self.temp_db.close()
        self.db_path = self.temp_db.name
        self.db = BatchDatabaseManager(self.db_path)
        self.engine = HybridRiskEngine(
            db_manager=self.db,
            campus_whitelist=DEFAULT_CAMPUS_WHITELIST,
        )

    def tearDown(self):
        try:
            self.db.close()
        except Exception:
            pass
        if os.path.exists(self.db_path):
            try:
                os.remove(self.db_path)
            except Exception:
                pass

    # =========================================================================
    # Check 5.1: Sister SSID Decay vs Exact Main Whitelist Floor Retention
    # =========================================================================
    def test_check_5_1_sister_ssid_decays_after_24h_while_eduroam_stays_medium(self):
        """
        Check 5.1:
        Verify an un-whitelisted 'Law_School_Faculty' AP with 100% IE match
        decays to LOW (< 30 pts) after 24h continuous uptime, while an un-whitelisted
        'eduroam' AP stays MEDIUM (>= 30 pts) until manually whitelisted.
        """
        sister_bssid = "00:14:22:11:22:33"
        sister_ssid = "Law_School_Faculty"

        eduroam_bssid = "00:14:22:44:55:66"
        eduroam_ssid = "eduroam"

        t0 = 10000.0

        # Mock 100% Campus IE Match Track 4B result for Sister SSID (-35 pts applied)
        res_4b_sister = Track4BResult(
            bssid=sister_bssid,
            is_anomaly=False,
            anomaly_types=[],
            score_delta=-35,
            risk_score=0,
            risk_tier="LOW",
            ie_match_status="100%_MATCH",
        )

        # Mock 100% Campus IE Match Track 4B result for Exact Whitelist SSID (0 pts applied)
        res_4b_eduroam = Track4BResult(
            bssid=eduroam_bssid,
            is_anomaly=False,
            anomaly_types=[],
            score_delta=0,
            risk_score=0,
            risk_tier="LOW",
            ie_match_status="100%_MATCH",
        )

        # ---------------------------------------------------------------------
        # Phase 1: Initial Discovery at t = t0 (age = 0s < 24h)
        # ---------------------------------------------------------------------
        # Sister AP initially: New AP Probation (+20 pts, floor 30) - 35 pts discount
        # Score = max(floor 30, points 0) = 30 pts (MEDIUM tier)
        state_sister = BSSIDState(
            bssid=sister_bssid,
            current_ssid=sister_ssid,
            is_whitelisted=0,
            first_seen_ts=t0,
            last_seen_ts=t0,
        )
        assess_sister_t0 = self.engine.compute_risk(
            bssid=sister_bssid,
            ssid=sister_ssid,
            bssid_state=state_sister,
            track_4b_result=res_4b_sister,
            now_ts=t0,
        )
        self.assertEqual(assess_sister_t0.risk_score, 30)
        self.assertEqual(assess_sister_t0.risk_tier, "MEDIUM")
        self.assertTrue(assess_sister_t0.is_sister_ssid)
        self.assertFalse(assess_sister_t0.is_exact_whitelist)

        # Eduroam AP initially: Exact Whitelist Floor (30 pts) + New AP probation (+20 pts)
        # Score = max(floor 30, points 20) = 30 pts (MEDIUM tier)
        state_eduroam = BSSIDState(
            bssid=eduroam_bssid,
            current_ssid=eduroam_ssid,
            is_whitelisted=0,
            first_seen_ts=t0,
            last_seen_ts=t0,
        )
        assess_eduroam_t0 = self.engine.compute_risk(
            bssid=eduroam_bssid,
            ssid=eduroam_ssid,
            bssid_state=state_eduroam,
            track_4b_result=res_4b_eduroam,
            now_ts=t0,
        )
        self.assertEqual(assess_eduroam_t0.risk_score, 30)
        self.assertEqual(assess_eduroam_t0.risk_tier, "MEDIUM")
        self.assertTrue(assess_eduroam_t0.is_exact_whitelist)

        # ---------------------------------------------------------------------
        # Phase 2: Advance clock by 24 hours + 1 second (continuous uptime = 86,401s)
        # ---------------------------------------------------------------------
        t_after_24h = t0 + PROBATION_PERIOD_SEC + 1.0  # 24h + 1s

        # Continuous uptime simulation: last seen regularly (no gap > 3600s)
        state_sister.last_seen_ts = t_after_24h - 10.0
        state_eduroam.last_seen_ts = t_after_24h - 10.0

        # Evaluate Sister AP after 24h continuous uptime:
        # Probation floor has decayed! Score becomes max(0, -35) = 0 pts (LOW / Watchlist)
        assess_sister_24h = self.engine.compute_risk(
            bssid=sister_bssid,
            ssid=sister_ssid,
            bssid_state=state_sister,
            track_4b_result=res_4b_sister,
            now_ts=t_after_24h,
        )
        self.assertLess(assess_sister_24h.risk_score, 30, "Sister SSID must decay to LOW (< 30) after 24h uptime")
        self.assertEqual(assess_sister_24h.risk_score, 0)
        self.assertEqual(assess_sister_24h.risk_tier, "LOW")

        # Evaluate Eduroam AP after 24h continuous uptime:
        # RETAINS MEDIUM FLOOR (>= 30 pts) indefinitely!
        assess_eduroam_24h = self.engine.compute_risk(
            bssid=eduroam_bssid,
            ssid=eduroam_ssid,
            bssid_state=state_eduroam,
            track_4b_result=res_4b_eduroam,
            now_ts=t_after_24h,
        )
        self.assertGreaterEqual(assess_eduroam_24h.risk_score, 30, "Eduroam AP must retain MEDIUM floor after 24h")
        self.assertEqual(assess_eduroam_24h.risk_score, 30)
        self.assertEqual(assess_eduroam_24h.risk_tier, "MEDIUM")

        # ---------------------------------------------------------------------
        # Phase 3: Advance clock to 48 hours (172,800s): Eduroam still MEDIUM
        # ---------------------------------------------------------------------
        t_after_48h = t0 + (2 * PROBATION_PERIOD_SEC)
        state_eduroam.last_seen_ts = t_after_48h - 5.0
        assess_eduroam_48h = self.engine.compute_risk(
            bssid=eduroam_bssid,
            ssid=eduroam_ssid,
            bssid_state=state_eduroam,
            track_4b_result=res_4b_eduroam,
            now_ts=t_after_48h,
        )
        self.assertEqual(assess_eduroam_48h.risk_score, 30)
        self.assertEqual(assess_eduroam_48h.risk_tier, "MEDIUM")

        # ---------------------------------------------------------------------
        # Phase 4: Admin manually whitelists the Eduroam AP
        # ---------------------------------------------------------------------
        state_eduroam.is_whitelisted = 1
        assess_eduroam_whitelisted = self.engine.compute_risk(
            bssid=eduroam_bssid,
            ssid=eduroam_ssid,
            bssid_state=state_eduroam,
            track_4b_result=res_4b_eduroam,
            now_ts=t_after_48h,
            is_whitelisted=True,
        )
        self.assertEqual(assess_eduroam_whitelisted.risk_score, 0)
        self.assertEqual(assess_eduroam_whitelisted.risk_tier, "LOW")

    def test_check_5_1b_offline_gap_over_1h_resets_probation_on_sister_ssid(self):
        """
        Check 5.1b:
        If a Sister AP was online for 25 hours, but then went dark for > 1 hour (3600s),
        its continuous uptime is broken. Probation resets, returning the AP to MEDIUM (30 pts).
        """
        sister_bssid = "00:14:22:77:88:99"
        sister_ssid = "Law_School_Faculty"
        t0 = 20000.0

        state = BSSIDState(
            bssid=sister_bssid,
            current_ssid=sister_ssid,
            is_whitelisted=0,
            first_seen_ts=t0,
            last_seen_ts=t0 + 90000.0,  # 25 hours later
        )

        res_4b = Track4BResult(
            bssid=sister_bssid,
            is_anomaly=False,
            anomaly_types=[],
            score_delta=-35,
            risk_score=0,
            risk_tier="LOW",
            ie_match_status="100%_MATCH",
        )

        # Before offline gap: uptime 25h -> LOW (0 pts)
        assess1 = self.engine.compute_risk(
            bssid=sister_bssid,
            ssid=sister_ssid,
            bssid_state=state,
            track_4b_result=res_4b,
            now_ts=t0 + 90000.0,
        )
        self.assertEqual(assess1.risk_tier, "LOW")
        self.assertEqual(assess1.risk_score, 0)

        # Now simulate an offline gap of 3,700s (> 3600s)
        now_after_gap = state.last_seen_ts + 3700.0
        assess2 = self.engine.compute_risk(
            bssid=sister_bssid,
            ssid=sister_ssid,
            bssid_state=state,
            track_4b_result=res_4b,
            now_ts=now_after_gap,
        )
        # Because gap > 3600s, probation reset occurs: age = 0s -> returns to MEDIUM (30 pts)!
        self.assertEqual(assess2.risk_tier, "MEDIUM")
        self.assertEqual(assess2.risk_score, 30)

    # =========================================================================
    # Master Risk Scoring Table Floors & Points (Ranks 1 to 10)
    # =========================================================================
    def test_rank_1_deauth_storm_floor_high(self):
        """Rank 1: Deauth storm triggers Floor HIGH (75 pts)."""
        bssid = "00:22:33:44:55:01"
        res_4a = Track4AResult(
            bssid=bssid,
            is_anomaly=True,
            anomaly_type="DEAUTH_FLOOD",
            score_delta=75,
            risk_score=75,
            risk_tier="HIGH",
            deauth_count_10s=16,
            deauth_count_60s=16,
        )
        assess = self.engine.compute_risk(
            bssid=bssid,
            ssid="Guest_WiFi",
            track_4a_result=res_4a,
            now_ts=100.0,
        )
        self.assertGreaterEqual(assess.risk_score, FLOOR_DEAUTH_STORM)
        self.assertEqual(assess.risk_tier, "HIGH")

    def test_rank_1b_same_channel_collision_floor_high(self):
        """Rank 1b: Same-channel collision triggers Floor HIGH (75 pts)."""
        bssid = "00:22:33:44:55:02"
        res_4a = Track4AResult(
            bssid=bssid,
            is_anomaly=True,
            anomaly_type="SAME_CHANNEL_COLLISION",
            score_delta=75,
            risk_score=75,
            risk_tier="HIGH",
        )
        assess = self.engine.compute_risk(
            bssid=bssid,
            ssid="Guest_WiFi",
            track_4a_result=res_4a,
            now_ts=100.0,
        )
        self.assertGreaterEqual(assess.risk_score, FLOOR_SAME_CHANNEL_COLLISION)
        self.assertEqual(assess.risk_tier, "HIGH")

    def test_rank_2_multi_channel_clone_floor_high(self):
        """Rank 2: Type A Multi-Channel clone triggers Floor HIGH (70 pts)."""
        bssid = "00:22:33:44:55:03"
        res_4a = Track4AResult(
            bssid=bssid,
            is_anomaly=True,
            anomaly_type="MULTI_CHANNEL_CLONE",
            score_delta=70,
            risk_score=70,
            risk_tier="HIGH",
            active_channels=[1, 6],
        )
        assess = self.engine.compute_risk(
            bssid=bssid,
            ssid="Guest_WiFi",
            track_4a_result=res_4a,
            now_ts=100.0,
        )
        self.assertGreaterEqual(assess.risk_score, FLOOR_MULTI_CHANNEL_CLONE)
        self.assertEqual(assess.risk_tier, "HIGH")

    def test_rank_3_severe_ie_mismatch_points(self):
        """Rank 3: Severe IE Mismatch adds +55 pts."""
        bssid = "00:22:33:44:55:04"
        res_4b = Track4BResult(
            bssid=bssid,
            is_anomaly=True,
            anomaly_types=["SEVERE_MISMATCH"],
            score_delta=55,
            risk_score=55,
            risk_tier="MEDIUM",
            ie_match_status="SEVERE_MISMATCH",
        )
        # AP with uptime > 24h (no probation) + severe mismatch
        state = BSSIDState(
            bssid=bssid,
            current_ssid="CoffeeShop",
            is_whitelisted=0,
            first_seen_ts=1.0,
            last_seen_ts=100000.0,
        )
        assess = self.engine.compute_risk(
            bssid=bssid,
            ssid="CoffeeShop",
            bssid_state=state,
            track_4b_result=res_4b,
            now_ts=100000.0,
        )
        self.assertEqual(assess.risk_score, 55)
        self.assertEqual(assess.risk_tier, "MEDIUM")

    def test_rank_4_channel_match_type_b_spoof(self):
        """Rank 4: Channel Match Type B (DS Tag 3 Spoof) adds +45 pts."""
        bssid = "00:22:33:44:55:05"
        res_4b = Track4BResult(
            bssid=bssid,
            is_anomaly=True,
            anomaly_types=["CHANNEL_MATCH_TYPE_B"],
            score_delta=45,
            risk_score=45,
            risk_tier="MEDIUM",
            ie_match_status="NO_BASELINE",
        )
        state = BSSIDState(
            bssid=bssid,
            current_ssid="Airport_Free",
            is_whitelisted=0,
            first_seen_ts=1.0,
            last_seen_ts=100000.0,
        )
        assess = self.engine.compute_risk(
            bssid=bssid,
            ssid="Airport_Free",
            bssid_state=state,
            track_4b_result=res_4b,
            now_ts=100000.0,
        )
        self.assertEqual(assess.risk_score, 45)
        self.assertEqual(assess.risk_tier, "MEDIUM")

    def test_rank_5_bssid_name_mutation_option_m2(self):
        """Rank 5: BSSID Name Mutation (Option M2) adds +45 pts."""
        bssid = "00:22:33:44:55:06"
        state = BSSIDState(
            bssid=bssid,
            current_ssid="Original_SSID",
            is_whitelisted=0,
            first_seen_ts=1.0,
            last_seen_ts=100000.0,
        )
        assess = self.engine.compute_risk(
            bssid=bssid,
            ssid="Mutated_SSID",
            bssid_state=state,
            is_mutated=True,
            now_ts=100000.0,
        )
        self.assertEqual(assess.risk_score, 45)
        self.assertEqual(assess.risk_tier, "MEDIUM")

    def test_rank_7_strict_beacon_timing_jitter(self):
        """Rank 7: Strict Beacon Timing Jitter > 20ms adds +20 pts."""
        bssid = "00:22:33:44:55:07"
        res_4b = Track4BResult(
            bssid=bssid,
            is_anomaly=True,
            anomaly_types=["JITTER_ANOMALY"],
            score_delta=20,
            risk_score=20,
            risk_tier="LOW",
            sample_error_ms=30.2,
            ie_match_status="NO_BASELINE",
        )
        state = BSSIDState(
            bssid=bssid,
            current_ssid="Random_AP",
            is_whitelisted=0,
            first_seen_ts=1.0,
            last_seen_ts=100000.0,
        )
        assess = self.engine.compute_risk(
            bssid=bssid,
            ssid="Random_AP",
            bssid_state=state,
            track_4b_result=res_4b,
            now_ts=100000.0,
        )
        self.assertEqual(assess.risk_score, 20)
        self.assertEqual(assess.risk_tier, "LOW")

    def test_rank_8_rssi_volatility(self):
        """Rank 8: RSSI Volatility (> 15 dB jump) adds +20 pts."""
        bssid = "00:22:33:44:55:08"
        res_4b = Track4BResult(
            bssid=bssid,
            is_anomaly=True,
            anomaly_types=["RSSI_VOLATILITY"],
            score_delta=20,
            risk_score=20,
            risk_tier="LOW",
            rssi_delta=18.0,
            ie_match_status="NO_BASELINE",
        )
        state = BSSIDState(
            bssid=bssid,
            current_ssid="Random_AP",
            is_whitelisted=0,
            first_seen_ts=1.0,
            last_seen_ts=100000.0,
        )
        assess = self.engine.compute_risk(
            bssid=bssid,
            ssid="Random_AP",
            bssid_state=state,
            track_4b_result=res_4b,
            now_ts=100000.0,
        )
        self.assertEqual(assess.risk_score, 20)
        self.assertEqual(assess.risk_tier, "LOW")

    def test_rank_9_partial_ie_mismatch(self):
        """Rank 9: Partial IE Mismatch adds +15 pts."""
        bssid = "00:22:33:44:55:09"
        res_4b = Track4BResult(
            bssid=bssid,
            is_anomaly=True,
            anomaly_types=["PARTIAL_MISMATCH"],
            score_delta=15,
            risk_score=15,
            risk_tier="LOW",
            ie_match_status="PARTIAL_MISMATCH",
        )
        state = BSSIDState(
            bssid=bssid,
            current_ssid="Random_AP",
            is_whitelisted=0,
            first_seen_ts=1.0,
            last_seen_ts=100000.0,
        )
        assess = self.engine.compute_risk(
            bssid=bssid,
            ssid="Random_AP",
            bssid_state=state,
            track_4b_result=res_4b,
            now_ts=100000.0,
        )
        self.assertEqual(assess.risk_score, 15)
        self.assertEqual(assess.risk_tier, "LOW")

    def test_rank_9_non_standard_channel_alone_and_combined(self):
        """
        Rank 9 specifies: 'Partial info mismatch / Non-Std Ch: +15 pts each'.
        - Non-standard channel alone (e.g. Ch 3) -> +15 pts.
        - Combined non-standard channel AND minor tag order variance -> +30 pts (+15 pts each).
        """
        bssid = "00:22:33:44:55:09b"
        state = BSSIDState(
            bssid=bssid,
            current_ssid="Random_AP",
            is_whitelisted=0,
            first_seen_ts=1.0,
            last_seen_ts=100000.0,
            primary_channel=3,  # Non-standard 2.4 GHz channel
        )

        # 1. Non-standard channel alone: +15 pts
        assess_ch_alone = self.engine.compute_risk(
            bssid=bssid,
            ssid="Random_AP",
            bssid_state=state,
            track_4b_result=None,
            now_ts=100000.0,
        )
        self.assertEqual(assess_ch_alone.risk_score, 15)
        self.assertEqual(assess_ch_alone.applied_points, [("NON_STANDARD_CHANNEL", 15)])

        # 2. Combined: Non-standard channel AND Partial IE mismatch -> +30 pts (+15 pts each)
        res_4b_partial = Track4BResult(
            bssid=bssid,
            is_anomaly=True,
            anomaly_types=["PARTIAL_MISMATCH"],
            score_delta=30,
            risk_score=30,
            risk_tier="MEDIUM",
            ie_match_status="PARTIAL_MISMATCH",
            details={
                "ie_blueprint": {
                    "reasons": [
                        "Non-standard 2.4 GHz channel 3 (outside {1, 6, 11})",
                        "Minor IE tag sequence order variance relative to locked blueprint",
                    ]
                }
            },
        )
        assess_combined = self.engine.compute_risk(
            bssid=bssid,
            ssid="Random_AP",
            bssid_state=state,
            track_4b_result=res_4b_partial,
            now_ts=100000.0,
        )
        self.assertEqual(assess_combined.risk_score, 30)
        applied_point_keys = [k for k, _ in assess_combined.applied_points]
        self.assertIn("NON_STANDARD_CHANNEL", applied_point_keys)
        self.assertIn("PARTIAL_IE_MISMATCH", applied_point_keys)

    def test_multi_anomaly_clamping_to_100(self):
        """Multiple stacked severe anomalies accumulate and clamp cleanly at exactly 100."""
        bssid = "00:22:33:44:55:10"
        res_4a = Track4AResult(
            bssid=bssid,
            is_anomaly=True,
            anomaly_type="DEAUTH_FLOOD",
            score_delta=75,
            risk_score=75,
            risk_tier="HIGH",
            deauth_count_10s=20,
        )
        res_4b = Track4BResult(
            bssid=bssid,
            is_anomaly=True,
            anomaly_types=["SEVERE_MISMATCH", "CHANNEL_MATCH_TYPE_B", "JITTER_ANOMALY"],
            score_delta=120,
            risk_score=100,
            risk_tier="HIGH",
            ie_match_status="SEVERE_MISMATCH",
        )
        assess = self.engine.compute_risk(
            bssid=bssid,
            ssid="Free_WiFi",
            track_4a_result=res_4a,
            track_4b_result=res_4b,
            is_mutated=True,
            now_ts=100.0,
        )
        self.assertEqual(assess.risk_score, 100)
        self.assertEqual(assess.risk_tier, "HIGH")


class TestStep5WiFiIDSPipeline(unittest.TestCase):

    def setUp(self):
        self.temp_db = tempfile.NamedTemporaryFile(delete=False, suffix=".db")
        self.temp_db.close()
        self.db_path = self.temp_db.name
        self.pipeline = WiFiIDSPipeline(
            db_path=self.db_path,
            campus_whitelist=DEFAULT_CAMPUS_WHITELIST,
            auto_train_xgb=True,
        )

    def tearDown(self):
        try:
            self.pipeline.close()
        except Exception:
            pass
        if os.path.exists(self.db_path):
            try:
                os.remove(self.db_path)
            except Exception:
                pass

    # =========================================================================
    # Pre-Stage-0 Management Demux (0x0C / 0x0A)
    # =========================================================================
    def test_pre_stage_0_deauth_demux_flood(self):
        """
        Pre-Stage-0 Ingress Router: Subtypes 0x0C / 0x0A route directly by BSSID
        to Track 4A sliding deauth counter. Flood (>= 15 in 10s) triggers Floor HIGH (75 pts).
        """
        target_bssid = "00:14:22:de:ad:01"
        now_ts = 1000.0

        # Send 14 deauth frames -> below threshold (14 < 15)
        for i in range(14):
            res = self.pipeline.process_frame(
                {"subtype": 0x0C, "addr3": target_bssid},
                now_ts=now_ts + (i * 0.1),
            )
            self.assertEqual(res.stage_reached, "PRE_STAGE_0_DEMUX")
            self.assertEqual(res.frame_type, "DEAUTH")
            self.assertFalse(res.is_anomaly)
            self.assertEqual(res.risk_score, 0, f"Deauth frame {i+1} must not accumulate risk before flood threshold")
            self.assertEqual(res.risk_tier, "LOW")

        # 15th frame hits the threshold -> escalates to HIGH (75 pts)!
        res_flood = self.pipeline.process_frame(
            {"subtype": 0x0C, "addr3": target_bssid},
            now_ts=now_ts + 1.5,
        )
        self.assertEqual(res_flood.stage_reached, "PRE_STAGE_0_DEMUX")
        self.assertTrue(res_flood.is_anomaly)
        self.assertGreaterEqual(res_flood.risk_score, 75)
        self.assertEqual(res_flood.risk_tier, "HIGH")

    def test_pre_stage_0_single_deauth_no_false_probation_alert(self):
        """
        Single deauth frame from a brand new BSSID must NOT trigger New AP probation
        or MEDIUM tier alert. Deauth frames carry no SSID.
        """
        unknown_bssid = "00:77:88:99:aa:bb"
        res = self.pipeline.process_frame(
            {"subtype": 0x0C, "addr3": unknown_bssid},
            now_ts=2000.0,
        )
        self.assertEqual(res.stage_reached, "PRE_STAGE_0_DEMUX")
        self.assertEqual(res.risk_score, 0)
        self.assertEqual(res.risk_tier, "LOW")
        self.assertFalse(res.is_anomaly)
        self.assertFalse(res.flushed)

    # =========================================================================
    # Stage 0: Whitelisted AP Integrity Check & Collision/Clone Verification
    # =========================================================================
    def test_stage_0_whitelisted_ap_bypasses_ai_and_stays_low(self):
        """
        Stage 0: An authorized whitelisted BSSID broadcasting its expected SSID
        skips AI screening (0 ms queue wait) and exits as LOW / BENIGN (0 pts).
        """
        wl_bssid = "00:14:22:aa:bb:01"
        wl_ssid = "University Campus 5G"

        # Whitelist the BSSID
        self.pipeline.whitelist_bssid(wl_bssid)

        beacon_frame = {
            "subtype": 0x08,
            "bssid": wl_bssid,
            "ssid": wl_ssid,
            "tag3_channel": 6,
            "seq": 100,
            "tsf": 1000000,
            "akm_suites": ["802.1X"],
            "pairwise_ciphers": ["CCMP"],
            "mimo_streams": 4,
            "has_mdid": True,
            "has_vendor_221": True,
        }

        res = self.pipeline.process_frame(beacon_frame, now_ts=500.0)
        self.assertEqual(res.stage_reached, "STAGE_0_WHITELISTED")
        self.assertFalse(res.is_anomaly)
        self.assertEqual(res.risk_score, 0)
        self.assertEqual(res.risk_tier, "LOW")

    def test_stage_0_whitelisted_ap_clone_attack_escalates_to_high(self):
        """
        Point 1 Architectural Fix: An attacker cloning an authorized whitelisted BSSID
        on a different Tag 3 channel (Ch 6 and Ch 1 active simultaneously) is caught by
        Track 4A integrity check and escalates to Floor HIGH (70 pts).
        """
        wl_bssid = "00:14:22:aa:bb:02"
        wl_ssid = "University Campus 5G"
        self.pipeline.whitelist_bssid(wl_bssid)

        t = 600.0
        # Legitimate AP on Channel 6
        frame_ch6 = {
            "bssid": wl_bssid,
            "ssid": wl_ssid,
            "tag3_channel": 6,
            "seq": 10,
            "tsf": 1000,
        }
        res1 = self.pipeline.process_frame(frame_ch6, now_ts=t)
        self.assertEqual(res1.risk_score, 0)

        # Attacker transmits on Channel 1 within 15 seconds!
        frame_ch1 = {
            "bssid": wl_bssid,
            "ssid": wl_ssid,
            "tag3_channel": 1,
            "seq": 15,
            "tsf": 100000,
        }
        res2 = self.pipeline.process_frame(frame_ch1, now_ts=t + 2.0)
        self.assertEqual(res2.stage_reached, "STAGE_0_WHITELISTED")
        self.assertTrue(res2.is_anomaly)
        self.assertGreaterEqual(res2.risk_score, 70)
        self.assertEqual(res2.risk_tier, "HIGH")

    # =========================================================================
    # Stage 0: BSSID Name Mutation Check (Option M2)
    # =========================================================================
    def test_stage_0_bssid_name_mutation_option_m2(self):
        """
        Option M2: A known BSSID broadcasting a new SSID flags is_mutated=1 (+45 pts)
        and forces full parallel evaluation.
        """
        bssid = "00:14:22:cc:dd:01"
        t = 700.0

        # Initial broadcast: "Campus_Library"
        frame1 = {"bssid": bssid, "ssid": "Campus_Library", "tag3_channel": 6, "seq": 1, "tsf": 1000}
        res1 = self.pipeline.process_frame(frame1, now_ts=t)

        # Subsequent broadcast: "Free_Campus_Lure"
        frame2 = {"bssid": bssid, "ssid": "Free_Campus_Lure", "tag3_channel": 6, "seq": 2, "tsf": 2000}
        res2 = self.pipeline.process_frame(frame2, now_ts=t + 5.0)

        self.assertTrue(res2.stage25_result.is_mutated)
        self.assertGreaterEqual(res2.risk_score, 45)

    # =========================================================================
    # Stage 2.5: Dynamic PSK Gatekeeper Test
    # =========================================================================
    def test_stage_2_5_dynamic_psk_gate_suppresses_benign_psk(self):
        """
        Dynamic Stage 2.5 Gate:
        - When an AP broadcasts an SSID with PSK encryption, eff_bge = 0.5 * bge_cos.
        - If eff_bge < 0.60 and xgb_prob < 0.50: routes to STAGE_2_5_BENIGN (Brief Logging).
        """
        bssid = "00:14:22:ee:ff:01"
        # "My_Home_WiFi" has low similarity to campus whitelist
        frame = {
            "bssid": bssid,
            "ssid": "My_Home_WiFi",
            "tag3_channel": 1,
            "seq": 10,
            "tsf": 1000,
            "akm_suites": ["PSK"],
            "encryption_type": "PSK",
        }
        res = self.pipeline.process_frame(frame, now_ts=800.0)
        self.assertEqual(res.stage_reached, "STAGE_2_5_BENIGN")
        self.assertFalse(res.is_suspicious_name)
        self.assertEqual(res.risk_tier, "LOW")

    # =========================================================================
    # Coalesced Instant Alert Bypass vs Routine Batch Flush
    # =========================================================================
    def test_instant_alert_bypass_flushes_immediately_for_high_alert(self):
        """
        Coalesced Instant Alert Bypass:
        An escalation from LOW to HIGH triggers immediate SQLite WAL commit (< 10ms wait),
        while routine LOW-risk frames buffer up to 3.0s.
        """
        initial_commits = self.pipeline.db_manager.commit_count

        # 1. Routine LOW-risk beacon: buffers in RAM without immediate disk commit
        low_bssid = "00:14:22:11:00:01"
        frame_low = {
            "bssid": low_bssid,
            "ssid": "Home_Router_Safe",
            "tag3_channel": 6,
            "seq": 1,
            "tsf": 1000,
            "akm_suites": ["PSK"],
            "encryption_type": "PSK",
        }
        res_low = self.pipeline.process_frame(frame_low, now_ts=1000.0)
        self.assertEqual(res_low.risk_tier, "LOW")
        # Commit count should NOT have increased immediately
        self.assertEqual(self.pipeline.db_manager.commit_count, initial_commits)

        # 2. Severe Threat: Multi-Channel Clone on an un-whitelisted AP -> escalates to HIGH!
        # First ensure elapsed >= 0.25s cooldown
        high_bssid = "00:14:22:99:99:99"
        # Channel 6
        self.pipeline.process_frame(
            {"bssid": high_bssid, "ssid": "University Campus 5G", "tag3_channel": 6, "seq": 10, "tsf": 1000},
            now_ts=1001.0,
        )
        # Channel 1 -> Multi-Ch clone triggers HIGH!
        res_high = self.pipeline.process_frame(
            {"bssid": high_bssid, "ssid": "University Campus 5G", "tag3_channel": 1, "seq": 11, "tsf": 2000},
            now_ts=1001.5,
        )
        self.assertEqual(res_high.risk_tier, "HIGH")
        self.assertTrue(res_high.flushed, "Instant Alert Bypass must commit immediately on HIGH escalation")
        self.assertGreater(self.pipeline.db_manager.commit_count, initial_commits)

    # =========================================================================
    # Check 5.1 End-to-End Through Pipeline
    # =========================================================================
    def test_check_5_1_end_to_end_pipeline(self):
        """
        Full end-to-end integration test of Check 5.1 through WiFiIDSPipeline:
        1. Lock campus baseline profile via learn_baseline.
        2. Feed beacons from 'Law_School_Faculty' and 'eduroam' with 100% IE match.
        3. Verify both start at MEDIUM (30 pts).
        4. Advance time by 24h continuous uptime.
        5. Verify 'Law_School_Faculty' decays to LOW (0 pts), while 'eduroam' stays MEDIUM (30 pts).
        6. Manually whitelist 'eduroam' via pipeline.whitelist_bssid; verify it drops to LOW.
        """
        # 1. Lock enterprise profile
        self.pipeline.learn_baseline([
            {
                "ssid": "University Campus 5G",
                "akm_suites": ["802.1X"],
                "pairwise_ciphers": ["CCMP"],
                "has_mdid": True,
                "has_vendor_221": True,
                "mimo_streams": 4,
            }
        ])

        sister_bssid = "00:50:56:11:22:33"
        eduroam_bssid = "00:50:56:44:55:66"
        t0 = 50000.0

        perfect_sister_frame = {
            "bssid": sister_bssid,
            "ssid": "Law_School_Faculty",
            "tag3_channel": 6,
            "radio_channel": 6,
            "seq": 10,
            "tsf": 1000000,
            "rssi": -65,
            "akm_suites": ["802.1X"],
            "pairwise_ciphers": ["CCMP"],
            "has_mdid": True,
            "has_vendor_221": True,
            "mimo_streams": 4,
        }

        perfect_eduroam_frame = {
            "bssid": eduroam_bssid,
            "ssid": "eduroam",
            "tag3_channel": 6,
            "radio_channel": 6,
            "seq": 10,
            "tsf": 1000000,
            "rssi": -65,
            "akm_suites": ["802.1X"],
            "pairwise_ciphers": ["CCMP"],
            "has_mdid": True,
            "has_vendor_221": True,
            "mimo_streams": 4,
        }

        # Step A: Initial frame processing at t = t0 (age = 0s < 24h)
        res_sister_t0 = self.pipeline.process_frame(perfect_sister_frame, now_ts=t0)
        self.assertEqual(res_sister_t0.risk_score, 30)
        self.assertEqual(res_sister_t0.risk_tier, "MEDIUM")

        res_eduroam_t0 = self.pipeline.process_frame(perfect_eduroam_frame, now_ts=t0 + 0.5)
        self.assertEqual(res_eduroam_t0.risk_score, 30)
        self.assertEqual(res_eduroam_t0.risk_tier, "MEDIUM")

        # Step B: Advance clock by 24h + 1s (86,401s continuous uptime)
        t_24h = t0 + PROBATION_PERIOD_SEC + 1.0

        # Update last_seen continuously
        state_s = self.pipeline.db_manager.get_bssid(sister_bssid)
        state_e = self.pipeline.db_manager.get_bssid(eduroam_bssid)
        state_s.last_seen_ts = t_24h - 5.0
        state_e.last_seen_ts = t_24h - 5.0

        # Process frame for Sister AP at 24h: must decay to LOW!
        perfect_sister_frame["seq"] = 20
        perfect_sister_frame["tsf"] = 2000000
        res_sister_24h = self.pipeline.process_frame(perfect_sister_frame, now_ts=t_24h)
        self.assertEqual(res_sister_24h.risk_score, 0, "Sister SSID must decay to 0 pts after 24h uptime")
        self.assertEqual(res_sister_24h.risk_tier, "LOW")

        # Process frame for Eduroam AP at 24h: must STAY MEDIUM!
        perfect_eduroam_frame["seq"] = 20
        perfect_eduroam_frame["tsf"] = 2000000
        res_eduroam_24h = self.pipeline.process_frame(perfect_eduroam_frame, now_ts=t_24h + 0.5)
        self.assertGreaterEqual(res_eduroam_24h.risk_score, 30, "Eduroam AP must stay MEDIUM after 24h")
        self.assertEqual(res_eduroam_24h.risk_tier, "MEDIUM")

        # Step C: Admin manually marks Eduroam as whitelisted
        self.pipeline.whitelist_bssid(eduroam_bssid)
        perfect_eduroam_frame["seq"] = 30
        perfect_eduroam_frame["tsf"] = 3000000
        res_eduroam_wl = self.pipeline.process_frame(perfect_eduroam_frame, now_ts=t_24h + 2.0)
        self.assertEqual(res_eduroam_wl.risk_score, 0)
        self.assertEqual(res_eduroam_wl.risk_tier, "LOW")

    # =========================================================================
    # Adversarial Pipeline Tests
    # =========================================================================
    def test_adversarial_psk_to_open_cache_poisoning_mitigation(self):
        """
        Adversarial Test:
        Attacker tries cache poisoning by broadcasting 'Free_University_Campus' first as WPA2-PSK.
        Stage 2.5 calculates eff_bge = 0.5 * bge_cos.
        Attacker then flips to OPEN on the same SSID.
        Stage 2.5 dynamically evaluates the OPEN beacon using eff_bge = 1.0 * bge_cos,
        catching the evil twin without being blinded by the prior PSK frame.
        """
        bssid = "00:11:22:33:44:99"
        lure_ssid = "Free_University_Campus"
        t0 = 60000.0

        # 1. PSK beacon
        psk_frame = {
            "bssid": bssid,
            "ssid": lure_ssid,
            "tag3_channel": 6,
            "seq": 1,
            "tsf": 1000,
            "akm_suites": ["PSK"],
            "encryption_type": "PSK",
        }
        res_psk = self.pipeline.process_frame(psk_frame, now_ts=t0)
        # PSK multiplier halves semantic similarity
        self.assertLessEqual(res_psk.details.get("eff_bge", 1.0), 0.50)

        # 2. Open beacon on the same SSID
        open_frame = {
            "bssid": bssid,
            "ssid": lure_ssid,
            "tag3_channel": 6,
            "seq": 2,
            "tsf": 2000,
            "akm_suites": [],
            "encryption_type": "OPEN",
        }
        res_open = self.pipeline.process_frame(open_frame, now_ts=t0 + 1.0)
        # Dynamic gate catches the open lure!
        self.assertTrue(res_open.is_suspicious_name)
        self.assertEqual(res_open.stage_reached, "STAGE_5_SCORING")
        self.assertGreaterEqual(res_open.risk_score, SCORE_THRESHOLD_MEDIUM)

    def test_adversarial_burst_flush_coalescing(self):
        """
        Adversarial Test:
        Inject 20 distinct HIGH-threat BSSIDs within 0.1s.
        Verify Coalesced Instant Alert Bypass caps commits (does not commit 20 times in 0.1s),
        and that urgent_flush_pending is set for subsequent frames until cooldown passes.
        """
        t0 = 70000.0
        start_commits = self.pipeline.db_manager.commit_count

        for i in range(20):
            fake_bssid = f"00:99:88:77:66:{i:02x}"
            # Multi-channel clone on new BSSID
            self.pipeline.process_frame(
                {"bssid": fake_bssid, "ssid": "University Campus 5G", "tag3_channel": 6, "seq": 1, "tsf": 1000},
                now_ts=t0 + (i * 0.005),
            )
            res = self.pipeline.process_frame(
                {"bssid": fake_bssid, "ssid": "University Campus 5G", "tag3_channel": 1, "seq": 2, "tsf": 2000},
                now_ts=t0 + (i * 0.005) + 0.001,
            )
            self.assertEqual(res.risk_tier, "HIGH")

        # In 0.1s, at most 1 or 2 commits can occur due to 250ms cooldown!
        elapsed_commits = self.pipeline.db_manager.commit_count - start_commits
        self.assertLessEqual(elapsed_commits, 2, f"Expected <= 2 commits in 0.1s flood, got {elapsed_commits}")
        self.assertTrue(self.pipeline.db_manager.urgent_flush_pending)

        # After cooldown passes (> 0.25s), next frame triggers the coalesced commit!
        t_after = t0 + 0.30
        res_after = self.pipeline.process_frame(
            {"bssid": "00:99:88:77:66:ff", "ssid": "University Campus 5G", "tag3_channel": 6, "seq": 10, "tsf": 5000},
            now_ts=t_after,
        )
        self.assertFalse(self.pipeline.db_manager.urgent_flush_pending)

    def test_external_db_whitelist_hot_reload_via_pragma_data_version(self):
        """
        Adversarial Test:
        An external admin updates SQLite directly (e.g. Dashboard UI):
        UPDATE bssid_devices SET is_whitelisted = 1 WHERE bssid = ...
        On the next beacon frame, pipeline detects PRAGMA data_version change,
        hot-reloads the whitelist into RAM, and clears the MEDIUM floor.
        """
        bssid = "00:50:56:88:99:00"
        ssid = "eduroam"
        t0 = 80000.0

        # Frame 1: Un-whitelisted eduroam AP -> MEDIUM floor
        res1 = self.pipeline.process_frame(
            {"bssid": bssid, "ssid": ssid, "tag3_channel": 6, "seq": 1, "tsf": 1000},
            now_ts=t0,
        )
        self.assertEqual(res1.risk_tier, "MEDIUM")

        # External SQLite write via separate connection simulating web dashboard
        import sqlite3
        ext_conn = sqlite3.connect(self.db_path)
        with ext_conn:
            ext_conn.execute("UPDATE bssid_devices SET is_whitelisted = 1 WHERE bssid = ?", (bssid,))
        ext_conn.close()

        # Frame 2: Process next frame -> triggers data_version sync, hot-reloading whitelist
        res2 = self.pipeline.process_frame(
            {"bssid": bssid, "ssid": ssid, "tag3_channel": 6, "seq": 2, "tsf": 2000},
            now_ts=t0 + 1.0,
        )
        self.assertEqual(res2.stage_reached, "STAGE_0_WHITELISTED")
        self.assertEqual(res2.risk_tier, "LOW")
        self.assertEqual(res2.risk_score, 0)

    def test_pipeline_escalation_triggers_instant_flush_and_marks_escalation(self):
        """
        Verify that an incoming beacon causing an escalation from LOW to MEDIUM or HIGH
        correctly marks assessment.prev_risk_tier == 'LOW', assessment.is_escalation == True,
        and triggers instant flush through WiFiIDSPipeline without Track 4B corrupting prev_tier.
        """
        # Baseline profile with 802.1X
        self.pipeline.learn_baseline([
            {"akm_suites": ["802.1X"], "pairwise_ciphers": ["CCMP"], "has_mdid": True, "has_vendor_221": True, "mimo_streams": 4}
        ])

        target_bssid = "00:50:56:fa:ce:01"
        t0 = 90000.0

        # Frame with Severe IE Mismatch (Open on enterprise baseline)
        frame = {
            "bssid": target_bssid,
            "ssid": "University Campus 5G",
            "tag3_channel": 6,
            "seq": 1,
            "tsf": 1000,
            "akm_suites": [],
            "encryption_type": "OPEN",
            "has_mdid": False,
            "has_vendor_221": False,
        }

        res = self.pipeline.process_frame(frame, now_ts=t0)
        self.assertEqual(res.risk_tier, "HIGH")  # Severe mismatch (+55) + probation (+20, floor 30) = 75 (HIGH)
        self.assertIsNotNone(res.risk_assessment)
        self.assertEqual(res.risk_assessment.prev_risk_tier, "LOW")
        self.assertTrue(res.risk_assessment.is_escalation)
        self.assertTrue(res.flushed)
        self.assertTrue(res.risk_assessment.triggered_instant_flush)

    def test_adversarial_malformed_ssid_with_null_bytes_and_raw_bytes(self):
        """
        Adversarial Test:
        Attacker transmits malformed frames with raw bytes, embedded null bytes (\x00),
        and invalid UTF-8 octets in the SSID.
        Verify pipeline safely decodes, sanitizes, and evaluates without exceptions.
        """
        bssid = "00:50:56:00:ff:11"
        t0 = 95000.0

        # Frame with bytes and embedded nulls
        frame_nulls = {
            "bssid": bssid,
            "ssid": b"University\x00_Campus\x00_5G",
            "tag3_channel": 6,
            "seq": 1,
            "tsf": 1000,
            "akm_suites": ["802.1X"],
            "encryption_type": "OPEN",
        }
        res1 = self.pipeline.process_frame(frame_nulls, now_ts=t0)
        self.assertNotIn("\x00", res1.ssid)
        self.assertTrue(res1.stage_reached in ("STAGE_5_SCORING", "STAGE_2_5_BENIGN"))

        # Frame with invalid UTF-8 octets
        frame_invalid_utf8 = {
            "bssid": "00:50:56:00:ff:22",
            "ssid": b"\xff\xfe\x80Malformed",
            "tag3_channel": 6,
            "seq": 1,
            "tsf": 1000,
        }
        res2 = self.pipeline.process_frame(frame_invalid_utf8, now_ts=t0 + 1.0)
        self.assertIsInstance(res2.ssid, str)


if __name__ == "__main__":
    unittest.main()

