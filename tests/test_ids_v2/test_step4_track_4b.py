"""
Step 4 Unit Test Harness: Track 4B Deep Beacon IE & Strict Jitter Analyzer (v2.1.2)
Verifies:
- Check 4.1: Strict un-diluted timing jitter with 1 dropped beacon (seq_diff=2, delta_t=235ms, expected=204.8ms -> error 30.2ms > 20ms, +20 pts).
- Check 4.1b: Dilution trap test (proving error is NOT divided by k=2).
- Check 4.1c: Normal jitter within tolerance (< 20ms) does NOT trigger anomaly.
- Check 4.1d: Jitter evaluation bounds (60ms <= dt <= 245ms, 1 <= seq_diff <= 6).
- Check 4.2: --learn-baseline locks campus_ie_profile in SQLite WAL with ZERO auto-whitelisting of bssid_devices.
- Check 4.3: Channel Match Type B (DS Tag 3 Spoof Check: 2.4GHz >= 2 ch off, 5GHz any mismatch triggers +45 pts).
- Check 4.3b: 2.4GHz bleed-over tolerance (1 channel difference does NOT trigger spoof).
- Check 4.4: Severe IE Mismatch (+55 pts: Open vs 802.1X, WPS on enterprise, 1x1 PHY downgrade, missing MDID/Tag 221).
- Check 4.5: Partial IE Mismatch (+15 pts: Non-standard 2.4GHz channel outside {1, 6, 11}, tag order variance).
- Check 4.6: 100% Campus IE Blueprint Match (-35 pts applies ONLY to Sister SSIDs, NEVER overriding un-whitelisted exact whitelist SSIDs).
- Check 4.7: RSSI Volatility (+20 pts on Delta_RSSI > 15 dB) & Static RSSI Gate (>= -70 dBm: FULL_FRAME, 0 pts).
- Check 4.8: Multi-anomaly cumulative risk scoring.
- Check 4.9: Mock and Scapy frame element extraction compatibility.
"""

import math
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
from detector.ids_v2.track_4b_beacon import (
    Track4BBeaconAnalyzer,
    Track4BResult,
    extract_beacon_features,
    SCORE_SEVERE_IE_MISMATCH,
    SCORE_CHANNEL_MATCH_TYPE_B,
    SCORE_JITTER_ANOMALY,
    SCORE_RSSI_VOLATILITY,
    SCORE_PARTIAL_IE_MISMATCH,
    SCORE_CAMPUS_BLUEPRINT_MATCH,
)


class TestStep4Track4B(unittest.TestCase):

    def setUp(self):
        self.temp_db = tempfile.NamedTemporaryFile(delete=False, suffix=".db")
        self.temp_db.close()
        self.db_path = self.temp_db.name
        self.db = BatchDatabaseManager(self.db_path)
        self.analyzer = Track4BBeaconAnalyzer(
            db_manager=self.db,
            campus_whitelist=DEFAULT_CAMPUS_WHITELIST,
            profile_name="campus_default",
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
    # Check 4.1: Strict Un-Diluted Timing Jitter (Point 7 Refinement)
    # =========================================================================
    def test_check_4_1_strict_undiluted_jitter_dropped_beacon(self):
        """
        Check 4.1: Feed beacons with 1 dropped frame (seq_diff = 2, delta_t = 235 ms, expected = 204.8 ms).
        Verify un-diluted error is exactly 30.2 ms (> 20.0 ms threshold) and triggers +20 pts.
        """
        bssid = "00:14:22:01:02:03"
        # Beacon 1: seq=1, tsf=1000000 at t=1.000
        frame1 = {"seq": 1, "tsf": 1000000, "tag3_channel": 6}
        res1 = self.analyzer.analyze_beacon(
            bssid=bssid, frame=frame1, radio_channel=6, rssi=-60, now_ts=1.000
        )
        self.assertFalse(res1.is_anomaly)
        self.assertNotIn("JITTER_ANOMALY", res1.anomaly_types)

        # Beacon 2: seq=3 (seq_diff = 2 -> 1 dropped frame).
        # Arrival delta_t = 235 ms (now_ts = 1.235).
        # TSF advances by 235,000 us (235 ms): 1,000,000 -> 1,235,000
        frame2 = {"seq": 3, "tsf": 1235000, "tag3_channel": 6}
        res2 = self.analyzer.analyze_beacon(
            bssid=bssid, frame=frame2, radio_channel=6, rssi=-60, now_ts=1.235
        )

        # Expected calculation:
        # k = 2 (since delta_t_ms = 235.0 >= 153.6)
        # expected_ms = 2 * 102.4 = 204.8 ms
        # arrival_err_ms = abs(235.0 - 204.8) = 30.2 ms
        self.assertAlmostEqual(res2.sample_error_ms, 30.2, places=1)
        self.assertTrue(res2.is_anomaly)
        self.assertIn("JITTER_ANOMALY", res2.anomaly_types)
        self.assertGreaterEqual(res2.score_delta, SCORE_JITTER_ANOMALY)

    def test_check_4_1b_dilution_trap_validation(self):
        """
        Check 4.1b: Dilution trap test.
        If an incorrect implementation divided error by k=2: 30.2 / 2 = 15.1 ms (< 20 ms),
        it would fail to trigger an alert.
        Verify that evaluate_jitter returns sample_error_ms > 20.0 and is_anomaly == True.
        """
        bssid = "00:14:22:aa:bb:cc"
        self.analyzer.evaluate_jitter(bssid, curr_seq=10, curr_tsf=100000, now_ts=10.000)

        # 1 dropped frame: seq_diff=2, delta_t=235ms
        is_anomaly, err_ms, _ = self.analyzer.evaluate_jitter(
            bssid, curr_seq=12, curr_tsf=335000, now_ts=10.235
        )
        self.assertTrue(is_anomaly, "Un-diluted 30.2ms error must trigger anomaly without division by k=2")
        self.assertAlmostEqual(err_ms, 30.2, places=1)
        self.assertGreater(err_ms, 20.0)

    def test_check_4_1c_normal_jitter_within_tolerance(self):
        """
        Check 4.1c: Legitimate hardware beacon with low jitter (< 4 ms) must NOT trigger anomaly.
        """
        bssid = "00:14:22:33:44:55"
        self.analyzer.evaluate_jitter(bssid, curr_seq=1, curr_tsf=100000, now_ts=1.000)

        # 104 ms elapsed (expected 102.4 ms -> err = 1.6 ms)
        is_anomaly, err_ms, _ = self.analyzer.evaluate_jitter(
            bssid, curr_seq=2, curr_tsf=204000, now_ts=1.104
        )
        self.assertFalse(is_anomaly)
        self.assertAlmostEqual(err_ms, 1.6, places=1)

    def test_check_4_1d_jitter_evaluation_bounds(self):
        """
        Check 4.1d: Jitter is evaluated only when 1 <= seq_diff <= 6 and 60.0 <= delta_t <= 245.0.
        Large gaps (> 245 ms or > 6 frames) must NOT evaluate jitter.
        """
        bssid = "00:14:22:55:66:77"
        self.analyzer.evaluate_jitter(bssid, curr_seq=1, curr_tsf=100000, now_ts=1.000)

        # 400 ms gap (missed > 2 frames)
        is_anomaly, err_ms, _ = self.analyzer.evaluate_jitter(
            bssid, curr_seq=5, curr_tsf=500000, now_ts=1.400
        )
        self.assertFalse(is_anomaly, "Large time gap (> 245ms) must skip jitter check")
        self.assertEqual(err_ms, 0.0)

    # =========================================================================
    # Check 4.2: Campus IE Blueprint Learning & Zero Auto-Whitelisting (Point 5)
    # =========================================================================
    def test_check_4_2_learn_baseline_zero_auto_whitelisting(self):
        """
        Check 4.2: Verify --learn-baseline locks campus_ie_profile in SQLite WAL
        and strictly leaves bssid_devices.is_whitelisted = 0 for all APs.
        Zero auto-whitelisting!
        """
        campus_bssid = "00:14:22:88:99:aa"

        # 1. Simulate an un-whitelisted campus AP in the database
        un_wl_state = BSSIDState(
            bssid=campus_bssid,
            current_ssid="University Campus 5G",
            is_whitelisted=0,
            primary_channel=6,
            first_seen_ts=1000.0,
            last_seen_ts=1000.0,
        )
        self.db.put_bssid(un_wl_state)
        self.assertEqual(self.db.get_bssid(campus_bssid).is_whitelisted, 0)

        # 2. Feed legitimate campus AP beacon frames to learn_baseline
        sample_campus_frames = [
            {
                "ssid": "University Campus 5G",
                "tag3_channel": 6,
                "akm_suites": ["802.1X"],
                "pairwise_ciphers": ["CCMP"],
                "has_mdid": True,
                "has_vendor_221": True,
                "mimo_streams": 4,
                "has_wps": False,
            },
            {
                "ssid": "eduroam",
                "tag3_channel": 1,
                "akm_suites": ["802.1X"],
                "pairwise_ciphers": ["CCMP"],
                "has_mdid": True,
                "has_vendor_221": True,
                "mimo_streams": 4,
                "has_wps": False,
            },
        ]

        locked_profile = self.analyzer.learn_baseline(sample_campus_frames, profile_name="campus_default")

        # 3. Verify campus_ie_profile is locked in SQLite WAL
        self.assertIsNotNone(locked_profile)
        self.assertEqual(locked_profile.profile_name, "campus_default")
        self.assertIn("802.1X", locked_profile.akm_suites)
        self.assertIn("CCMP", locked_profile.pairwise_ciphers)
        self.assertEqual(locked_profile.has_mdid, 1)
        self.assertEqual(locked_profile.has_vendor_221, 1)
        self.assertEqual(locked_profile.mimo_streams, 4)

        # 4. CRITICAL HARD RULE (Point 5):
        # Verify bssid_devices.is_whitelisted is STILL 0 in RAM and SQLite!
        fetched_state = self.db.get_bssid(campus_bssid)
        self.assertEqual(
            fetched_state.is_whitelisted,
            0,
            "CRITICAL: learn_baseline MUST NOT auto-whitelist any BSSID. is_whitelisted must remain 0!",
        )

        # Verify SQLite table directly after flush
        self.db.flush_to_sqlite(force=True)
        cursor = self.db.conn.cursor()
        cursor.execute("SELECT is_whitelisted FROM bssid_devices WHERE bssid = ?", (campus_bssid,))
        row = cursor.fetchone()
        self.assertIsNotNone(row)
        self.assertEqual(row[0], 0, "SQLite bssid_devices.is_whitelisted must be 0")

    # =========================================================================
    # Check 4.3: Channel Match Type B (DS Tag 3 Spoof Check)
    # =========================================================================
    def test_check_4_3_channel_match_type_b_spoof_24ghz(self):
        """
        Check 4.3: Declared Tag 3 channel != captured radio channel.
        In 2.4 GHz, triggers if abs(radio_ch - tag3_ch) >= 2 (+45 pts).
        """
        bssid = "00:11:22:33:44:01"
        # Declared Tag 3 = 1, but receiver captured on Radio Channel 6 (diff = 5 >= 2)
        frame = {"tag3_channel": 1, "seq": 10, "tsf": 1000}
        res = self.analyzer.analyze_beacon(
            bssid=bssid, frame=frame, radio_channel=6, rssi=-65, now_ts=100.0
        )
        self.assertTrue(res.is_anomaly)
        self.assertIn("CHANNEL_MATCH_TYPE_B", res.anomaly_types)
        self.assertGreaterEqual(res.score_delta, SCORE_CHANNEL_MATCH_TYPE_B)

    def test_check_4_3b_channel_match_type_b_bleed_over_tolerance_24ghz(self):
        """
        Check 4.3b: In 2.4 GHz, adjacent channel difference of 1 (bleed-over) is tolerated (0 pts).
        """
        bssid = "00:11:22:33:44:02"
        # Declared Tag 3 = 1, receiver on Radio Channel 2 (bleed-over of 1 ch)
        frame = {"tag3_channel": 1, "seq": 10, "tsf": 1000}
        res = self.analyzer.analyze_beacon(
            bssid=bssid, frame=frame, radio_channel=2, rssi=-65, now_ts=100.0
        )
        self.assertNotIn("CHANNEL_MATCH_TYPE_B", res.anomaly_types)

    def test_check_4_3c_channel_match_type_b_strict_in_5ghz(self):
        """
        Check 4.3c: In 5 GHz, ANY channel mismatch triggers Channel Match Type B (+45 pts).
        """
        bssid = "00:11:22:33:44:03"
        # Declared Tag 3 = 36, receiver on Radio Channel 40 (5 GHz band)
        frame = {"tag3_channel": 36, "seq": 10, "tsf": 1000}
        res = self.analyzer.analyze_beacon(
            bssid=bssid, frame=frame, radio_channel=40, rssi=-65, now_ts=100.0
        )
        self.assertTrue(res.is_anomaly)
        self.assertIn("CHANNEL_MATCH_TYPE_B", res.anomaly_types)
        self.assertGreaterEqual(res.score_delta, SCORE_CHANNEL_MATCH_TYPE_B)

    # =========================================================================
    # Check 4.4: Severe IE Mismatch (+55 pts)
    # =========================================================================
    def test_check_4_4_severe_ie_mismatch_open_on_enterprise(self):
        """
        Check 4.4a: Campus baseline is 802.1X enterprise.
        Observed AP has OPEN encryption -> Severe IE Mismatch (+55 pts).
        """
        # Lock enterprise profile
        self.analyzer.learn_baseline([
            {
                "ssid": "University Campus 5G",
                "akm_suites": ["802.1X"],
                "pairwise_ciphers": ["CCMP"],
                "has_mdid": True,
                "has_vendor_221": True,
                "mimo_streams": 4,
            }
        ])

        bssid = "00:50:56:00:11:01"
        # Attacker creates OPEN evil twin
        open_frame = {
            "ssid": "University Campus 5G",
            "tag3_channel": 6,
            "akm_suites": [],
            "encryption_type": "OPEN",
            "mimo_streams": 4,
            "has_mdid": True,
            "has_vendor_221": True,
        }
        res = self.analyzer.analyze_beacon(
            bssid=bssid, frame=open_frame, radio_channel=6, rssi=-65, now_ts=200.0
        )
        self.assertTrue(res.is_anomaly)
        self.assertIn("SEVERE_MISMATCH", res.anomaly_types)
        self.assertEqual(res.ie_match_status, "SEVERE_MISMATCH")
        self.assertGreaterEqual(res.score_delta, SCORE_SEVERE_IE_MISMATCH)

    def test_check_4_4b_severe_ie_mismatch_wps_present(self):
        """
        Check 4.4b: Consumer WPS tag present on enterprise AP -> Severe IE Mismatch (+55 pts).
        """
        self.analyzer.learn_baseline([
            {"akm_suites": ["802.1X"], "pairwise_ciphers": ["CCMP"], "has_mdid": True, "has_vendor_221": True, "mimo_streams": 4}
        ])

        bssid = "00:50:56:00:11:02"
        wps_frame = {
            "ssid": "University Campus 5G",
            "tag3_channel": 6,
            "akm_suites": ["802.1X"],
            "pairwise_ciphers": ["CCMP"],
            "has_wps": True,  # WPS tag injected by consumer rogue AP
            "mimo_streams": 4,
            "has_mdid": True,
            "has_vendor_221": True,
        }
        res = self.analyzer.analyze_beacon(
            bssid=bssid, frame=wps_frame, radio_channel=6, rssi=-65, now_ts=200.0
        )
        self.assertTrue(res.is_anomaly)
        self.assertIn("SEVERE_MISMATCH", res.anomaly_types)
        self.assertGreaterEqual(res.score_delta, SCORE_SEVERE_IE_MISMATCH)

    def test_check_4_4c_severe_ie_mismatch_phy_downgrade(self):
        """
        Check 4.4c: 1x1 PHY USB adapter pretending to be a 4x4 campus AP -> Severe IE Mismatch (+55 pts).
        """
        self.analyzer.learn_baseline([
            {"akm_suites": ["802.1X"], "pairwise_ciphers": ["CCMP"], "has_mdid": True, "has_vendor_221": True, "mimo_streams": 4}
        ])

        bssid = "00:50:56:00:11:03"
        phy1x1_frame = {
            "ssid": "University Campus 5G",
            "tag3_channel": 6,
            "akm_suites": ["802.1X"],
            "pairwise_ciphers": ["CCMP"],
            "mimo_streams": 1,  # 1x1 PHY downgrade
            "has_mdid": True,
            "has_vendor_221": True,
        }
        res = self.analyzer.analyze_beacon(
            bssid=bssid, frame=phy1x1_frame, radio_channel=6, rssi=-65, now_ts=200.0
        )
        self.assertTrue(res.is_anomaly)
        self.assertIn("SEVERE_MISMATCH", res.anomaly_types)
        self.assertGreaterEqual(res.score_delta, SCORE_SEVERE_IE_MISMATCH)

    def test_check_4_4d_severe_ie_mismatch_missing_mdid_or_vendor221(self):
        """
        Check 4.4d: Missing MDID (Tag 54) or Tag 221 when campus baseline requires them -> Severe IE Mismatch (+55 pts).
        """
        self.analyzer.learn_baseline([
            {"akm_suites": ["802.1X"], "pairwise_ciphers": ["CCMP"], "has_mdid": True, "has_vendor_221": True, "mimo_streams": 4}
        ])

        bssid = "00:50:56:00:11:04"
        missing_mdid_frame = {
            "ssid": "University Campus 5G",
            "tag3_channel": 6,
            "akm_suites": ["802.1X"],
            "pairwise_ciphers": ["CCMP"],
            "mimo_streams": 4,
            "has_mdid": False,  # Missing MDID!
            "has_vendor_221": True,
        }
        res = self.analyzer.analyze_beacon(
            bssid=bssid, frame=missing_mdid_frame, radio_channel=6, rssi=-65, now_ts=200.0
        )
        self.assertTrue(res.is_anomaly)
        self.assertIn("SEVERE_MISMATCH", res.anomaly_types)
        self.assertGreaterEqual(res.score_delta, SCORE_SEVERE_IE_MISMATCH)

    # =========================================================================
    # Check 4.5: Partial IE Mismatch (+15 pts)
    # =========================================================================
    def test_check_4_5_partial_ie_mismatch_non_standard_24ghz_channel(self):
        """
        Check 4.5: 2.4 GHz channel outside {1, 6, 11} triggers Partial IE Mismatch (+15 pts).
        """
        self.analyzer.learn_baseline([
            {"akm_suites": ["802.1X"], "pairwise_ciphers": ["CCMP"], "has_mdid": True, "has_vendor_221": True, "mimo_streams": 4}
        ])

        bssid = "00:50:56:00:22:01"
        # Non-standard channel 3 in 2.4 GHz
        non_std_frame = {
            "ssid": "University Campus 5G",
            "tag3_channel": 3,
            "akm_suites": ["802.1X"],
            "pairwise_ciphers": ["CCMP"],
            "mimo_streams": 4,
            "has_mdid": True,
            "has_vendor_221": True,
        }
        res = self.analyzer.analyze_beacon(
            bssid=bssid, frame=non_std_frame, radio_channel=3, rssi=-65, now_ts=300.0
        )
        self.assertTrue(res.is_anomaly)
        self.assertIn("PARTIAL_MISMATCH", res.anomaly_types)
        self.assertEqual(res.ie_match_status, "PARTIAL_MISMATCH")
        self.assertEqual(res.score_delta, SCORE_PARTIAL_IE_MISMATCH)

    # =========================================================================
    # Check 4.6: 100% Campus IE Blueprint Match (-35 pts Sister Only)
    # =========================================================================
    def test_check_4_6a_100_percent_match_on_sister_ssid_gets_discount(self):
        """
        Check 4.6a: A Departmental Sister SSID (e.g. 'Law_School_Faculty') matching the
        Campus IE Blueprint receives the -35 pts discount.
        """
        self.analyzer.learn_baseline([
            {"akm_suites": ["802.1X"], "pairwise_ciphers": ["CCMP"], "has_mdid": True, "has_vendor_221": True, "mimo_streams": 4}
        ])

        bssid = "00:50:56:77:88:99"
        sister_ssid = "Law_School_Faculty"

        # Give the BSSID an initial score in DB (e.g. 50 from probation / name screener)
        state = BSSIDState(
            bssid=bssid,
            current_ssid=sister_ssid,
            is_whitelisted=0,
            current_risk_score=50,
            risk_tier="MEDIUM",
        )
        self.db.put_bssid(state)

        frame = {
            "ssid": sister_ssid,
            "tag3_channel": 6,
            "akm_suites": ["802.1X"],
            "pairwise_ciphers": ["CCMP"],
            "mimo_streams": 4,
            "has_mdid": True,
            "has_vendor_221": True,
        }

        res = self.analyzer.analyze_beacon(
            bssid=bssid, frame=frame, radio_channel=6, rssi=-65, now_ts=400.0, ssid=sister_ssid
        )
        self.assertEqual(res.ie_match_status, "100%_MATCH")
        self.assertEqual(res.score_delta, SCORE_CAMPUS_BLUEPRINT_MATCH)  # -35 pts
        # Risk score reduced from 50 to 15 (LOW)
        self.assertEqual(res.risk_score, 15)
        self.assertEqual(res.risk_tier, "LOW")

    def test_check_4_6b_100_percent_match_on_exact_whitelist_ssid_preserves_medium_floor(self):
        """
        Check 4.6b: An un-whitelisted AP broadcasting an EXACT whitelist SSID (e.g. 'eduroam')
        does NOT receive -35 pts! Score delta must be 0, preserving the MEDIUM floor until manual UI whitelisting.
        """
        self.analyzer.learn_baseline([
            {"akm_suites": ["802.1X"], "pairwise_ciphers": ["CCMP"], "has_mdid": True, "has_vendor_221": True, "mimo_streams": 4}
        ])

        bssid = "00:50:56:99:aa:bb"
        exact_ssid = "eduroam"

        state = BSSIDState(
            bssid=bssid,
            current_ssid=exact_ssid,
            is_whitelisted=0,
            current_risk_score=50,
            risk_tier="MEDIUM",
        )
        self.db.put_bssid(state)

        frame = {
            "ssid": exact_ssid,
            "tag3_channel": 6,
            "akm_suites": ["802.1X"],
            "pairwise_ciphers": ["CCMP"],
            "mimo_streams": 4,
            "has_mdid": True,
            "has_vendor_221": True,
        }

        res = self.analyzer.analyze_beacon(
            bssid=bssid, frame=frame, radio_channel=6, rssi=-65, now_ts=400.0, ssid=exact_ssid
        )
        self.assertEqual(res.ie_match_status, "100%_MATCH")
        # HARD RULE: Un-whitelisted exact whitelist APs MUST NOT get -35 pts!
        self.assertEqual(
            res.score_delta,
            0,
            "Exact campus whitelist SSID un-whitelisted must NOT receive -35 pts discount!",
        )
        self.assertEqual(res.risk_score, 50)
        self.assertEqual(res.risk_tier, "MEDIUM")

    # =========================================================================
    # Check 4.7: RSSI Volatility & Static Gating
    # =========================================================================
    def test_check_4_7_rssi_volatility_and_static_gating(self):
        """
        Check 4.7:
        1. Sudden jump Delta_RSSI > 15 dB triggers RSSI Volatility (+20 pts).
        2. Stable RSSI (Delta_RSSI <= 15 dB) triggers 0 pts.
        3. Static RSSI >= -70 dBm sets FULL_FRAME, < -70 dBm sets INFREQUENT (0 pts gate).
        """
        bssid = "00:50:56:44:55:66"

        # Initial beacon at -80 dBm (< -70 dBm -> INFREQUENT)
        res1 = self.analyzer.analyze_beacon(
            bssid=bssid, frame={"tag3_channel": 6}, radio_channel=6, rssi=-80, now_ts=500.0
        )
        self.assertEqual(res1.logging_mode, "INFREQUENT")
        self.assertNotIn("RSSI_VOLATILITY", res1.anomaly_types)

        # Beacon 2: Sudden jump to -55 dBm (Delta_RSSI = 25 dB > 15 dB)
        # Also >= -70 dBm -> FULL_FRAME
        res2 = self.analyzer.analyze_beacon(
            bssid=bssid, frame={"tag3_channel": 6}, radio_channel=6, rssi=-55, now_ts=502.0
        )
        self.assertTrue(res2.is_anomaly)
        self.assertIn("RSSI_VOLATILITY", res2.anomaly_types)
        self.assertEqual(res2.logging_mode, "FULL_FRAME")
        self.assertEqual(res2.rssi_delta, 25.0)
        self.assertGreaterEqual(res2.score_delta, SCORE_RSSI_VOLATILITY)

        # Beacon 3: Small variation to -58 dBm (Delta_RSSI = 3 dB <= 15 dB -> stable)
        res3 = self.analyzer.analyze_beacon(
            bssid=bssid, frame={"tag3_channel": 6}, radio_channel=6, rssi=-58, now_ts=504.0
        )
        self.assertNotIn("RSSI_VOLATILITY", res3.anomaly_types)
        self.assertEqual(res3.logging_mode, "FULL_FRAME")

    # =========================================================================
    # Check 4.8: Multi-Anomaly Cumulative Scoring
    # =========================================================================
    def test_check_4_8_multi_anomaly_cumulative_scoring(self):
        """
        Check 4.8: Multiple anomalies (Jitter + Channel Spoof) accumulate score deltas.
        """
        bssid = "00:50:56:33:22:11"
        # Seed initial beacon
        self.analyzer.analyze_beacon(
            bssid=bssid, frame={"seq": 1, "tsf": 1000000, "tag3_channel": 1},
            radio_channel=1, rssi=-75, now_ts=600.0
        )

        # Beacon 2:
        # 1. Dropped frame jitter (seq=3, dt=235ms -> +20 pts)
        # 2. Tag 3 = 1, Radio Channel = 6 (+45 pts)
        # Total delta = 20 + 45 = 65 pts -> escalates to MEDIUM / HIGH
        frame2 = {"seq": 3, "tsf": 1235000, "tag3_channel": 1}
        res = self.analyzer.analyze_beacon(
            bssid=bssid, frame=frame2, radio_channel=6, rssi=-75, now_ts=600.235
        )
        self.assertTrue(res.is_anomaly)
        self.assertIn("JITTER_ANOMALY", res.anomaly_types)
        self.assertIn("CHANNEL_MATCH_TYPE_B", res.anomaly_types)
        self.assertEqual(res.score_delta, 65)
        self.assertEqual(res.risk_score, 65)
        self.assertEqual(res.risk_tier, "MEDIUM")

    # =========================================================================
    # Check 4.9: Feature Extraction Compatibility
    # =========================================================================
    def test_check_4_9_element_list_and_mock_extraction(self):
        """
        Check 4.9: Verify extract_beacon_features correctly parses raw element lists
        and mock objects into standard features.
        """
        # Dict with element tuples
        dict_frame = {
            "seq": 42,
            "tsf": 99999,
            "elements": [
                (0, b"Custom_SSID"),
                (3, b"\x06"),
                (45, b"\x00\x00\x00\x00\x00\x00\xff"),  # 4x4 MIMO
                (48, b"\x01\x00\x00\x0f\xac\x04\x01\x00\x00\x0f\xac\x04\x01\x00\x00\x0f\xac\x01\x00\x00"),  # 802.1X, CCMP
                (54, b"\x12\x34"),  # MDID
                (221, b"\x00\x40\x96\x01\x02"),  # Cisco vendor IE
            ]
        }
        feat = extract_beacon_features(dict_frame)
        self.assertEqual(feat["ssid"], "Custom_SSID")
        self.assertEqual(feat["seq_num"], 42)
        self.assertEqual(feat["tsf_timestamp"], 99999)
        self.assertEqual(feat["tag3_channel"], 6)
        self.assertEqual(feat["mimo_streams"], 4)
        self.assertIn("802.1X", feat["akm_suites"])
        self.assertIn("CCMP", feat["pairwise_ciphers"])
        self.assertTrue(feat["has_mdid"])
        self.assertTrue(feat["has_vendor_221"])
        self.assertFalse(feat["has_wps"])
        self.assertEqual(feat["encryption_type"], "802.1X")


    # =========================================================================
    # Additional Deep Rigorous Tests (N+1 Review Remediation)
    # =========================================================================
    def test_check_4_10_multi_beacon_continuous_score_stability(self):
        """
        Check 4.10: Sending multiple consecutive beacons for a non-standard channel
        (Partial Mismatch, +15 pts) must hold risk score stable at 15 pts,
        rather than compounding frame-by-frame and exploding to 100 pts.
        """
        self.analyzer.learn_baseline([
            {"akm_suites": ["802.1X"], "pairwise_ciphers": ["CCMP"], "has_mdid": True, "has_vendor_221": True, "mimo_streams": 4}
        ])

        bssid = "00:50:56:44:33:22"
        frame = {
            "ssid": "Sister_Network",
            "tag3_channel": 3,
            "akm_suites": ["802.1X"],
            "pairwise_ciphers": ["CCMP"],
            "mimo_streams": 4,
            "has_mdid": True,
            "has_vendor_221": True,
        }

        # Send 10 consecutive beacons (1 second of real-world traffic)
        for i in range(10):
            res = self.analyzer.analyze_beacon(
                bssid=bssid, frame=frame, radio_channel=3, rssi=-65, now_ts=100.0 + (i * 0.102)
            )
            self.assertEqual(res.score_delta, SCORE_PARTIAL_IE_MISMATCH)
            self.assertEqual(res.risk_score, 15, f"Beacon {i+1} score must stay 15, not explode!")
            self.assertEqual(res.risk_tier, "LOW")

    def test_check_4_11_sister_ssid_continuous_score_stability(self):
        """
        Check 4.11: Sending multiple consecutive beacons for a 100% matched Sister SSID
        must hold risk score stable at 15 pts (50 - 35), rather than continually
        subtracting down to 0 and erasing future anomalies.
        """
        self.analyzer.learn_baseline([
            {"akm_suites": ["802.1X"], "pairwise_ciphers": ["CCMP"], "has_mdid": True, "has_vendor_221": True, "mimo_streams": 4}
        ])

        bssid = "00:50:56:55:66:77"
        sister_ssid = "Law_School_Faculty"

        # Initial state in DB with base score 50
        state = BSSIDState(
            bssid=bssid,
            current_ssid=sister_ssid,
            is_whitelisted=0,
            current_risk_score=50,
            risk_tier="MEDIUM",
        )
        self.db.put_bssid(state)

        frame = {
            "ssid": sister_ssid,
            "tag3_channel": 6,
            "akm_suites": ["802.1X"],
            "pairwise_ciphers": ["CCMP"],
            "mimo_streams": 4,
            "has_mdid": True,
            "has_vendor_221": True,
        }

        # Send 5 normal matching beacons
        for i in range(5):
            res = self.analyzer.analyze_beacon(
                bssid=bssid, frame=frame, radio_channel=6, rssi=-65, now_ts=200.0 + (i * 0.102), ssid=sister_ssid
            )
            self.assertEqual(res.score_delta, SCORE_CAMPUS_BLUEPRINT_MATCH)
            self.assertEqual(res.risk_score, 15, f"Beacon {i+1} score must stay at 15!")
            self.assertEqual(res.risk_tier, "LOW")

        # Now Beacon 6 has a sudden Jitter Anomaly (+20 pts)
        jitter_frame = dict(frame)
        jitter_frame["seq"] = 12
        jitter_frame["tsf"] = 1235000
        # Seed prior sequence so jitter triggers
        self.analyzer.evaluate_jitter(bssid, curr_seq=10, curr_tsf=1000000, now_ts=201.000)
        res_jitter = self.analyzer.analyze_beacon(
            bssid=bssid, frame=jitter_frame, radio_channel=6, rssi=-65, now_ts=201.235, ssid=sister_ssid
        )
        self.assertIn("JITTER_ANOMALY", res_jitter.anomaly_types)
        # Score is 50 - 35 + 20 = 35 (MEDIUM)
        self.assertEqual(res_jitter.risk_score, 35)
        self.assertEqual(res_jitter.risk_tier, "MEDIUM")

    def test_check_4_12_learned_raw_ies_hash_and_tag_order_variance(self):
        """
        Check 4.12: learn_baseline preserves raw_ies_hash so legitimate baseline frames
        match 100%, and frames with altered tag order / raw IEs trigger Partial Mismatch (+15 pts).
        """
        legit_frame = {
            "ssid": "Sister_Campus",
            "tag3_channel": 6,
            "akm_suites": ["802.1X"],
            "pairwise_ciphers": ["CCMP"],
            "has_mdid": True,
            "has_vendor_221": True,
            "mimo_streams": 4,
            "raw_ies_hash": "cisco_catalyst_firmware_v1",
        }
        self.analyzer.learn_baseline([legit_frame])

        # Test 1: Legitimate AP broadcasting identical raw IEs
        bssid_legit = "00:50:56:aa:bb:01"
        res_legit = self.analyzer.analyze_beacon(
            bssid=bssid_legit, frame=legit_frame, radio_channel=6, rssi=-60, now_ts=300.0, ssid="Sister_Campus"
        )
        self.assertEqual(res_legit.ie_match_status, "100%_MATCH")
        self.assertEqual(res_legit.score_delta, SCORE_CAMPUS_BLUEPRINT_MATCH)

        # Test 2: Rogue AP broadcasting altered tag order / raw IEs
        bssid_rogue = "00:50:56:aa:bb:02"
        rogue_frame = dict(legit_frame)
        rogue_frame["raw_ies_hash"] = "hostapd_altered_tag_order"
        res_rogue = self.analyzer.analyze_beacon(
            bssid=bssid_rogue, frame=rogue_frame, radio_channel=6, rssi=-60, now_ts=300.0, ssid="Sister_Campus"
        )
        self.assertEqual(res_rogue.ie_match_status, "PARTIAL_MISMATCH")
        self.assertIn("PARTIAL_MISMATCH", res_rogue.anomaly_types)
        self.assertEqual(res_rogue.score_delta, SCORE_PARTIAL_IE_MISMATCH)

    def test_check_4_13_whitelisted_bssid_initialization(self):
        """
        Check 4.13: Verify that a BSSID registered in whitelisted_bssids is initialized
        with is_whitelisted = 1 when first evaluated by analyze_beacon.
        """
        wl_bssid = "00:14:22:99:88:77"
        self.db.whitelisted_bssids.add(wl_bssid)
        frame = {
            "ssid": "eduroam",
            "tag3_channel": 6,
            "akm_suites": ["802.1X"],
            "pairwise_ciphers": ["CCMP"],
            "mimo_streams": 4,
        }
        res = self.analyzer.analyze_beacon(
            bssid=wl_bssid, frame=frame, radio_channel=6, rssi=-60, now_ts=400.0
        )
        self.assertEqual(res.bssid_state.is_whitelisted, 1)
        self.assertEqual(res.risk_score, 0)
        self.assertEqual(res.risk_tier, "LOW")

    def test_check_4_14_channel_match_type_b_cross_band(self):
        """
        Check 4.14: Radio channel in 5 GHz (Ch 36) vs Declared Tag 3 in 2.4 GHz (Ch 1)
        is cross-band spoofing and must trigger CHANNEL_MATCH_TYPE_B (+45 pts).
        """
        bssid = "00:14:22:11:33:55"
        frame = {"tag3_channel": 1, "seq": 10, "tsf": 1000}
        res = self.analyzer.analyze_beacon(
            bssid=bssid, frame=frame, radio_channel=36, rssi=-65, now_ts=500.0
        )
        self.assertTrue(res.is_anomaly)
        self.assertIn("CHANNEL_MATCH_TYPE_B", res.anomaly_types)
        self.assertGreaterEqual(res.score_delta, SCORE_CHANNEL_MATCH_TYPE_B)


if __name__ == "__main__":
    unittest.main()
