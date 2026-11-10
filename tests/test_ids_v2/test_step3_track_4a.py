"""
Step 3 Unit Test Harness: Track 4A Stateful Active RF Tracker & Demux (v2.1.2)
Verifies:
- Check 3.1: Clone a whitelisted BSSID on a second Tag 3 channel; verify Stage 0 routes it to Track 4A and triggers HIGH (+70 pts).
- Check 3.2: Move a single BSSID from Tag 3 Ch 6 to Ch 1 (one-way); verify Ch 6 expires after 15s and primary_channel updates to 1 with 0 pts.
- Check 3.3: Advance clock by 3,700 s without beacons on an un-whitelisted AP; verify first_seen_ts resets to now.
- Check 3.4: Deauth flood detection (>= 15 in 10s window triggers Floor HIGH +75 pts).
- Check 3.5: Deauth flood detection (>= 30 in 60s window triggers Floor HIGH +75 pts).
- Check 3.6: Benign deauth traffic (< 15 in 10s, < 30 in 60s) remains LOW / 0 pts.
- Check 3.7: Same-channel backward sequence regression (prev_seq > curr_seq + 5) triggers Floor HIGH (+75 pts).
- Check 3.8: 802.11 sequence number 4096 rollover (4095 -> 0, 1, 2) is NOT flagged as collision.
- Check 3.9: Same-channel TSF regression (curr_tsf < prev_tsf - 1_000_000 us) triggers Floor HIGH (+75 pts).
- Check 3.10: Whitelisted BSSID integrity verification path (clean AP exits as BENIGN / LOW, collision escalates to HIGH).
- Check 3.11: Pre-Stage-0 Management Demultiplexer routes Subtype 0x0C (Deauth) and 0x0A (Disassoc) by addr3.
- Check 3.12: Channel Tag 3 / Tag 61 extraction vs Radiotap receiver frequency isolation.
- Check 3.13: New AP 24h probation age tracker & whitelist immunity to offline reset.
"""

import os
import tempfile
import time
import unittest

from detector.ids_v2.config import (
    CHANNEL_WINDOW_SEC,
    DEAUTH_THRESHOLD_10S,
    DEAUTH_THRESHOLD_60S,
    DEFAULT_CAMPUS_WHITELIST,
    OFFLINE_RESET_SEC,
    SCORE_THRESHOLD_HIGH,
    SCORE_THRESHOLD_MEDIUM,
)
from detector.ids_v2.db_manager import (
    BatchDatabaseManager,
    BSSIDState,
)
from detector.ids_v2.name_screener import (
    CampusNameScreener,
)
from detector.ids_v2.track_4a_state import (
    Track4AStateTracker,
    Track4AResult,
    extract_tag3_or_61_channel,
    SCORE_FLOOR_DEAUTH_FLOOD,
    SCORE_FLOOR_SAME_CHANNEL_COLLISION,
    SCORE_FLOOR_MULTI_CHANNEL_CLONE,
)


class TestStep3Track4A(unittest.TestCase):

    def setUp(self):
        self.temp_db = tempfile.NamedTemporaryFile(delete=False, suffix=".db")
        self.temp_db.close()
        self.db_path = self.temp_db.name
        self.db = BatchDatabaseManager(self.db_path)
        self.screener = CampusNameScreener(
            db_manager=self.db,
            whitelist=DEFAULT_CAMPUS_WHITELIST,
            threads=2,
        )
        self.tracker = Track4AStateTracker(
            db_manager=self.db,
            screener=self.screener,
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
    # Check 3.1: Clone a whitelisted BSSID on a second Tag 3 channel
    # =========================================================================
    def test_check_3_1_cloned_whitelisted_bssid_multi_channel(self):
        """
        Check 3.1: Clone a whitelisted BSSID on a second Tag 3 channel;
        verify Stage 0 routes it to Track 4A and triggers HIGH (+70 pts).
        """
        wl_bssid = "00:14:22:01:23:45"
        wl_ssid = "University Campus 5G"

        # 1. Manually whitelist the BSSID in SQLite WAL
        state = BSSIDState(
            bssid=wl_bssid,
            current_ssid=wl_ssid,
            is_whitelisted=1,
            primary_channel=6,
            active_channels_map={6: 1000.0},
            first_seen_ts=1000.0,
            last_seen_ts=1000.0,
            risk_tier="LOW",
            current_risk_score=0,
        )
        self.db.put_bssid(state)
        self.db.flush_to_sqlite(force=True)

        # 2. Legitimate beacon on Ch 6 at t=1000.0
        res1 = self.screener.screen_beacon(
            bssid=wl_bssid,
            ssid=wl_ssid,
            encryption_type="802.1X",
            tag3_channel=6,
            seq_num=100,
            tsf_timestamp=10_000_000,
            now_ts=1000.0,
        )
        self.assertFalse(res1.is_suspicious_name)
        self.assertTrue(res1.is_whitelisted)
        self.assertIsNotNone(res1.track_4a_result)
        self.assertFalse(res1.track_4a_result.is_anomaly)
        self.assertEqual(res1.track_4a_result.risk_score, 0)
        self.assertEqual(res1.track_4a_result.risk_tier, "LOW")

        # 3. Rogue Evil Twin clones the whitelisted BSSID + SSID on Tag 3 Ch 1 at t=1002.0 (dt=2s < 15s)
        res2 = self.screener.screen_beacon(
            bssid=wl_bssid,
            ssid=wl_ssid,
            encryption_type="802.1X",
            tag3_channel=1,
            seq_num=150,
            tsf_timestamp=10_204_800,
            now_ts=1002.0,
        )
        # Verify Stage 0 routed to Track 4A and triggered HIGH (+70 pts)
        self.assertIsNotNone(res2.track_4a_result)
        self.assertTrue(res2.track_4a_result.is_anomaly)
        self.assertEqual(res2.track_4a_result.anomaly_type, "MULTI_CHANNEL_CLONE")
        self.assertEqual(res2.track_4a_result.added_score, SCORE_FLOOR_MULTI_CHANNEL_CLONE)
        self.assertGreaterEqual(res2.track_4a_result.risk_score, 70)
        self.assertEqual(res2.track_4a_result.risk_tier, "HIGH")

        # Verify channels {1, 6} are both recorded as active in DB state
        saved_state = self.db.get_bssid(wl_bssid)
        self.assertIn(1, saved_state.active_channels_map)
        self.assertIn(6, saved_state.active_channels_map)
        self.assertEqual(saved_state.risk_tier, "HIGH")

    # =========================================================================
    # Check 3.2: Move a single BSSID from Tag 3 Ch 6 to Ch 1 (one-way)
    # =========================================================================
    def test_check_3_2_one_way_channel_move_expires_after_15s(self):
        """
        Check 3.2: Move a single BSSID from Tag 3 Ch 6 to Ch 1 (one-way);
        verify Ch 6 expires after 15s and primary_channel updates to 1 with 0 pts.
        """
        bssid = "00:11:22:33:44:aa"
        ssid = "Campus_IoT_Sensor"

        # 1. Initial broadcast on Ch 6 at t=100.0
        res1 = self.tracker.process_beacon_frame(
            bssid=bssid,
            observed_ssid=ssid,
            tag3_channel=6,
            seq_num=10,
            tsf_timestamp=10_000_000,
            now_ts=100.0,
        )
        self.assertFalse(res1.is_anomaly)
        self.assertEqual(res1.primary_channel, 6)
        self.assertEqual(res1.active_channels, [6])

        # 2. Advance time by 16.0s (> 15.0s expiry); AP now broadcasts on Ch 1 at t=116.0
        res2 = self.tracker.process_beacon_frame(
            bssid=bssid,
            observed_ssid=ssid,
            tag3_channel=1,
            seq_num=11,
            tsf_timestamp=11_600_000,
            now_ts=116.0,
        )

        # Ch 6 must have expired; only Ch 1 active, primary_channel updated to 1 with 0 pts
        self.assertFalse(res2.is_anomaly)
        self.assertEqual(res2.anomaly_type, "NONE")
        self.assertEqual(res2.added_score, 0)
        self.assertEqual(res2.primary_channel, 1)
        self.assertEqual(res2.active_channels, [1])

        # Database state reflects clean transition
        state = self.db.get_bssid(bssid)
        self.assertEqual(state.primary_channel, 1)
        self.assertNotIn(6, state.active_channels_map)
        self.assertIn(1, state.active_channels_map)

    # =========================================================================
    # Check 3.3: 1-Hour Offline Gap Resets first_seen_ts on Un-whitelisted AP
    # =========================================================================
    def test_check_3_3_one_hour_offline_probation_reset(self):
        """
        Check 3.3: Advance clock by 3,700 s without beacons on an un-whitelisted AP;
        verify first_seen_ts resets to now (Point 4 PoE Assumption).
        """
        bssid = "00:11:22:33:44:bb"
        ssid = "Department_Staff"

        # 1. First seen at t=1000.0
        res1 = self.tracker.process_beacon_frame(
            bssid=bssid,
            observed_ssid=ssid,
            tag3_channel=6,
            seq_num=100,
            tsf_timestamp=100_000,
            now_ts=1000.0,
        )
        state1 = self.db.get_bssid(bssid)
        self.assertEqual(state1.first_seen_ts, 1000.0)
        self.assertEqual(state1.last_seen_ts, 1000.0)

        # 2. Advance clock by 3,700s (> 3600s / 1 hour offline gap)
        now_ts = 1000.0 + 3700.0  # 4700.0
        res2 = self.tracker.process_beacon_frame(
            bssid=bssid,
            observed_ssid=ssid,
            tag3_channel=6,
            seq_num=101,
            tsf_timestamp=200_000,
            now_ts=now_ts,
        )

        # Verify probation timer was reset: first_seen_ts must now be 4700.0
        state2 = self.db.get_bssid(bssid)
        self.assertEqual(state2.first_seen_ts, 4700.0)
        self.assertEqual(state2.last_seen_ts, 4700.0)
        self.assertTrue(res2.details.get("was_offline_over_1h"))

    # =========================================================================
    # Check 3.4: Deauth Flood Detection (10-Second Sliding Window)
    # =========================================================================
    def test_check_3_4_deauth_flood_10s_window(self):
        """
        Check 3.4: Send >= 15 deauth frames within 10s;
        verify Hard Floor HIGH (+75 pts) triggers.
        """
        bssid = "00:11:22:33:44:cc"
        t0 = 500.0

        # Inject 14 deauth frames in 7s (2 frames/sec)
        for i in range(14):
            res = self.tracker.process_deauth_frame(bssid, now_ts=t0 + i * 0.5)
            self.assertFalse(res.is_anomaly)
            self.assertEqual(res.deauth_count_10s, i + 1)
            self.assertEqual(res.risk_tier, "LOW")

        # 15th frame arrives at t0 + 7.0s
        res15 = self.tracker.process_deauth_frame(bssid, now_ts=t0 + 7.0)
        self.assertTrue(res15.is_anomaly)
        self.assertEqual(res15.anomaly_type, "DEAUTH_FLOOD")
        self.assertEqual(res15.added_score, SCORE_FLOOR_DEAUTH_FLOOD)
        self.assertGreaterEqual(res15.risk_score, 75)
        self.assertEqual(res15.risk_tier, "HIGH")

        # Verify DB behavior log was queued
        self.assertEqual(len(self.db.pending_behavior_logs), 1)
        log = self.db.pending_behavior_logs[0]
        self.assertEqual(log[0], bssid)
        self.assertEqual(log[6], "DEAUTH_FLOOD")

    # =========================================================================
    # Check 3.5: Deauth Flood Detection (60-Second Sliding Window)
    # =========================================================================
    def test_check_3_5_deauth_flood_60s_window(self):
        """
        Check 3.5: Send >= 30 deauth frames spread across 50s (so < 15 in any 10s window);
        verify Hard Floor HIGH (+75 pts) triggers on the 30th frame.
        """
        bssid = "00:11:22:33:44:dd"
        t0 = 1000.0

        # Send 29 frames over 50s (one frame every ~1.7s -> ~6 frames per 10s, well below 15)
        for i in range(29):
            res = self.tracker.process_deauth_frame(bssid, now_ts=t0 + i * 1.7)
            self.assertFalse(res.is_anomaly)
            self.assertLess(res.deauth_count_10s, 15)

        # 30th frame arrives at t0 + 49.3s
        res30 = self.tracker.process_deauth_frame(bssid, now_ts=t0 + 49.3)
        self.assertTrue(res30.is_anomaly)
        self.assertEqual(res30.anomaly_type, "DEAUTH_FLOOD")
        self.assertEqual(res30.added_score, SCORE_FLOOR_DEAUTH_FLOOD)
        self.assertGreaterEqual(res30.risk_score, 75)
        self.assertEqual(res30.risk_tier, "HIGH")

    # =========================================================================
    # Check 3.6: Benign Deauth Traffic
    # =========================================================================
    def test_check_3_6_benign_deauth_traffic_remains_low(self):
        """
        Check 3.6: Benign deauth traffic (< 15 in 10s, < 30 in 60s) remains LOW / 0 pts.
        """
        bssid = "00:11:22:33:44:ee"
        t0 = 2000.0

        for i in range(10):
            res = self.tracker.process_deauth_frame(bssid, now_ts=t0 + i * 1.0)
            self.assertFalse(res.is_anomaly)
            self.assertEqual(res.risk_score, 0)
            self.assertEqual(res.risk_tier, "LOW")

    # =========================================================================
    # Check 3.7: Same-Channel Backward Sequence Regression
    # =========================================================================
    def test_check_3_7_same_channel_backward_seq_regression(self):
        """
        Check 3.7: On the same channel, if sequence jumps backwards by > 5 frames
        without rollover (e.g. 1000 -> 800), trigger Floor HIGH (+75 pts).
        """
        bssid = "00:11:22:33:44:ff"
        ssid = "Campus_AP_Normal"

        # Frame 1: Seq 1000, Ch 6, t=10.0
        res1 = self.tracker.process_beacon_frame(
            bssid=bssid,
            observed_ssid=ssid,
            tag3_channel=6,
            seq_num=1000,
            tsf_timestamp=10_000_000,
            now_ts=10.0,
        )
        self.assertFalse(res1.is_anomaly)

        # Frame 2: Seq 800 (jumps backwards by 200 > 5), Ch 6, t=10.1
        res2 = self.tracker.process_beacon_frame(
            bssid=bssid,
            observed_ssid=ssid,
            tag3_channel=6,
            seq_num=800,
            tsf_timestamp=10_102_400,
            now_ts=10.1,
        )
        self.assertTrue(res2.is_anomaly)
        self.assertEqual(res2.anomaly_type, "SAME_CHANNEL_COLLISION")
        self.assertEqual(res2.added_score, SCORE_FLOOR_SAME_CHANNEL_COLLISION)
        self.assertGreaterEqual(res2.risk_score, 75)
        self.assertEqual(res2.risk_tier, "HIGH")

    # =========================================================================
    # Check 3.8: 802.11 Modulo 4096 Sequence Rollover
    # =========================================================================
    def test_check_3_8_seq_modulo_4096_rollover_is_benign(self):
        """
        Check 3.8: Sequence 4094 -> 2 is a legitimate forward rollover (distance=4 <= 5).
        Must NOT be flagged as collision!
        """
        bssid = "00:11:22:33:55:01"
        ssid = "Campus_AP_Rollover"

        # Frame 1: Seq 4094, Ch 1, t=20.0
        res1 = self.tracker.process_beacon_frame(
            bssid=bssid,
            observed_ssid=ssid,
            tag3_channel=1,
            seq_num=4094,
            tsf_timestamp=20_000_000,
            now_ts=20.0,
        )
        self.assertFalse(res1.is_anomaly)

        # Frame 2: Seq 2 (normal forward rollover: (2 - 4094) % 4096 = 4), Ch 1, t=20.4
        res2 = self.tracker.process_beacon_frame(
            bssid=bssid,
            observed_ssid=ssid,
            tag3_channel=1,
            seq_num=2,
            tsf_timestamp=20_409_600,
            now_ts=20.4,
        )
        self.assertFalse(res2.is_anomaly, "Forward rollover 4094 -> 2 must not be flagged as collision")
        self.assertEqual(res2.anomaly_type, "NONE")
        self.assertEqual(res2.added_score, 0)

    # =========================================================================
    # Check 3.9: Same-Channel TSF Regression
    # =========================================================================
    def test_check_3_9_same_channel_tsf_regression(self):
        """
        Check 3.9: On the same channel, if TSF drops backwards by > 1,000,000 us (1.0s),
        trigger Floor HIGH (+75 pts).
        """
        bssid = "00:11:22:33:55:02"
        ssid = "Campus_AP_TSF"

        # Frame 1: TSF = 50,000,000 us, Ch 11, t=30.0
        res1 = self.tracker.process_beacon_frame(
            bssid=bssid,
            observed_ssid=ssid,
            tag3_channel=11,
            seq_num=500,
            tsf_timestamp=50_000_000,
            now_ts=30.0,
        )
        self.assertFalse(res1.is_anomaly)

        # Frame 2: Seq forward (501), but TSF drops to 48,000,000 us (2s regression > 1s), Ch 11, t=30.1
        res2 = self.tracker.process_beacon_frame(
            bssid=bssid,
            observed_ssid=ssid,
            tag3_channel=11,
            seq_num=501,
            tsf_timestamp=48_000_000,
            now_ts=30.1,
        )
        self.assertTrue(res2.is_anomaly)
        self.assertEqual(res2.anomaly_type, "SAME_CHANNEL_COLLISION")
        self.assertEqual(res2.added_score, SCORE_FLOOR_SAME_CHANNEL_COLLISION)
        self.assertGreaterEqual(res2.risk_score, 75)
        self.assertEqual(res2.risk_tier, "HIGH")

    # =========================================================================
    # Check 3.10: Whitelisted BSSID Integrity Verification Path
    # =========================================================================
    def test_check_3_10_whitelisted_bssid_integrity_path(self):
        """
        Check 3.10: Whitelisted BSSID with unchanged SSID bypasses AI,
        runs Track 4A:
        - If clean: stays BENIGN / LOW (0 pts).
        - If collision occurs: escalates to HIGH (+75 pts).
        """
        wl_bssid = "00:14:22:99:88:77"
        wl_ssid = "University Campus 5G"

        state = BSSIDState(
            bssid=wl_bssid,
            current_ssid=wl_ssid,
            is_whitelisted=1,
            primary_channel=6,
            active_channels_map={6: 50.0},
            risk_tier="LOW",
            current_risk_score=0,
        )
        self.db.put_bssid(state)

        # 1. Clean beacon: Seq 100 -> Seq 101, TSF forward
        res1 = self.tracker.process_beacon_frame(
            bssid=wl_bssid,
            observed_ssid=wl_ssid,
            tag3_channel=6,
            seq_num=100,
            tsf_timestamp=100_000_000,
            now_ts=50.0,
        )
        self.assertFalse(res1.is_anomaly)
        self.assertTrue(res1.is_whitelisted)
        self.assertEqual(res1.risk_score, 0)
        self.assertEqual(res1.risk_tier, "LOW")

        res2 = self.tracker.process_beacon_frame(
            bssid=wl_bssid,
            observed_ssid=wl_ssid,
            tag3_channel=6,
            seq_num=101,
            tsf_timestamp=100_102_400,
            now_ts=50.1,
        )
        self.assertFalse(res2.is_anomaly)
        self.assertEqual(res2.risk_score, 0)
        self.assertEqual(res2.risk_tier, "LOW")

        # 2. Injected Evil Twin with backward sequence (Seq 80) on same channel
        res3 = self.tracker.process_beacon_frame(
            bssid=wl_bssid,
            observed_ssid=wl_ssid,
            tag3_channel=6,
            seq_num=80,
            tsf_timestamp=100_204_800,
            now_ts=50.2,
        )
        self.assertTrue(res3.is_anomaly)
        self.assertEqual(res3.anomaly_type, "SAME_CHANNEL_COLLISION")
        self.assertEqual(res3.risk_score, 75)
        self.assertEqual(res3.risk_tier, "HIGH")

    # =========================================================================
    # Check 3.11: Pre-Stage-0 Ingress Demux (Deauth Subtype 0x0C / 0x0A)
    # =========================================================================
    def test_check_3_11_pre_stage_0_management_demux(self):
        """
        Check 3.11: Pre-Stage-0 Management Demultiplexer routes Subtype 0x0C (Deauth)
        and Subtype 0x0A (Disassoc) by addr3 BSSID directly into Track 4A.
        """
        bssid = "00:11:22:33:55:03"
        t0 = 300.0

        # Inject 15 frames using route_management_frame with subtype 0x0C and 0x0A
        for i in range(10):
            res = self.tracker.route_management_frame(
                subtype=0x0C,
                bssid=bssid,
                now_ts=t0 + i * 0.2,
            )
            self.assertIsNotNone(res)

        for i in range(5):
            res = self.tracker.route_management_frame(
                subtype=0x0A,
                bssid=bssid,
                now_ts=t0 + 2.0 + i * 0.2,
            )
            self.assertIsNotNone(res)

        # 15th management frame (total 10 Deauth + 5 Disassoc = 15) triggers HIGH
        self.assertTrue(res.is_anomaly)
        self.assertEqual(res.anomaly_type, "DEAUTH_FLOOD")
        self.assertEqual(res.risk_tier, "HIGH")

    # =========================================================================
    # Check 3.12: Channel Tag 3 / Tag 61 Extraction vs Radiotap Isolation
    # =========================================================================
    def test_check_3_12_extract_channel_tag3_and_tag61(self):
        """
        Check 3.12: extract_tag3_or_61_channel parses operating channel from:
        - Dictionary with tag3_channel / channel
        - Raw element list (Tag 3 DS Parameter Set, Tag 61 HT Operation)
        - Confirms receiver Radiotap frequency is ignored.
        """
        # Dict test
        dict_tag3 = {"tag3_channel": 6, "radiotap_freq": 2412}
        self.assertEqual(extract_tag3_or_61_channel(dict_tag3), 6)

        dict_tag61 = {"elements": [(61, bytes([36, 1, 0]))], "radiotap_freq": 5180}
        self.assertEqual(extract_tag3_or_61_channel(dict_tag61), 36)

        # Mock object test
        class MockFrame:
            def __init__(self, tag3_channel):
                self.tag3_channel = tag3_channel
                self.frequency = 2462

        mock = MockFrame(tag3_channel=11)
        self.assertEqual(extract_tag3_or_61_channel(mock), 11)

    # =========================================================================
    # Check 3.13: New AP Probation & Whitelist Immunity to Offline Reset
    # =========================================================================
    def test_check_3_13_probation_age_and_whitelist_immunity(self):
        """
        Check 3.13:
        1. New AP with age < 24h has is_probation_active == True.
        2. AP with age >= 24h (86,400s) has is_probation_active == False.
        3. Whitelisted AP has is_probation_active == False and never resets first_seen_ts
           even after > 1 hour offline gap.
        """
        un_bssid = "00:11:22:33:66:01"
        wl_bssid = "00:14:22:66:02"

        # 1. Un-whitelisted AP first seen at t=0.0
        self.tracker.process_beacon_frame(un_bssid, "Unwhitelisted_AP", 6, 1, 100, now_ts=0.0)
        self.assertTrue(self.tracker.is_probation_active(un_bssid, now_ts=3600.0))
        self.assertEqual(self.tracker.get_probation_age(un_bssid, now_ts=3600.0), 3600.0)

        # After 25 hours (90,000s) continuous: probation inactive
        self.assertFalse(self.tracker.is_probation_active(un_bssid, now_ts=90000.0))

        # 2. Whitelisted AP: never on probation
        wl_state = BSSIDState(
            bssid=wl_bssid,
            current_ssid="University Campus 5G",
            is_whitelisted=1,
            first_seen_ts=100.0,
            last_seen_ts=100.0,
        )
        self.db.put_bssid(wl_state)
        self.assertFalse(self.tracker.is_probation_active(wl_bssid, now_ts=200.0))

        # Whitelisted AP goes dark for 4,000s (> 1 hour): first_seen_ts must NOT reset!
        self.tracker.process_beacon_frame(wl_bssid, "University Campus 5G", 6, 2, 200, now_ts=4100.0)
        state = self.db.get_bssid(wl_bssid)
        self.assertEqual(state.first_seen_ts, 100.0, "Whitelisted AP first_seen_ts must remain intact")

    # =========================================================================
    # Check 3.14: Deauth Flood Alert Not Erased by Subsequent Clean Beacon
    # =========================================================================
    def test_check_3_14_deauth_flood_not_erased_by_subsequent_beacon(self):
        """
        Check 3.14: An active deauth flood on a whitelisted BSSID must NOT
        be instantly erased to LOW (0 pts) by the arrival of a clean beacon.
        """
        wl_bssid = "00:14:22:aa:bb:cc"
        wl_ssid = "University Campus 5G"
        state = BSSIDState(
            bssid=wl_bssid,
            current_ssid=wl_ssid,
            is_whitelisted=1,
            primary_channel=6,
            active_channels_map={6: 100.0},
        )
        self.db.put_bssid(state)

        # 1. Inject 15 deauth frames -> triggers DEAUTH_FLOOD (HIGH, 75 pts)
        for i in range(15):
            res_deauth = self.tracker.process_deauth_frame(wl_bssid, now_ts=100.0 + i * 0.1)
        self.assertTrue(res_deauth.is_anomaly)
        self.assertEqual(res_deauth.anomaly_type, "DEAUTH_FLOOD")
        self.assertEqual(res_deauth.risk_tier, "HIGH")

        # 2. Legitimate AP sends its normal beacon 100ms later (t=101.5)
        res_beacon = self.tracker.process_beacon_frame(
            bssid=wl_bssid,
            observed_ssid=wl_ssid,
            tag3_channel=6,
            seq_num=100,
            tsf_timestamp=10_000_000,
            now_ts=101.5,
        )
        # Verify the deauth flood alert is PRESERVED, not erased!
        self.assertTrue(res_beacon.is_anomaly)
        self.assertEqual(res_beacon.anomaly_type, "DEAUTH_FLOOD")
        self.assertEqual(res_beacon.risk_score, 75)
        self.assertEqual(res_beacon.risk_tier, "HIGH")

    # =========================================================================
    # Check 3.15: Same-Channel Collision Window Persists Across Interleaved Packets
    # =========================================================================
    def test_check_3_15_same_channel_collision_persists_across_interleaved_packets(self):
        """
        Check 3.15:
        1. Legitimate AP on Ch 6 at t=10.0 (Seq 1000).
        2. Rogue packet arrives on Ch 6 at t=10.05 (Seq 800) -> SAME_CHANNEL_COLLISION (HIGH, 75 pts).
        3. Legitimate packet arrives at t=10.10 (Seq 1001) -> Must remain HIGH (not erased after 50ms).
        4. Advance time by 16.0s (t=26.1) with clean packets -> Recovers to LOW (0 pts).
        """
        wl_bssid = "00:14:22:11:22:33"
        wl_ssid = "University Campus 5G"
        state = BSSIDState(
            bssid=wl_bssid,
            current_ssid=wl_ssid,
            is_whitelisted=1,
            primary_channel=6,
            active_channels_map={6: 10.0},
        )
        self.db.put_bssid(state)

        # 1. Clean beacon (Seq 1000)
        self.tracker.process_beacon_frame(wl_bssid, wl_ssid, 6, 1000, 10_000_000, now_ts=10.0)

        # 2. Rogue packet with backward seq (Seq 800)
        r2 = self.tracker.process_beacon_frame(wl_bssid, wl_ssid, 6, 800, 10_050_000, now_ts=10.05)
        self.assertTrue(r2.is_anomaly)
        self.assertEqual(r2.anomaly_type, "SAME_CHANNEL_COLLISION")
        self.assertEqual(r2.risk_score, 75)

        # 3. Next legitimate beacon 50ms later (Seq 1001)
        r3 = self.tracker.process_beacon_frame(wl_bssid, wl_ssid, 6, 1001, 10_100_000, now_ts=10.10)
        self.assertTrue(r3.is_anomaly, "Collision alert must NOT be wiped out 50ms later by legitimate packet!")
        self.assertEqual(r3.anomaly_type, "SAME_CHANNEL_COLLISION")
        self.assertEqual(r3.risk_score, 75)
        self.assertEqual(r3.risk_tier, "HIGH")

        # 4. Advance time by 16.0s without rogue packets
        r4 = self.tracker.process_beacon_frame(wl_bssid, wl_ssid, 6, 1161, 26_100_000, now_ts=26.10)
        self.assertFalse(r4.is_anomaly, "After 16s collision window expiry, AP must cleanly recover to LOW")
        self.assertEqual(r4.risk_score, 0)
        self.assertEqual(r4.risk_tier, "LOW")

    # =========================================================================
    # Check 3.16: Cross-Channel Interleaving Cannot Evade Sequence Collision
    # =========================================================================
    def test_check_3_16_cross_channel_interleaving_does_not_evade_seq_collision(self):
        """
        Check 3.16: Per-channel RF history prevents attacker from evading
        same-channel collision by interleaving packets on a second channel.
        """
        bssid = "00:11:22:33:77:88"
        ssid = "Campus_IoT"

        # 1. Legitimate AP on Ch 6: Seq 1000 at t=100.0
        self.tracker.process_beacon_frame(bssid, ssid, 6, 1000, 10_000_000, now_ts=100.0)

        # 2. Interleaved packet on Ch 1: Seq 500 at t=100.05
        self.tracker.process_beacon_frame(bssid, ssid, 1, 500, 10_000_000, now_ts=100.05)

        # 3. Rogue packet on Ch 6: Seq 200 (backward from 1000) at t=100.10
        r3 = self.tracker.process_beacon_frame(bssid, ssid, 6, 200, 10_000_000, now_ts=100.10)
        self.assertTrue(r3.details.get("is_seq_collision"), "Must detect sequence collision on Ch 6 despite Ch 1 packet")
        self.assertEqual(r3.risk_tier, "HIGH")

    # =========================================================================
    # Check 3.17: Deauth Frame Cannot Bypass 1-Hour Offline Probation Reset
    # =========================================================================
    def test_check_3_17_deauth_cannot_bypass_1hour_offline_reset(self):
        """
        Check 3.17: If an un-whitelisted AP went dark for > 1 hour (3,700s),
        injecting a deauth frame must reset first_seen_ts = now rather than
        refreshing last_seen_ts and spoofing continuous uptime.
        """
        bssid = "00:11:22:33:88:99"
        ssid = "Test_Department_AP"

        # 1. AP first seen at t=1000.0
        self.tracker.process_beacon_frame(bssid, ssid, 6, 100, 100_000, now_ts=1000.0)

        # 2. Advance clock by 3,700s (> 3600s). Attacker injects a deauth frame at t=4700.0
        self.tracker.process_deauth_frame(bssid, now_ts=4700.0)

        state = self.db.get_bssid(bssid)
        self.assertEqual(
            state.first_seen_ts,
            4700.0,
            "Deauth frame must enforce 1-hour offline reset, not preserve old first_seen_ts!"
        )

    # =========================================================================
    # Check 3.18: Probation Age Reports Broken Uptime When Offline > 1 Hour
    # =========================================================================
    def test_check_3_18_probation_age_when_offline_over_1hour(self):
        """
        Check 3.18: If an un-whitelisted AP has been offline for > 1 hour,
        is_probation_active must return True and get_probation_age must return 0.0
        even before a new beacon is received.
        """
        bssid = "00:11:22:33:99:aa"
        ssid = "Test_Probation_AP"

        # AP was active from t=0 to t=90,000 (continuous uptime > 24 hours)
        state = BSSIDState(
            bssid=bssid,
            current_ssid=ssid,
            is_whitelisted=0,
            first_seen_ts=0.0,
            last_seen_ts=90000.0,
        )
        self.db.put_bssid(state)

        # While online at t=90,000: probation inactive
        self.assertFalse(self.tracker.is_probation_active(bssid, now_ts=90000.0))

        # AP goes dark for 4,000s (now_ts = 94,000.0 > 90,000 + 3600):
        # Continuous uptime broken! Probation must be active again, age = 0.0
        self.assertTrue(self.tracker.is_probation_active(bssid, now_ts=94000.0))
        self.assertEqual(self.tracker.get_probation_age(bssid, now_ts=94000.0), 0.0)

    # =========================================================================
    # Check 3.19: Scapy Packet with RadioTap Wrapper Demux
    # =========================================================================
    def test_check_3_19_scapy_radiotap_frame_demux(self):
        """
        Check 3.19: Verify demux_frame correctly unpacks Dot11 layer
        when wrapped in RadioTap monitor-mode header.
        """
        class MockDot11:
            def __init__(self, subtype, addr3, tag3_channel, seq, tsf):
                self.type = 0
                self.subtype = subtype
                self.addr3 = addr3
                self.addr2 = addr3
                self.tag3_channel = tag3_channel
                self.seq = seq
                self.timestamp = tsf
                self.info = "Mock_Campus_SSID"

        class MockRadioTap:
            def __init__(self, dot11_layer):
                self._dot11 = dot11_layer

            def haslayer(self, layer_cls):
                return True

            def getlayer(self, layer_cls):
                return self._dot11

        mock_dot11 = MockDot11(subtype=8, addr3="00:14:22:44:55:66", tag3_channel=6, seq=100, tsf=1000)
        mock_radiotap = MockRadioTap(mock_dot11)

        res = self.tracker.demux_frame(mock_radiotap, now_ts=100.0)
        self.assertIsNotNone(res, "RadioTap wrapped Dot11 packet must not return None")
        self.assertEqual(res.bssid, "00:14:22:44:55:66")
        self.assertEqual(res.primary_channel, 6)


    # =========================================================================
    # Part 3 Remediation Tests
    # =========================================================================
    def test_check_3_20_mutated_whitelisted_ap_retains_risk(self):
        """
        Remediation 1: If a whitelisted AP has mutated its SSID (is_mutated == 1),
        it must NOT have its risk score cleared to 0 / LOW.
        """
        wl_bssid = "00:14:22:99:88:77"
        state = BSSIDState(
            bssid=wl_bssid,
            current_ssid="Evil_Campus_SSID",
            is_whitelisted=1,
            is_mutated=1,
            current_risk_score=45,
            risk_tier="MEDIUM",
            primary_channel=6,
            active_channels_map={6: 100.0},
            first_seen_ts=100.0,
            last_seen_ts=100.0,
        )
        self.db.put_bssid(state)

        # Process a beacon without collision or deauth anomaly
        res = self.tracker.process_beacon_frame(
            bssid=wl_bssid,
            observed_ssid="Evil_Campus_SSID",
            tag3_channel=6,
            seq_num=10,
            tsf_timestamp=2000000,
            now_ts=101.0,
        )
        self.assertEqual(res.risk_score, 45)
        self.assertEqual(res.risk_tier, "MEDIUM")
        fetched = self.db.get_bssid(wl_bssid)
        self.assertEqual(fetched.current_risk_score, 45)
        self.assertEqual(fetched.risk_tier, "MEDIUM")

    def test_check_3_21_large_sequence_jump_disambiguation(self):
        """
        Remediation 2: When (prev_seq - seq_num) % 4096 < 2048, do not flag collision
        if time gap >= 10.0s UNLESS TSF collision is confirmed.
        """
        bssid = "00:50:56:11:22:33"
        # Initial beacon: seq 100, tsf 1,000,000 at t=10.0
        self.tracker.process_beacon_frame(bssid, "Normal_AP", 6, 100, 1000000, now_ts=10.0)

        # Advance by 12 seconds (time_gap = 12.0 >= 10.0s).
        # Normal AP transmitted 2500 frames while unwatched -> seq jumps from 100 to 2600.
        # (100 - 2600) % 4096 = (-2500) % 4096 = 1596 < 2048.
        # TSF increases forward legitimately: 1,000,000 -> 13,000,000
        res = self.tracker.process_beacon_frame(bssid, "Normal_AP", 6, 2600, 13000000, now_ts=22.0)
        self.assertFalse(res.is_anomaly, "Large forward jump after >= 10s without TSF regression must not flag collision")
        self.assertNotEqual(res.anomaly_type, "SAME_CHANNEL_COLLISION")

        # But if TSF also regressed, flag collision!
        res_regress = self.tracker.process_beacon_frame(bssid, "Normal_AP", 6, 1100, 500000, now_ts=35.0)
        self.assertTrue(res_regress.is_anomaly, "Large jump with TSF regression must flag collision")
        self.assertEqual(res_regress.anomaly_type, "SAME_CHANNEL_COLLISION")

    def test_check_3_22_uninitialized_ap_probation_guard(self):
        """
        Remediation 3: An uninitialized AP in DB (never observed, or first_seen_ts == 0.0)
        must return is_probation_active == True and get_probation_age == 0.0.
        """
        uninit_bssid = "00:de:ad:be:ef:01"
        state = BSSIDState(
            bssid=uninit_bssid,
            current_ssid="",
            first_seen_ts=0.0,
            last_seen_ts=0.0,
            active_channels_map={},
        )
        self.db.put_bssid(state)
        self.assertTrue(self.tracker.is_probation_active(uninit_bssid, now_ts=1000.0))
        self.assertEqual(self.tracker.get_probation_age(uninit_bssid, now_ts=1000.0), 0.0)

        # None state also returns True
        self.assertTrue(self.tracker.is_probation_active("00:00:00:00:00:00", now_ts=1000.0))
        self.assertEqual(self.tracker.get_probation_age("00:00:00:00:00:00", now_ts=1000.0), 0.0)

    def test_check_3_23_deauth_windows_bounded_memory(self):
        """
        Remediation 4: When all deauth timestamps expire (> 60s), the BSSID key is popped
        from _deauth_windows to avoid memory leaks.
        """
        bssid = "00:11:22:33:44:55"
        self.tracker.process_deauth_frame(bssid, now_ts=100.0)
        self.assertIn("00:11:22:33:44:55", self.tracker._deauth_windows)

        # Query count after 70 seconds -> all timestamps expired
        count = self.tracker.get_deauth_count(bssid, 60.0, now_ts=175.0)
        self.assertEqual(count, 0)
        self.assertNotIn("00:11:22:33:44:55", self.tracker._deauth_windows)

    def test_check_3_24_deauth_windows_scale_prune(self):
        """
        Remediation 4b: Verify automatic sweep of expired deauth windows when tracked BSSIDs exceed 512.
        """
        # Populate 600 BSSIDs at t = 10.0
        for i in range(600):
            bssid = f"00:99:{i//256:02x}:{i%256:02x}:00:01"
            self.tracker.process_deauth_frame(bssid, now_ts=10.0)

        # Now send 1 frame at t = 100.0 (past 60s expiration). The sweep should prune the 600 expired BSSIDs!
        self.tracker.process_deauth_frame("00:99:ff:ff:ff:ff", now_ts=100.0)
        self.assertLessEqual(len(self.tracker._deauth_windows), 10)


if __name__ == "__main__":
    unittest.main()

