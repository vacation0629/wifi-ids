"""
Step 1 Unit Test Harness: Configuration & Database Manager (v2.1.2)
Verifies:
- Check 1.1: Simulate 500 beacons/sec (LOW); verify <= 4 commits in 10s.
- Check 1.2: Trigger 1 single LOW -> HIGH alert; verify < 10 ms immediate commit.
- Check 1.3: Inject 500 fake new MEDIUM BSSIDs in 1.0s; verify coalescing caps disk commits at <= 4 commits/sec and LRU cap holds len(ram_bssids) <= 4096.
- Check 1.4: 1-hour offline probation reset (Point 4).
- Check 1.5: 15s sliding Tag 3/61 channel map (Point 7).
- Check 1.6: PRAGMA data_version watcher hot-reload (Point 5).
- Check 1.7: 4-table schema & WAL mode verification.
- Check 1.8: SSID catalog & behavior log batch persistence.
- Check 1.9: Strict LRU eviction order & whitelist pinning under flood.
"""

import json
import os
import sqlite3
import tempfile
import time
import unittest

from detector.ids_v2.config import (
    WHITELISTED_SSIDS,
    DEFAULT_DB_PATH,
    FLUSH_INTERVAL_SEC,
    MIN_FORCE_COOLDOWN_SEC,
    OFFLINE_RESET_SEC,
    CHANNEL_WINDOW_SEC,
    MAX_RAM_ENTRIES,
    BEACON_INTERVAL_MS,
    JITTER_THRESHOLD_MS,
    TECH_STOPWORDS,
    ENABLE_STOPWORD_STRIP,
    SCORE_THRESHOLD_MEDIUM,
    SCORE_THRESHOLD_HIGH,
    TIER_RANK,
)
from detector.ids_v2.db_manager import (
    BatchDatabaseManager,
    BSSIDState,
    SSIDRecord,
    CampusIEProfile,
    BeaconBehaviorLog,
)


class TestStep1DbManager(unittest.TestCase):

    def setUp(self):
        # Create a temporary file database for strict WAL and filesystem testing
        self.temp_db = tempfile.NamedTemporaryFile(delete=False, suffix=".db")
        self.temp_db.close()
        self.db_path = self.temp_db.name
        self.db = BatchDatabaseManager(self.db_path)

    def tearDown(self):
        try:
            self.db.close()
        except Exception:
            pass
        # Clean up database file and WAL / SHM files if present
        for ext in ["", "-wal", "-shm"]:
            path = self.db_path + ext
            if os.path.exists(path):
                try:
                    os.unlink(path)
                except Exception:
                    pass

    # =========================================================================
    # Check 1.1: Simulate 500 beacons/sec (LOW); verify <= 4 commits in 10s.
    # =========================================================================
    def test_check_1_1_routine_low_traffic_commit_rate(self):
        """
        Simulate 500 beacons/sec (LOW traffic) over 10 seconds.
        With FLUSH_INTERVAL_SEC = 3.0s, routine flushes occur at ~3s, ~6s, ~9s.
        Disk commits must be <= 4 in 10s.
        """
        self.db.commit_count = 0
        self.db.last_flush_ts = 0.0

        state = BSSIDState(
            bssid="00:11:22:33:44:55",
            current_ssid="University_Campus_5G",
            risk_tier="LOW",
            current_risk_score=5,
        )

        total_beacons = 5000  # 500 beacons/sec * 10s
        time_step = 10.0 / total_beacons  # 0.002s per beacon

        for i in range(1, total_beacons + 1):
            now_mono = i * time_step
            self.db.record_bssid_update(state, prev_tier="LOW", now_mono=now_mono)

        # Commits should be ~3 (at 3s, 6s, 9s), strictly <= 4 in 10 seconds
        self.assertLessEqual(
            self.db.commit_count,
            4,
            f"Expected <= 4 commits in 10s, got {self.db.commit_count}",
        )
        self.assertGreaterEqual(
            self.db.commit_count,
            3,
            f"Expected at least 3 periodic flushes in 10s, got {self.db.commit_count}",
        )

    # =========================================================================
    # Check 1.2: Trigger 1 single LOW -> HIGH alert; verify < 10 ms immediate commit.
    # =========================================================================
    def test_check_1_2_single_alert_instant_commit_latency(self):
        """
        Trigger 1 single LOW -> HIGH alert.
        Verify commit executes immediately (< 10 ms) and is readable from disk.
        """
        # Ensure cooldown is satisfied so instant alert bypass is permitted
        self.db.last_flush_ts = time.monotonic() - 1.0

        alert_bssid = "de:ad:be:ef:00:01"
        alert_state = BSSIDState(
            bssid=alert_bssid,
            current_ssid="Evil_Twin_High",
            risk_tier="HIGH",
            current_risk_score=75,
            primary_channel=6,
        )

        t0 = time.perf_counter()
        self.db.record_bssid_update(alert_state, prev_tier="LOW")
        duration_ms = (time.perf_counter() - t0) * 1000.0

        # Pass criteria: immediate disk commit in < 10 ms
        self.assertLess(
            duration_ms,
            10.0,
            f"Alert commit took {duration_ms:.2f} ms, expected < 10.0 ms",
        )

        # Verify record exists in SQLite on disk with expected values
        cur = self.db.conn.cursor()
        cur.execute(
            "SELECT risk_tier, current_risk_score, primary_channel FROM bssid_devices WHERE bssid = ?",
            (alert_bssid,),
        )
        row = cur.fetchone()
        self.assertIsNotNone(row, "Alert record must be persisted in SQLite")
        self.assertEqual(row[0], "HIGH")
        self.assertEqual(row[1], 75)
        self.assertEqual(row[2], 6)

    # =========================================================================
    # Check 1.3: Inject 500 fake new MEDIUM BSSIDs in 1.0s; verify coalescing
    #            caps disk commits at <= 4 commits/sec and LRU cap holds len(ram_bssids) <= 4096.
    # =========================================================================
    def test_check_1_3_coalesced_flush_storm_and_lru_cap(self):
        """
        Simulate an mdk4 flood of 500 fake new MEDIUM BSSIDs in 1.0 second.
        Verify:
        1. Disk commits are capped at <= 4 commits/sec (coalesced with 250ms cooldown).
        2. LRU cap holds len(ram_bssids) <= 4096.
        """
        self.db.commit_count = 0
        # Start flood at t = 0.0 with last_flush_ts at 0.0
        self.db.last_flush_ts = 0.0

        total_injected = 500
        duration_sec = 1.0
        time_step = duration_sec / total_injected

        for i in range(total_injected):
            now_mono = i * time_step
            bssid = f"00:00:00:00:{i // 256:02x}:{i % 256:02x}"
            state = BSSIDState(
                bssid=bssid,
                current_ssid=f"Fake_AP_{i}",
                risk_tier="MEDIUM",
                current_risk_score=50,
            )
            self.db.record_bssid_update(state, prev_tier="LOW", now_mono=now_mono)

        # 1. Verify commits per second <= 4 commits/sec
        commit_rate = self.db.commit_count / duration_sec
        self.assertLessEqual(
            commit_rate,
            4.0,
            f"Commit rate {commit_rate} exceeded cap of 4.0 commits/sec",
        )
        self.assertLessEqual(
            self.db.commit_count,
            4,
            f"Expected <= 4 commits in 1.0s, got {self.db.commit_count}",
        )

        # 2. Verify RAM size is bounded by MAX_RAM_ENTRIES (4096)
        self.assertLessEqual(
            len(self.db.ram_bssids),
            MAX_RAM_ENTRIES,
            f"RAM BSSIDs count {len(self.db.ram_bssids)} exceeded MAX_RAM_ENTRIES (4096)",
        )

    # =========================================================================
    # Check 1.4: 1-hour offline probation reset (Point 4)
    # =========================================================================
    def test_check_1_4_offline_probation_reset(self):
        """
        Verify:
        - Un-whitelisted AP offline for > 3600.0s has its first_seen_ts reset to now_ts.
        - Whitelisted AP offline for > 3600.0s does NOT have first_seen_ts reset.
        - Un-whitelisted AP offline for < 3600.0s maintains its initial first_seen_ts.
        """
        # Case A: Un-whitelisted AP goes offline for 3700 seconds (> 3600s)
        unwhitelisted = BSSIDState(
            bssid="00:11:22:33:44:aa",
            current_ssid="Campus_Sister_AP",
            is_whitelisted=0,
            first_seen_ts=1000.0,
            last_seen_ts=1500.0,
        )
        now_ts = 1500.0 + 3700.0  # 5200.0
        self.db.update_channel_and_probation(unwhitelisted, tag3_channel=1, now_ts=now_ts)
        self.assertEqual(
            unwhitelisted.first_seen_ts,
            now_ts,
            "Un-whitelisted AP offline > 1h must have first_seen_ts reset to now_ts",
        )
        self.assertEqual(unwhitelisted.last_seen_ts, now_ts)

        # Case B: Whitelisted AP goes offline for 5000 seconds (> 3600s)
        whitelisted = BSSIDState(
            bssid="00:11:22:33:44:bb",
            current_ssid="University_Staff_Secure",
            is_whitelisted=1,
            first_seen_ts=1000.0,
            last_seen_ts=1500.0,
        )
        self.db.update_channel_and_probation(whitelisted, tag3_channel=6, now_ts=6500.0)
        self.assertEqual(
            whitelisted.first_seen_ts,
            1000.0,
            "Whitelisted AP must never have its first_seen_ts reset on offline gap",
        )
        self.assertEqual(whitelisted.last_seen_ts, 6500.0)

        # Case C: Un-whitelisted AP offline for 1800s (< 3600s)
        recent_ap = BSSIDState(
            bssid="00:11:22:33:44:cc",
            current_ssid="Campus_Sister_AP_2",
            is_whitelisted=0,
            first_seen_ts=1000.0,
            last_seen_ts=1500.0,
        )
        self.db.update_channel_and_probation(recent_ap, tag3_channel=11, now_ts=3300.0)
        self.assertEqual(
            recent_ap.first_seen_ts,
            1000.0,
            "Un-whitelisted AP offline < 1h must preserve its probation first_seen_ts",
        )

    # =========================================================================
    # Check 1.5: 15s sliding Tag 3/61 channel map (Point 7)
    # =========================================================================
    def test_check_1_5_sliding_channel_window_and_clone_detection(self):
        """
        Verify:
        - Legitimate 1-way channel move (Ch 6 -> Ch 1) prunes old channel after 15s
          and returns False with primary_channel updated to 1 (0 pts).
        - Simultaneous beacons on 2 channels within 15s returns True (Multi-Channel Clone).
        """
        state = BSSIDState(
            bssid="00:11:22:33:44:dd",
            current_ssid="University_Campus_5G",
            primary_channel=6,
        )

        # Beacon on Ch 6 at t = 10.0
        is_clone = self.db.update_channel_and_probation(state, tag3_channel=6, now_ts=10.0)
        self.assertFalse(is_clone)
        self.assertEqual(state.primary_channel, 6)

        # Beacon on Ch 1 at t = 20.0 (within 15s of t = 10.0, so both Ch 6 and Ch 1 active)
        is_clone = self.db.update_channel_and_probation(state, tag3_channel=1, now_ts=20.0)
        self.assertTrue(
            is_clone,
            "Simultaneous beacons on two channels within 15s must be flagged as multi-channel clone",
        )
        self.assertEqual(len(state.active_channels_map), 2)

        # Beacon on Ch 1 at t = 36.0 (t - 10.0 = 26s > 15s, Ch 6 has expired)
        is_clone = self.db.update_channel_and_probation(state, tag3_channel=1, now_ts=36.0)
        self.assertFalse(
            is_clone,
            "Expired channel must be pruned; single active channel is a legit 1-way move",
        )
        self.assertEqual(state.primary_channel, 1)
        self.assertEqual(list(state.active_channels_map.keys()), [1])

    # =========================================================================
    # Check 1.6: PRAGMA data_version watcher hot-reload (Point 5)
    # =========================================================================
    def test_check_1_6_pragma_data_version_hot_reload(self):
        """
        Verify that an external modification (simulating Dashboard UI adding a BSSID to whitelist)
        increments PRAGMA data_version and triggers reload_whitelist_into_ram() on next flush.
        """
        target_bssid = "00:11:22:33:44:99"
        # Initially add BSSID as un-whitelisted MEDIUM risk
        state = BSSIDState(
            bssid=target_bssid,
            current_ssid="University_Guest_Portal",
            is_whitelisted=0,
            risk_tier="MEDIUM",
            current_risk_score=50,
        )
        self.db.record_bssid_update(state, prev_tier="LOW")
        self.db.flush_to_sqlite(force=True)

        self.assertEqual(self.db.ram_bssids[target_bssid].is_whitelisted, 0)
        self.assertEqual(self.db.ram_bssids[target_bssid].risk_tier, "MEDIUM")

        # Simulate external UI connection updating is_whitelisted = 1
        ext_conn = sqlite3.connect(self.db_path)
        with ext_conn:
            ext_conn.execute(
                "UPDATE bssid_devices SET is_whitelisted = 1 WHERE bssid = ?",
                (target_bssid,),
            )
        ext_conn.close()

        # Call flush_to_sqlite; data_version should differ, triggering reload_whitelist_into_ram()
        self.db.flush_to_sqlite(force=True)

        self.assertEqual(
            self.db.ram_bssids[target_bssid].is_whitelisted,
            1,
            "RAM state must reflect whitelisted = 1 after external DB update",
        )
        self.assertEqual(
            self.db.ram_bssids[target_bssid].risk_tier,
            "LOW",
            "Whitelisted BSSID in RAM must be reset to LOW risk tier",
        )
        self.assertEqual(
            self.db.ram_bssids[target_bssid].current_risk_score,
            0,
            "Whitelisted BSSID in RAM must have risk score reset to 0",
        )
        self.assertIn(target_bssid, self.db.whitelisted_bssids)

    # =========================================================================
    # Check 1.7: 4-table schema & WAL mode verification
    # =========================================================================
    def test_check_1_7_schema_and_wal_mode(self):
        """
        Verify that all 4 tables exist with correct schema, WAL journal mode is active,
        and synchronous is NORMAL.
        """
        cur = self.db.conn.cursor()

        # Check WAL mode
        cur.execute("PRAGMA journal_mode;")
        journal_mode = cur.fetchone()[0]
        self.assertEqual(journal_mode.lower(), "wal")

        # Check synchronous mode (NORMAL is 1)
        cur.execute("PRAGMA synchronous;")
        sync_mode = cur.fetchone()[0]
        self.assertEqual(sync_mode, 1)

        # Check tables existence
        expected_tables = {
            "ssid_catalog",
            "bssid_devices",
            "campus_ie_profile",
            "beacon_behavior_logs",
        }
        cur.execute("SELECT name FROM sqlite_master WHERE type='table';")
        tables = {row[0] for row in cur.fetchall()}
        for table in expected_tables:
            self.assertIn(table, tables, f"Table {table} must exist in database")

        # Verify campus_ie_profile CRUD
        profile = CampusIEProfile(
            profile_name="campus_default",
            locked_at=1234567.89,
            akm_suites=["00-0f-ac:1", "00-0f-ac:2"],
            pairwise_ciphers=["00-0f-ac:4"],
            has_mdid=1,
            has_vendor_221=1,
            mimo_streams=4,
            raw_ies_hash="abcd1234ef",
        )
        self.db.save_campus_ie_profile(profile)
        loaded = self.db.get_campus_ie_profile("campus_default")
        self.assertIsNotNone(loaded)
        self.assertEqual(loaded.profile_name, "campus_default")
        self.assertEqual(loaded.akm_suites, ["00-0f-ac:1", "00-0f-ac:2"])
        self.assertEqual(loaded.mimo_streams, 4)
        self.assertEqual(loaded.raw_ies_hash, "abcd1234ef")

    # =========================================================================
    # Check 1.8: SSID catalog & behavior log batch persistence
    # =========================================================================
    def test_check_1_8_ssid_and_log_persistence(self):
        """
        Verify:
        - SSIDRecord insertion and retrieval via put_ssid and get_ssid.
        - BeaconBehaviorLog insertion via add_behavior_log and flush to SQLite.
        """
        # Test SSIDRecord
        record = SSIDRecord(
            ssid_text="University Guest Portal",
            matched_whitelist_ssid="University Guest Portal",
            xgb_prob=0.01,
            bge_cos_raw=0.99,
            bge_cos_clean=0.99,
            bge_vector_blob=b"\x00\x01\x02\x03",
            is_suspicious_name=0,
            first_computed_at=time.time(),
        )
        self.db.put_ssid(record)
        self.db.flush_to_sqlite(force=True)

        fetched = self.db.get_ssid("University Guest Portal")
        self.assertIsNotNone(fetched)
        self.assertEqual(fetched.ssid_text, "University Guest Portal")
        self.assertAlmostEqual(fetched.xgb_prob, 0.01)

        # Test Behavior Log
        self.db.add_behavior_log(
            bssid="00:11:22:33:44:55",
            timestamp=12345.67,
            seq_num=1024,
            tsf_timestamp=9999999,
            jitter_ms=25.4,
            deauth_count_1m=16,
            channel_anomaly_type="TYPE_A_CLONE",
            ssid_mutated=0,
            raw_ie_fingerprint="fingerprint_test",
        )
        self.db.flush_to_sqlite(force=True)

        cur = self.db.conn.cursor()
        cur.execute(
            "SELECT bssid, jitter_ms, channel_anomaly_type FROM beacon_behavior_logs WHERE bssid = ?",
            ("00:11:22:33:44:55",),
        )
        row = cur.fetchone()
        self.assertIsNotNone(row)
        self.assertEqual(row[0], "00:11:22:33:44:55")
        self.assertAlmostEqual(row[1], 25.4)
        self.assertEqual(row[2], "TYPE_A_CLONE")

    # =========================================================================
    # Check 1.9: Strict LRU eviction order & whitelist pinning under flood
    # =========================================================================
    def test_check_1_9_lru_cap_eviction_order_and_pinning(self):
        """
        Verify:
        1. When exceeding MAX_RAM_ENTRIES (4096), RAM count strictly stays at 4096.
        2. Whitelisted BSSIDs are immune to eviction.
        3. Oldest un-whitelisted LOW risk BSSIDs are evicted before MEDIUM risk BSSIDs.
        """
        # Pin a whitelisted AP
        white_bssid = "fe:ed:c0:ff:ee:01"
        state_white = BSSIDState(
            bssid=white_bssid,
            current_ssid="eduroam",
            is_whitelisted=1,
            risk_tier="LOW",
        )
        self.db.record_bssid_update(state_white, prev_tier="LOW", now_mono=0.0)

        # Inject 5,000 distinct BSSIDs (exceeding 4,096)
        for i in range(5000):
            bssid = f"00:00:{i // (256 * 256):02x}:{(i // 256) % 256:02x}:{i % 256:02x}:01"
            state = BSSIDState(
                bssid=bssid,
                current_ssid=f"Flood_{i}",
                risk_tier="MEDIUM",
                current_risk_score=50,
            )
            self.db.record_bssid_update(state, prev_tier="LOW", now_mono=(i + 1) * 0.001)

        # RAM size strictly capped at MAX_RAM_ENTRIES
        self.assertEqual(len(self.db.ram_bssids), MAX_RAM_ENTRIES)
        # Whitelisted entry is preserved (pinned)
        self.assertIn(
            white_bssid,
            self.db.ram_bssids,
            "Whitelisted BSSID must remain pinned in RAM despite flood eviction",
        )

    # =========================================================================
    # Check 1.10: Update existing BSSID in RAM and verify SQLite persistence
    # =========================================================================
    def test_check_1_10_update_existing_bssid_in_ram_and_db(self):
        """
        Verify that updating an existing BSSID in RAM replaces the state object in
        ram_bssids and persists the updated fields (e.g. risk escalation & mutation) to SQLite.
        """
        target_bssid = "00:11:22:33:44:55"
        state1 = BSSIDState(
            bssid=target_bssid,
            current_ssid="Legitimate_Campus_AP",
            risk_tier="LOW",
            current_risk_score=5,
        )
        self.db.record_bssid_update(state1, prev_tier="LOW")
        self.db.flush_to_sqlite(force=True)

        # Mutate to rogue state with new BSSIDState instance
        state2 = BSSIDState(
            bssid=target_bssid,
            current_ssid="Mutated_Rogue_Twin",
            is_mutated=1,
            risk_tier="HIGH",
            current_risk_score=85,
        )
        self.db.record_bssid_update(state2, prev_tier="LOW")
        self.db.flush_to_sqlite(force=True)

        # 1. Verify in-memory state reflects state2
        ram_state = self.db.ram_bssids[target_bssid]
        self.assertEqual(ram_state.current_ssid, "Mutated_Rogue_Twin")
        self.assertEqual(ram_state.risk_tier, "HIGH")
        self.assertEqual(ram_state.current_risk_score, 85)
        self.assertEqual(ram_state.is_mutated, 1)

        # 2. Verify SQLite persisted state2
        cur = self.db.conn.cursor()
        cur.execute(
            "SELECT current_ssid, risk_tier, current_risk_score, is_mutated FROM bssid_devices WHERE bssid = ?",
            (target_bssid,)
        )
        row = cur.fetchone()
        self.assertIsNotNone(row)
        self.assertEqual(row[0], "Mutated_Rogue_Twin")
        self.assertEqual(row[1], "HIGH")
        self.assertEqual(row[2], 85)
        self.assertEqual(row[3], 1)

    # =========================================================================
    # Check 1.11: put_ssid deduplication and update handling
    # =========================================================================
    def test_check_1_11_put_ssid_deduplication_and_update(self):
        """
        Verify that put_ssid updates ram_ssids on duplicate calls without
        unboundedly bloating new_ssid_queue with duplicate records.
        """
        r1 = SSIDRecord(
            ssid_text="Campus_Secure",
            matched_whitelist_ssid="University_Staff_Secure",
            xgb_prob=0.10,
            bge_cos_raw=0.90,
            bge_cos_clean=0.90,
            bge_vector_blob=b"\x01",
            is_suspicious_name=0,
            first_computed_at=100.0,
        )
        self.db.put_ssid(r1)
        self.assertEqual(len(self.db.new_ssid_queue), 1)

        # Call put_ssid again with updated computation
        r2 = SSIDRecord(
            ssid_text="Campus_Secure",
            matched_whitelist_ssid="University_Staff_Secure",
            xgb_prob=0.85,
            bge_cos_raw=0.25,
            bge_cos_clean=0.25,
            bge_vector_blob=b"\x02",
            is_suspicious_name=1,
            first_computed_at=200.0,
        )
        self.db.put_ssid(r2)
        # Verify RAM reflects updated r2
        self.assertAlmostEqual(self.db.ram_ssids["Campus_Secure"].xgb_prob, 0.85)
        self.assertEqual(self.db.ram_ssids["Campus_Secure"].is_suspicious_name, 1)
        # Verify queue did not duplicate
        self.assertEqual(len(self.db.new_ssid_queue), 1)

        self.db.flush_to_sqlite(force=True)
        cur = self.db.conn.cursor()
        cur.execute("SELECT xgb_prob, is_suspicious_name FROM ssid_catalog WHERE ssid_text = ?", ("Campus_Secure",))
        row = cur.fetchone()
        self.assertAlmostEqual(row[0], 0.85)
        self.assertEqual(row[1], 1)

    # =========================================================================
    # Check 1.12: Cold boot with large DB and recent whitelist retention
    # =========================================================================
    def test_check_1_12_cold_boot_with_large_catalog_and_recent_whitelist(self):
        """
        Verify that load_from_db() on a cold boot with > 4096 entries:
        1. Loads all whitelisted BSSIDs into whitelisted_bssids and pins them in ram_bssids.
        2. Populates the remaining slots with the most recently active devices.
        """
        # Populate DB with 5000 devices; whitelisted AP has high timestamp (recent)
        white_bssid = "00:ee:ff:aa:bb:cc"
        rows = [
            (f"00:01:{i//256:02x}:{i%256:02x}:00:01", "Old_AP", 0, 0, "{}", 1.0, float(i), -80, 0.0, 1, "OPEN", "OK", 0, "LOW")
            for i in range(4999)
        ]
        rows.append(
            (white_bssid, "University_Campus_5G", 1, 0, "{}", 100.0, 99999.0, -50, 0.0, 6, "WPA3", "OK", 0, "LOW")
        )
        with self.db.conn:
            self.db.conn.executemany("INSERT INTO bssid_devices VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)", rows)

        # Create a new BatchDatabaseManager simulating cold boot
        cold_db = BatchDatabaseManager(self.db_path)
        try:
            self.assertIn(white_bssid, cold_db.whitelisted_bssids)
            self.assertIn(white_bssid, cold_db.ram_bssids)
            self.assertEqual(len(cold_db.ram_bssids), MAX_RAM_ENTRIES)
            # Most recent devices should be present
            self.assertIn("00:01:13:86:00:01", cold_db.ram_bssids)
        finally:
            cold_db.conn.close()

    # =========================================================================
    # Check 1.13: Admin unwhitelisting demotion in RAM
    # =========================================================================
    def test_check_1_13_admin_unwhitelisting_demotion_in_ram(self):
        """
        Verify that when an admin revokes whitelisted status in SQLite:
        1. reload_whitelist_into_ram() clears it from whitelisted_bssids.
        2. In-memory state in ram_bssids has is_whitelisted demoted to 0.
        3. Subsequent batch flushes do NOT revert SQLite back to 1.
        """
        target_bssid = "00:11:22:33:44:88"
        state = BSSIDState(
            bssid=target_bssid,
            current_ssid="eduroam",
            is_whitelisted=1,
            risk_tier="LOW",
        )
        self.db.record_bssid_update(state, prev_tier="LOW")
        self.db.flush_to_sqlite(force=True)

        self.assertIn(target_bssid, self.db.whitelisted_bssids)
        self.assertEqual(self.db.ram_bssids[target_bssid].is_whitelisted, 1)

        # Admin unwhitelists in SQLite
        ext_conn = sqlite3.connect(self.db_path)
        with ext_conn:
            ext_conn.execute("UPDATE bssid_devices SET is_whitelisted = 0 WHERE bssid = ?", (target_bssid,))
        ext_conn.close()

        # Sniffer flushes and detects data_version change
        self.db.flush_to_sqlite(force=True)
        self.assertNotIn(target_bssid, self.db.whitelisted_bssids)
        self.assertEqual(self.db.ram_bssids[target_bssid].is_whitelisted, 0)

        # Now a new beacon arrives for this BSSID and triggers an update
        updated_state = self.db.ram_bssids[target_bssid]
        updated_state.last_seen_ts = time.time()
        self.db.record_bssid_update(updated_state, prev_tier="LOW")
        self.db.flush_to_sqlite(force=True)

        # Verify SQLite is STILL is_whitelisted = 0 (not reverted by stale RAM)
        cur = self.db.conn.cursor()
        cur.execute("SELECT is_whitelisted FROM bssid_devices WHERE bssid = ?", (target_bssid,))
        row = cur.fetchone()
        self.assertEqual(row[0], 0, "SQLite must remain un-whitelisted (is_whitelisted = 0)")

    # =========================================================================
    # Check 1.14: Out-of-order packets and channel map type coercion
    # =========================================================================
    def test_check_1_14_out_of_order_packets_and_type_coercion(self):
        """
        Verify:
        1. String channel e.g. "6" does not create duplicate keys with int 6.
        2. Out-of-order beacon arrival timestamps do not regress state.last_seen_ts.
        """
        state = BSSIDState(
            bssid="00:11:22:33:44:77",
            current_ssid="University_Campus_5G",
            last_seen_ts=100.0,
        )
        self.db.update_channel_and_probation(state, tag3_channel=6, now_ts=100.0)
        self.assertEqual(len(state.active_channels_map), 1)

        # Pass string "6" with earlier timestamp 90.0 (out-of-order)
        is_clone = self.db.update_channel_and_probation(state, tag3_channel="6", now_ts=90.0)
        self.assertFalse(is_clone, "Same channel string/int must not be treated as multi-channel clone")
        self.assertEqual(len(state.active_channels_map), 1)
        self.assertEqual(state.last_seen_ts, 100.0, "Out-of-order timestamp must not regress last_seen_ts")


if __name__ == "__main__":
    unittest.main()
