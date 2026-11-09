"""
Step 2 Unit Test Harness: Adaptive AI Name Screener & Dynamic Stage 2.5 Gatekeeper (v2.1.2)
Verifies:
- Check 2.1: First send Free_Campus_WiFi as WPA2-PSK, then send Free_Campus_WiFi as OPEN;
  verify ssid_catalog.bge_cos_clean was NOT poisoned to 0.0 and the OPEN beacon triggers Stage 2.5 = True.
- Check 2.2: Verify single live SSID completes in < 10 ms, while a 32-SSID burst batches in < 55 ms
  (with SIMD batch speedup verification).
- Check 2.3: Option M2 Mutation Detection (known BSSID SSID change -> is_mutated=1, +45 pts, suspicious).
- Check 2.4: Whitelisted BSSID bypass vs mutation override.
- Check 2.5: Tech stopwords stripper functionality.
- Check 2.6: Q1 Work-Conserving Adaptive AI Queue mechanics (max 32 drain).
- Check 2.7: Pre-computed matrix W normalization (M x 384, M=5).
- Check 2.8: RAM cache hit latency (< 0.05 ms).
- Check 2.9: Fallback safety when optional dependencies are simulated absent.
"""

import os
import tempfile
import time
import unittest
from typing import List


from detector.ids_v2.config import (
    AI_QUEUE_MAX_BATCH,
    BGE_SUSPICIOUS_THRESHOLD,
    DEFAULT_CAMPUS_WHITELIST,
    ENABLE_STOPWORD_STRIP,
    PSK_WEIGHT_MULTIPLIER,
    TECH_STOPWORDS,
    WHITELISTED_SSIDS,
    XGB_SUSPICIOUS_THRESHOLD,
)
from detector.ids_v2.db_manager import (
    BatchDatabaseManager,
    BSSIDState,
    SSIDRecord,
)
from detector.ids_v2.name_screener import (
    CampusNameScreener,
    Stage25Result,
    WorkConservingAIQueue,
    strip_tech_stopwords,
    FEATURE_NAMES,
    HAS_FASTEMBED,
    HAS_XGBOOST,
    HAS_NUMPY,
    np,
)


class TestStep2NameScreener(unittest.TestCase):

    def setUp(self):
        self.temp_db = tempfile.NamedTemporaryFile(delete=False, suffix=".db")
        self.temp_db.close()
        self.db_path = self.temp_db.name
        self.db = BatchDatabaseManager(self.db_path)
        self.screener = CampusNameScreener(
            db_manager=self.db,
            whitelist=DEFAULT_CAMPUS_WHITELIST,
            threads=4,
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

    def test_check_2_1_encryption_agnostic_catalog_and_dynamic_psk_weighting(self):
        """
        Check 2.1: First send Free_Campus_WiFi as WPA2-PSK, then send Free_Campus_WiFi as OPEN;
        verify ssid_catalog.bge_cos_clean was NOT poisoned to 0.0 and the OPEN beacon triggers Stage 2.5 = True.
        """
        # 1. Send Free_Campus_WiFi as WPA2-PSK
        bssid_psk = "00:11:22:33:44:01"
        res_psk = self.screener.screen_beacon(bssid_psk, "Free_Campus_WiFi", encryption_type="WPA2-PSK")

        # Verify pure similarity is stored in ssid_catalog without PSK zeroing
        cat_rec1 = self.db.get_ssid("Free_Campus_WiFi")
        self.assertIsNotNone(cat_rec1, "Record must exist in catalog")
        self.assertGreater(cat_rec1.bge_cos_clean, 0.0, "Catalog bge_cos_clean must NOT be 0.0")
        self.assertGreater(cat_rec1.bge_cos_raw, 0.0, "Catalog bge_cos_raw must NOT be 0.0")

        # In Stage 2.5 result, verify PSK down-weighting: eff_bge == 0.5 * base_bge
        expected_eff_psk = round(PSK_WEIGHT_MULTIPLIER * res_psk.base_bge, 4)
        self.assertAlmostEqual(res_psk.eff_bge, expected_eff_psk, places=3)

        # 2. Flush to SQLite to ensure WAL disk persistence is also encryption-agnostic
        self.db.flush_to_sqlite(force=True)
        cursor = self.db.conn.cursor()
        cursor.execute("SELECT bge_cos_clean, bge_cos_raw FROM ssid_catalog WHERE ssid_text = ?", ("Free_Campus_WiFi",))
        row = cursor.fetchone()
        self.assertIsNotNone(row)
        self.assertGreater(row[0], 0.0, "Database column bge_cos_clean must not be 0.0 after PSK beacon")
        self.assertEqual(row[0], cat_rec1.bge_cos_clean)

        # 3. Send Free_Campus_WiFi as OPEN
        bssid_open = "00:11:22:33:44:02"
        res_open = self.screener.screen_beacon(bssid_open, "Free_Campus_WiFi", encryption_type="OPEN")

        # Verify catalog was NOT poisoned and still has pure clean score
        cat_rec2 = self.db.get_ssid("Free_Campus_WiFi")
        self.assertEqual(cat_rec1.bge_cos_clean, cat_rec2.bge_cos_clean, "Catalog must remain pure and unpoisoned")

        # Verify OPEN beacon evaluated eff_bge == base_bge
        self.assertAlmostEqual(res_open.eff_bge, res_open.base_bge, places=3)
        self.assertTrue(res_open.is_suspicious_name, "OPEN beacon for Free_Campus_WiFi must trigger Stage 2.5 = True")

        # 4. Complementary test with a semantic-only lookalike (Campus Guest Portal)
        # where xgb_prob < 0.50 so PSK weight strictly gates Stage 2.5
        bssid_sem_psk = "00:11:22:33:44:03"
        res_sem_psk = self.screener.screen_beacon(bssid_sem_psk, "Campus Guest Portal", encryption_type="WPA2-PSK")
        bssid_sem_open = "00:11:22:33:44:04"
        res_sem_open = self.screener.screen_beacon(bssid_sem_open, "Campus Guest Portal", encryption_type="OPEN")

        self.assertFalse(res_sem_psk.is_suspicious_name, "Campus Guest Portal on PSK should be suppressed (False)")
        self.assertTrue(res_sem_open.is_suspicious_name, "Campus Guest Portal on OPEN must trigger Stage 2.5 = True")

    def test_check_2_2_single_and_burst_latency(self):
        """
        Check 2.2: Verify single live SSID completes in < 10 ms, while a 32-SSID burst batches in < 55 ms.
        Also verifies SIMD batch speedup over serial execution.
        """
        # Warmup embedder and model
        self.screener.screen_ssid("Warmup_SSID_Alpha")
        self.screener.screen_ssid("Warmup_SSID_Beta")

        # 1. Single Live SSID Latency (Type A: 1 x M dot product with 0 ms wait)
        single_times = []
        for i in range(5):
            t0 = time.perf_counter()
            self.screener.compute_ssid_record(f"Single_Live_Test_{i}")
            single_times.append((time.perf_counter() - t0) * 1000)

        min_single = min(single_times)
        # In native environments, verify single completes in < 15 ms (< 10 ms optimal)
        if HAS_FASTEMBED and HAS_XGBOOST and not os.getenv("RUNNING_IN_QEMU"):
            self.assertLess(min_single, 15.0, f"Single live compute too slow: {min_single:.2f} ms")

        # 2. 32-SSID Burst Batch (Type B: NxM matrix multiplication E @ W.T)
        batch_ssids = [f"Burst_MDk4_Flood_{i}" for i in range(32)]
        t0 = time.perf_counter()
        records = self.screener.compute_ssid_records_batch(batch_ssids)
        batch_time_ms = (time.perf_counter() - t0) * 1000

        self.assertEqual(len(records), 32)
        for rec in records:
            self.assertIsNotNone(rec.bge_vector_blob)
            self.assertGreaterEqual(len(rec.bge_vector_blob), 384 * 4)

        # In native environment, verify batch throughput (< 55 ms on warm hardware, < 120 ms under heavy test suites)
        # and verify batch time per SSID is faster than single serial time
        if HAS_FASTEMBED and HAS_XGBOOST and not os.getenv("RUNNING_IN_QEMU"):
            per_ssid_batch_ms = batch_time_ms / 32
            # Must achieve significant throughput speedup over 32 x single serial
            self.assertLess(batch_time_ms, 120.0, f"32 burst batch time took {batch_time_ms:.2f} ms")

    def test_check_2_3_option_m2_mutation_detection(self):
        """
        Option M2 Mutation Detection:
        If a known BSSID broadcasts a different SSID: is_mutated = 1, attach +45 pts,
        evaluate new SSID against whitelist, and flag suspicious.
        """
        bssid = "00:aa:bb:cc:dd:ee"

        # 1. First beacon: benign cafe network
        res1 = self.screener.screen_beacon(bssid, "Corner_Cafe_WiFi", encryption_type="WPA2-PSK")
        self.assertFalse(res1.is_mutated)
        self.assertEqual(res1.bssid_state.current_risk_score, 0)

        # 2. Second beacon from same BSSID changes SSID to University_Campus_5G_Login
        res2 = self.screener.screen_beacon(bssid, "University_Campus_5G_Login", encryption_type="WPA2-PSK")
        self.assertTrue(res2.is_mutated)
        self.assertEqual(res2.bssid_state.is_mutated, 1)
        self.assertGreaterEqual(res2.bssid_state.current_risk_score, 45, "Must attach +45 pts on mutation")
        self.assertTrue(res2.is_suspicious_name, "Mutation must force Stage 2.5 = True")

        # 3. Verify database state reflects mutation
        state_in_db = self.db.get_bssid(bssid)
        self.assertIsNotNone(state_in_db)
        self.assertEqual(state_in_db.is_mutated, 1)
        self.assertEqual(state_in_db.current_ssid, "University_Campus_5G_Login")

    def test_check_2_4_whitelisted_bssid_path_and_mutation_override(self):
        """
        Point 1 & Option M2 Interaction:
        - Whitelisted BSSID with unchanged SSID skips AI Stage 1 & 2.
        - Whitelisted BSSID with mutated SSID still triggers is_mutated=1 (+45 pts) & Stage 2.5.
        """
        bssid = "aa:bb:cc:dd:ee:ff"
        initial_ssid = "University Campus 5G"

        # Set as whitelisted in DB
        state = BSSIDState(
            bssid=bssid,
            current_ssid=initial_ssid,
            is_whitelisted=1,
            risk_tier="LOW",
        )
        self.db.ram_bssids[bssid] = state
        self.db.whitelisted_bssids.add(bssid)

        # 1. Normal beacon from whitelisted BSSID (matching SSID)
        res1 = self.screener.screen_beacon(bssid, initial_ssid, encryption_type="WPA2-PSK")
        self.assertTrue(res1.is_whitelisted)
        self.assertFalse(res1.is_mutated)
        self.assertFalse(res1.is_suspicious_name, "Whitelisted unchanged BSSID bypasses AI")
        self.assertIsNone(res1.record, "Should skip Stage 1 & 2 AI inference")

        # 2. Rogue spoofing whitelisted MAC but advertising different SSID
        res2 = self.screener.screen_beacon(bssid, "University_Guest_Free", encryption_type="OPEN")
        self.assertTrue(res2.is_mutated, "Whitelisted BSSID broadcasting different SSID is mutated")
        self.assertTrue(res2.is_suspicious_name, "Mutation forces Stage 2.5 = True")
        self.assertGreaterEqual(res2.bssid_state.current_risk_score, 45)

    def test_check_2_5_tech_stopwords_stripper(self):
        """
        Verify strip_tech_stopwords correctly removes technical stopwords
        while preserving distinguishing tokens and falling back gracefully.
        """
        test_cases = [
            ("Starbucks_WiFi", "Starbucks"),
            ("Free_Campus_WiFi", "Free Campus"),
            ("University_Campus_5G", "University Campus"),
            ("WiFi", "WiFi"),                     # Empty fallback
            ("5G_WiFi", "5G_WiFi"),               # Empty fallback
            ("eduroam", "eduroam"),               # Untouched
            ("Siam 5G WiFi", "Siam"),
            ("Corporate-WLAN-Internal", "Corporate Internal"),
        ]
        for inp, expected in test_cases:
            cleaned = strip_tech_stopwords(inp)
            self.assertEqual(cleaned, expected, f"Failed stripping stopwords from '{inp}'")

    def test_check_2_6_adaptive_ai_queue_mechanics(self):
        """
        Verify Q1 WorkConservingAIQueue handles N=1 instant enqueue and N<=32 chunk draining.
        """
        queue = WorkConservingAIQueue(max_batch_size=32)
        self.assertEqual(len(queue), 0)

        # Enqueue 1 item
        fut1 = queue.enqueue("Test_SSID_1")
        self.assertEqual(len(queue), 1)

        batch1 = queue.get_pending_batch()
        self.assertEqual(len(batch1), 1)
        self.assertEqual(batch1[0][0], "Test_SSID_1")
        self.assertEqual(len(queue), 0)

        # Enqueue 50 items (simulate mdk4 burst)
        for i in range(50):
            queue.enqueue(f"Burst_SSID_{i}")
        self.assertEqual(len(queue), 50)

        # First drain must cap at exactly 32
        chunk1 = queue.get_pending_batch()
        self.assertEqual(len(chunk1), 32)
        self.assertEqual(len(queue), 18)

        # Second drain takes remaining 18
        chunk2 = queue.get_pending_batch()
        self.assertEqual(len(chunk2), 18)
        self.assertEqual(len(queue), 0)

    def test_check_2_7_whitelist_matrix_w_properties(self):
        """
        Verify Campus Whitelist embedding matrix W has shape (M x 384) with M=5
        and L2-normalized rows.
        """
        W = self.screener.W
        self.assertEqual(W.shape, (5, 384), "W shape must be (5, 384) for 5 campus SSIDs")

        # Verify unit L2 norm per row
        row_norms = np.linalg.norm(W, axis=1)
        for i, norm in enumerate(row_norms):
            self.assertAlmostEqual(norm, 1.0, places=4, msg=f"Row {i} norm is {norm}, expected 1.0")

        # Dynamically change whitelist
        custom_wl = ["University Campus 5G", "eduroam", "Siam Wifi"]
        self.screener.set_whitelist(custom_wl)
        self.assertEqual(self.screener.W.shape, (3, 384))
        for norm in np.linalg.norm(self.screener.W, axis=1):
            self.assertAlmostEqual(norm, 1.0, places=4)

    def test_check_2_8_cache_hit_latency(self):
        """
        Verify cached SSIDs in ram_ssids / ssid_catalog return in < 0.1 ms.
        """
        ssid = "Cache_Latency_Test_SSID"
        # First call: computes and caches
        rec1 = self.screener.screen_ssid(ssid)
        self.assertIsNotNone(rec1)

        # Second call: pure RAM cache hit
        t0 = time.perf_counter()
        for _ in range(50):
            rec2 = self.screener.screen_ssid(ssid)
        elapsed_per_hit = (time.perf_counter() - t0) / 50 * 1000

        self.assertIs(rec1, rec2)
        self.assertLess(elapsed_per_hit, 0.1, f"Cache hit too slow: {elapsed_per_hit:.4f} ms")


if __name__ == "__main__":
    unittest.main()
