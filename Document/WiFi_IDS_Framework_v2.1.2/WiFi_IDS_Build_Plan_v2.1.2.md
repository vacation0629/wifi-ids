# Edge Wi-Fi Evil Twin Detection Framework — Overview & Build Plan (v2.1.2)

**Document ID:** BUILD-PLAN-v2.1.2  
**Target Environment:** Raspberry Pi 5 Edge Sensor (Monitor Mode 802.11 Sniffer \+ SQLite WAL Database)  
**Protected Campus Whitelist:** `['University_Campus_5G', 'University_Staff_Secure', 'University_Student_WiFi', 'University_Guest_Portal', 'eduroam']`  
**Companion Specifications:** `WiFi_IDS_Arch_Spec_v2.1.2.md`, `WiFi_IDS_Batching_Spec_v2.1.2.md`, `WiFi_IDS_CHANGELOG_v2.1.2.md`

---

## Part 1: System Overview (For Human Developers)

### 1.1 The Two-Group Pipeline & v2.1.2 Hardening

The framework separates detection into **Group 1 (Name Screening)** and **Group 2 (Parallel RF & Beacon Behavior Detection `4A` & `4B`)**, backed by an adversarial-safe RAM \+ SQLite WAL batch engine:

1. **Pre-Stage-0 Frame Demux & Whitelisted BSSID Integrity Check (Points 1 & 2):**  
   * **Deauth/Disassoc Ingress (`subtype 0x0C / 0x0A`):** Because 802.11 Deauth frames have no SSID field, they are demultiplexed before Stage 0 and routed directly by `addr3` BSSID into Track 4A's sliding counter (`>= 15` frames in `10 s` or `>= 30` in `60 s` triggers `HIGH +75 pts`).  
   * **Whitelisted BSSID Path:** A whitelisted BSSID (`is_whitelisted == 1`) with an unchanged SSID skips Group 1 AI (`Stage 1 & 2`) to save CPU, **but still runs Track 4A** (backward Seq/TSF collision and 15s Tag 3/61 multi-channel clone checks) before exiting as `BENIGN`.  
2. **Encryption-Agnostic `ssid_catalog` & Dynamic Stage 2.5 PSK Weighting (Point 3):**  
   * `ssid_catalog` caches `xgb_prob`, `bge_cos_raw`, and `bge_cos_clean` (stopwords stripped) purely by `ssid_text` without ever zeroing PSK networks in the database.  
   * At **Stage 2.5**, the current beacon's encryption dynamically weights semantic similarity (`eff_bge = 0.5 * bge_cos` if `WPA2/3-PSK`, else `bge_cos`), stopping attackers from poisoning the cache with a PSK beacon before flipping to Open.  
3. **24-Hour Probation with 1-Hour Offline Reset & Manual-Only Whitelisting (Points 4 & 5):**  
   * **Physical Uptime Assumption:** Legitimate campus and departmental ceiling APs are PoE-powered infrastructure that stay online 24/7; they do not go dark for hours during deployment. If an un-whitelisted BSSID goes offline for **`> 1 hour` (`now - last_seen_ts > 3600s`)**, its probation timer resets (`first_seen_ts = now`).  
   * **Decay Scope:** Departmental Sister SSIDs (`Law_School_Faculty`) matching the Campus IE Blueprint (`-35 pts`) decay to `Watchlist` after 24 hours of continuous uptime. Exact main whitelist SSIDs (`eduroam`) keep their `MEDIUM` floor until manually whitelisted via the UI `[+ Add to Whitelist]` button.  
   * **Manual-Only Whitelisting:** `--learn-baseline` locks `campus_ie_profile` only; `is_whitelisted = 1` is never auto-populated from noisy airwaves.  
4. **15-Second Sliding Tag 3/61 Channel Map & Strict Un-Diluted Jitter (Point 7):**  
   * **Channel Changes vs. Clones:** Track 4A extracts the AP's declared channel from Beacon **IE Tag 3 or Tag 61** (never the receiver's `Radiotap` frequency) into a `{channel: last_seen_ts}` map with a `15 s` expiry. If a legitimate AP moves channels (`Ch 6 -> Ch 1`), the old channel expires in `15 s` and updates `primary_channel` (`0 pts`). Simultaneous beacons on two channels within `15 s` trigger **Type A Clone (`+70 pts HIGH`)**.  
   * **Strict Jitter:** Standard 802.11 beacon interval is `100 TU = 102.4 ms` (enterprise ASIC APs hold `< 4 ms` TSF jitter and `< 8 ms` arrival jitter). Jitter is evaluated only when `1 <= seq_diff <= 6` and `60.0 <= delta_t_ms <= 245.0` (`k in {1, 2}`, `expected_ms = k * 102.4`), taking `max(abs(delta_t_ms - expected_ms), abs(tsf_delta_ms - expected_ms))` with **no division by `k`**.  
5. **Flood-Safe Adaptive AI Queue & `250 ms` Flush Cooldown (Point 8):**  
   * Single new SSIDs in normal traffic evaluate immediately (`0 ms` wait, `7.2 ms` compute), while `mdk4` SSID floods drain in `Type B` batches of up to `32`.  
   * First alerts flush to SQLite in `0 ms`, while back-to-back flood alerts coalesce on a `250 ms` cooldown (max 4 commits/sec). `ram_bssids` and `ram_ssids` are LRU-capped at `4,096` entries.

---

## Part 2: AI Coding Assistant Specification & Ruleset

### 2.1 Hard Architectural Rules (DO NOT Violate)

1. **Demux Deauth/Disassoc before Stage 0 and route Whitelisted BSSIDs through Track 4A.** Never exit a whitelisted BSSID before running Track 4A's Seq/TSF collision and Tag 3/61 multi-channel clone checks.  
2. **Never store encryption-dependent zeros in `ssid_catalog`.** Always compute and store true `bge_cos_clean` (stopwords stripped) in `ssid_catalog`. Apply the `0.5x` PSK multiplier dynamically at Stage 2.5:

```py
base_bge = row.bge_cos_clean if config.ENABLE_STOPWORD_STRIP else row.bge_cos_raw
eff_bge = (0.5 * base_bge) if bssid_state.encryption_type == "PSK" else base_bge
is_suspicious_name = (row.xgb_prob >= 0.50) or (eff_bge >= 0.60) or bssid_state.is_mutated
```

3. **Never divide jitter error by `k`.** Use the exact un-diluted formula:

```py
seq_diff = (curr_seq - prev_seq) % 4096
if 1 <= seq_diff <= 6 and 60.0 <= delta_t_ms <= 245.0:
    k = 1 if delta_t_ms < 153.6 else 2
    expected_ms = k * 102.4
    arrival_err_ms = abs(delta_t_ms - expected_ms)
    tsf_err_ms = abs(((curr_tsf - prev_tsf) / 1000.0) - expected_ms)
    sample_error_ms = max(arrival_err_ms, tsf_err_ms)
```

4. **Use Beacon IE Tag 3 / Tag 61 for `active_channels_json` with a `15.0 s` sliding expiry.** Never use `Radiotap` receiver frequency for Type A clone tracking.  
5. **Enforce the 1-Hour (`3600 s`) Offline Probation Reset & Manual-Only Whitelisting.** If `not state.is_whitelisted and (now - state.last_seen_ts) > 3600.0`, reset `state.first_seen_ts = now`. Never set `is_whitelisted = 1` automatically during `--learn-baseline`.  
6. **Enforce the `250 ms` Forced-Flush Cooldown & `4,096` LRU Cache Cap.**

---

## Part 3: Step-by-Step Build Plan & Verification Criteria (v2.1.2)

| Step | Module | Implementation Task | Verification Criteria (Pass/Fail Check) |
| :---: | :---- | :---- | :---- |
| **1** | `config.py` & `db_manager.py` | Create 4-table SQLite WAL database, `4,096`\-cap `OrderedDict` LRU caches, `3.0 s` routine flush, `250 ms` coalesced Instant Alert Bypass, and `PRAGMA data_version` watcher. | **Check 1.1:** Simulate 500 beacons/sec (`LOW`); verify `<= 4` commits in 10s. **Check 1.2:** Trigger 1 single `LOW -> HIGH` alert; verify `< 10 ms` immediate commit. **Check 1.3:** Inject 500 fake new `MEDIUM` BSSIDs in 1.0 second; verify coalescing caps disk commits at `<= 4 commits/sec` and LRU cap holds `len(ram_bssids) <= 4096`. |
| **2** | `name_screener.py` | Implement work-conserving adaptive AI queue (`N=1` instant `1xM` vs `N<=32` batch `NxM`), encryption-agnostic `ssid_catalog`, dynamic Stage 2.5 `0.5x` PSK weight, and `Option M2` mutation population. | **Check 2.1:** First send `Free_Campus_WiFi` as `WPA2-PSK`, then send `Free_Campus_WiFi` as `OPEN`; verify `ssid_catalog.bge_cos_clean` was NOT poisoned to `0.0` and the `OPEN` beacon triggers `Stage 2.5 = True`. **Check 2.2:** Verify single live SSID completes in `< 10 ms`, while a 32-SSID burst batches in `< 55 ms`. |
| **3** | `track_4a_state.py` | Implement pre-Stage-0 Deauth demux (`>=15/10s`), whitelisted BSSID Track 4A routing, 15s sliding Tag 3/61 channel map, and 1-hour offline probation reset. | **Check 3.1:** Clone a whitelisted BSSID on a second Tag 3 channel; verify Stage 0 routes it to Track 4A and triggers `HIGH (+70 pts)`. **Check 3.2:** Move a single BSSID from Tag 3 `Ch 6` to `Ch 1` (one-way); verify `Ch 6` expires after 15s and `primary_channel` updates to `1` with `0 pts`. **Check 3.3:** Advance clock by `3,700 s` without beacons on an un-whitelisted AP; verify `first_seen_ts` resets to `now`. |
| **4** | `track_4b_beacon.py` | Implement `--learn-baseline` (locks `campus_ie_profile` only, zero auto-whitelisting), strict un-diluted TSF/Arrival jitter (`k in {1,2}`), Tag 3 vs radio spoof check (`+45`), and RSSI gate (`0 pts`). | **Check 4.1:** Feed beacons with 1 dropped frame (`seq_diff = 2`, `delta_t = 235 ms`, `expected = 204.8 ms`); verify un-diluted error is `30.2 ms` (`> 20 ms` threshold) and triggers `+20 pts`. **Check 4.2:** Verify `--learn-baseline` leaves `bssid_devices.is_whitelisted = 0` for all APs until manual UI update. |
| **5** | `risk_engine.py` | Combine Track 4A & 4B floors/points (`0–100`), Sister-only `-35 pts` / 24h W2 decay, and exact-whitelist-SSID `MEDIUM` floor retention. | **Check 5.1:** Verify an un-whitelisted `Law_School_Faculty` AP with 100% IE match decays to `LOW` after 24h continuous uptime, while an un-whitelisted `eduroam` AP stays `MEDIUM` until manually whitelisted. |

