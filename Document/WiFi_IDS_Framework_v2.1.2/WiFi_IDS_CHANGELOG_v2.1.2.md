# Edge Wi-Fi Evil Twin Detection Framework — Changelog (CHANGELOG\_v2.1.2.md)

All notable architectural, routing, scoring, batching, and database changes to the **Edge Wi-Fi Evil Twin Detection Framework** are documented in this file.

---

## \[v2.1.2\] — 2026-11-09

### Added

* **Pre-Stage-0 Management Frame Demultiplexer for Deauth/Disassoc Ingress (Point 2 Fix):**  
  * Added an explicit subtype demux (`0x0C` Deauthentication / `0x0A` Disassociation) prior to `Read SSID` so SSID-less management frames route directly by `addr3` BSSID into Track 4A's sliding window counter (`>= 15` frames in `10 s` or `>= 30` frames in `60 s` triggers Hard Floor `HIGH +75 pts`).  
* **Whitelisted BSSID Track 4A Integrity Verification Path (Point 1 Fix):**  
  * Whitelisted BSSIDs (`is_whitelisted == 1`) with matching SSIDs still bypass Group 1 AI (`Stage 1 & 2`), but now route through **Track 4A** to execute \$O(1)\$ backward Seq/TSF collision and multi-channel clone checks before exiting as `BENIGN`.  
* **1-Hour Offline Probation Reset & Documented PoE Uptime Assumption (Point 4 Fix):**  
  * Documented the core physical infrastructure assumption: legitimate campus and departmental ceiling APs are PoE-powered with continuous 24/7 uptime, whereas rogue kits are transient.  
  * Added an offline gap check (`now - last_seen_ts > 3600s`): if an un-whitelisted AP goes dark for more than 1 hour during its probation window, `first_seen_ts` resets to `now` (defeating hit-and-run 24h timer priming).  
  * Scoped the `-35 pts` IE Blueprint credit and 24-hour W2 auto-decay strictly to Departmental Sister SSIDs (`Law_School_Faculty`), while un-whitelisted exact main whitelist SSIDs (`eduroam`) retain their `MEDIUM` floor until manually whitelisted via the UI.  
* **15-Second Sliding IE Tag 3/61 Channel Map for Legitimate Channel Moves vs. Clones (Point 7 Fix):**  
  * Track 4A now extracts the operating channel from Beacon **IE Tag 3 (`DS Parameter Set`) or IE Tag 61 (`HT Operation`)** into a `{channel: last_seen_ts}` dictionary with a `15.0 s` sliding expiration window.  
  * One-way channel changes by legitimate Campus IT APs expire the old channel after `15 s` and update `primary_channel` (`0 pts`), while simultaneous multi-channel transmissions (`6 <-> 1` ping-pong within `15 s`) trigger Type A Multi-Channel Clone (`+70 pts HIGH`).  
* **Flood-Resilient Coalesced Flush (`250 ms` Cooldown), Adaptive AI Queue & Bounded LRU Caches (Point 8 Fix):**  
  * Added `MIN_FORCE_COOLDOWN_SEC = 0.25s` to `flush_to_sqlite(force=True)` so single alerts still commit in `0 ms`, while `mdk4` beacon floods coalesce forced commits to a safe maximum of 4 commits/sec.  
  * Upgraded `Q1` to a work-conserving adaptive queue (`N=1` instant `1xM` when idle; `N<=32` batch `NxM` when flooded) and capped `ram_bssids` and `ram_ssids` at `4,096` entries via `OrderedDict` LRU eviction.

### Changed

* **Encryption-Agnostic `ssid_catalog` with Dynamic Stage 2.5 PSK Weighting (Point 3 Fix):**  
  * Removed `WPA2/3-PSK` zeroing from `ssid_catalog.bge_cos_clean` to prevent PSK-to-Open cache poisoning. `Stage 2.5` now dynamically applies `eff_bge = 0.5 * bge_cos` when the current beacon uses `PSK`.  
* **Tightened Un-Diluted Hardware TSF & Arrival Jitter Formula (Point 7 Refinement):**  
  * Replaced the overly loose modulo-division formula with a strict un-diluted check over `1 <= seq_diff <= 6` and `60.0 <= delta_t_ms <= 245.0` (at most 1 lost beacon, `k in {1, 2}`, `expected_ms = k * 102.4`), taking `max(abs(delta_t_ms - expected_ms), abs(tsf_delta_ms - expected_ms))` against the `20 ms` threshold.  
* **Strict Manual-Only BSSID Whitelisting (Point 5 Refinement):**  
  * Clarified that `--learn-baseline` only locks `campus_ie_profile` and never auto-sets `is_whitelisted = 1` from noisy campus airwaves; BSSID whitelisting is performed exclusively via the static Dashboard UI `[+ Add to Whitelist]` button.

---

## \[v2.1.1\] — 2026-10-23

### Added

* **Dedicated Batching, Caching & I/O Engine Specification (`WiFi_IDS_Batching_Spec_v2.1.1.md`):**  
  * Created standalone 3-phase batching specification, deduplication math, and `BatchDatabaseManager` skeleton.  
* **Instant Alert Bypass Flush (`Q2 = Option 1` — Solves `Trap 2`):**  
  * Added event-driven bypass (`flush_to_sqlite(force=True)`) on `MEDIUM` / `HIGH` escalations.  
* **Separated Cold-Boot \$N \\times M\$ Batching from Live \$1 \\times M\$ Instant Evaluation (`Q1 = Option 1` — Solves `Trap 1`).**

---

## \[v2.1.0\] — 2026-10-23

### Added

* **Explicit Outgoing Route for BSSID Name Mutation (`Option M2`).**  
* **Hot-Reloading Whitelist Synchronization via `PRAGMA data_version` (Method 1).**  
* **Simplified `Stage 2.5: Suspicious Name?` (G1 OR-Gate) Diagram Node.**