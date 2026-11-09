# Edge Wi-Fi Evil Twin Detection Framework — Changelog (`CHANGELOG_v2.1.1.md`)

All notable architectural, routing, scoring, batching, and database changes to the **Edge Wi-Fi Evil Twin Detection Framework** are documented in this file.

## [`v2.1.1`] — 2026-10-23

### Added

* **Dedicated Batching, Caching & I/O Engine Specification (WiFi_IDS_Batching_Spec_v2.1.1.md):**
  * Created a standalone architecture and design specification covering the 3-phase batching lifecycle (Phase A Cold-Boot Initialization, Phase B Live 500 pkt/s RAM Capture Loop, and Phase C Atomic SQLite WAL Transaction & `PRAGMA data_version` Sync), complete with a large end-to-end logical flowchart, RAM memory footprint math, deduplication analysis (`1,500 frames -> 50 BSSID rows` per 3s window), and a reference `BatchDatabaseManager` Python implementation.
* **Instant Alert Bypass Flush (Q2 = Option 1** **— Solves** **Trap 2):**
  * Added an event-driven bypass (`flush_to_sqlite(force=True)`) whenever a BSSID enters or escalates to `MEDIUM (30–69 pts)` or `HIGH (>= 70 pts)`.
  * Eliminates the 3.0-second batch delay for active threats (`< 10 ms` latency to the Dashboard UI) while preserving the `3.0-second` periodic batch flush (`0.33 fsync/sec`) for routine `Brief Logging` and `Watchlist` traffic.
* **Separated Cold-Boot $N \times M$ Batching from Live $1 \times M$ Instant Evaluation (Q1 = Option 1** **— Solves** **Trap 1):**
  * Removed the `100 ms` multi-SSID collection window from steady-state live sniffing so single newly discovered SSIDs ($N = 1$) are evaluated immediately (`0 ms` queue wait, `7.2 ms` total compute) via `Type A` $1 \times M$ matrix multiplication (`v @ W.T`) against the pre-cached $M \times 384$ whitelist matrix $\mathbf{W}$.
  * Restricted `Type B` ($N \times M$ multi-SSID burst batching) strictly to cold-boot / startup scans when $N$ uncached SSIDs are discovered simultaneously.
* **New Build Plan Verification Checks (Check 1.3** **&** **Check 2.3):**
  * Added `Check 1.3` (verifying `< 10 ms` Instant Alert Bypass commit on `LOW -> HIGH` escalation) and `Check 2.3` (verifying `< 10 ms` zero-queue live $1 \times M$ evaluation) to `WiFi_IDS_Build_Plan_v2.1.1.md`.
## [`v2.1.0`] — 2026-10-23

### Added

* **Explicit Outgoing Route for BSSID Name Mutation (Option M2):**
  * When a known `BSSID` in `bssid_devices` changes its broadcast `SSID` (`db_ssid != observed_ssid`), the `BSSID Name Mutation Detector` sets `is_mutated = True (+45 pts)` and routes via an explicit outgoing arrow into `Stage 1 (ssid_catalog Cache Check)`.
  * Guarantees that even if the mutated SSID is a brand-new string, its `xgb_prob`, `bge_cos_raw`, `bge_cos_clean`, and `384d` vector columns are populated in `ssid_catalog` (zero `NULL` gaps) before being force-routed through `Stage 2.5` into Parallel Tracks `4A & 4B`.
* **Hot-Reloading Whitelist Synchronization via** **PRAGMA data_version** **(Method 1):**
  * Allows the static Dashboard UI `[+ Add to Whitelist]` button to execute standard SQL `INSERT`/`UPDATE` statements directly against SQLite without requiring an HTTP API inside the sniffer.
  * During every 3.0-second batch flush, the sniffer queries `PRAGMA data_version;` (`0.001 ms`) and hot-reloads the RAM whitelist and $M \times 384$ `bge-small` whitelist matrix whenever an external UI write is detected.
* **File Output Version Control Naming:**
  * Standardized output artifact filenames while preserving internal section names (`Version 1`, `Version 2`, `Version 3`).
### Changed

* **Simplified** **Stage 2.5: Suspicious Name?** **(G1 OR-Gate) Diagram Node:**
  * Cleaned the decision diamond expression to `xgb_prob >= 0.50 OR bge_cos >= 0.60 OR is_mutated == True`.
  * Moved `ENABLE_STOPWORD_STRIP` toggle details (`bge_cos_clean` [ON] vs `bge_cos_raw` [OFF]) and `WPA2/3-PSK` zeroing notes out of the decision diamond into the global configuration specification.
* **Decoupled Dashboard UI** **[+ Add to Whitelist]** **from the** **Active Alert** **Flow Node:**
  * Restored the `Active Alert (30–69 pts)` node label to `"Prompt text alert to application"` since `[+ Add to Whitelist]` is a static global UI control on the dashboard rather than a category-specific row button.
## [`v2.0.0`] — 2026-10-23

### Added

* **Parallel Execution of Track** **4A** **and Track** **4B** **in Group 2:**
  * Split Group 2 (Right Column) into two concurrent tracks triggered when `Suspicious Name? = Yes`:
    * **Parallel Track 4A:** Active RF & State Listener (`Deauth storm`, `Same-Channel BSSID Collision`, `Multi-Channel Clone`, `AP first-seen age`).
    * **Parallel Track 4B:** RSSI Volatility, RSSI Logging Gate (`>= -70 dBm`), and Deep Beacon Frame IE Analysis.
* **3-Tier** **Channel Match** **Scoring Architecture:**
  * **Type A (+70 pts, Hard Floor** **HIGH):** Multi-Channel BSSID Clone (same BSSID transmitting on 2 channels simultaneously).
  * **Type B (+45 pts):** Beacon IE Tag 3 (`DS Parameter Set`) channel mismatch (`>= 2` channels off in 2.4 GHz or any mismatch in 5 GHz; `1` channel off in 2.4 GHz scored as `0 pts` RF bleed-over).
  * **Type C (+15 pts):** Non-standard overlapping 2.4 GHz channel (outside `1, 6, 11`).
* **Auto-Learned Campus IE Blueprint (campus_ie_profile):**
  * Replaced spoofable 3-byte MAC OUI checks with deep Beacon IE inspection (`Tag 48 RSN 802.1X`, `Tag 54 MDID`, `Tag 221/133 Controller TLV`, `Tag 45/191/255 MIMO spatial streams`, and ordered IE tag sequences).
  * Added **Severe** **info mismatch** **(+55 pts)**, **Partial** **info mismatch** **(+15 pts)**, and **100% Campus IE Blueprint Match (-35 pts)**.
* **Zero-Trust New AP Floor with 24-Hour Time Decay (Option N2 + W2):**
  * Un-whitelisted BSSIDs passing `Stage 2.5` with `first_seen_age < 24h` receive a **Hard Floor of** **MEDIUM (30 pts)** **+** **+20 pts**, decaying automatically to `0` after 24 hours.
### Changed

* **Removed Static RSSI from Risk Point Scoring (0 pts):**
  * Static strong RSSI (`>= -70 dBm`) no longer adds risk points (preventing false positives on ceiling APs near the sensor) and exclusively controls full-frame vs. infrequent logging.
  * Kept **RSSI Range Volatility ($\Delta\text{RSSI} > 15\text{ dB}$)** at `+20 pts`.
## [`v1.0.0`] — Initial Baseline Concept

* Original single-path conceptual flowchart (`Read SSID -> Whitelist + Fuzzy Match -> miniLM Semantic Model -> Suspicious Name? -> Right-Column Behavior & Risk Scoring`) and 9-model benchmark across 210 campus test cases (`BAAI/bge-small-en-v1.5` selected as the `66.4 MB` edge champion alongside `XGBoost`).