# ⚔️ Red Team Adversary Analysis: 7 Original SSID Attack Categories (88 Test Cases)
## Comprehensive Wireless Offensive Mechanics, Deceptive Intent, & Evasion Profiling

> **Author:** Offensive Wireless Security Specialist (Red Team Adversary)  
> **Target Framework:** `ssid_feature_framework` (`test_cases.json`)  
> **Scope:** Complete offensive deconstruction of all 88 test cases across the 7 foundational categories.  
> **Baseline Authorized Whitelist:**  
> 1. `University_Campus_5G`  
> 2. `University_Staff_Secure`  
> 3. `University_Student_WiFi`  
> 4. `University_Guest_Portal`  
> 5. `eduroam`

---

## Executive Overview: The Red Team Perspective on SSID Attacks

In 802.11 wireless offensive operations, the Service Set Identifier (SSID) is not merely a human-readable network label—it is the **primary attack interface** for:
1. **Manipulating Client Station (STA) Automations:** Exploiting Preferred Network Lists (PNL) and 802.11 probe request/response state machines for zero-interaction auto-association.
2. **Cognitive & Psycholinguistic Deception:** Inducing human target association via kerning illusions, brand spoofing, and social engineering lures under split-second decision latency.
3. **Sensor & ML Pipeline Evasion:** Exploiting tokenization splits, non-linear edit distances, and embedding cosine conflation to paralyze heuristic and machine learning Wireless Intrusion Detection Systems (WIDS).

The following analysis dissects all 7 core categories in the benchmark suite.

---

## Category 1: `authorized_exact` (Whitelist Cloning & Masquerade)
**Samples (5):** `University_Campus_5G`, `University_Staff_Secure`, `University_Student_WiFi`, `University_Guest_Portal`, `eduroam`  
**Ground Truth Label:** `BENIGN` (Legitimate Baseline) / **Red Team Vector:** Exact Clone Evil Twin & Rogue AP Insertion

```
+---------------------------------------------------------------------------------------------------+
| 802.11 Management Frame: Beacon / Probe Response                                                  |
| Tag Number: 0 (SSID Parameter Set) | Tag Length: 20 bytes                                         |
| Payload: 55 6e 69 76 65 72 73 69 74 79 5f 43 61 6d 70 75 73 5f 35 47 ("University_Campus_5G")   |
+---------------------------------------------------------------------------------------------------+
```

### 1. Adversary Reconnaissance & Targeting
* **Passive RF Surveying:** Using tools like `kismet`, `airodump-ng`, or SDRs (HackRF/BladeRF), the adversary surveys the campus 2.4 GHz, 5 GHz, and 6 GHz spectrum. They map all legitimate BSSIDs, operational channels, beacon intervals (typically 100 TUs / ~102.4 ms), Supported Rates, Extended Rates, RSN Information Elements (AKM suite: 802.1X vs PSK, pairwise ciphers: CCMP/GCMP), and Country Information Elements.
* **Network Segmentation Profiling:**
  * `University_Campus_5G`: Targeted for bulk unauthenticated traffic interception and high-speed data capture.
  * `University_Staff_Secure`: High-value target for harvesting enterprise Active Directory / LDAP credentials.
  * `University_Student_WiFi`: Broad surface for student portal session hijacking and credential harvesting.
  * `University_Guest_Portal`: Trivial entry point where clients inherently expect an open unencrypted association followed by a captive portal web redirect.
  * `eduroam`: The premier global prize. A captured RADIUS credential grants access to thousands of universities worldwide.

### 2. Why Attackers Must Match Exact Strings
* **Preferred Network List (PNL) Exploitation:** Client STAs store historical connection profiles indexed strictly by SSID byte sequences. If an SSID does not match byte-for-byte, modern mobile OSs (iOS, Android, Windows, macOS) will **never** silently auto-associate.
* **Zero-Touch Association:** For an attacker to capture victim traffic without user awareness, the SSID broadcast by the rogue AP must match the victim's stored PNL entry down to the exact case and byte string.

### 3. Attack Mechanics & Execution
* **Physical Layer Dominance:**
  * **RF Signal Overpowering:** The rogue AP uses high-gain directional antennas (e.g., Alfa AWUS036ACH with 9dBi dipoles or directional panel) transmitting at maximum regulatory TX power (+20 to +30 dBm). 802.11 roaming algorithms dictate that STAs prefer the AP with the strongest Received Signal Strength Indicator (RSSI), typically roaming when $\Delta \text{RSSI} \ge 10\text{ dB}$.
  * **Targeted Deauthentication / Disassociation Injection:** The adversary injects raw 802.11 Management Frames with subtype `0x000c` (Deauthentication) and Reason Code 7 (`Class 3 frame received from nonassociated STA`) or Reason Code 2 (`Previous authentication no longer valid`), spoofing the BSSID of the legitimate campus AP. This forcibly disconnects victim STAs, which immediately initiate active scanning and re-associate with the rogue AP exhibiting superior RSSI.
* **BSSID Masquerading & Vendor OUI Spoofing:**
  * Advanced adversaries do not use default MAC addresses (e.g. Raspberry Pi Foundation `B8:27:EB`). They spoof the BSSID using the exact Organizationally Unique Identifier (OUI) of the legitimate campus AP vendor (e.g., Cisco `00:40:96`, Aruba/HPE `00:0B:86`, Ruckus `00:13:92`) to bypass naive MAC-based rogue detection.
* **Karma & Mana Attacks:**
  * In classic Karma attacks, the rogue AP listens for directed probe requests emitted by STAs probing for their saved PNL networks and dynamically responds with probe responses claiming to be that network.
  * Under MANA (Modern Evil Twin framework), the AP observes probe requests, builds an active profile of the victim's saved networks, and broadcasts targeted beacon frames.
* **Credential Harvesting in Exact Clones:**
  * **802.1X Downgrade / Rogue RADIUS (Hostapd-WPE, EAPHammer):** When spoofing `eduroam` or `University_Staff_Secure`, the rogue AP runs an EAP authenticator. If BYOD client devices do not enforce strict CA certificate validation (trusting any system cert or failing to specify the server domain), the rogue AP negotiates EAP-PEAP/MSCHAPv2, captures the username and NetNTLM/MSCHAPv2 challenge-response hashes, and feeds them to hashcat for offline recovery.

### 4. Defensive Blindspot
* **The Tier 1 Whitelist Trap:** A naive detector evaluating only the SSID string evaluates `observed_ssid == target_authorized_ssid` as `True` ($100\%$ match) and whitelists the frame with $0\text{ ms}$ processing. Without cross-referencing Tier 3 physical telemetry (BSSID tables, RSSI variance, 802.11 frame sequence numbers, and channel validity), exact whitelist clones pass undetected.

---

## Category 2: `homoglyph_typo` (ASCII Leetspeak, Kerning Illusions, & Transpositions)
**Samples (16):**  
* Leetspeak: `Un1versity_Campus_5G`, `Un1versity_Staff_Secure`, `University_5taff_Secure`, `University_Staff_5ecure`, `University_Staff_Secur3`, `University_Student_WiF1`, `University_Gue5t_Portal`, `University_Guest_P0rtal`, `edur0am`  
* Kerning: `University_Carnpus_5G`, `eduroarn`, `University_Student_VVIFi`  
* Transposition & Typos: `University_Campup_5G`, `Unversity_Campus_5G`, `University_Campuss_5G`, `University_Studnet_WiFi`  
**Ground Truth Label:** `EVIL_TWIN`

### 1. Offensive Mechanics & Cognitive Illusions
* **Kerning Illusions (The `rn` $\rightarrow$ `m` and `vv` $\rightarrow$ `w` Exploits):**
  * `University_Carnpus_5G` and `eduroarn`: In sans-serif proportional fonts used by mobile Wi-Fi UI pickers (e.g., San Francisco on iOS, Roboto on Android, Segoe UI on Windows), the glyphs `r` (U+0072) and `n` (U+006E) placed contiguously have a negative kerning metric. The arch of the `r` visually connects to the left vertical stem of the `n`, rendering a glyph cluster virtually indistinguishable from lowercase `m` (U+006D).
  * `University_Student_VVIFi`: Two uppercase `V` characters (`U+0056 U+0056`) render with overlapping top serifs/apexes, closely matching uppercase `W` (`U+0057`).
  * *Human Visual Vulnerability:* In glanceable user interfaces (e.g., selecting Wi-Fi while walking across campus), human cognitive processing uses rapid word-shape pattern matching rather than character-by-character parsing.
* **ASCII Leetspeak Substitutions:**
  * Substitutions like `1` $\leftrightarrow$ `i`/`l`, `0` $\leftrightarrow$ `o`, `5` $\leftrightarrow$ `S`/`s`, and `3` $\leftrightarrow$ `e` exploit low visual contrast on mobile screens with small display scaling factors (e.g. 10pt or 12pt fonts in taskbar drop-downs).
  * `edur0am` and `WiF1`: These represent tactical lures for mobile users whose screens render numbers and letters with identical glyph heights.
* **Typoglycemia & Keyboard Transposition:**
  * `University_Studnet_WiFi`: Exploits the typoglycemia cognitive phenomenon—if the first and last letters of a word remain intact, interior character swaps (`dn` for `nd`) are automatically auto-corrected by the reader's visual cortex without conscious realization.
  * `University_Campup_5G`: Keyboard proximity typo on standard QWERTY layouts ('p' adjacent to 'o' and near '[' / enter line, or mobile keyboard fat-finger simulation).
  * `Unversity_Campus_5G` (omission) and `University_Campuss_5G` (duplication): Rely on visual length blindness where a $\pm 1$ character difference across a 20-character string escapes detection.

### 2. Adversarial Evasion Strategy against AI & Detectors
* **Subword Tokenizer Shattering (The NLP Killer):**
  * Subword tokenizers (WordPiece, Byte-Pair Encoding / BPE) rely on pre-computed vocabularies.
  * In authentic networks, `eduroam` is tokenized as a single, high-frequency token: `['eduroam']`.
  * In the attack `edur0am`, the presence of the digit `0` breaks the vocabulary match, forcing the tokenizer to split the string into multiple low-frequency sub-tokens: `['edu', 'r', '0', 'am']`.
  * When fed into a 1D transformer embedding model (like `all-MiniLM-L6-v2`), this token fragmentation drastically alters the mean-pooled output vector. Cosine similarity plunges from $> 0.95$ down to $0.62 - 0.67$. If the defensive threshold is set at $0.75$, the attack **completely bypasses detection**.
* **Edit Distance Resistance:**
  * Levenshtein edit distance is only 1 for single-char typos, yielding $f_1 \ge 0.88 - 0.95$. However, against pure regex or literal string matching systems, a 1-character difference provides a $100\%$ bypass.

---

## Category 3: `word_addition` (Social Engineering Suffix/Prefix Inflation)
**Samples (15):**  
* Performance/Privilege Lures: `University_Campus_5G_Fast`, `University_Campus_5G_VIP`  
* Free Access Lures: `Free_University_Campus_5G`, `University_Student_WiFi_Free`, `Free_University_Student_WiFi`, `University_Guest_Portal_Free`  
* Authority/Pretexting Lures: `Official_University_Campus_5G`, `Official_University_Staff_Secure`  
* Credential Harvesting Traps: `University_Staff_Secure_Login`, `University_Staff_Secure_Verify`, `University_Student_WiFi_Portal`, `University_Guest_Portal_Login`  
* Onboarding/Persistence Traps: `University_Student_WiFi_AutoConnect`, `eduroam_AutoConnect`, `eduroam_Setup`  
**Ground Truth Label:** `EVIL_TWIN`

```
Authentic Target:  [University_Campus_5G]
Rogue Inflation:   [Free_] + [University_Campus_5G]                 (Prefix Inflation)
Rogue Inflation:   [University_Campus_5G] + [_Fast]                 (Suffix Inflation)
```

### 1. Social Engineering Lures & Pretexting Dynamics
* **The "Fast" and "VIP" Bandwidth Trap:**
  * University wireless networks frequently suffer from heavy congestion, aggressive QoS throttling, and blocked peer-to-peer or streaming ports.
  * By deploying `University_Campus_5G_Fast` or `_VIP`, the adversary preys on students and researchers frustrated with sluggish speeds. Victims voluntarily disconnect from the authorized network to join the rogue AP, believing it to be a prioritized enterprise subnet.
* **The "Free" Gratuitous Access Lure:**
  * `Free_University_Campus_5G` and `Free_University_Student_WiFi`: Many university networks enforce strict credential checks or daily device session limits. Visitors and students eagerly connect to "Free" alternatives to bypass captive registration.
* **The "Official" Authority Pretext:**
  * `Official_University_Campus_5G`: Exploits the authority bias. When multiple networks appear in the Wi-Fi list, users assume that an SSID labeled "Official" is the authenticated standard, suspecting the simpler name might be an outdated deployment.
* **The "Login" / "Verify" Credential Trap:**
  * `University_Staff_Secure_Login` and `University_Staff_Secure_Verify`: In enterprise spear-phishing over Wi-Fi, the adversary aligns the SSID with a scheduled IT compliance scare (e.g., "Mandatory Staff Password Reset"). When staff connect, the captive portal prompts for corporate Active Directory / Office 365 credentials under the guise of an IT security verification check.
* **The "Setup" Certificate Harvesting Trap:**
  * `eduroam_Setup`: Eduroam configuration is complex, typically requiring the Eduroam CAT (Configuration Assistant Tool) mobile profile. Attackers broadcast `eduroam_Setup` as an open network that serves a malicious Apple Mobileconfig or Android CA certificate profile, installing an adversary-controlled Root CA into the device's trust store to perform full HTTPS decryption.

### 2. Mathematical Impact on Detection Features
* **Prefix Inflation Destroys Prefix Metrics ($f_3$ Jaro-Winkler):**
  * Jaro-Winkler calculates string similarity with a prefix bonus scaled by up to 4 initial matching characters:
    $$f_3 = \text{Jaro} + \ell \cdot p \cdot (1 - \text{Jaro})$$
  * When the attacker prepends `Free_` or `Official_`, the first 4 characters do not match ($\ell = 0$). Jaro-Winkler similarity immediately drops from $> 0.95$ down to $0.60 - 0.68$, tricking prefix-biased heuristics.
* **Edit Distance Dilution ($f_1$ Levenshtein Ratio):**
  * Adding 5 to 11 characters inflates the denominator ($\max(\text{len}_{\text{obs}}, \text{len}_{\text{auth}})$) and numerator:
    $$\text{Levenshtein}("Free\_University\_Campus\_5G", "University\_Campus\_5G") = 5$$
    $$f_1 = 1.0 - \frac{5}{25} = 0.80$$
  * For longer additions like `Official_University_Staff_Secure`, $f_1$ drops to $0.74$. Naive systems requiring $f_1 \ge 0.85$ classify these as unrelated networks.
* **Asymmetric Token Containment:**
  * Despite the edit distance drop, the full authorized target string remains 100% contained as a contiguous substring within the rogue SSID. Detectors evaluating n-gram Jaccard ($f_4, f_5$) or substring containment flag these attacks reliably.

---

## Category 4: `word_subtraction` (Truncation & Solitary Brand Stripping)
**Samples (12):**  
* Qualifier Dropping: `University_Campus`, `University_Staff`, `University_Student`, `University_Guest`  
* Prefix Dropping: `Campus_5G`, `Staff_Secure`, `Student_WiFi`, `Guest_Portal`  
* Single-Word Brand Truncation: `University`, `Campus`, `Staff`, `Student`  
**Ground Truth Label:** `EVIL_TWIN`

### 1. Offensive Rationale & Truncation Mechanics
* **Dropping Security Qualifiers (`_Secure`, `_Portal`, `_WiFi`):**
  * `University_Staff`: By stripping `_Secure`, the attacker creates an open (unencrypted) or WPA2-Personal clone. When faculty members experience 802.1X certificate authentication errors on the genuine network, they fall back to `University_Staff`, assuming the IT department created an unencrypted fallback.
  * `University_Guest`: Stripping `_Portal` lures visitors who want direct internet access without filling out captive portal registration forms.
* **Dropping Institutional Identifiers:**
  * `Staff_Secure`, `Campus_5G`, `Student_WiFi`: On smaller mobile displays (smartwatches, budget smartphones), SSIDs are truncated horizontally in the UI menu. Users reading right-to-left or glancing quickly register the functional suffix and tap without noticing the missing university brand.
* **Single-Word Brand Harvesting (`University`, `Campus`, `Staff`, `Student`):**
  * **PNL Promiscuous Trapping:** Users who travel frequently or connect to temporary event networks often have broad, generic names stored in their PNL (e.g., a visitor who connected to another campus named "Campus" or "University"). Broadcasting a solitary root keyword harvests these stray auto-probes.
  * **Brand Heuristic Association:** The solitary word `University` projects maximum authority through simplicity. Users assume it is the master network umbrella.

### 2. Detection Evasion Dynamics
* **Severe Metric Collapse:**
  * Absolute Length Difference ($f_7$) spikes dramatically ($f_7 \ge 10 - 15$).
  * Length Ratio ($f_8$) collapses to $0.35 - 0.45$.
  * Normalized Levenshtein ($f_1$) drops below $0.50$:
    $$\text{Levenshtein}("University", "University\_Campus\_5G") = 10 \implies f_1 = 1.0 - \frac{10}{20} = 0.50$$
* **The Substring Paradox:**
  * To a distance-based classifier, $0.50$ appears as an unrelated background network. However, orthographically, `"University"` is an exact prefix substring ($100\%$ character match over its entire length). Classifiers lacking directional subset features fail to catch solitary brand stripping.

---

## Category 5: `delimiter_case` (Delimiter Mutations & Casing Evasion)
**Samples (12):**  
* Delimiter Swaps: `University-Campus-5G`, `University Campus 5G`, `University.Campus.5G`, `University-Staff-Secure`, `University Staff Secure`, `University.Staff.Secure`, `University-Student-WiFi`, `University Student WiFi`  
* Case Mutations: `university_campus_5g`, `university_staff_secure`, `EDUROAM`, `Eduroam`  
**Ground Truth Label:** `EVIL_TWIN`

### 1. Offensive Mechanics & Protocol-Level Realities
* **802.11 Protocol Standard Strictness:**
  * Under IEEE Std 802.11-2020 Clause 9.4.2.2, the SSID field is defined as an octet sequence of 0 to 32 octets. It is **strictly case-sensitive binary data**.
  * A client device with a saved profile for `University_Campus_5G` will treat `university_campus_5g` or `University Campus 5G` as completely distinct networks and will **never** automatically associate.
* **Human Case-Insensitivity & UI Visual Parity:**
  * While the 802.11 MAC layer treats `_` and ` ` as totally distinct bytes (`0x5F` vs `0x20`), human visual perception treats them as equivalent whitespace separators.
  * In mobile UI pickers, spaces and underscores often occupy similar visual width. A victim searching for their network manually will gladly click `University Campus 5G` or `University-Campus-5G` without recognizing the delimiter variance.
* **The Eduroam Specification Anomaly:**
  * The international **eduroam** technical compliance standard (GÉANT / eduroam.org) mandates that all compliant beacons broadcast strictly lowercase: `eduroam`.
  * Broadcasting `EDUROAM` or `Eduroam` is a classic operational indicator of an amateur rogue AP deployment or a weaponized captive portal phishing lure attempting to harvest eduroam credentials from users manually configuring their connection.

### 2. Detection Evasion Dynamics
* **Bypassing Exact String Filtering:**
  * Delimiter and casing mutations exist specifically to bypass static string whitelists (`if ssid in whitelist`).
  * If a WIDS pipeline does not perform canonical preprocessing (case-folding and delimiter neutralization), these variants slip past Tier 1 filters.
* **Feature Representation:**
  * For normalized character n-grams and token sets, these mutations retain high similarity ($f_4, f_5 \ge 0.70 - 0.85$).
  * The Levenshtein distance for delimiter swaps equals the count of delimiters (typically 2), preserving high $f_1 \ge 0.90$.

---

## Category 6: `semantic_relevant` (Institutional Synonyms vs Subnet Clones)
**Samples (14):**  
* Legitimate Affiliated Subnets / Venues (10 BENIGN): `College_Campus_5G`, `Faculty_Staff_Secure`, `University_Academic_WiFi`, `University_Library_Guest`, `Campus_Research_Lab_5G`, `Engineering_Faculty_Staff`, `University_Alumni_Portal`, `Medical_School_Staff_WLAN`, `Campus_Student_HighSpeed`, `Science_Complex_Guest`  
* Semantic Evil Twins (4 EVIL_TWIN): `Uni_Campus_Net`, `University_Intranet_Secure`, `University_Public_Access`, `Campus_Wide_Open_Net`

### 1. Offensive Deception via Semantic Concealment
* **Mimicking Departmental & Vernacular Infrastructure:**
  * Attackers who recognize that an organization monitors exact-match and typo-based SSIDs switch to semantic variations:
    * `Uni_Campus_Net`: Leverages informal Australian/British/international student slang ("Uni") combined with a generic networking term ("Net").
    * `University_Intranet_Secure`: Mimics a restricted internal administrative network, enticing faculty and IT workers to connect for internal server access.
    * `University_Public_Access`: Mimics municipal or public library access policies.
    * `Campus_Wide_Open_Net`: Exploits expectations of broad, unrestricted campus connectivity.

### 2. The "Impossible Threshold" Dilemma in Vector Embeddings
This category exposes the fundamental failure mode of relying purely on dense vector embeddings (e.g. `all-MiniLM-L6-v2`, `text-embedding-ada-002`, or BERT-style models) for wireless threat classification:

```
Embedding Cosine Similarity Space:
+---------------------------------------------------------------------------------------+
|  0.0                                0.70                    0.90               1.0   |
|   |-----------------------------------|-----------------------|-----------------|    |
|   Noise Floor                Ambiguous Boundary        Conflation Hazard              |
|                                                                                       |
|   Starbucks_Guest             Uni_Campus_Net          College_Campus_5G (0.957)       |
|   (Cosine ~ 0.12)             (Cosine ~ 0.812)        [BENIGN False Positive!]        |
|                                                                                       |
|                               Campus_Wide_Open_Net    Faculty_Staff_Secure (0.941)    |
|                               (Cosine ~ 0.765)        [BENIGN False Positive!]        |
+---------------------------------------------------------------------------------------+
```

* **The Dilemma:**
  1. **Semantic Overlap in Benign Cases:** Legitimate academic synonyms (`College` vs `University`, `Faculty` vs `Staff`, `School` vs `Campus`) have high semantic proximity in NLP language models. Their embedding vectors produce cosine similarities exceeding $0.94 - 0.96$. A pure vector-distance detector flags `College_Campus_5G` and `Faculty_Staff_Secure` as malicious Evil Twins, producing severe false alarm rates.
  2. **Lowering the Threshold Causes False Negatives:** If security engineers lower the cosine similarity threshold to $0.75$ to avoid alerting on `College_Campus_5G`, malicious lures like `Uni_Campus_Net` ($0.812$) or `Campus_Wide_Open_Net` ($0.765$) blend into the ambiguous zone.
* **Resolution:**
  * Resolving semantic confusion requires a multi-tier pipeline: Tier 2 XGBoost evaluates orthographic features (where `College` and `University` have high edit distance and low trigram overlap), while Tier 4 SLM (Small Language Model) applies institutional contextual reasoning to verify if an affiliated department is benign.

---

## Category 7: `irrelevant_noise` (Environmental Ambient Wi-Fi Clutter)
**Samples (14):** `Cafe_Amazon_WiFi`, `Starbucks_Guest`, `AIS_SUPER_WiFi`, `TrueMove_H_WiFi`, `dtac_WiFi`, `7Eleven_Public`, `Dorm_Room_302_5G`, `iPhone_15_Hotspot`, `Galaxy_S24_MobileAP`, `HP_LaserJet_Direct_4B`, `Bangkok_Bank_Branch_WiFi`, `KFC_Guest_Free`, `Subway_Customers_WiFi`, `Campus_Bus_Transit_FreeWiFi`  
**Ground Truth Label:** `BENIGN`

### 1. Operational Reality of Campus RF Environments
* A university campus is not an RF anechoic chamber. It is an urban ecosystem surrounded by commercial coffee concessions, fast-food retail outlets, bank branches, public transit systems, telecom carrier Wi-Fi offload infrastructure (especially pervasive in Southeast Asia/Thailand with AIS, TrueMove, and dtac carrier hotspots), student dormitory routers, mobile hotspot tethering, and Wi-Fi Direct printers.
* In typical 802.11 monitor mode captures, **over 80% to 90% of observed SSIDs represent benign environmental noise**.

### 2. Adversarial Exploitation of Ambient Clutter
* **Chaff & Sensor Blinding (Algorithmic Denial of Service):**
  * If a rogue detection system routes every newly observed beacon frame to a heavy Large/Small Language Model (e.g. running 4B to 8B parameter models requiring 1 to 2 seconds of GPU inference per SSID), an adversary can blind the sensor pipeline.
  * By running beacon flooding tools (`mdk4 b -f ssid_wordlist.txt` or `wifiphisher`), the adversary floods the airspace with hundreds of synthetic ambient SSIDs. The LLM inference queue saturates, backlogging alerts while the real Evil Twin operates undetected.
* **Camouflaging under Carrier & IoT Profiles:**
  * Attackers deliberately name their rogue APs after common telco or mobile hotspots (e.g., `AIS_SUPER_WiFi_Free` or `iPhone_Hotspot`) in areas where students gather, knowing casual SOC sweeps will categorize them as third-party noise.
* **Defensive Pipeline Filtering:**
  * Tier 2 XGBoost acts as the critical high-speed gatekeeper. By evaluating features $f_1 \dots f_{13}$, ambient noise yields $P(\text{Evil Twin}) < 0.30$ and is dropped in $< 0.15\text{ ms}$, safeguarding downstream GPU resources for genuine high-risk anomalies.

---

## Summary Matrix: Red Team Attack Vectors Across 7 Categories

| Category | Primary Offensive Vector | Psychological / Technical Mechanism | Evasion Strategy | Detection Antidote |
| :--- | :--- | :--- | :--- | :--- |
| **`authorized_exact`** | BSSID Clone, Deauth Injection, Karma/Mana | PNL zero-interaction auto-connect; signal dominance | Matches whitelist byte-for-byte; evades all text-only checks | Tier 3 802.11 Physical Telemetry (BSSID, OUI, RSSI variance) |
| **`homoglyph_typo`** | ASCII leetspeak, kerning illusions (`rn`/`m`) | Visual cortex word-shape recognition (typoglycemia); glanceable UI | Tokenizer shattering in LLMs; subword embedding distortion | $f_6$ Homoglyph mapping, $f_1$ Levenshtein, $f_2$ Damerau-Levenshtein |
| **`word_addition`** | Feature lures (`_Fast`, `_VIP`), Traps (`_Login`, `_Setup`) | Desire for speed, free access; urgent IT compliance; CA profile traps | Prefix inflation destroys Jaro-Winkler; edit distance dilution | $f_4, f_5$ N-gram Jaccard, Token containment |
| **`word_subtraction`** | Qualifier stripping (`_Secure`), Root word clone (`University`) | Promiscuous PNL probe harvesting; fallback open network assumption | High edit distance ($f_1 < 0.50$); large length discrepancy | Substring prefix subset extraction, token containment |
| **`delimiter_case`** | Delimiter swaps (`-`, `.`, ` `), Case mutations (`university_...`) | Human case/delimiter blindness in UI; eduroam spec violation | Bypasses literal case-sensitive hash table / string filters | Canonical normalization (case-folding, delimiter strip) |
| **`semantic_relevant`** | Semantic clones (`Uni_Campus_Net`, `_Intranet_Secure`) | Exploits institutional naming conventions and student slang | Causes "Impossible Threshold" dilemma in vector embeddings | Hybrid XGBoost orthographic features + Tier 4 SLM reasoning |
| **`irrelevant_noise`** | Environmental camouflage, Chaff flooding (`mdk4`) | Hides in urban noise floor; algorithmic DoS on GPU models | Floods queue with benign commercial/carrier names | Tier 2 XGBoost ultra-low latency drop ($< 0.15\text{ ms}$, $P < 0.30$) |
