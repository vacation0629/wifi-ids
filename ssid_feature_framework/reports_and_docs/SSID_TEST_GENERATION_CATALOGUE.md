# IEEE 802.11 SSID Threat Taxonomy & Synthetic Dataset Generation Specification

## 1. Overview and Core Principles

This specification establishes an objective, domain-agnostic taxonomy for IEEE 802.11 Service Set Identifiers (SSIDs) to support the systematic generation and evaluation of wireless intrusion detection test cases.

### 1.1 Structural Decomposition of Real-World SSIDs
In production environments, wireless network names predominantly follow a multi-token structure using ASCII space (`" "`) delimiters:

$$\text{SSID} = [\text{Brand/Organization}] + [\text{Department/Audience}] + [\text{Technology/Qualifier}]$$

* **Brand / Organization Root:** Primary identifying entity (e.g., `AcmeCorp`, `Hilton`, `Siam`, `Metropolitan`, `Delta`).
* **Department / Audience:** Organizational role or access tier (e.g., `Staff`, `Guest`, `Student`, `Executive`, `Visitor`, `VIP`).
* **Technology / Qualifier:** Band, protocol, or network feature (e.g., `WiFi`, `5G`, `Secure`, `Fast`, `Portal`, `WLAN`).

### 1.2 The Single-Variable Mutation Principle
When generating test cases to evaluate detection classifiers:
* **Single-Variable Rule:** Each test case must modify strictly one linguistic or structural feature (e.g., character substitution alone, delimiter mutation alone, or lure addition alone).
* **Isolation Constraint:** Do not combine multiple techniques (e.g., leetspeak substitution + space replacement with underscore) unless explicitly generating for **Category 13 (Stacked Multi-Layer Evasions)**. Unintended multi-vector combinations skew classifier feature separation.

---

## 2. Master 13-Category Classification Catalogue

```mermaid
flowchart TD
    SSID["Input 802.11 SSID Frame"] --> Type{"Frame Validity"}
    Type -->|Length > 32 or Bad UTF-8| Cat12["12. byte_level_breakage"]
    Type -->|Valid Frame| Baseline{"Exact Whitelist Match?"}
    
    Baseline -->|Exact Byte Match| Cat01["01. authorized_exact (BENIGN)"]
    Baseline -->|No Exact Match| Evasion{"Adversarial Encoding?"}
    
    Evasion -->|Cross-Script Homoglyph| Cat08["08. cross_script_homoglyphs"]
    Evasion -->|Non-Printable / Whitespace| Cat09["09. invisible_and_whitespace"]
    Evasion -->|Fullwidth / Accents| Cat10["10. normalization_accents"]
    Evasion -->|Emoji / Non-Latin| Cat11["11. emoji_and_non_latin"]
    Evasion -->|Stacked Exploits| Cat13["13. combined_adversarial_tricks"]
    
    Evasion -->|Standard ASCII Mutation| Ortho{"Structural Mutation Type"}
    Ortho -->|Character Swaps / Leetspeak| Cat02["02. homoglyph_typo"]
    Ortho -->|Lure Added (Free/Login)| Cat03["03. word_addition"]
    Ortho -->|Token Truncated / Dropped| Cat04["04. word_subtraction"]
    Ortho -->|Delimiters / Casing Altered| Cat05["05. delimiter_case"]
    Ortho -->|Related Org / Sister Branch| Cat06["06. semantic_relevant"]
    Ortho -->|Unrelated Third-Party| Cat07["07. irrelevant_noise"]
```

---

### Part 1: Baseline Orthographic & Lexical Categories

#### Category 01: `authorized_exact`
* **Ground Truth:** `BENIGN`
* **Technical Scope:** Legitimate production network broadcasts matching the organizational whitelist exactly. At the network layer, identical SSID clones deployed by adversaries (Evil Twins) are disambiguated via physical layer telemetry (BSSID MAC OUI, RSSI volatility, 802.1X certificate validation vs. Open Captive Portal).
* **Generation Rule:** Exactly matches an authorized baseline name without character, delimiter, or casing alterations.
* **Canonical Examples:**
  * Corporate: `AcmeCorp Secure`, `AcmeCorp Guest`
  * Hospitality: `Hilton Honors WiFi`, `Marriott Guest`
  * University: `Siam Wifi`, `SiamXP Wifi`, `University Campus 5G`, `eduroam`

#### Category 02: `homoglyph_typo`
* **Ground Truth:** `EVIL_TWIN`
* **Technical Scope:** Visual lookalike characters, keystroke transpositions, or typo variations designed to exploit casual human scanning while maintaining high visual similarity.
* **Generation Rules:**
  1. **ASCII Leetspeak:** Replace Latin characters with visually similar numbers:
     * `i` or `l` $\to$ `1` (e.g., `S1am Wifi`, `AcmeC0rp`)
     * `o` or `O` $\to$ `0` (e.g., `edur0am`, `Hilt0n`)
     * `s` or `S` $\to$ `5` (e.g., `5taff`, `Campu5`)
     * `e` or `E` $\to$ `3` (e.g., `Secur3`, `Ent3rprise`)
  2. **Kerning Imitation:** Sequences that visually render similarly in standard sans-serif system fonts:
     * `m` $\leftrightarrow$ `rn` (e.g., `Carnpus`, `eduroarn`)
     * `vv` $\leftrightarrow$ `w` (e.g., `VVIFi`)
  3. **Keystroke Transposition:** Invert two adjacent characters:
     * `Student` $\to$ `Studnet`
     * `Campus` $\to$ `Campup`
* **Boundary Condition:** Must remain within standard printable ASCII (`0x20`–`0x7E`). Do not inject Unicode, zero-width characters, or foreign alphabets.
* **Canonical Examples:**
  * Corporate: `AcrneCorp Secure`, `AcmeCorp 5ecure`, `AcmeCorp Secur3`
  * Hospitality: `Hilt0n Honors WiFi`, `Hilton Hon0rs WiFi`
  * University: `S1am Wifi`, `Siam W1f1`, `University Carnpus 5G`, `edur0am`

#### Category 03: `word_addition`
* **Ground Truth:** `EVIL_TWIN`
* **Technical Scope:** Retains the authorized brand identity while appending or prepending deceptive lure words to entice user connection or simulate captive authentication portals.
* **Generation Rules:**
  * **Pretext Lures:** `Free`, `Official`, `Public`, `Guest`, `Fast`, `HighSpeed`
  * **Authentication Lures:** `Login`, `Portal`, `Auth`, `Register`, `SignIn`
  * **Connectivity Lures:** `AutoConnect`, `VIP`, `Backup`, `5G`, `Express`
* **Structure:**
  * Prepend: `[Lure] + " " + [Authorized_SSID]`
  * Append: `[Authorized_SSID] + " " + [Lure]`
* **Boundary Condition:** The authorized base name must be completely intact. Do not introduce spelling errors or delimiter variations.
* **Canonical Examples:**
  * Corporate: `Free AcmeCorp Secure`, `AcmeCorp Secure Login`, `Official AcmeCorp Guest`
  * Hospitality: `Free Hilton Honors WiFi`, `Hilton Honors Fast WiFi`, `Hilton Guest Portal`
  * University: `Free Siam Wifi`, `Siam Wifi 5G`, `SiamXP Wifi Login`, `University Campus 5G AutoConnect`

#### Category 04: `word_subtraction`
* **Ground Truth:** `EVIL_TWIN`
* **Technical Scope:** Truncation of qualifiers, security designations, or frequency band indicators, leaving a shortened root brand name to impersonate umbrella organization authority.
* **Generation Rules:**
  * Remove the technology suffix: `[Brand] [Department] [Band]` $\to$ `[Brand] [Department]`
  * Remove the department qualifier: `[Brand] [Department]` $\to$ `[Brand]`
  * Single-word brand extraction: `Siam Wifi` $\to$ `Siam`
* **Boundary Condition:** Must be a strict substring subset of an authorized multi-token SSID.
* **Canonical Examples:**
  * Corporate: `AcmeCorp`, `AcmeCorp Staff` (targeting `AcmeCorp Staff Secure`)
  * Hospitality: `Hilton`, `Hilton Honors` (targeting `Hilton Honors WiFi`)
  * University: `Siam`, `SiamXP`, `University`, `Campus 5G`

#### Category 05: `delimiter_case`
* **Ground Truth:** `EVIL_TWIN` *(Except where uppercase is verified official signage)*
* **Technical Scope:** Alteration of standard word separators or letter casing. Adversaries exploit delimiter alterations to bypass rigid exact-string filters while appearing identical in compact mobile UI pickers.
* **Generation Rules:**
  1. **Delimiter Substitution:** Replace standard space with underscore (`_`), hyphen (`-`), dot (`.`), or repeated spaces (`  `):
     * `Siam Wifi` $\to$ `Siam_Wifi`
     * `AcmeCorp Secure` $\to$ `AcmeCorp-Secure`
     * `University Campus 5G` $\to$ `University.Campus.5G`
  2. **Casing Mutations:**
     * All uppercase: `SIAM WIFI`, `EDUROAM`, `ACMECORP SECURE`
     * All lowercase: `siam wifi`, `university campus 5g`
     * CamelCase spacing removal: `SiamXP Wifi` $\to$ `Siam XP Wifi`
* **Boundary Condition:** Words must not be misspelt or added. Only separators and casing are altered.
* **Canonical Examples:**
  * Corporate: `AcmeCorp_Secure`, `AcmeCorp-Secure`, `acmecorp secure`
  * Hospitality: `Hilton_Honors_WiFi`, `HILTON HONORS WIFI`
  * University: `Siam_Wifi`, `Siam-Wifi`, `Siam  Wifi`, `Siam XP Wifi`, `EDUROAM`

#### Category 06: `semantic_relevant`
* **Ground Truth:** Context-dependent (Legitimate Subnets = `BENIGN`; Unofficial / Rogue Clones = `EVIL_TWIN`)
* **Technical Scope:** Network names that share semantic, institutional, or departmental context with the target entity, but do not share direct word-level identity.
* **Generation Rules:**
  * **Affiliated Institutional Units:** Sister departments, colleges, laboratories, or internal infrastructure:
    * `[Organization] + [Faculty/Unit] + [Network]`
    * `[Synonym] + [Campus/HQ] + [Band]`
  * **Synonym Roots:** Replace `University` with `College`, `Institute`, `Academy`, `Polytechnic`; replace `Corp` with `Enterprises`, `Industries`, `Holdings`.
* **Boundary Condition:** Must share thematic/institutional vocabulary without matching the exact authorized whitelist tokens.
* **Canonical Examples:**
  * Corporate: `Acme Logistics Net`, `Acme Research Labs`, `Acme Partner WLAN`
  * Hospitality: `Hilton Executive Lounge`, `Hilton Conference Suites`, `Hilton Valet WiFi`
  * University: `Siam University Guest`, `Siam Engineering WiFi`, `College Campus 5G`, `Institute Student WLAN`

#### Category 07: `irrelevant_noise`
* **Ground Truth:** `BENIGN`
* **Technical Scope:** Environmental ambient wireless networks that operate in the same physical airspace but belong to completely unrelated third parties (retail, telecommunications, residential).
* **Generation Rules:**
  * Commercial hotspots: Coffee chains, retail stores, public transport, telecom operators.
  * Default residential hardware: ISP brand routers, default printer Wi-Fi Direct tags.
* **Boundary Condition:** Must have zero semantic or orthographic overlap with the protected organization's brand tokens.
* **Canonical Examples:**
  * Commercial: `Starbucks WiFi`, `Cafe Amazon WiFi`, `McDonalds Free WiFi`, `AIS SUPER WiFi`, `true_wifi`
  * Residential / Device: `DIRECT-72-HP OfficeJet`, `TP-Link_5G_Home`, `NETGEAR-Guest`, `Family_LivingRoom`

---

### Part 2: Advanced Adversarial Evasion Categories

#### Category 08: `cross_script_homoglyphs`
* **Ground Truth:** `EVIL_TWIN`
* **Technical Scope:** Injection of non-Latin Unicode graphemes (principally Cyrillic and Greek) that possess identical visual glyph rasterization to Latin characters in standard system fonts, bypassing simple ASCII comparisons.
* **Generation Rules:**
  * Cyrillic Small Letter `е` (`U+0435`) for Latin `e` (`U+0065`)
  * Cyrillic Small Letter `а` (`U+0430`) for Latin `a` (`U+0061`)
  * Cyrillic Small Letter `о` (`U+043E`) for Latin `o` (`U+006F`)
  * Cyrillic Small Letter `і` (`U+0456`) for Latin `i` (`U+0069`)
  * Cyrillic Capital Letter `Х` (`U+0425`) for Latin `X` (`U+0058`)
  * Cyrillic Capital Letter `Р` (`U+0420`) for Latin `P` (`U+0050`)
  * Greek Small Letter `ο` (`U+03BF`) for Latin `o` (`U+006F`)
* **Canonical Examples:**
  * `Sіam Wifi` (`\u0456` Cyrillic `і`)
  * `SiamХP Wifi` (`\u0425` Cyrillic `Х`)
  * `Univеrsity Campus 5G` (`\u0435` Cyrillic `е`)
  * `edurοam` (`\u03BF` Greek `ο`)

#### Category 09: `invisible_and_whitespace`
* **Ground Truth:** `EVIL_TWIN`
* **Technical Scope:** Insertion of zero-width, non-printable, or non-standard whitespace Unicode codepoints. These render completely invisible to human eyes in UI pickers but alter raw byte sequences.
* **Generation Rules:**
  * Zero-Width Space (ZWSP): `U+200B`
  * Zero-Width Non-Joiner (ZWNJ): `U+200C`
  * Byte Order Mark (BOM): `U+FEFF`
  * Non-Breaking Space (NBSP): `U+00A0`
  * Trailing ASCII Whitespace: Appending single or multiple space characters (`0x20`) to the end of the name.
* **Canonical Examples:**
  * `Siam Wifi​` (`Siam Wifi\u200B` - trailing ZWSP)
  * `\uFEFFSiam Wifi` (prepended BOM)
  * `Siam\u00A0Wifi` (NBSP separator)
  * `University Campus 5G ` (trailing space)

#### Category 10: `normalization_accents`
* **Ground Truth:** `EVIL_TWIN`
* **Technical Scope:** Exploiting Unicode normalization forms (NFC vs. NFD vs. NFKC). Includes fullwidth Latin characters from the East Asian Halfwidth/Fullwidth block and decomposed combining diacritic marks.
* **Generation Rules:**
  * Fullwidth Latin: `U+FF01` through `U+FF5E` (e.g. `Ｓ` `U+FF33`, `Ｕ` `U+FF35`)
  * Combining Diacritics: Latin base character + Combining Acute Accent (`U+0301`) or Grave Accent (`U+0300`)
* **Canonical Examples:**
  * `Ｓiam Wifi` (`\uFF33` Fullwidth `S`)
  * `Ｕniversity Campus 5G` (`\uFF35` Fullwidth `U`)
  * `Síam Wifi` (`i` + `\u0301` combining mark)

#### Category 11: `emoji_and_non_latin`
* **Ground Truth:** Context-dependent (Brand + Emoji = `EVIL_TWIN`; Pure Native Script = `BENIGN`)
* **Technical Scope:** 
  1. Appending signal indicator emojis or visual lures to authorized brands.
  2. Native non-Latin scripts (e.g., Thai, Arabic, Chinese, Japanese) operating in regional airspaces without Latin brand tokens.
* **Generation Rules:**
  * **Brand with Visual Emoji:** `[Authorized_SSID] + [📶 / 🌐 / 🔒 / ⚡]` $\to$ `EVIL_TWIN`
  * **Pure Non-Latin Language:** Authentic regional words (0% Latin characters) $\to$ `BENIGN`
* **Canonical Examples:**
  * Rogue Lure: `Siam Wifi📶`, `University Campus 5G🔒`, `AcmeCorp Guest🌐`
  * Benign Regional: `บ้านสุข` (Thai: Suk Home), `ร้านกาแฟสด` (Fresh Coffee Shop), `สำนักงานคณบดี` (Dean Office)

#### Category 12: `byte_level_breakage`
* **Ground Truth:** `MALFORMED` / `BENIGN_HIDDEN`
* **Technical Scope:** Deliberate violations of IEEE 802.11 management frame standards or RFC 3629 UTF-8 encoding rules to trigger parser crashes, buffer overflows, or exceptions.
* **Generation Rules:**
  * **Oversized SSID:** $> 32$ octets (IEEE 802.11 spec violation).
  * **Overlong UTF-8 Encoding:** RFC 3629 violation (e.g. `\xC1\xA1` representing ASCII `!`).
  * **Truncated Multi-Byte UTF-8:** Providing a lead byte (e.g. `\xE0\xB8`) without trailing continuation bytes.
  * **Hidden SSID:** Length of 0 octets or null padding (`\x00\x00\x00\x00\x00\x00`).
* **Canonical Examples:**
  * Oversized: `33 × 'A'` (33 bytes)
  * Malformed: `\xc1\xa1Siam Wifi`
  * Hidden: `""` (0 octets, benign hidden network)

#### Category 13: `combined_adversarial_tricks`
* **Ground Truth:** `EVIL_TWIN`
* **Technical Scope:** Stacked, multi-layered evasions combining two or more techniques from Categories 02 through 11 in a single broadcast payload.
* **Generation Rules:** Combine at least two distinct evasion layers:
  * Lure prefix + Leetspeak + Delimiter alteration
  * Zero-Width Space + Fullwidth character + Cyrillic lookalike + Appended emoji
* **Canonical Examples:**
  * `Free_S1am_Wifi` (Word addition + Leetspeak + Delimiter mutation)
  * `\u200BＳіam Wifi📶 ` (ZWSP + Fullwidth `S` + Cyrillic `і` + Emoji + Trailing space)

---

## 3. Macro Benchmark Rollup Matrix

When conducting macro-level evaluations (such as the 210-sample benchmark), the 13 fine-grained categories roll up into 4 high-level evaluation classes:

| Macro Category | Ground Truth | Included Fine-Grained Categories | Primary Target Behavior |
| :--- | :---: | :--- | :--- |
| **`classical_orthographic_evil_twin`** | `EVIL_TWIN` | `02_homoglyph_typo`<br>`03_word_addition`<br>`04_word_subtraction`<br>`05_delimiter_case`<br>`08_cross_script`<br>`09_invisible_chars`<br>`10_accents`<br>`13_combined` | Directly targets an authorized SSID with orthographic, lexical, or encoding manipulations. High character overlap with target. |
| **`zero_overlap_semantic_evil_twin`** | `EVIL_TWIN` | Advanced `03_word_addition` & `06_semantic_relevant` with zero lexical overlap | High-risk social engineering lures that avoid protected brand keywords entirely (e.g., `Complimentary Patron Access`, `Faculty Instructional Net`). |
| **`departmental_sister_benign`** | `BENIGN` | Legitimate `06_semantic_relevant` | Authorized subnets, research units, and sister campuses that share contextual terminology but represent legitimate operations. |
| **`ambient_environmental_noise`** | `BENIGN` | `07_irrelevant_noise`<br>Pure `11_emoji_and_non_latin` | External retail shops, cafes, neighboring home networks, and commercial hotspots operating safely in the airspace. |

---

## 4. Standard JSON Dataset Output Schema

To generate datasets compatible with the framework test engine, use the following JSON schema:

```json
[
  {
    "observed_ssid": "S1am Wifi",
    "target_authorized_ssid": "Siam Wifi",
    "category": "homoglyph_typo",
    "macro_category": "classical_orthographic_evil_twin",
    "ground_truth_label": "EVIL_TWIN",
    "description": "ASCII leetspeak substitution of Latin 'i' with digit '1' in brand root."
  },
  {
    "observed_ssid": "Starbucks WiFi",
    "target_authorized_ssid": null,
    "category": "irrelevant_noise",
    "macro_category": "ambient_environmental_noise",
    "ground_truth_label": "BENIGN",
    "description": "Commercial third-party coffee shop network with zero institutional overlap."
  }
]
```

---

## 5. Ready-to-Use LLM Generation Prompt Template

Copy and paste the template below into any LLM (e.g., Gemini, Claude, GPT) to generate new, strictly conforming test cases:

```text
You are an expert wireless network security test generator.
Generate a JSON array of [N] synthetic 802.11 SSID test cases targeting the authorized whitelist:
Authorized Baseline: ["AcmeCorp Secure", "AcmeCorp Guest", "Siam Wifi", "SiamXP Wifi", "eduroam"]

Follow these strict rules:
1. Adhere to the Single-Variable Mutation Principle: each test case must modify strictly ONE feature (homoglyph alone, lure addition alone, delimiter change alone) unless explicitly assigned to 'combined_adversarial_tricks'.
2. Use natural space delimiters (" ") as the real-world baseline. Do not use underscores in the baseline authorized target.
3. Distribute the cases across these categories:
   - authorized_exact (BENIGN)
   - homoglyph_typo (EVIL_TWIN)
   - word_addition (EVIL_TWIN)
   - word_subtraction (EVIL_TWIN)
   - delimiter_case (EVIL_TWIN)
   - semantic_relevant (BENIGN or EVIL_TWIN)
   - irrelevant_noise (BENIGN)
   - cross_script_homoglyphs (EVIL_TWIN - specify Unicode)
   - invisible_and_whitespace (EVIL_TWIN - specify Unicode)
   - normalization_accents (EVIL_TWIN - specify Unicode)
   - emoji_and_non_latin (EVIL_TWIN or BENIGN)

Output strictly valid JSON with keys:
"observed_ssid", "target_authorized_ssid", "category", "macro_category", "ground_truth_label", "description"
```
