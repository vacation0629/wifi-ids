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
* **Isolation Constraint:** Do not combine multiple techniques (e.g., leetspeak substitution + space replacement with underscore) unless explicitly generating for **Category 13 (combined_adversarial_tricks)**. Unintended multi-vector combinations skew classifier feature separation.

---

## 2. Master 13-Category Classification Catalogue

```mermaid
flowchart TD
    SSID["Input 802.11 SSID Frame"] --> Type{"Frame Validity"}
    Type -->|Length > 32 or Bad UTF-8| Cat12["12_byte_level_breakage"]
    Type -->|Valid Frame| Baseline{"Exact Whitelist Match?"}
    
    Baseline -->|Exact Byte Match| Cat01["01_authorized_exact (BENIGN)"]
    Baseline -->|No Exact Match| Evasion{"Adversarial Encoding?"}
    
    Evasion -->|Cross-Script Homoglyph| Cat08["08_cross_script_homoglyphs"]
    Evasion -->|Non-Printable / Whitespace| Cat09["09_invisible_and_whitespace"]
    Evasion -->|Fullwidth / Accents| Cat10["10_normalization_accents"]
    Evasion -->|Emoji / Non-Latin| Cat11["11_emoji_and_non_latin"]
    Evasion -->|Stacked Exploits| Cat13["13_combined_adversarial_tricks"]
    
    Evasion -->|Standard ASCII Mutation| Ortho{"Structural Mutation Type"}
    Ortho -->|Character Swaps / Leetspeak| Cat02["02_homoglyph_typo"]
    Ortho -->|Lure Added (Free/Login)| Cat03["03_word_addition"]
    Ortho -->|Token Truncated / Dropped| Cat04["04_word_subtraction"]
    Ortho -->|Delimiters / Casing Altered| Cat05["05_delimiter_case"]
    Ortho -->|Related Org / Sister Branch| Cat06["06_semantic_relevant"]
    Ortho -->|Unrelated Third-Party| Cat07["07_irrelevant_noise"]
```

---

### Part 1: Baseline Orthographic & Lexical Categories

#### Category 01: `authorized_exact`
* **Canonical Identifier:** `01_authorized_exact`
* **Ground Truth:** `BENIGN`
* **Technical Scope:** Legitimate production network broadcasts matching the organizational whitelist exactly. At the network layer, identical SSID clones deployed by adversaries (Evil Twins) are disambiguated via physical layer telemetry (BSSID MAC OUI, RSSI volatility, 802.1X certificate validation vs. Open Captive Portal).
* **Generation Rule:** Exactly matches an authorized baseline name without character, delimiter, or casing alterations.
* **Canonical Examples:**
  * Corporate: `AcmeCorp Secure`, `AcmeCorp Guest`
  * Hospitality: `Hilton Honors WiFi`, `Marriott Guest`
  * University: `Siam Wifi`, `SiamXP Wifi`, `University Campus 5G`, `eduroam`

#### Category 02: `homoglyph_typo`
* **Canonical Identifier:** `02_homoglyph_typo`
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
* **Canonical Identifier:** `03_word_addition`
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
* **Canonical Identifier:** `04_word_subtraction`
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
* **Canonical Identifier:** `05_delimiter_case`
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
* **Canonical Identifier:** `06_semantic_relevant`
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
* **Canonical Identifier:** `07_irrelevant_noise`
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
* **Canonical Identifier:** `08_cross_script_homoglyphs`
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
* **Canonical Identifier:** `09_invisible_and_whitespace`
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
* **Canonical Identifier:** `10_normalization_accents`
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
* **Canonical Identifier:** `11_emoji_and_non_latin`
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
* **Canonical Identifier:** `12_byte_level_breakage`
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
* **Canonical Identifier:** `13_combined_adversarial_tricks`
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

| Macro Category | Ground Truth | Included Fine-Grained Categories (Canonical Identifiers) | Primary Target Behavior |
| :--- | :---: | :--- | :--- |
| **`classical_orthographic_evil_twin`** | `EVIL_TWIN` | `02_homoglyph_typo`<br>`03_word_addition`<br>`04_word_subtraction`<br>`05_delimiter_case`<br>`08_cross_script_homoglyphs`<br>`09_invisible_and_whitespace`<br>`10_normalization_accents`<br>`13_combined_adversarial_tricks` | Directly targets an authorized SSID with orthographic, lexical, or encoding manipulations. High character overlap with target. |
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
    "category": "02_homoglyph_typo",
    "macro_category": "classical_orthographic_evil_twin",
    "ground_truth_label": "EVIL_TWIN",
    "description": "ASCII leetspeak substitution of Latin 'i' with digit '1' in brand root."
  },
  {
    "observed_ssid": "Starbucks WiFi",
    "target_authorized_ssid": null,
    "category": "07_irrelevant_noise",
    "macro_category": "ambient_environmental_noise",
    "ground_truth_label": "BENIGN",
    "description": "Commercial third-party coffee shop network with zero institutional overlap."
  }
]
```

---

## 5. Ready-to-Use LLM Generation Prompt Templates

Generating high-volume datasets (such as **50 samples per category across all 13 categories = 650 total samples**) requires distinct prompting strategies to avoid model output token truncation and repetitive pattern decay.

```mermaid
flowchart TD
    Choice{"Generation Volume"}
    Choice -->|Small Batch (N <= 30)| P1["Template 5.1: Multi-Category General Prompt\n(Quick balanced sampling across all categories)"]
    Choice -->|High-Volume (50 per Category = 650 Total)| P2["Template 5.2: Per-Category High-Volume Batch Prompt\n(50 diverse samples for ONE category at a time)"]
```

---

### 5.1 Multi-Category General Prompt (Small Batches: $N \le 30$)
Use this template for generating a rapid, balanced cross-section across all 13 categories in a single LLM request:

```text
You are an expert wireless network security test generator.
Generate a JSON array of [N] synthetic IEEE 802.11 SSID test cases targeting the authorized whitelist:
Authorized Baseline: ["AcmeCorp Secure", "AcmeCorp Guest", "Siam Wifi", "SiamXP Wifi", "eduroam"]

Follow these strict rules:
1. Adhere to the Single-Variable Mutation Principle: each test case must modify strictly ONE feature (homoglyph alone, lure addition alone, delimiter change alone) unless explicitly assigned to '13_combined_adversarial_tricks'.
2. Use natural space delimiters (" ") as the real-world baseline. Do not use underscores in the baseline authorized target.
3. Distribute the cases across ALL 13 categories using their canonical identifiers:
   - 01_authorized_exact (BENIGN)
   - 02_homoglyph_typo (EVIL_TWIN)
   - 03_word_addition (EVIL_TWIN)
   - 04_word_subtraction (EVIL_TWIN)
   - 05_delimiter_case (EVIL_TWIN)
   - 06_semantic_relevant (BENIGN or EVIL_TWIN)
   - 07_irrelevant_noise (BENIGN)
   - 08_cross_script_homoglyphs (EVIL_TWIN - specify Unicode codepoint in description)
   - 09_invisible_and_whitespace (EVIL_TWIN - specify Unicode codepoint like ZWSP \u200B or BOM \uFEFF)
   - 10_normalization_accents (EVIL_TWIN - specify fullwidth or combining accent Unicode)
   - 11_emoji_and_non_latin (EVIL_TWIN for brand+emoji, BENIGN for pure non-Latin regional script)
   - 12_byte_level_breakage (MALFORMED for length > 32 octets or bad UTF-8, BENIGN_HIDDEN for 0 bytes)
   - 13_combined_adversarial_tricks (EVIL_TWIN - multi-layer stacked tricks)

Output strictly valid JSON with keys:
"observed_ssid", "target_authorized_ssid", "category", "macro_category", "ground_truth_label", "description"
```

---

### 5.2 Per-Category High-Volume Batch Prompt (50 Samples per Category)

> [!IMPORTANT]
> **Why Per-Category Prompting is Required for 50 Samples:**  
> Asking an LLM to generate 650 JSON objects ($50 \times 13$) in a single call requires over 35,000 output tokens, exceeding the 4,096–8,192 token limit of modern LLM APIs and causing incomplete, truncated responses. Prompting **50 samples for ONE category at a time** consumes ~2,500 tokens, guaranteeing 100% completion, structural integrity, and rich diversity.

Copy and run this template once for each category (replacing `[CATEGORY_NAME]` with one of the 13 canonical IDs):

```text
You are an expert wireless network security test generator.
Generate exactly 50 UNIQUE, DIVERSE synthetic IEEE 802.11 SSID test cases strictly belonging to the single category:
Category: [CATEGORY_NAME]
Authorized Whitelist Baseline: ["AcmeCorp Secure", "AcmeCorp Staff", "AcmeCorp Guest", "Siam Wifi", "SiamXP Wifi", "University Campus 5G", "eduroam"]

Follow these strict diversity and generation guidelines:
1. Target Distribution: Evenly distribute the 50 cases across all authorized targets (approx. 7-10 test cases per target network).
2. Diversity Requirements for [CATEGORY_NAME]:
   - Vary character positions: apply modifications to the first token, middle token, and trailing tokens.
   - Vary mutation types specific to this category (see Section 2 specifications).
   - Ensure all 50 samples are distinct; do not repeat identical payloads with trivial variations.
3. Single-Variable Rule: Modify strictly ONE feature relevant to [CATEGORY_NAME]. Do NOT introduce accidental compound errors (e.g. do not add underscores in homoglyph tests unless testing 05_delimiter_case or 13_combined_adversarial_tricks).
4. IEEE 802.11 Compliance: Ensure all strings encode to <= 32 UTF-8 bytes (except for oversized test cases in 12_byte_level_breakage).
5. Ground Truth Label: Set accurately according to Section 2 specifications (BENIGN, EVIL_TWIN, or MALFORMED).

Output strictly a valid JSON array of 50 objects with these exact keys:
[
  {
    "observed_ssid": "...",
    "target_authorized_ssid": "...",
    "category": "[CATEGORY_NAME]",
    "macro_category": "...",
    "ground_truth_label": "...",
    "description": "..."
  }
]
```

---

## 6. Operational Instructions: Step-by-Step Dataset Generation Workflow

Follow these steps to generate, assemble, validate, and benchmark a complete 650-sample dataset (50 samples $\times$ 13 categories):

```mermaid
flowchart TD
    S1["Step 1: Set Whitelist Baseline\n(Enterprise, Campus, Hospitality)"] --> S2["Step 2: Generate 50 Samples per Category\n(13 Batches using Template 5.2 or Python Script)"]
    S2 --> S3["Step 3: Merge into Master JSON\n(test_cases_650.json)"]
    S3 --> S4["Step 4: Quality Control & Spec Validation\n(<=32 bytes, Single-Variable, Schema)"]
    S4 --> S5["Step 5: Run Benchmark & Model Evaluation\n(benchmark.py & run_extended_200_benchmark.py)"]
```

### Step 1: Select Target Environment & Whitelist
Choose and document your primary authorized baseline names. Ensure all targets use natural space delimiters (`" "`):
* **Siam University / Regional:** `["Siam Wifi", "SiamXP Wifi", "SIAM WIFI", "SIAM XP WIFI", "eduroam"]`
* **Enterprise Corporate:** `["AcmeCorp Secure", "AcmeCorp Staff", "AcmeCorp Guest"]`
* **Hospitality / Hotel:** `["Hilton Honors WiFi", "Hilton Guest", "Hilton Executive"]`

---

### Step 2: Generate 50 Samples per Category (The 13-Batch Process)

To achieve maximum diversity across the 50 samples in each category, follow these specific distribution targets:

| Category ID | Ground Truth | Diversity Strategy for 50 Samples |
| :--- | :---: | :--- |
| **`01_authorized_exact`** | `BENIGN` | 50 legitimate production SSIDs: Vary departmental units, buildings, and campus branches (`Siam Wifi`, `Siam Engineering 5G`, `AcmeCorp Executive`, `AcmeCorp Finance`, etc.). |
| **`02_homoglyph_typo`** | `EVIL_TWIN` | 15 Leetspeak (`1/i`, `0/o`), 15 Leetspeak (`5/s`, `3/e`), 10 Kerning (`rn/m`, `vv/w`), 10 Adjacent Transpositions (`Studnet`, `Campup`). |
| **`03_word_addition`** | `EVIL_TWIN` | 15 Pretext lures (`Free`, `Official`, `Public`), 15 Auth lures (`Login`, `Portal`, `Register`), 10 Speed/Band lures (`Fast`, `5G`, `AutoConnect`), 10 Prefix vs Suffix balance. |
| **`04_word_subtraction`**| `EVIL_TWIN` | 20 Technology suffix drops (`_5G`, `_WiFi`), 15 Department qualifier drops (`_Secure`, `_Portal`), 15 Single-word root identity clones (`Siam`, `AcmeCorp`, `University`). |
| **`05_delimiter_case`** | `EVIL_TWIN` | 10 Underscore replacements (`_`), 10 Hyphen replacements (`-`), 10 Dot replacements (`.`), 10 Multiple space injections (`  `), 10 Case mutations (`ALL CAPS`, `all lowercase`). |
| **`06_semantic_relevant`**| Context | 25 Legitimate sister units (`Siam Engineering WiFi`, `Acme Logistics Net` $\to$ `BENIGN`), 25 Deceptive unaffiliated clones (`College Campus Net`, `Academic WiFi` $\to$ `EVIL_TWIN`). |
| **`07_irrelevant_noise`**| `BENIGN` | 20 Commercial cafes & restaurants (`Starbucks`, `Cafe Amazon`), 15 Telecom hotspots (`AIS SUPER WiFi`, `true_wifi`), 15 Residential routers (`DIRECT-HP`, `TP-Link_5G`). |
| **`08_cross_script_homoglyphs`**| `EVIL_TWIN` | 25 Cyrillic substitutions (`\u0435` for `e`, `\u0430` for `a`, `\u0456` for `i`, `\u0425` for `X`), 25 Greek substitutions (`\u03BF` for `o`, `\u03B1` for `a`, `\u03B9` for `i`). |
| **`09_invisible_and_whitespace`**| `EVIL_TWIN` | 15 Zero-Width Spaces (`\u200B`), 10 Byte Order Marks (`\uFEFF`), 15 Non-Breaking Spaces (`\u00A0`), 10 Trailing ASCII spaces (` `). |
| **`10_normalization_accents`**| `EVIL_TWIN` | 25 Fullwidth Latin (`\uFF33` `Ｓ`, `\uFF35` `Ｕ`), 25 Decomposed Combining Diacritics (`e` + `\u0301` acute, `a` + `\u0300` grave). |
| **`11_emoji_and_non_latin`**| Context | 25 Brand + Signal Emojis (`Siam Wifi📶`, `AcmeCorp🔒` $\to$ `EVIL_TWIN`), 25 Pure Native Scripts (Thai `บ้านสุข`, `มหาวิทยาลัย` $\to$ `BENIGN`). |
| **`12_byte_level_breakage`**| Context | 15 Oversized frames ($33\text{--}40$ octets $\to$ `MALFORMED`), 15 RFC 3629 Overlong UTF-8 (`\xC1\xA1`), 10 Truncated UTF-8 (`\xE0\xB8`), 10 Hidden APs (0 octets $\to$ `BENIGN_HIDDEN`). |
| **`13_combined_adversarial_tricks`**| `EVIL_TWIN` | 50 Stacked Multi-Layer Evasions: Combining Lure + Homoglyph + Delimiter + Unicode (e.g. `Free_S1am_Wifi`, `\u200BＳіam Wifi📶 `). |

---

### Step 3: Automated Python Batch Generation Script

Instead of manually running 13 prompts in a chat window, save and run this automated Python script to generate all 650 samples in sequence using any OpenAI-compatible endpoint (LM Studio on port 1234, Ollama, or OpenAI/Gemini/Anthropic API):

```python
#!/usr/bin/env python3
"""
Automated 650-Sample Dataset Generator (50 Samples x 13 Categories)
Iterates through all 13 Master Taxonomy categories and merges into test_cases_650.json.
"""

import json
import re
import requests
import sys

API_URL = "http://localhost:1234/v1/chat/completions"  # Local LM Studio / vLLM / Ollama
MODEL_NAME = "local-model"  # or "gpt-4o", "gemini-1.5-pro", "claude-3-5-sonnet"

CATEGORIES = [
    "01_authorized_exact",
    "02_homoglyph_typo",
    "03_word_addition",
    "04_word_subtraction",
    "05_delimiter_case",
    "06_semantic_relevant",
    "07_irrelevant_noise",
    "08_cross_script_homoglyphs",
    "09_invisible_and_whitespace",
    "10_normalization_accents",
    "11_emoji_and_non_latin",
    "12_byte_level_breakage",
    "13_combined_adversarial_tricks"
]

WHITELIST = ["AcmeCorp Secure", "AcmeCorp Guest", "Siam Wifi", "SiamXP Wifi", "eduroam"]

def generate_category_batch(category_name, count=50):
    prompt = f"""
You are a senior wireless security researcher.
Generate exactly {count} distinct JSON objects for IEEE 802.11 SSID test cases strictly belonging to:
Category: {category_name}
Target Whitelist: {json.dumps(WHITELIST)}

Rules:
1. Apply the Single-Variable Mutation Principle (strictly modify 1 feature unless category is 13_combined_adversarial_tricks).
2. Distribute targets evenly across the whitelist.
3. Ensure high diversity across all {count} samples.
4. Output strictly a valid JSON array of {count} objects with keys:
"observed_ssid", "target_authorized_ssid", "category", "macro_category", "ground_truth_label", "description"
"""
    response = requests.post(
        API_URL,
        json={
            "model": MODEL_NAME,
            "messages": [{"role": "user", "content": prompt}],
            "temperature": 0.3,
            "max_tokens": 4000
        },
        timeout=120
    )
    raw_text = response.json()["choices"][0]["message"]["content"]
    # Extract JSON array
    json_match = re.search(r"\[\s*\{.*\}\s*\]", raw_text, re.DOTALL)
    if json_match:
        return json.loads(json_match.group(0))
    return json.loads(raw_text)

def main():
    master_dataset = []
    print(f"[*] Starting high-volume generation: 50 samples x 13 categories = 650 total")
    
    for cat in CATEGORIES:
        print(f"    -> Generating 50 samples for {cat}...")
        try:
            items = generate_category_batch(cat, count=50)
            master_dataset.extend(items)
            print(f"       [OK] Generated {len(items)} samples.")
        except Exception as e:
            print(f"       [!] Error on {cat}: {e}")
            
    out_file = "test_cases_650.json"
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(master_dataset, f, indent=2, ensure_ascii=False)
    print(f"\n[+] Successfully generated master dataset with {len(master_dataset)} samples: {out_file}")

if __name__ == "__main__":
    main()
```

---

### Step 4: Quality Control & Validation Checklist
Before feeding the generated JSON into intrusion detection models, run the following automated checks:
* [ ] **Sample Count Check:** Verify that exactly $50 \times 13 = 650$ objects are present (`len(data) == 650`).
* [ ] **Byte Length Check:** Verify `len(observed_ssid.encode('utf-8')) <= 32`. Any sample $> 32$ bytes must strictly belong to `12_byte_level_breakage`.
* [ ] **Single-Variable Rule:** Ensure non-Category 13 samples do not combine tricks (e.g. verify a `02_homoglyph_typo` sample does not also introduce an underscore delimiter).
* [ ] **JSON Syntax & Keys:** Confirm every record contains all 6 required fields: `observed_ssid`, `target_authorized_ssid`, `category`, `macro_category`, `ground_truth_label`, `description`.

---

### Step 5: Execute Automated Benchmark Evaluation
Run the generated test cases against the framework detection engines:
1. Save the validated JSON to a file: `ssid_feature_framework/test_cases_650.json`.
2. Run the unit test sanitization suite:
   ```powershell
   py ssid_feature_framework/adversarial_cases_research/test_defensive_sanitizer.py
   ```
3. Run the feature extraction decision tree benchmark:
   ```powershell
   py ssid_feature_framework/benchmark.py
   ```
4. Verify classifier output:
   * **Expected Detection Recall:** $\ge 98.0\%$ on evil twin categories.
   * **Expected Precision:** $\ge 95.0\%$ on benign noise discard.
   * **Sanitization Latency:** $< 0.05\text{ ms}$ per frame on CPU.
