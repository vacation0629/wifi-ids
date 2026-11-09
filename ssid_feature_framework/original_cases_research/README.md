# 🛡️ Baseline 7-Category SSID Threat Detection & Feature Research Catalogue
## Collaborative Red Team & Blue Team Multi-Agent Research, Feature Mathematics & Architectural Specifications

> **Research Environment:** `D:\Antigravity Project\Rogue wifi\ssid_feature_framework\original_cases_research`  
> **Target Whitelist AP Baseline:** `['University_Campus_5G', 'University_Staff_Secure', 'University_Student_WiFi', 'University_Guest_Portal', 'eduroam']`  
> **Total Evaluated Dataset:** 88 Curated Campus Wireless SSIDs (`test_cases.json`)  
> **Participating Autonomous Agents:**  
> * 🔴 **Agent A:** Offensive Wireless Security Researcher (Red Team Adversary)  
> * 🛡️ **Agent B:** Defensive Wireless Security Architect (Blue Team Defender)  

---

## 📑 Master Catalogue of 7 Original Case Groups

| Case Group | Specification Document | Threat Mechanics / Attack Vector | Sample Count | Actual Class | Key Defensive Mechanism & Feature Behavior |
| :---: | :--- | :--- | :---: | :---: | :--- |
| **01** | [**`01_authorized_exact.md`**](file:///D:/Antigravity%20Project/Rogue%20wifi/ssid_feature_framework/original_cases_research/01_authorized_exact.md) | Whitelist baseline broadcasts; potential exact clone Evil Twin | 5 | **BENIGN** | **Tier 1 Exact Hash Fast Path:** $< 0.001\text{ ms}$ lookup ($35\text{ ns}$ in C), 0% AI overhead. Exact clones verified via Tier 3 Physical Telemetry (BSSID OUI, 802.1X vs Open). |
| **02** | [**`02_homoglyph_typo.md`**](file:///D:/Antigravity%20Project/Rogue%20wifi/ssid_feature_framework/original_cases_research/02_homoglyph_typo.md) | Visual lookalikes (`1/l`, `0/o`, `5/s`), kerning attacks (`rn/m`), keystroke transpositions | 16 | **EVIL_TWIN** | **$f_2$ Damerau-Levenshtein ($0.9565$)** captures adjacent swaps in 1 edit; **$f_6$ ASCII Homoglyph Flag** counts lookalike substitutions ($f_6 \ge 1$); XGBoost scores $P \ge 0.8507$. |
| **03** | [**`03_word_addition.md`**](file:///D:/Antigravity%20Project/Rogue%20wifi/ssid_feature_framework/original_cases_research/03_word_addition.md) | Captive portal lures (`_Login`, `_Portal`), speed lures (`_Fast`), authority lures (`Official_`) | 15 | **EVIL_TWIN** | **Multi-Feature Compensation:** When edit distance $f_1$ dilutes ($0.3684$), **$f_{11}$ Lure Flag ($=1$)**, **$f_{13}$ Prefix Ratio ($1.0$)**, and **$f_9$ Token Jaccard ($0.75$)** maintain $P \ge 0.9321$. |
| **04** | [**`04_word_subtraction.md`**](file:///D:/Antigravity%20Project/Rogue%20wifi/ssid_feature_framework/original_cases_research/04_word_subtraction.md) | Security/frequency qualifier omission (`_Secure`, `_5G`), single-word brand-jacking (`Staff`) | 12 | **EVIL_TWIN** | **$f_7$ Len Diff ($14\text{--}18$)**, **$f_8$ Len Ratio ($0.21\text{--}0.50$)**, and **$f_9$ Token Jaccard ($0.3333$)** isolate single-word root identity theft; XGBoost scores $P=0.7972\text{--}0.9825$. |
| **05** | [**`05_delimiter_case.md`**](file:///D:/Antigravity%20Project/Rogue%20wifi/ssid_feature_framework/original_cases_research/05_delimiter_case.md) | Delimiter substitutions (`-`, `.`, space) and uppercase/lowercase casing mutations (`EDUROAM`) | 12 | **EVIL_TWIN** | **Delimiter-Agnostic Tokenization ($f_9 = 1.0000$)**; **$f_{10}$ Separator Delta ($=2$)**; Case-folded n-grams (**$f_5 = 1.0000$**) overcome $f_1=0.0000$ on `EDUROAM` ($P=0.8988$). |
| **06** | [**`06_semantic_relevant.md`**](file:///D:/Antigravity%20Project/Rogue%20wifi/ssid_feature_framework/original_cases_research/06_semantic_relevant.md) | Affiliated colleges, research labs, alumni subnets vs rogue networks (`Uni_Campus_Net`) | 14 | 10 BENIGN<br>4 EVIL_TWIN | **Orthographic Disambiguation:** XGBoost separates `College` ($P=0.0902$) from `Uni` ($P=0.8734$) where embeddings failed ($\cos > 0.95$); **Tier 3 Physical Telemetry** resolves boundary case `University_Academic_WiFi` ($P=0.6656$). |
| **07** | [**`07_irrelevant_noise.md`**](file:///D:/Antigravity%20Project/Rogue%20wifi/ssid_feature_framework/original_cases_research/07_irrelevant_noise.md) | Coffee shops (`Starbucks`), telco hotspots (`AIS`), dorm APs, wireless printers | 14 | **BENIGN** | **Instant Noise Discard ($P \le 0.05$):** $f_1 \le 0.20$, **$f_5 = 0.0000$**, $f_9 = 0.0000$; multi-tree negative margin prevents false alarms on incidental lures (`KFC_Guest_Free` $P=0.0657$). |

---

## 2. Multi-Tier Wireless Threat Detection Pipeline

```
                                [Incoming 802.11 Beacon / Probe Frame]
                                                  │
                                                  ▼
     ┌────────────────────────────────────────────────────────────────────────────────────────┐
     │ TIER 0: Byte Gateway & RFC 3629 UTF-8 Sanitizer (defensive_sanitizer.py)              │
     │ - 802.11 Octet Bounds Check (0 <= len <= 32)                                           │
     │ - Strict UTF-8 Validation (rejection of overlong \xc1\xa1, truncated bytes)           │
     │ - Hidden AP Identification (len == 0 -> BENIGN_HIDDEN)                                │
     │ - Zero-Width & Invisible Codepoints Stripping (U+200B, U+FEFF, trailing space -> IOA)   │
     │ - UTS #39 Confusables Skeleton Mapping (Cyrillic \u0435 -> Latin e in < 3 us)          │
     └────────────────────────────────────────────────────────────────────────────────────────┘
                                                  │
                                                  ▼
     ┌────────────────────────────────────────────────────────────────────────────────────────┐
     │ TIER 1: Exact Whitelist Fast Path (0.0008 ms, 0% AI Overhead)                         │
     │ - frozenset lookup in C-level hash table                                               │
     └────────────────────────────────────────────────────────────────────────────────────────┘
                                │                                                  │
                     Matched (s_obs in W_auth)                       Unmatched (s_obs not in W_auth)
                                │                                                  │
                                ▼                                                  ▼
     ┌────────────────────────────────────┐             ┌──────────────────────────────────────────────┐
     │ TIER 3: Physical Telemetry Check   │             │ TIER 2: 13-Feature Vector Extraction         │
     │ - BSSID Vendor OUI Registry        │             │ (f1..f13: Levenshtein, Damerau, N-Grams,     │
     │ - 802.1X vs Unencrypted Open AP    │             │  Homoglyphs, Delimiters, Lures, Roles)       │
     └────────────────────────────────────┘             └──────────────────────────────────────────────┘
               │                │                                              │
         Verified Safe     Hardware Conflict                                   ▼
               │                │                       ┌──────────────────────────────────────────────┐
               ▼                ▼                       │ TIER 2: XGBoost Classifier (50 Boosted Trees)│
        [AUTHORIZED AP]    [🚨 EXACT CLONE]             │ - Inference Latency: ~0.15 ms                │
                                                        │ - Evaluates Calibrated Continuous P(Evil)    │
                                                        └──────────────────────────────────────────────┘
                                                                               │
                                       ┌───────────────────────────────────────┼───────────────────────────────────────┐
                                       ▼                                       ▼                                       ▼
                       ┌──────────────────────────────┐        ┌──────────────────────────────┐        ┌──────────────────────────────┐
                       │ P(Evil) < 0.30               │        │ 0.30 <= P(Evil) <= 0.70      │        │ P(Evil) > 0.70               │
                       │ Status: BENIGN NOISE / DROP  │        │ Status: AMBIGUOUS CANDIDATE  │        │ Status: HIGH RISK ROGUE AP   │
                       │ (e.g. Starbucks, Dorm APs)   │        │ (e.g. University_Academic)   │        │ (e.g. Un1versity, edur0am)   │
                       └──────────────────────────────┘        └──────────────────────────────┘        └──────────────────────────────┘
                                                                               │                                       │
                                                                               └───────────────────┬───────────────────┘
                                                                                                   │
                                                                                                   ▼
                                                                               ┌──────────────────────────────────────┐
                                                                               │ TIER 3: Physical Telemetry Engine    │
                                                                               │ - Campus OUI Match?                  │
                                                                               │ - Enterprise 802.1X RADIUS Auth?     │
                                                                               │ - Sequence Number Jitter?            │
                                                                               └──────────────────────────────────────┘
                                                                                                   │
                                                                      ┌────────────────────────────┴───────────────────────────┐
                                                                      ▼                                                        ▼
                                                        ┌─────────────────────────────┐                         ┌─────────────────────────────┐
                                                        │ Cisco/Aruba + 802.1X Cert   │                         │ Consumer Hardware / Open AP │
                                                        │ Status: BENIGN DEPARTMENTAL │                         │ Status: CONFIRMED EVIL TWIN │
                                                        │ (Admin Whitelist Update)    │                         └─────────────────────────────┘
                                                        └─────────────────────────────┘                                        │
                                                                                                                               ▼
                                                                                                                ┌─────────────────────────────┐
                                                                                                                │ TIER 4: Local SLM Explainer │
                                                                                                                │ (Nemotron-Mini-4B via Vulkan│
                                                                                                                │ Generates SOC Threat Report)│
                                                                                                                └─────────────────────────────┘
```

---

## 3. Mathematical Feature Summary ($f_1 \dots f_{13}$)

| Feature | Formal Mathematical Definition | Detection Objective & Behavioral Response | Top Gain Driver |
| :--- | :--- | :--- | :---: |
| **$f_1$ (Levenshtein Ratio)** | $1.0 - \frac{\text{Lev}(s_1, s_2)}{\max(\text{len}_1, \text{len}_2)}$ | Measures single-character insertions, deletions, and substitutions. | 12.75% |
| **$f_2$ (Damerau Ratio)** | $1.0 - \frac{\text{Dam}(s_1, s_2)}{\max(\text{len}_1, \text{len}_2)}$ | Treats adjacent character transpositions as 1 operation (e.g. `Studnet` $\to$ `0.9565`). | 15.11% |
| **$f_3$ (Jaro-Winkler)** | $\text{Jaro} + \ell \cdot p \cdot (1 - \text{Jaro})$ | Heavily weights identical prefix prefixes up to 4 characters. | 7.70% |
| **$f_4$ (2-Gram Jaccard)** | $\frac{\lvert N_2(s_1) \cap N_2(s_2) \rvert}{\lvert N_2(s_1) \cup N_2(s_2) \rvert}$ | Case-folded character bigram continuity invariant to word ordering. | 13.35% |
| **$f_5$ (3-Gram Jaccard)** | $\frac{\lvert N_3(s_1) \cap N_3(s_2) \rvert}{\lvert N_3(s_1) \cup N_3(s_2) \rvert}$ | Strict 3-character subword root preservation; drops to 0.0000 on environmental noise. | **17.31%** (Rank 1) |
| **$f_6$ (Homoglyph Count)** | $\sum_{(c_f, c_r) \in \mathcal{H}} \text{count}(c_f \in s_1 \mid c_r \in s_2)$ | Detects ASCII visual lookalikes (`1/l`, `0/o`, `5/s`, `rn/m`, `vv/w`, `cl/d`). | Deterministic IOA |
| **$f_7$ (Length Abs Diff)** | $\lvert \text{len}(s_1) - \text{len}(s_2) \rvert$ | Detects string expansion (lures) or radical truncation (single-word traps). | Auxiliary |
| **$f_8$ (Length Ratio)** | $\frac{\min(\text{len}_1, \text{len}_2)}{\max(\text{len}_1, \text{len}_2)}$ | Scale-invariant string length proportionality ($0.21$ on `Staff` vs $23$ chars). | Auxiliary |
| **$f_9$ (Token Jaccard)** | $\frac{\lvert T_1 \cap T_2 \rvert}{\lvert T_1 \cup T_2 \rvert}$ | Delimiter-agnostic word token overlap; maintains $1.0000$ across delimiter mutations. | 6.60% |
| **$f_{10}$ (Separator Delta)** | $\lvert \text{delims}(s_1) \mathbin{\Delta} \text{delims}(s_2) \rvert$ | Quantifies delimiter substitution tampering (`_` $\to$ `-`, `.`, space). | Auxiliary |
| **$f_{11}$ (Phishing Lure)** | $\max(0, \lvert T_1 \cap \mathcal{L} \rvert - \lvert T_2 \cap \mathcal{L} \rvert)$ | Flags added deceptive tokens (`login`, `free`, `portal`, `verify`, `official`). | Auxiliary |
| **$f_{12}$ (Role Collision)** | $1 \iff (R_1 \ne R_2 \land \lvert R_1 \rvert > 0 \land \lvert R_2 \rvert > 0)$ | Flags switches between departmental roles (`staff`, `student`, `college`, `library`). | 9.70% |
| **$f_{13}$ (Prefix Ratio)** | $\frac{\text{CommonPrefixLen}(s_1, s_2)}{\text{len}(s_2)}$ | Quantifies brand root anchoring on suffix lure attacks ($1.0000$ on `..._Fast`). | Auxiliary |

---

## 4. Empirical Performance Across All 88 Campus Benchmark Cases

```
===================================================================================================
                   EMPIRICAL ACCURACY & PERFORMANCE COMPARISON (N = 88 SAMPLES)
===================================================================================================
Category                     Count   Actual Label    Decision Tree (CART)    XGBoost Classifier
---------------------------------------------------------------------------------------------------
1. authorized_exact            5     BENIGN (Safe)   100.0% (5/5 Correct)    100.0% (5/5 Correct, P=0.2027)
2. homoglyph_typo             16     EVIL_TWIN       100.0% (16/16 Correct)  100.0% (16/16 Correct, P>=0.8507)
3. word_addition              15     EVIL_TWIN       100.0% (15/15 Correct)  100.0% (15/15 Correct, P>=0.9321)
4. word_subtraction           12     EVIL_TWIN       100.0% (12/12 Correct)  100.0% (12/12 Correct, P>=0.7972)
5. delimiter_case             12     EVIL_TWIN       100.0% (12/12 Correct)  100.0% (12/12 Correct, P>=0.8988)
6. semantic_relevant          14     10 BEN / 4 EVIL  92.9% (1 Ambiguous)     92.9% (1 Ambiguous P=0.6656 -> Tier 3)
7. irrelevant_noise           14     BENIGN (Safe)   100.0% (14/14 Correct)  100.0% (14/14 Correct, P<=0.3417)
---------------------------------------------------------------------------------------------------
OVERALL BENCHMARK TOTAL       88     59 EVIL / 29 BEN 98.86% Accuracy        98.86% Accuracy (0.9991 ROC-AUC)
===================================================================================================
```
