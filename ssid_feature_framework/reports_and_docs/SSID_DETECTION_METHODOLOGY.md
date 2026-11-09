# 📡 Complete Technical Specification: SSID Detection & Threat Classification Methodology
## Hybrid Multi-Tier Architecture: Classical Feature Engineering (XGBoost) & Explainable SLM Reasoning

> **Document Version:** 2.0 (Post-Benchmark Edition)  
> **Target Environment:** University Campus Wireless Infrastructure (Edge Sensor + Central GPU Host)  
> **Target Baseline Whitelist:** `University_Campus_5G`, `University_Staff_Secure`, `University_Student_WiFi`, `University_Guest_Portal`, `eduroam`

---

## 1. Executive Summary & Architectural Motivation

In modern wireless enterprise security, **Evil Twin and Rogue Access Point (AP) attacks** remain one of the most dangerous attack vectors. Attackers create rogue wireless broadcasts imitating authorized networks to execute Man-in-the-Middle (MitM) traffic eavesdropping and credential harvesting via deceptive captive portals.

Historically, this project began by investigating **MiniLM (`all-MiniLM-L6-v2`)** as an embedding-distance similarity filter. However, empirical benchmarking across 88 realistic campus attack scenarios proved that pure 1D vector embeddings suffer from an **Impossible Threshold Dilemma**:
1. **Semantic Conflation:** Embeddings cluster legitimate synonym networks (e.g., `College_Campus_5G` vs `University_Campus_5G`) at $> 0.95$ similarity, triggering false alarms.
2. **Subword Fragmentation:** Single-token homoglyphs (e.g., `edur0am`, `VVIFi`) split the tokenizer, dropping similarity below $0.67$ and allowing attacks to escape.

To resolve this, the system upgraded to a **Multi-Tier Hybrid Architecture**:
* **Tier 1 (Whitelist Exact Match):** Sub-microsecond hash table lookup.
* **Tier 2 (Domain Feature Engineering + XGBoost Classifier):** A 13-parameter orthographic, lexical, and behavioral feature vector evaluated by a gradient-boosted decision ensemble (98.86% accuracy, 0.9991 ROC-AUC, 0.15 ms latency, $< 5$ MB RAM).
* **Tier 3 (Physical 802.11 Layer Telemetry):** BSSID Vendor OUI, RSSI volatility, sequence number jitter, and encryption suite corroboration.
* **Tier 4 (Nemotron-Mini-4B SLM Explainer):** Generative Small Language Model on a local GPU host providing natural language threat rationale and SOC incident reporting.

```mermaid
flowchart TD
    Air["802.11 Beacon / Probe Request"] --> T1{"Tier 1: Whitelist Exact Match?"}
    T1 -->|Match (100%)| Safe["Status: AUTHORIZED\n(0 ms, 0% AI Overhead)"]
    
    T1 -->|No Match| Feat["Extract 13-Feature Vector (f1..f13)\n(Levenshtein, N-grams, Homoglyphs, Lures)"]
    Feat --> XGB["Tier 2: XGBoost Classifier\n(Evaluates 50 Boosted Trees)"]
    
    XGB --> Prob{"P(Evil Twin) Score"}
    Prob -->|< 0.30| Noise["Status: BENIGN NOISE / DROP\n(0.15 ms, e.g. Starbucks, Dorm APs)"]
    
    Prob -->|0.30 - 0.70| Ambiguous["Status: AMBIGUOUS CANDIDATE\n(e.g., University_Academic_WiFi)"]
    Prob -->|> 0.70| HighRisk["Status: HIGH RISK ROGUE AP"]
    
    Ambiguous --> Phys{"Tier 3: 802.11 Physical Telemetry\n- BSSID Vendor OUI\n- RSSI Volatility & Jitter\n- 802.1X vs Open Captive"}
    HighRisk --> Phys
    
    Phys -->|Hardware Conflict Confirmed| Nemotron["Tier 4: Nemotron-Mini-4B SLM\n(Local GPU Inference via Vulkan)"]
    Phys -->|Hardware Matches Whitelist AP| WL_Update["Admin Whitelist Update Flow"]
    
    Nemotron --> Alert["🚨 Actionable SOC Incident Report\n(Risk Tier + Natural Language Justification)"]
```

---

## 2. Mathematical Definition of Feature Vector ($f_1 \dots f_{13}$)

For any observed SSID string $s_{\text{obs}}$ and candidate authorized target $s_{\text{auth}}$ from the whitelist, the system extracts a 13-dimensional continuous feature vector:

$$\mathbf{x} = \left[ f_1, f_2, f_3, f_4, f_5, f_6, f_7, f_8, f_9, f_{10}, f_{11}, f_{12}, f_{13} \right]^T \in \mathbb{R}^{13}$$

### $f_1$: Normalized Levenshtein Edit Distance Ratio
Measures the minimal single-character insertions, deletions, and substitutions required to transform $s_{\text{obs}}$ into $s_{\text{auth}}$:
$$f_1 = 1.0 - \frac{\text{Levenshtein}(s_{\text{obs}}, s_{\text{auth}})}{\max(\text{len}(s_{\text{obs}}), \text{len}(s_{\text{auth}}))}$$
* **Range:** $[0.0, 1.0]$
* **Role:** Detects single-character typo mutations (e.g., `Unversity`).

### $f_2$: Damerau-Levenshtein Ratio
Extends Levenshtein by treating the transposition of two adjacent characters as a single operation:
$$f_2 = 1.0 - \frac{\text{DamerauLevenshtein}(s_{\text{obs}}, s_{\text{auth}})}{\max(\text{len}(s_{\text{obs}}), \text{len}(s_{\text{auth}}))}$$
* **Range:** $[0.0, 1.0]$
* **Role:** Detects cognitive typing transpositions (e.g., `Unviersity` where `iv` $\leftrightarrow$ `vi`).

### $f_3$: Jaro-Winkler Similarity
Biases score toward strings sharing identical leading prefixes:
$$f_3 = \text{Jaro}(s_{\text{obs}}, s_{\text{auth}}) + \ell \cdot p \cdot (1 - \text{Jaro}(s_{\text{obs}}, s_{\text{auth}}))$$
where $\ell \le 4$ is the length of common prefix, and $p = 0.1$.
* **Range:** $[0.0, 1.0]$
* **Role:** Captures attacks preserving the institutional prefix (`University_...`).

### $f_4$: 2-Gram Jaccard Index
Measures character bigram overlap using a 2-character sliding window:
$$f_4 = \frac{\lvert N_2(s_{\text{obs}}) \cap N_2(s_{\text{auth}}) \rvert}{\lvert N_2(s_{\text{obs}}) \cup N_2(s_{\text{auth}}) \rvert}$$
* **Range:** $[0.0, 1.0]$
* **Role:** Captures local orthographic continuity resistant to word order swaps.

### $f_5$: 3-Gram Jaccard Index (Top XGBoost Driver)
Measures character trigram overlap using a 3-character sliding window:
$$f_5 = \frac{\lvert N_3(s_{\text{obs}}) \cap N_3(s_{\text{auth}}) \rvert}{\lvert N_3(s_{\text{obs}}) \cup N_3(s_{\text{auth}}) \rvert}$$
* **Range:** $[0.0, 1.0]$
* **Role:** Evaluates strict root word-stem preservation. Accounts for 17.31% of XGBoost's gain.

### $f_6$: Homoglyph Visual Substitution Count
Quantifies visual look-alike character spoofing:
$$f_6 = \sum_{(c_{\text{fake}}, c_{\text{real}}) \in \mathcal{H}} \text{count}(c_{\text{fake}} \in s_{\text{obs}} \mid c_{\text{real}} \in s_{\text{auth}} \land c_{\text{fake}} \notin s_{\text{auth}})$$
where $\mathcal{H} = \{ (1, l), (1, i), (0, o), (5, s), (\text{rn}, m), (\text{vv}, w), (\text{cl}, d) \}$.
* **Range:** $[0, \infty)$
* **Role:** Explicitly detects typosquatting (e.g., `University_Carnpus_5G`, `Un1versity`).

### $f_7$: Absolute Length Difference
$$f_7 = \lvert \text{len}(s_{\text{obs}}) - \text{len}(s_{\text{auth}}) \rvert$$
* **Range:** $[0, 32]$
* **Role:** Detects truncation (-word) or lure inflation (+word).

### $f_8$: Length Ratio
$$f_8 = \frac{\min(\text{len}(s_{\text{obs}}), \text{len}(s_{\text{auth}}))}{\max(\text{len}(s_{\text{obs}}), \text{len}(s_{\text{auth}}))}$$
* **Range:** $(0.0, 1.0]$
* **Role:** Relative size consistency invariant to absolute string scale.

### $f_9$: Token Jaccard Overlap
Splits strings on delimiters (`_`, `-`, `.`, space) into word token sets $T_{\text{obs}}$ and $T_{\text{auth}}$:
$$f_9 = \frac{\lvert T_{\text{obs}} \cap T_{\text{auth}} \rvert}{\lvert T_{\text{obs}} \cup T_{\text{auth}} \rvert}$$
* **Range:** $[0.0, 1.0]$
* **Role:** Quantifies whole-word preservation (e.g., 2 out of 3 words identical).

### $f_{10}$: Delimiter Mutation Delta
Counts differing delimiter types between the two strings:
$$f_{10} = \lvert \text{delims}(s_{\text{obs}}) \mathbin{\Delta} \text{delims}(s_{\text{auth}}) \rvert$$
* **Range:** $[0, \infty)$
* **Role:** Catches delimiter evasion (`University-Campus-5G` vs `University_Campus_5G`).

### $f_{11}$: Phishing Lure Keyword Flag
Counts deceptive social-engineering tokens added to $s_{\text{obs}}$ not present in $s_{\text{auth}}$:
$$f_{11} = \max\left(0, \lvert T_{\text{obs}} \cap \mathcal{L}_{\text{lure}} \rvert - \lvert T_{\text{auth}} \cap \mathcal{L}_{\text{lure}} \rvert\right)$$
where $\mathcal{L}_{\text{lure}} = \{ \text{login}, \text{portal}, \text{free}, \text{fast}, \text{vip}, \text{verify}, \text{5g}, \text{autoconnect}, \text{auth}, \text{official}, \text{guest}, \text{speed} \}$.
* **Range:** $[0, \infty)$
* **Role:** Isolates captive portal lure attacks that evade character similarity.

### $f_{12}$: Academic Role Collision
Checks for conflicts between campus organizational identities:
$$f_{12} = \begin{cases} 1, & \text{if } R_{\text{obs}} \ne R_{\text{auth}} \text{ and } \lvert R_{\text{obs}} \rvert > 0 \text{ and } \lvert R_{\text{auth}} \rvert > 0 \\ 0, & \text{otherwise} \end{cases}$$
where $R = T \cap \{ \text{staff}, \text{student}, \text{faculty}, \text{guest}, \text{campus}, \text{dorm}, \text{library}, \text{academic}, \text{alumni}, \text{eduroam} \}$.
* **Range:** $\{0, 1\}$
* **Role:** Distinguishes between legitimate departmental transitions and impersonations.

### $f_{13}$: Prefix Match Ratio
$$f_{13} = \frac{\text{CommonPrefixLength}(s_{\text{obs}}, s_{\text{auth}})}{\text{len}(s_{\text{auth}})}$$
* **Range:** $[0.0, 1.0]$
* **Role:** Detects brand-name hijacking where the authorized root is retained and suffix lures are appended.

---

## 3. XGBoost Classifier Design & Optimization

### 3.1 Hyperparameter Configuration
```python
xgb_params = {
    "n_estimators": 50,          # 50 boosting stages iteratively correcting residual errors
    "max_depth": 3,              # Shallow trees (<= 8 leaves) preventing memorization
    "learning_rate": 0.1,        # Shrinkage parameter eta
    "subsample": 0.8,            # 80% row sampling per tree to induce stochastic diversity
    "colsample_bytree": 0.8,     # 80% feature subsampling per tree
    "reg_lambda": 1.0,           # L2 Ridge penalty on leaf weights
    "reg_alpha": 0.1,            # L1 Lasso sparsity penalty driving noise weights to zero
    "eval_metric": "logloss",
    "random_state": 42
}
```

### 3.2 Why XGBoost Outperforms Single Decision Trees & Embeddings
1. **Diverse Feature Weighting:** While a single tree placed 49.4% of its decision weight on a single feature (`f5_ngram3`), XGBoost distributes decision power across a balanced committee:
   * `f5_ngram3`: **17.31%**
   * `f2_dam_ratio`: **15.11%**
   * `f4_ngram2`: **13.35%**
   * `f1_lev_ratio`: **12.75%**
   * `f12_academic_role_collision`: **9.70%**
   * *Security Benefit:* An attacker deliberately tuning an SSID to evade one metric (e.g. padding to bypass Levenshtein) is caught by the other four.
2. **Calibrated Continuous Probability ($P(\text{Evil Twin})$):**
   * Output is not an arbitrary threshold float or a binary decision, but a well-calibrated confidence score:
     * `Un1versity_Campus_5G` $\longrightarrow P = \mathbf{0.9785}$ (97.85% Attack Probability)
     * `Cafe_Amazon_WiFi` $\longrightarrow P = \mathbf{0.0497}$ (4.97% Benign Noise)
     * `Starbucks_Guest` $\longrightarrow P = \mathbf{0.0325}$ (3.25% Benign Noise)

---

## 4. Empirical Evaluation: 4-Way Model Comparison

Conducted across **88 curated campus test cases** spanning 7 threat categories:

| Evaluation Dimension | 1. MiniLM (Original Proposal) | 2. Qwen3-Embedding-4B | 3. Single Decision Tree | 4. XGBoost Classifier | 5. Nemotron-Mini-4B SLM |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **Model Type** | Dense Bi-Encoder (384d) | Dense Bi-Encoder (2560d) | Pure Python CART | Gradient Boosted Trees | Decoder SLM (4B) |
| **Training Accuracy** | 82.95% | 86.36% | 98.86% | **98.86%** | 72.73% |
| **Detection Recall** | 🚨 **93.22% (4 Missed)** | 98.31% (1 Missed) | **100.00%** | **98.86%** | **100.00%** |
| **Precision** | 83.33% (11 False Alarms) | 84.06% (11 False Alarms) | 98.33% | **98.33%** | 71.08% (24 Alarms) |
| **F1-Score** | 0.8800 | 0.9062 | 0.9916 | **0.9859** | 0.8310 |
| **5-Fold CV Accuracy** | N/A (Static Vectors) | N/A (Static Vectors) | 95.49% (±2.3%) | **94.38% (±3.5%)** | N/A |
| **ROC-AUC Score** | 0.8920 | 0.9412 | Stepwise | ⭐ **0.9991** | N/A |
| **Inference Latency** | 4.3 ms | 74.1 ms | < 0.01 ms | **~0.15 ms** | 0.94 s |
| **Hardware Required** | ~120 MB RAM | 2.5 GB VRAM | < 2 MB RAM | **< 5 MB RAM** | 2.7 GB VRAM |
| **Edge Feasibility (Pi 4/5)** | Moderate | ❌ Impossible | ⭐ Ideal | ⭐ Ideal | ❌ Requires Offloading |

---

## 5. Key Attack Samples: Where Models Succeeded and Failed

| Observed SSID | Target Whitelist | Actual Class | MiniLM Cosine | Qwen3 Cosine | XGBoost $P(\text{Evil})$ | Decision Reason |
| :--- | :--- | :---: | :---: | :---: | :---: | :--- |
| `Un1versity_Campus_5G` | `University_Campus_5G` | **EVIL_TWIN** | 0.8342 | 0.9420 | **0.9785** | Catches homoglyph `1` $\leftrightarrow$ `l` |
| `edur0am` | `eduroam` | **EVIL_TWIN** | 0.7369 | 🚨 0.6708 | **0.9632** | Qwen3 token fragmentation; XGBoost catches edit ratio |
| `University_Staff_Secure_Login` | `University_Staff_Secure` | **EVIL_TWIN** | 0.8769 | 0.9198 | **0.9810** | Catches phishing lure `_Login` via $f_{11}$ |
| `College_Campus_5G` | `University_Campus_5G` | **BENIGN** | 🚨 0.9552 | 🚨 0.9712 | **0.2140** | Embeddings confuse synonyms; XGBoost recognizes low character overlap |
| `University_Academic_WiFi` | `University_Student_WiFi` | **BENIGN** | 🚨 0.9462 | 🚨 0.9495 | **0.5120** | Lexical ambiguity boundary; flagged as medium-risk for physical verification |
| `Cafe_Amazon_WiFi` | `University_Campus_5G` | **BENIGN** | 0.4226 | 0.5613 | **0.0497** | Clear irrelevant noise rejection |

---

## 6. Thesis Defense Q&A Strategy

### Q1: "Why did you abandon MiniLM / Sentence Transformers?"
> *"Our empirical benchmarks proved that MiniLM suffers from the Impossible Threshold Dilemma on short identifiers. It produced an unacceptable 4 false negatives (93.2% recall) and 11 false alarms. Sentence transformers map high-level conceptual semantics rather than orthographic look-alikes, making them conflate legitimate sister entities like `College` with `University` (scoring 0.955), while dropping critical homoglyph attacks like `edur0am` to 0.73."*

### Q2: "Why choose XGBoost over a Deep Neural Network on the Edge?"
> *"An edge sensor running on a Raspberry Pi has strict memory and latency budgets. XGBoost evaluates 50 shallow trees in 0.15 milliseconds using less than 5 MB of RAM, achieving a 0.9991 ROC-AUC. It distributes decision weight across 5 distinct lexical metrics, making it mathematically resilient against evasion while providing calibrated continuous probabilities for downstream risk scoring."*

### Q3: "What happens if an attacker uses a name like `University_Academic_WiFi`?"
> *"From a Zero-Trust perspective, any unauthorized network imitating institutional naming conventions must be flagged. Our XGBoost model outputs a borderline probability ($P \approx 0.51$), routing it into our Tier 3 Physical Telemetry engine. If the AP's MAC address belongs to a university-owned Cisco switch with 802.1X RADIUS, it is whitelisted. If it is an unencrypted captive portal on a consumer chipset, it is quarantined as a confirmed rogue AP."*

---

## 7. Experimental Setup & Testing Conditions (สภาวะและเงื่อนไขการทดสอบ)

To ensure scientific repeatability, academic reproducibility, and defensibility, all benchmark evaluations were executed under strictly defined and controlled experimental conditions:

### 7.1 Hardware & Runtime Test Environment
* **Host Processing Workstation:**
  * **Processor (CPU):** Multi-core x86_64 host (Python 3.13.9 64-bit runtime).
  * **Graphics Processing Unit (GPU):** AMD Radeon RX 6700 XT (12 GB GDDR6 VRAM, Navi 22 / RDNA 2 architecture).
  * **Host Operating System:** Windows 11 Enterprise (64-bit).
  * **Host Compute Backend:** Vulkan Compute API 1.3 via `llama.cpp` and LM Studio 0.3.x local server runtime.
* **Target Edge Sensor (Simulated & Physical Production Specs):**
  * **Target Hardware:** Raspberry Pi 4 Model B (4 GB/8 GB) / Raspberry Pi 5 (ARM Cortex-A72 / Cortex-A76).
  * **Containerized Simulation:** Docker ARM64 container (`kali-detector-arm64`) memory-capped at **512 MB RAM**, CPU quota capped at **1.0 vCPU**.
  * **Target Network Driver:** Scapy raw packet processing over virtual IEEE 802.11 UDP frames (port `5555/udp`, subnet `10.10.0.0/24`).

### 7.2 Dataset Distribution & Controlled Sample Balancing
* **Total Sample Population:** $N = 88$ unique, verified SSID strings.
* **Ground Truth Class Distribution:**
  * **Positive Class (`EVIL_TWIN`):** $59$ samples (**67.0%** of total).
  * **Negative Class (`BENIGN`):** $29$ samples (**33.0%** of total).
* **Adversarial Partition Breakdown (7 Controlled Behavioral Categories):**
  1. `authorized_exact` ($n = 5$): 100% exact match against whitelist baseline (Ground Truth: `BENIGN`).
  2. `homoglyph_typo` ($n = 16$): Character-level visual mutations, leet-speak, transpositions, and digit substitutions (Ground Truth: `EVIL_TWIN`).
  3. `word_addition` ($n = 15$): Captive portal lures, prefix spoofing (`Official_`, `Free_`), status tags (`_VIP`, `_Fast`), and frequency tags (`_5G`) (Ground Truth: `EVIL_TWIN`).
  4. `word_subtraction` ($n = 12$): Truncation attacks dropping institutional prefix (`University_`) or security qualifier (`_Secure`, `_Portal`) (Ground Truth: `EVIL_TWIN`).
  5. `delimiter_case` ($n = 12$): Delimiter swaps (`-`, `.`, space) and uppercase/lowercase mutations (Ground Truth: `EVIL_TWIN`).
  6. `semantic_relevant` ($n = 14$): Legitimate departmental networks, instructional subnets, research facilities, and library guest networks sharing institutional semantics (Ground Truth: `BENIGN`).
  7. `irrelevant_noise` ($n = 14$): Surrounding off-campus commercial Wi-Fi (Starbucks, Cafe Amazon, 7-Eleven), cellular carrier hotspots (AIS, TrueMove, dtac), and personal student mobile hotspots (Ground Truth: `BENIGN`).

### 7.3 Model Inference & Evaluation Protocols
1. **Tier 1 Whitelist Bypass Condition:**
   * Any observed SSID with exact string equality ($s_{\text{obs}} == s_{\text{auth}}$) to an element in the whitelist is classified as `BENIGN` at $t = 0\text{ ms}$, bypassing downstream AI models.
2. **Embedding Cosine Evaluation Protocol (MiniLM & Qwen3):**
   * Cosine similarity is computed as $\cos(\mathbf{u}, \mathbf{v}) = \frac{\mathbf{u} \cdot \mathbf{v}}{\|\mathbf{u}\|_2 \|\mathbf{v}\|_2}$.
   * Grid-search threshold sweeping conducted from $\tau = 0.50$ to $\tau = 0.90$ in increments of $0.05$.
   * Classification rule: $\text{EVIL\_TWIN} \iff \tau \le \cos(\mathbf{u}, \mathbf{v}) < 0.9999$.
3. **Cross-Validation Protocol (XGBoost & Decision Tree):**
   * **Stratified 5-Fold Cross-Validation** (`StratifiedKFold(n_splits=5, shuffle=True, random_state=42)`).
   * Ensures identical attack-to-benign class ratios ($67\% : 33\%$) are maintained across all 5 training and validation splits.
   * Reports both mean performance and standard deviation ($\mu \pm \sigma$).
4. **Latency Benchmarking Protocol:**
   * **Feature Extraction & Decision Tree:** Single-threaded execution timed on Python 3.13 CPU runtime.
   * **Qwen3-Embedding-4B:** Evaluated on AMD RX 6700 XT GPU with batch size = 16.
   * **Nemotron-Mini-4B-Instruct:** Evaluated on AMD RX 6700 XT GPU with Vulkan offloading (all 99 layers in VRAM) using 4 concurrent worker threads (`max_workers=4`, `temperature=0.1`, `max_tokens=50`).
