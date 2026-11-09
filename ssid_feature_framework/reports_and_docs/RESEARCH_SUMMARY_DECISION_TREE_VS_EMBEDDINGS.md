# 📚 Comprehensive Research Summary: Decision Trees, Semantic Embeddings, & Edge Wi-Fi IDS
## From Foundational Theory to a Definitive 9-Model Benchmark Across 210 Operational Samples

> **Document Purpose:** Systematic synthesis of research findings, empirical benchmarks, and architectural insights developed during the investigative session.  
> **Target Environment:** University Campus Wireless Intrusion Detection System (Edge Sensor on Raspberry Pi + Local Central GPU Host)  
> **Primary Whitelist Baseline:** `['University_Campus_5G', 'University_Staff_Secure', 'University_Student_WiFi', 'University_Guest_Portal', 'eduroam']`  
> **Source Directory:** `ssid_feature_framework/`  

---

## 1. Theoretical Foundation: Can a Decision Tree Classify "Same Meaning"?

### 1.1 The Mathematical Reality of Decision Trees
A Decision Tree (e.g., CART, ID3, C4.5, Random Forest, XGBoost) **cannot detect semantic meaning on its own**. 

* **Axis-Aligned Orthogonal Cuts:** A decision tree partitions data by placing orthogonal thresholds on continuous or categorical feature values:
  $$\text{Split Condition: } x_j \le \theta$$
* **The Word Dimension Problem:** If text is converted into Bag-of-Words or One-Hot vectors:
  $$\mathbf{x}_{\text{"staff"}} = [1, 0, 0], \quad \mathbf{x}_{\text{"faculty"}} = [0, 1, 0], \quad \mathbf{x}_{\text{"refrigerator"}} = [0, 0, 1]$$
  To the tree, `"staff"` and `"faculty"` are completely orthogonal and independent dimensions. The distance between `"staff"` and `"faculty"` is identical to the distance between `"staff"` and `"refrigerator"`.
* **Zero Latent Generalization:** If an unseen synonym appears at test time (e.g., `"academic"` or `"employee"`), Bag-of-Words yields $0$, and the tree is blind to the relationship.

### 1.2 How a Decision Tree "Appears" to Detect Meaning
A Decision Tree can only handle semantic equivalence if meaning is **pre-computed and translated into numbers** before reaching the tree:

1. **Approach A: Handcrafted Feature Engineering (Domain Dictionaries):**
   * Pre-define role dictionaries: $\text{ACADEMIC\_ROLES} = \{\text{"staff"}, \text{"faculty"}, \text{"student"}, \text{"campus"}\}$.
   * Pre-define lure dictionaries: $\text{LURE\_KEYWORDS} = \{\text{"free"}, \text{"login"}, \text{"portal"}, \text{"fast"}\}$.
   * Extract binary flags: $f_{11} = \mathbb{I}(\text{token} \in \text{LURE\_KEYWORDS})$.
   * *Limitation:* Brittle. Fails immediately on zero-day synonyms not in the list.
2. **Approach B: Dense Semantic Vector Embeddings:**
   * An external neural model (e.g., MiniLM, BGE, Qwen) projects text into a continuous latent space:
     $$\mathbf{v}_1 = \text{Embed}(s_1), \quad \mathbf{v}_2 = \text{Embed}(s_2)$$
   * Compute cosine similarity: $\cos(\theta) = \frac{\mathbf{v}_1 \cdot \mathbf{v}_2}{\|\mathbf{v}_1\| \|\mathbf{v}_2\|}$.
   * The Decision Tree then simply splits: $\text{if } \cos(\theta) \ge 0.65 \implies \text{Match}$.
   * *Takeaway:* The **embedding model** understood the meaning; the tree merely evaluated a numerical threshold.

---

## 2. Audit of the Campus Baseline Dataset (Category 06: `semantic_relevant`)

### 2.1 The 14 Baseline Semantic Cases
In the original 88-sample campus dataset (`ssid_feature_framework/test_cases.json`), Category 06 contained 14 curated samples:

* **Sub-group A: Legitimate Sister / Departmental Networks (10 Samples, `BENIGN`):**
  * `College_Campus_5G` (Target: `University_Campus_5G`) — *College* $\approx$ *University*
  * `Faculty_Staff_Secure` (Target: `University_Staff_Secure`) — *Faculty* $\approx$ *Staff*
  * `University_Academic_WiFi` (Target: `University_Student_WiFi`) — *Academic* $\approx$ *Student*
  * `University_Library_Guest`, `Campus_Research_Lab_5G`, `Engineering_Faculty_Staff`, `University_Alumni_Portal`, `Medical_School_Staff_WLAN`, `Campus_Student_HighSpeed`, `Science_Complex_Guest`.
* **Sub-group B: Semantic Deception / Rogue APs (4 Samples, `EVIL_TWIN`):**
  * `Uni_Campus_Net` (Target: `University_Campus_5G`) — Informal slang abbreviation + *Net*
  * `University_Intranet_Secure` (Target: `University_Staff_Secure`) — Administrative synonym *Intranet*
  * `University_Public_Access` (Target: `University_Guest_Portal`) — Visitor synonym *Public Access*
  * `Campus_Wide_Open_Net` (Target: `University_Campus_5G`) — Deceptive open network lure

### 2.2 The "Impossible Threshold Dilemma" in Dense Embeddings
Early benchmarks revealed a critical vulnerability in dense sentence transformers on short SSID strings:
* **Pre-trained Semantic Conflation:** Because `"College"` and `"University"` appear in identical contexts in text corpora, `all-MiniLM-L6-v2` assigned a massive **`0.9552`** cosine similarity to `College_Campus_5G` vs `University_Campus_5G` (and Qwen3 assigned **`0.9712`**).
* **The Dilemma:**
  * Legitimate sister network `College_Campus_5G` scored **`0.9552`**.
  * Malicious rogue network `Uni_Campus_Net` scored **`0.9120`**.
  * A threshold $\tau = 0.90$ triggered a **False Positive** on legitimate college networks.
  * Raising the threshold to $\tau = 0.96$ created a **False Negative**, allowing the rogue AP to slip through.

### 2.3 Why XGBoost Outperformed Embeddings on Baseline Sub-group A
In the baseline test, XGBoost achieved **90.0% accuracy (9 / 10 correct)** on Sub-group A:
* **Trigram Disjointness ($f_5$):** `"College"` shares **zero** trigrams with `"University"` (`col, oll, lle, leg, ege` vs `uni, niv, ive, ver, ers, rsi, sit, ity`).
* Because XGBoost focuses on character overlap rather than conceptual synonymy, it assigned $P(\text{Evil}) = \mathbf{0.0902}$ to `College_Campus_5G`, correctly identifying it as benign.
* **The Ambiguous Boundary (#63):** `University_Academic_WiFi` scored $P = \mathbf{0.6656}$ because the words `"University"` and `"WiFi"` matched the whitelist target exactly ($f_1 = 0.75$), correctly triggering Tier 3 physical verification.

---

## 3. The Hypothesis: Proving the Room for Semantic Models (Zero-Overlap Lures)

### 3.1 The Vulnerability of Classical Lexical Models
While XGBoost excelled on typos (`Un1versity`), it relies on:
1. Character overlap metrics ($f_1, f_2, f_4, f_5$).
2. A hardcoded dictionary of 19 lure words (`LURE_KEYWORDS`).

**Hypothesis:** If an attacker deploys an Evil Twin using **zero-day social engineering vocabulary** with **zero character overlap** to the whitelist, XGBoost will suffer a complete false-negative failure, proving that an AI/semantic model is strictly necessary.

### 3.2 The Initial 8-Sample Proof-of-Concept
Eight novel test cases were engineered with zero-day vocabulary outside the 19 hardcoded words:

| # | Observed SSID | Whitelist Target | Actual | XGBoost $P(\text{Evil})$ | MiniLM Cos | Qwen3 Cos | Nemotron SLM | Outcome |
| :-: | :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| 1 | `Complimentary_Visitor_Broadband` | `University_Guest_Portal` | **EVIL_TWIN** | 🚨 `0.0627` | `0.3650` | `0.6742` | ✅ **EVIL_TWIN** | XGBoost Bypassed |
| 2 | `Campus_Registration_Desk` | `University_Guest_Portal` | **EVIL_TWIN** | 🚨 `0.0266` | `0.4397` | `0.7445` | ✅ **EVIL_TWIN** | XGBoost Bypassed |
| 3 | `Institutional_Faculty_WLAN` | `University_Staff_Secure` | **EVIL_TWIN** | 🚨 `0.0234` | `0.4842` | `0.8330` | ✅ **EVIL_TWIN** | XGBoost Bypassed |
| 4 | `Dormitory_Instructional_Net` | `University_Student_WiFi` | **EVIL_TWIN** | 🚨 `0.0429` | `0.5008` | `0.6833` | ✅ **EVIL_TWIN** | XGBoost Bypassed |
| 5 | `HighBandwidth_Express_Access` | `University_Campus_5G` | **EVIL_TWIN** | 🚨 `0.1063` | `0.2681` | `0.6363` | ✅ **EVIL_TWIN** | XGBoost Bypassed |
| 6 | `Campus_Portal_Verification` | `University_Guest_Portal` | **EVIL_TWIN** | 🚨 `0.0377` | `0.6773` | `0.7677` | ✅ **EVIL_TWIN** | XGBoost Bypassed |
| 7 | `Library_Study_Commons` | `University_Campus_5G` | **BENIGN** | `0.0234` | `0.2505` | `0.6757` | ⚠️ **EVIL_TWIN** | Departmental |
| 8 | `Alumni_Association_Lounge` | `University_Guest_Portal` | **BENIGN** | `0.0248` | `0.5940` | `0.6448` | ⚠️ **EVIL_TWIN** | Hospitality |

### 3.3 Key Concept: Verbalized Pseudo-Confidence vs. Calibrated Probability
* **Nemotron-Mini-4B (Autoregressive Decoder):** Generates next-token text. When instructed to output confidence, it outputs characters (`"9"`, `"5"`, `"%"`) based on conversational patterns, not statistical mathematics.
* **XGBoost (Calibrated Classifier):** Outputs real mathematical probability $P(\text{Evil}) \in [0, 1]$ computed by minimizing logistic logloss across decision tree leaves.
* **Takeaway:** They cannot replace each other: XGBoost provides calibrated statistical filtering; Nemotron provides contextual reasoning and human explainability for SOC incident response.

---

## 4. Edge Hardware Realities: Finding the Sub-1B Embedding Sweet Spot

### 4.1 The Standalone Edge Constraint
A 4-Billion parameter model (Qwen or Nemotron) requires **2.5 GB – 4.0 GB of RAM/VRAM** and takes **~100 ms – 900 ms** per query. Hosting two 4B models on a standalone Raspberry Pi sensor (capped at 512 MB – 2 GB RAM) is impossible.

### 4.2 Benchmark of Sub-1B Edge Candidates
Five lightweight ONNX models were evaluated via `fastembed` (running 100% locally on CPU without PyTorch or cloud APIs):

| Model Name | Parameter Count | Model Disk Size | Edge RAM Usage | Latency (CPU) | Avg Score on 6 Attacks | Edge Viability |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| 🥇 **`BAAI/bge-small-en-v1.5`** | **33M (0.033B)** | **66.4 MB** | **< 100 MB** | **~5.8 ms** | ⭐ **`0.7034`** | 🏆 **The Ideal Edge Sweet Spot** |
| 🥈 **`snowflake-arctic-embed-s`** | **33M (0.033B)** | **126.9 MB** | **~120 MB** | **~4.7 ms** | ⭐ **`0.6839`** | Highly viable |
| 🥉 **`BAAI/bge-base-en-v1.5`** | **109M (0.11B)** | **207.7 MB** | **~250 MB** | **~16.6 ms** | **`0.6745`** | Higher memory footprint |
| 4. **`nomic-embed-text-v1.5-Q`** | 137M (0.14B) | 130.9 MB | ~180 MB | ~15.1 ms | `0.5206` | Lower resolution on short names |
| 5. **`all-MiniLM-L6-v2`** | 22M (0.022B) | 86.2 MB | ~80 MB | ~3.0 ms | `0.4560` | Obsolete on compressed SSIDs |

### 4.3 Deep Dive: The `0.833` vs. `0.661` Divergence on `Institutional_Faculty_WLAN`
* **Qwen3 (4B, 2560d) $\to$ `0.833`:** Pre-trained on trillions of tokens, Qwen contains deep latent world knowledge that `"Institutional"` is a formal administrative synonym for `"University"`, and `"Faculty"` directly couples with `"Staff"`.
* **BGE-Small (33M, 384d) $\to$ `0.661`:** Compresses semantic representations into 384 dimensions. It recognizes `"Faculty"` $\approx$ `"Staff"` strongly, but treats `"Institutional"` as a general organizational term.
* **Operational Significance:** A score of `0.661` is vastly above the ambient noise floor (`< 0.35`), making `bge-small` fully capable of triggering edge alerts at 1/40th the memory cost.

---

## 5. Comprehensive 210-Sample Benchmark: All 9 Models Evaluated

### 5.1 Dataset Architecture (`extended_200_test_cases.json`)
Synthesized and validated across 4 balanced categories:
1. `zero_overlap_semantic_evil_twin` (70 samples): Rogue APs exploiting zero-day pretexts (patrons, matriculation, instructional subnets). Ground truth: `EVIL_TWIN`.
2. `classical_orthographic_evil_twin` (40 samples): Typo-squatting, homoglyphs, casing, and delimiter variations. Ground truth: `EVIL_TWIN`.
3. `departmental_sister_benign` (60 samples): Authentic departmental subnets, specialized schools, and research labs. Ground truth: `BENIGN`.
4. `ambient_environmental_noise` (40 samples): Coffee shops, transit networks, telecom cellular offloads, and personal hotspots. Ground truth: `BENIGN`.

### 5.2 Master Audit Table Across All 9 Models

| # | Model Name | Model Type | Disk Size | CPU/GPU Latency | Zero-Overlap Lures (70) | Classical Ortho (40) | Departmental Sister (60) | Ambient Noise (40) | Overall Accuracy | Total Attack Recall (110) |
| :-: | :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **1** | **Decision Tree (CART)** | Classical Tree | `< 2 MB` | **1.4 ms** | 18.6% | **100.0%** | **86.7%** | **97.5%** | **68.6%** | 48.2% |
| **2** | **XGBoost Classifier** | Boosted Trees | `< 5 MB` | **1.4 ms** | 🚨 **2.9%** | **100.0%** | **93.3%** | **97.5%** | **65.2%** | 38.2% |
| **3** | **all-MiniLM-L6-v2** | Bi-Encoder (384d) | `86 MB` | **3.0 ms** | 5.7% | **100.0%** | **95.0%** | **97.5%** | **66.7%** | 40.0% |
| **4** | **BAAI/bge-small-en-v1.5** | Bi-Encoder (384d) | **66 MB** | **5.8 ms** | ⭐ **97.1%** | **100.0%** | 13.3% | 5.0% | **56.2%** | ⭐ **98.2%** |
| **5** | **snowflake-arctic-embed-s** | Bi-Encoder (384d) | `127 MB` | **4.7 ms** | ⭐ **100.0%** | **100.0%** | 0.0% | 0.0% | **52.4%** | ⭐ **100.0%** |
| **6** | **BAAI/bge-base-en-v1.5** | Bi-Encoder (768d) | `208 MB` | **16.6 ms** | **77.1%** | **100.0%** | 41.7% | 30.0% | **62.4%** | 85.5% |
| **7** | **nomic-embed-text-v1.5-Q** | Matryoshka (768d) | `131 MB` | **15.1 ms** | 20.0% | **100.0%** | 73.3% | 52.5% | **56.7%** | 49.1% |
| **8** | **Qwen3-Embedding-4B** | Large Dense (2560d) | `2.3 GB` | **26.6 ms** | **68.6%** | **100.0%** | 51.7% | 52.5% | **66.7%** | 80.0% |
| **9** | **Nemotron-Mini-4B-SLM** | Generative Decoder | `2.5 GB` | **1270 ms** | ⭐ **100.0%** | **100.0%** | 0.0% | 0.0% | **52.4%** | ⭐ **100.0%** |

### 5.3 Core Benchmark Findings
1. **The Classical ML Superpower & Fatal Flaw:**
   * XGBoost is unmatched at rejecting ambient noise (**97.5%**) and catching spelling mutations (**100%**) at near-zero latency ($1.4\text{ ms}$).
   * However, it suffers an catastrophic **97.14% false-negative rate (2.9% accuracy)** when attackers use zero-overlap vocabulary.
2. **The 67 MB Semantic Shield (`bge-small-en-v1.5`):**
   * Catches **97.1% of zero-overlap attacks** in $5.8\text{ ms}$ on CPU, matching or exceeding 4B parameter models at a fraction of the compute cost.
3. **The Generic Keyword Trap of Pure Embeddings:**
   * When ambient networks contain generic words like `"WiFi"` or `"Guest"` (`Starbucks_WiFi`, `Costa_Coffee_Guest`), pure embeddings get pulled into high similarity scores ($> 0.65$), achieving only **5%–17% specificity** on noise when evaluated in isolation.
4. **The Indispensability of Tier 3 Telemetry:**
   * Legitimate sister subnets (`Law_School_Faculty`) share conceptual similarity with the university. While embeddings flag them as suspicious, Tier 3 physical hardware checks (Cisco/Aruba BSSID OUI + 802.1X RADIUS) resolve the ambiguity without manual alert fatigue.

---

## 6. Directory of Local Model Files & Assets

| Asset Description | Format | Size | Exact File Path on Local Disk |
| :--- | :---: | :---: | :--- |
| **`bge-small-en-v1.5` (Edge Champion)** | ONNX | **66.4 MB** | `C:\Users\dobbl\AppData\Local\Temp\fastembed_cache\models--Qdrant--bge-small-en-v1.5-onnx-Q\snapshots\*\model_optimized.onnx` |
| **`snowflake-arctic-embed-s`** | ONNX | 126.9 MB | `C:\Users\dobbl\AppData\Local\Temp\fastembed_cache\models--Snowflake--snowflake-arctic-embed-s\snapshots\*\model.onnx` |
| **`all-MiniLM-L6-v2`** | ONNX | 86.2 MB | `C:\Users\dobbl\AppData\Local\Temp\fastembed_cache\models--Qdrant--all-MiniLM-L6-v2-onnx\snapshots\*\model.onnx` |
| **`bge-base-en-v1.5`** | ONNX | 207.7 MB | `C:\Users\dobbl\AppData\Local\Temp\fastembed_cache\models--Qdrant--bge-base-en-v1.5-onnx-Q\snapshots\*\model_optimized.onnx` |
| **`nomic-embed-text-v1.5`** | ONNX | 130.9 MB | `C:\Users\dobbl\AppData\Local\Temp\fastembed_cache\models--nomic-ai--nomic-embed-text-v1.5\snapshots\*\model_quantized.onnx` |
| **`Nemotron-Mini-4B-Instruct`** | GGUF | **2.51 GB** | [`d:\Antigravity Project\Rogue wifi\local_llm\models\Nemotron-Mini-4B-Instruct-Q4_K_M.gguf`](file:///d:/Antigravity%20Project/Rogue%20wifi/local_llm/models/Nemotron-Mini-4B-Instruct-Q4_K_M.gguf) |
| **`Qwen3-Embedding-4B`** | GGUF | **2.33 GB** | `C:\Users\dobbl\.lmstudio\models\Qwen\Qwen3-Embedding-4B-GGUF\Qwen3-Embedding-4B-Q4_K_M.gguf` |
| **`llama-server.exe` (Vulkan Backend)** | Binary | 37.1 MB | [`d:\Antigravity Project\Rogue wifi\local_llm\bin\llama-server.exe`](file:///d:/Antigravity%20Project/Rogue%20wifi/local_llm/bin/llama-server.exe) |
| **210-Sample Extended Dataset** | JSON | 87.2 KB | [`d:\Antigravity Project\Rogue wifi\ssid_feature_framework\extended_200_test_cases.json`](file:///d:/Antigravity%20Project/Rogue%20wifi/ssid_feature_framework/extended_200_test_cases.json) |
| **Master Benchmark Script** | Python | 15.3 KB | [`d:\Antigravity Project\Rogue wifi\ssid_feature_framework\run_all_models_master.py`](file:///d:/Antigravity%20Project/Rogue%20wifi/ssid_feature_framework/run_all_models_master.py) |
| **Raw 9-Model Prediction Log** | JSON | 148.5 KB | [`d:\Antigravity Project\Rogue wifi\ssid_feature_framework\all_9_models_210_results.json`](file:///d:/Antigravity%20Project/Rogue%20wifi/ssid_feature_framework/all_9_models_210_results.json) |

---

## 7. The Resulting Architectural Dilemma (The Pivot to Pipeline Design)

The empirical benchmark revealed a fundamental paradox that directly motivated the next stage of system engineering:

> **The Architectural Dilemma:**  
> Since XGBoost outputs low attack probabilities ($P \approx 0.08 - 0.09$) for **both** ambient noise (`Starbucks_WiFi`) and zero-overlap attacks (`Complimentary_Patron_Broadband`), **XGBoost alone cannot decide which SSIDs to ignore and which to send to the embedding model.**  
> * If XGBoost drops everything with $P < 0.15 \implies$ Zero-overlap attacks slip through undetected.  
> * If XGBoost sends everything with $P < 0.15$ to the embedding model $\implies$ Pure embeddings get triggered by generic words like `"WiFi"` in coffee shops, causing alert fatigue.

This discovery established the necessity of incorporating **Physical RF Telemetry (RSSI proximity gating and Open/Captive Portal inspection)** alongside **networking stopword filtering** to orchestrate the multi-tier defense.
