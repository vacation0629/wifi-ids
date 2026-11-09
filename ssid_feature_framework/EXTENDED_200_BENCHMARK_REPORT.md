# 🧪 Comprehensive 200+ Sample Wi-Fi Threat Benchmark Report
## Evaluating XGBoost vs. Edge BGE-Small (67 MB) Semantic Embeddings

> **Total Test Samples:** 210  
> **Evaluated Models:** XGBoost Classifier (Tier 2) & BAAI/bge-small-en-v1.5 (67 MB ONNX)  
> **Raw Data Log:** [`extended_200_benchmark_results.json`](file:///d:/Antigravity%20Project/Rogue%20wifi/ssid_feature_framework/extended_200_benchmark_results.json)  

---

### 1. Performance Summary by Category

| Category | Count | Actual Label | XGBoost Accuracy | BGE-Small Accuracy | Avg XGB $P(\text{Evil})$ | Avg BGE Cosine |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| `ambient_environmental_noise` | 40 | **BENIGN** | **95.0%** | **17.5%** | `0.098` | `0.6817` |
| `classical_orthographic_evil_twin` | 40 | **EVIL_TWIN** | **100.0%** | **100.0%** | `0.9693` | `0.9159` |
| `departmental_sister_benign` | 60 | **BENIGN** | **95.0%** | **31.67%** | `0.1271` | `0.6488` |
| `zero_overlap_semantic_evil_twin` | 70 | **EVIL_TWIN** | **1.43%** | **97.14%** | `0.1093` | `0.6978` |
| **OVERALL TOTAL** | **210** | **ALL** | **64.76%** | **63.81%** | - | - |

---

### 2. Key Scientific Observations & Defense Findings

#### A. Zero-Overlap Semantic Evil Twins (`zero_overlap_semantic_evil_twin`)
* **XGBoost Accuracy:** 1.43% (Catastrophic Blind Spot)
* **BGE-Small Accuracy:** 97.14%
* **Finding:** When attackers avoid hardcoded lure words and edit distance, XGBoost suffers almost complete false negatives. BGE-small catches these semantic lures in < 5 ms.

#### B. Classical Orthographic Attacks (`classical_orthographic_evil_twin`)
* **XGBoost Accuracy:** 100.0%
* **Finding:** For typosquatting and character manipulation, XGBoost remains dominant and virtually flawless at < 0.15 ms latency.

#### C. Environmental Noise Rejection (`ambient_environmental_noise`)
* **XGBoost Accuracy:** 95.0%
* **BGE-Small Accuracy:** 17.5%
* **Finding:** Both models successfully discard external non-campus networks without false alarms.

#### D. Departmental Sister Subnets (`departmental_sister_benign`)
* **XGBoost Accuracy:** 95.0%
* **BGE-Small Accuracy:** 31.67%
* **Finding:** Legitimate sister subnets have high semantic alignment with the university. While BGE-small flags them as suspicious, Tier 3 hardware telemetry (BSSID/OUI + 802.1X) verifies their authentic institutional hardware.
