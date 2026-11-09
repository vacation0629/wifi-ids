# 🧪 Comprehensive Benchmark: Decision Tree vs. XGBoost Classifier

## 1. Hyperparameter Comparison Audit

| Hyperparameter | Decision Tree (CART) | XGBoost (Gradient Boosted) | Engineering Rationale |
| :--- | :--- | :--- | :--- |
| `model_type` | Single Binary Tree | Ensemble of 50 Boosted Trees | Tradeoff between pure explainability and boosting ensemble |
| `max_depth` | `3` | `3` | Depth 3 limits tree to at most 8 leaves, strictly preventing overfitting |
| `n_estimators` | `1` (single tree) | `50` | 50 boosting stages iteratively correcting previous residual errors |
| `learning_rate` | N/A (deterministic) | `0.1` | Shrinkage step size preventing any single tree from dominating |
| `subsample` | `1.0` (all samples) | `0.8` | Row bagging adding stochastic diversity to trees |
| `colsample_bytree` | `1.0` (all features) | `0.8` | Random feature subsampling per tree |
| `reg_lambda` (L2) | N/A | `1.0` | Ridge penalty on leaf weights to avoid extreme weights |
| `reg_alpha` (L1) | N/A | `0.1` | Lasso sparsity penalty driving irrelevant feature weights to zero |

## 2. Statistical Benchmark Summary

| Metric | Decision Tree | XGBoost Classifier | Difference / Gain |
| :--- | :---: | :---: | :---: |
| **Training Accuracy** | **98.98%** | **98.98%** | Equal |
| **5-Fold CV Accuracy** | **93.89%** (±1.95%) | **93.89%** (±1.95%) | +0.00% |
| **5-Fold CV Recall** | **97.03%** | **95.49%** | -1.54% |
| **5-Fold CV F1-Score** | **0.9560** | **0.9554** | -0.0006 |
| **ROC-AUC Score** | N/A (Step output) | **0.9995** | Continuous well-calibrated curve |
| **Inference Latency** | **< 0.01 ms** | **~0.15 ms** | Both ultra-fast on CPU |
| **Output Format** | Binary {0, 1} | Probability P(Evil) in [0, 1] | Probabilities allow adjustable risk thresholds |

## 3. Top Feature Importances (XGBoost)

| Rank | Feature | XGBoost Gain (%) | Role in Detection |
| :-: | :--- | :---: | :--- |
| 1 | `f1_lev_ratio` | 19.23% | Primary split driver |
| 2 | `f2_dam_ratio` | 18.59% | Primary split driver |
| 3 | `f4_ngram2` | 17.05% | Primary split driver |
| 4 | `f12_academic_role_collision` | 16.66% | Primary split driver |
| 5 | `f9_token_jaccard` | 6.57% | Primary split driver |
| 6 | `f13_prefix_ratio` | 5.49% | Primary split driver |
| 7 | `f3_jaro_winkler` | 4.71% | Primary split driver |

## 4. Complete Per-Sample Raw Prediction Log (88 Samples)

| # | Observed SSID | Target Authorized | Category | Actual | Tree Pred | XGB Pred | XGB Prob $P(\text{Evil})$ | Match? |
| :-: | :--- | :--- | :--- | :-: | :-: | :-: | :-: | :-: |
| 1 | `University Campus 5G` | `University Campus 5G` | `authorized_exact` | **BENIGN** | BENIGN | BENIGN | `0.1357` | ✅ |
| 2 | `University Staff Secure` | `University Staff Secure` | `authorized_exact` | **BENIGN** | BENIGN | BENIGN | `0.1357` | ✅ |
| 3 | `University Student WiFi` | `University Student WiFi` | `authorized_exact` | **BENIGN** | BENIGN | BENIGN | `0.1357` | ✅ |
| 4 | `University Guest Portal` | `University Guest Portal` | `authorized_exact` | **BENIGN** | BENIGN | BENIGN | `0.1357` | ✅ |
| 5 | `eduroam` | `eduroam` | `authorized_exact` | **BENIGN** | BENIGN | BENIGN | `0.1357` | ✅ |
| 6 | `Siam Wifi` | `Siam Wifi` | `authorized_exact` | **BENIGN** | BENIGN | BENIGN | `0.1357` | ✅ |
| 7 | `SiamXP Wifi` | `SiamXP Wifi` | `authorized_exact` | **BENIGN** | BENIGN | BENIGN | `0.1357` | ✅ |
| 8 | `Un1versity Campus 5G` | `University Campus 5G` | `homoglyph_typo` | **EVIL_TWIN** | EVIL_TWIN | EVIL_TWIN | `0.9811` | ✅ |
| 9 | `University Carnpus 5G` | `University Campus 5G` | `homoglyph_typo` | **EVIL_TWIN** | EVIL_TWIN | EVIL_TWIN | `0.9722` | ✅ |
| 10 | `University Campup 5G` | `University Campus 5G` | `homoglyph_typo` | **EVIL_TWIN** | EVIL_TWIN | EVIL_TWIN | `0.9773` | ✅ |
| 11 | `Unversity Campus 5G` | `University Campus 5G` | `homoglyph_typo` | **EVIL_TWIN** | EVIL_TWIN | EVIL_TWIN | `0.9722` | ✅ |
| 12 | `University Campuss 5G` | `University Campus 5G` | `homoglyph_typo` | **EVIL_TWIN** | EVIL_TWIN | EVIL_TWIN | `0.9475` | ✅ |
| 13 | `University 5taff Secure` | `University Staff Secure` | `homoglyph_typo` | **EVIL_TWIN** | EVIL_TWIN | EVIL_TWIN | `0.9726` | ✅ |
| 14 | `University Staff 5ecure` | `University Staff Secure` | `homoglyph_typo` | **EVIL_TWIN** | EVIL_TWIN | EVIL_TWIN | `0.9619` | ✅ |
| 15 | `University Staff Secur3` | `University Staff Secure` | `homoglyph_typo` | **EVIL_TWIN** | EVIL_TWIN | EVIL_TWIN | `0.9539` | ✅ |
| 16 | `Un1versity Staff Secure` | `University Staff Secure` | `homoglyph_typo` | **EVIL_TWIN** | EVIL_TWIN | EVIL_TWIN | `0.9726` | ✅ |
| 17 | `University Student WiF1` | `University Student WiFi` | `homoglyph_typo` | **EVIL_TWIN** | EVIL_TWIN | EVIL_TWIN | `0.9539` | ✅ |
| 18 | `University Student VVIFi` | `University Student WiFi` | `homoglyph_typo` | **EVIL_TWIN** | EVIL_TWIN | EVIL_TWIN | `0.9706` | ✅ |
| 19 | `University Studnet WiFi` | `University Student WiFi` | `homoglyph_typo` | **EVIL_TWIN** | EVIL_TWIN | EVIL_TWIN | `0.9464` | ✅ |
| 20 | `University Gue5t Portal` | `University Guest Portal` | `homoglyph_typo` | **EVIL_TWIN** | EVIL_TWIN | EVIL_TWIN | `0.9619` | ✅ |
| 21 | `University Guest P0rtal` | `University Guest Portal` | `homoglyph_typo` | **EVIL_TWIN** | EVIL_TWIN | EVIL_TWIN | `0.9575` | ✅ |
| 22 | `eduroarn` | `eduroam` | `homoglyph_typo` | **EVIL_TWIN** | EVIL_TWIN | EVIL_TWIN | `0.9173` | ✅ |
| 23 | `edur0am` | `eduroam` | `homoglyph_typo` | **EVIL_TWIN** | EVIL_TWIN | EVIL_TWIN | `0.8820` | ✅ |
| 24 | `Siam W1f1` | `Siam Wifi` | `homoglyph_typo` | **EVIL_TWIN** | EVIL_TWIN | EVIL_TWIN | `0.9289` | ✅ |
| 25 | `SiamXP W1f1` | `SiamXP Wifi` | `homoglyph_typo` | **EVIL_TWIN** | EVIL_TWIN | EVIL_TWIN | `0.9468` | ✅ |
| 26 | `University Campus 5G Fast` | `University Campus 5G` | `word_addition` | **EVIL_TWIN** | EVIL_TWIN | EVIL_TWIN | `0.9805` | ✅ |
| 27 | `Free University Campus 5G` | `University Campus 5G` | `word_addition` | **EVIL_TWIN** | EVIL_TWIN | EVIL_TWIN | `0.9669` | ✅ |
| 28 | `Official University Campus 5G` | `University Campus 5G` | `word_addition` | **EVIL_TWIN** | EVIL_TWIN | EVIL_TWIN | `0.9764` | ✅ |
| 29 | `University Campus 5G VIP` | `University Campus 5G` | `word_addition` | **EVIL_TWIN** | EVIL_TWIN | EVIL_TWIN | `0.9746` | ✅ |
| 30 | `University Staff Secure Login` | `University Staff Secure` | `word_addition` | **EVIL_TWIN** | EVIL_TWIN | EVIL_TWIN | `0.9805` | ✅ |
| 31 | `University Staff Secure Verify` | `University Staff Secure` | `word_addition` | **EVIL_TWIN** | EVIL_TWIN | EVIL_TWIN | `0.9788` | ✅ |
| 32 | `Official University Staff Secure` | `University Staff Secure` | `word_addition` | **EVIL_TWIN** | EVIL_TWIN | EVIL_TWIN | `0.9698` | ✅ |
| 33 | `University Student WiFi Free` | `University Student WiFi` | `word_addition` | **EVIL_TWIN** | EVIL_TWIN | EVIL_TWIN | `0.9805` | ✅ |
| 34 | `University Student WiFi Portal` | `University Student WiFi` | `word_addition` | **EVIL_TWIN** | EVIL_TWIN | EVIL_TWIN | `0.9788` | ✅ |
| 35 | `University Student WiFi AutoConnect` | `University Student WiFi` | `word_addition` | **EVIL_TWIN** | EVIL_TWIN | EVIL_TWIN | `0.9843` | ✅ |
| 36 | `Free University Student WiFi` | `University Student WiFi` | `word_addition` | **EVIL_TWIN** | EVIL_TWIN | EVIL_TWIN | `0.9700` | ✅ |
| 37 | `University Guest Portal Free` | `University Guest Portal` | `word_addition` | **EVIL_TWIN** | EVIL_TWIN | EVIL_TWIN | `0.9805` | ✅ |
| 38 | `University Guest Portal Login` | `University Guest Portal` | `word_addition` | **EVIL_TWIN** | EVIL_TWIN | EVIL_TWIN | `0.9805` | ✅ |
| 39 | `eduroam AutoConnect` | `eduroam` | `word_addition` | **EVIL_TWIN** | EVIL_TWIN | EVIL_TWIN | `0.9426` | ✅ |
| 40 | `eduroam Setup` | `eduroam` | `word_addition` | **EVIL_TWIN** | EVIL_TWIN | EVIL_TWIN | `0.9609` | ✅ |
| 41 | `Free Siam Wifi` | `Siam Wifi` | `word_addition` | **EVIL_TWIN** | EVIL_TWIN | EVIL_TWIN | `0.9764` | ✅ |
| 42 | `Siam Wifi Fast` | `Siam Wifi` | `word_addition` | **EVIL_TWIN** | EVIL_TWIN | EVIL_TWIN | `0.9843` | ✅ |
| 43 | `University Campus` | `University Campus 5G` | `word_subtraction` | **EVIL_TWIN** | EVIL_TWIN | EVIL_TWIN | `0.9725` | ✅ |
| 44 | `Campus 5G` | `University Campus 5G` | `word_subtraction` | **EVIL_TWIN** | EVIL_TWIN | EVIL_TWIN | `0.9417` | ✅ |
| 45 | `University Staff` | `University Staff Secure` | `word_subtraction` | **EVIL_TWIN** | EVIL_TWIN | EVIL_TWIN | `0.9843` | ✅ |
| 46 | `Staff Secure` | `University Staff Secure` | `word_subtraction` | **EVIL_TWIN** | EVIL_TWIN | EVIL_TWIN | `0.9530` | ✅ |
| 47 | `University Student` | `University Student WiFi` | `word_subtraction` | **EVIL_TWIN** | EVIL_TWIN | EVIL_TWIN | `0.9788` | ✅ |
| 48 | `Student WiFi` | `University Student WiFi` | `word_subtraction` | **EVIL_TWIN** | EVIL_TWIN | EVIL_TWIN | `0.9417` | ✅ |
| 49 | `University Guest` | `University Guest Portal` | `word_subtraction` | **EVIL_TWIN** | EVIL_TWIN | EVIL_TWIN | `0.9843` | ✅ |
| 50 | `Guest Portal` | `University Guest Portal` | `word_subtraction` | **EVIL_TWIN** | EVIL_TWIN | EVIL_TWIN | `0.9417` | ✅ |
| 51 | `University` | `University Campus 5G` | `word_subtraction` | **EVIL_TWIN** | EVIL_TWIN | EVIL_TWIN | `0.9589` | ✅ |
| 52 | `Campus` | `University Campus 5G` | `word_subtraction` | **EVIL_TWIN** | EVIL_TWIN | EVIL_TWIN | `0.9204` | ✅ |
| 53 | `Staff` | `University Staff Secure` | `word_subtraction` | **EVIL_TWIN** | EVIL_TWIN | EVIL_TWIN | `0.7974` | ✅ |
| 54 | `Student` | `University Student WiFi` | `word_subtraction` | **EVIL_TWIN** | EVIL_TWIN | EVIL_TWIN | `0.9368` | ✅ |
| 55 | `Siam` | `Siam Wifi` | `word_subtraction` | **EVIL_TWIN** | EVIL_TWIN | EVIL_TWIN | `0.9518` | ✅ |
| 56 | `University-Campus-5G` | `University Campus 5G` | `delimiter_case` | **EVIL_TWIN** | EVIL_TWIN | EVIL_TWIN | `0.9792` | ✅ |
| 57 | `University_Campus_5G` | `University Campus 5G` | `delimiter_case` | **EVIL_TWIN** | EVIL_TWIN | EVIL_TWIN | `0.9792` | ✅ |
| 58 | `University.Campus.5G` | `University Campus 5G` | `delimiter_case` | **EVIL_TWIN** | EVIL_TWIN | EVIL_TWIN | `0.9792` | ✅ |
| 59 | `university campus 5g` | `University Campus 5G` | `delimiter_case` | **EVIL_TWIN** | EVIL_TWIN | EVIL_TWIN | `0.9617` | ✅ |
| 60 | `University-Staff-Secure` | `University Staff Secure` | `delimiter_case` | **EVIL_TWIN** | EVIL_TWIN | EVIL_TWIN | `0.9802` | ✅ |
| 61 | `University_Staff_Secure` | `University Staff Secure` | `delimiter_case` | **EVIL_TWIN** | EVIL_TWIN | EVIL_TWIN | `0.9802` | ✅ |
| 62 | `University.Staff.Secure` | `University Staff Secure` | `delimiter_case` | **EVIL_TWIN** | EVIL_TWIN | EVIL_TWIN | `0.9802` | ✅ |
| 63 | `university staff secure` | `University Staff Secure` | `delimiter_case` | **EVIL_TWIN** | EVIL_TWIN | EVIL_TWIN | `0.9712` | ✅ |
| 64 | `University-Student-WiFi` | `University Student WiFi` | `delimiter_case` | **EVIL_TWIN** | EVIL_TWIN | EVIL_TWIN | `0.9802` | ✅ |
| 65 | `University_Student_WiFi` | `University Student WiFi` | `delimiter_case` | **EVIL_TWIN** | EVIL_TWIN | EVIL_TWIN | `0.9802` | ✅ |
| 66 | `EDUROAM` | `eduroam` | `delimiter_case` | **EVIL_TWIN** | EVIL_TWIN | EVIL_TWIN | `0.8828` | ✅ |
| 67 | `Eduroam` | `eduroam` | `delimiter_case` | **EVIL_TWIN** | EVIL_TWIN | EVIL_TWIN | `0.9712` | ✅ |
| 68 | `Siam_Wifi` | `Siam Wifi` | `delimiter_case` | **EVIL_TWIN** | EVIL_TWIN | EVIL_TWIN | `0.9792` | ✅ |
| 69 | `Siam-Wifi` | `Siam Wifi` | `delimiter_case` | **EVIL_TWIN** | EVIL_TWIN | EVIL_TWIN | `0.9792` | ✅ |
| 70 | `SiamXP_Wifi` | `SiamXP Wifi` | `delimiter_case` | **EVIL_TWIN** | EVIL_TWIN | EVIL_TWIN | `0.9792` | ✅ |
| 71 | `College Campus 5G` | `University Campus 5G` | `semantic_relevant` | **BENIGN** | BENIGN | BENIGN | `0.1336` | ✅ |
| 72 | `Faculty Staff Secure` | `University Staff Secure` | `semantic_relevant` | **BENIGN** | BENIGN | BENIGN | `0.1820` | ✅ |
| 73 | `University Academic WiFi` | `University Student WiFi` | `semantic_relevant` | **BENIGN** | EVIL_TWIN | EVIL_TWIN | `0.7146` | ⚠️ |
| 74 | `University Library Guest` | `University Guest Portal` | `semantic_relevant` | **BENIGN** | BENIGN | BENIGN | `0.1741` | ✅ |
| 75 | `Campus Research Lab 5G` | `University Campus 5G` | `semantic_relevant` | **BENIGN** | BENIGN | BENIGN | `0.0544` | ✅ |
| 76 | `Engineering Faculty Staff` | `University Staff Secure` | `semantic_relevant` | **BENIGN** | BENIGN | BENIGN | `0.0643` | ✅ |
| 77 | `University Alumni Portal` | `University Guest Portal` | `semantic_relevant` | **BENIGN** | BENIGN | BENIGN | `0.3238` | ✅ |
| 78 | `Medical School Staff WLAN` | `University Staff Secure` | `semantic_relevant` | **BENIGN** | BENIGN | BENIGN | `0.0847` | ✅ |
| 79 | `Campus Student HighSpeed` | `University Student WiFi` | `semantic_relevant` | **BENIGN** | BENIGN | BENIGN | `0.0633` | ✅ |
| 80 | `Science Complex Guest` | `University Guest Portal` | `semantic_relevant` | **BENIGN** | BENIGN | BENIGN | `0.0577` | ✅ |
| 81 | `Uni Campus Net` | `University Campus 5G` | `semantic_relevant` | **EVIL_TWIN** | EVIL_TWIN | EVIL_TWIN | `0.8857` | ✅ |
| 82 | `University Intranet Secure` | `University Staff Secure` | `semantic_relevant` | **EVIL_TWIN** | EVIL_TWIN | EVIL_TWIN | `0.8881` | ✅ |
| 83 | `University Public Access` | `University Guest Portal` | `semantic_relevant` | **EVIL_TWIN** | EVIL_TWIN | EVIL_TWIN | `0.7169` | ✅ |
| 84 | `Campus Wide Open Net` | `University Campus 5G` | `semantic_relevant` | **EVIL_TWIN** | EVIL_TWIN | EVIL_TWIN | `0.5207` | ✅ |
| 85 | `Cafe Amazon WiFi` | `University Campus 5G` | `irrelevant_noise` | **BENIGN** | BENIGN | BENIGN | `0.0509` | ✅ |
| 86 | `Starbucks Guest` | `University Campus 5G` | `irrelevant_noise` | **BENIGN** | BENIGN | BENIGN | `0.0386` | ✅ |
| 87 | `AIS SUPER WiFi` | `University Campus 5G` | `irrelevant_noise` | **BENIGN** | BENIGN | BENIGN | `0.0748` | ✅ |
| 88 | `TrueMove H WiFi` | `University Campus 5G` | `irrelevant_noise` | **BENIGN** | BENIGN | BENIGN | `0.0556` | ✅ |
| 89 | `dtac WiFi` | `University Campus 5G` | `irrelevant_noise` | **BENIGN** | BENIGN | BENIGN | `0.1297` | ✅ |
| 90 | `7Eleven Public` | `University Campus 5G` | `irrelevant_noise` | **BENIGN** | BENIGN | BENIGN | `0.0678` | ✅ |
| 91 | `Dorm Room 302 5G` | `University Campus 5G` | `irrelevant_noise` | **BENIGN** | BENIGN | BENIGN | `0.0338` | ✅ |
| 92 | `iPhone 15 Hotspot` | `University Campus 5G` | `irrelevant_noise` | **BENIGN** | BENIGN | BENIGN | `0.0470` | ✅ |
| 93 | `Galaxy S24 MobileAP` | `University Campus 5G` | `irrelevant_noise` | **BENIGN** | BENIGN | BENIGN | `0.0441` | ✅ |
| 94 | `HP LaserJet Direct 4B` | `University Campus 5G` | `irrelevant_noise` | **BENIGN** | BENIGN | BENIGN | `0.0365` | ✅ |
| 95 | `Bangkok Bank Branch WiFi` | `University Campus 5G` | `irrelevant_noise` | **BENIGN** | BENIGN | BENIGN | `0.0390` | ✅ |
| 96 | `KFC Guest Free` | `University Campus 5G` | `irrelevant_noise` | **BENIGN** | BENIGN | BENIGN | `0.0522` | ✅ |
| 97 | `Subway Customers WiFi` | `University Campus 5G` | `irrelevant_noise` | **BENIGN** | BENIGN | BENIGN | `0.0744` | ✅ |
| 98 | `Campus Bus Transit FreeWiFi` | `University Campus 5G` | `irrelevant_noise` | **BENIGN** | BENIGN | BENIGN | `0.3194` | ✅ |
