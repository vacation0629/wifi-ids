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
| **Training Accuracy** | **98.86%** | **98.86%** | Equal |
| **5-Fold CV Accuracy** | **95.49%** (±2.26%) | **94.38%** (±3.52%) | -1.11% |
| **5-Fold CV Recall** | **96.67%** | **94.85%** | -1.82% |
| **5-Fold CV F1-Score** | **0.9659** | **0.9571** | -0.0088 |
| **ROC-AUC Score** | N/A (Step output) | **0.9991** | Continuous well-calibrated curve |
| **Inference Latency** | **< 0.01 ms** | **~0.15 ms** | Both ultra-fast on CPU |
| **Output Format** | Binary {0, 1} | Probability P(Evil) in [0, 1] | Probabilities allow adjustable risk thresholds |

## 3. Top Feature Importances (XGBoost)

| Rank | Feature | XGBoost Gain (%) | Role in Detection |
| :-: | :--- | :---: | :--- |
| 1 | `f5_ngram3` | 17.31% | Primary split driver |
| 2 | `f2_dam_ratio` | 15.11% | Primary split driver |
| 3 | `f4_ngram2` | 13.35% | Primary split driver |
| 4 | `f1_lev_ratio` | 12.75% | Primary split driver |
| 5 | `f12_academic_role_collision` | 9.70% | Primary split driver |
| 6 | `f3_jaro_winkler` | 7.70% | Primary split driver |
| 7 | `f9_token_jaccard` | 6.60% | Primary split driver |

## 4. Complete Per-Sample Raw Prediction Log (88 Samples)

| # | Observed SSID | Target Authorized | Category | Actual | Tree Pred | XGB Pred | XGB Prob $P(\text{Evil})$ | Match? |
| :-: | :--- | :--- | :--- | :-: | :-: | :-: | :-: | :-: |
| 1 | `University_Campus_5G` | `University_Campus_5G` | `authorized_exact` | **BENIGN** | BENIGN | BENIGN | `0.2027` | ✅ |
| 2 | `University_Staff_Secure` | `University_Staff_Secure` | `authorized_exact` | **BENIGN** | BENIGN | BENIGN | `0.2027` | ✅ |
| 3 | `University_Student_WiFi` | `University_Student_WiFi` | `authorized_exact` | **BENIGN** | BENIGN | BENIGN | `0.2027` | ✅ |
| 4 | `University_Guest_Portal` | `University_Guest_Portal` | `authorized_exact` | **BENIGN** | BENIGN | BENIGN | `0.2027` | ✅ |
| 5 | `eduroam` | `eduroam` | `authorized_exact` | **BENIGN** | BENIGN | BENIGN | `0.2027` | ✅ |
| 6 | `Un1versity_Campus_5G` | `University_Campus_5G` | `homoglyph_typo` | **EVIL_TWIN** | EVIL_TWIN | EVIL_TWIN | `0.9785` | ✅ |
| 7 | `University_Carnpus_5G` | `University_Campus_5G` | `homoglyph_typo` | **EVIL_TWIN** | EVIL_TWIN | EVIL_TWIN | `0.9642` | ✅ |
| 8 | `University_Campup_5G` | `University_Campus_5G` | `homoglyph_typo` | **EVIL_TWIN** | EVIL_TWIN | EVIL_TWIN | `0.9705` | ✅ |
| 9 | `Unversity_Campus_5G` | `University_Campus_5G` | `homoglyph_typo` | **EVIL_TWIN** | EVIL_TWIN | EVIL_TWIN | `0.9678` | ✅ |
| 10 | `University_Campuss_5G` | `University_Campus_5G` | `homoglyph_typo` | **EVIL_TWIN** | EVIL_TWIN | EVIL_TWIN | `0.9087` | ✅ |
| 11 | `University_5taff_Secure` | `University_Staff_Secure` | `homoglyph_typo` | **EVIL_TWIN** | EVIL_TWIN | EVIL_TWIN | `0.9664` | ✅ |
| 12 | `University_Staff_5ecure` | `University_Staff_Secure` | `homoglyph_typo` | **EVIL_TWIN** | EVIL_TWIN | EVIL_TWIN | `0.9589` | ✅ |
| 13 | `University_Staff_Secur3` | `University_Staff_Secure` | `homoglyph_typo` | **EVIL_TWIN** | EVIL_TWIN | EVIL_TWIN | `0.9541` | ✅ |
| 14 | `Un1versity_Staff_Secure` | `University_Staff_Secure` | `homoglyph_typo` | **EVIL_TWIN** | EVIL_TWIN | EVIL_TWIN | `0.9664` | ✅ |
| 15 | `University_Student_WiF1` | `University_Student_WiFi` | `homoglyph_typo` | **EVIL_TWIN** | EVIL_TWIN | EVIL_TWIN | `0.9495` | ✅ |
| 16 | `University_Student_VVIFi` | `University_Student_WiFi` | `homoglyph_typo` | **EVIL_TWIN** | EVIL_TWIN | EVIL_TWIN | `0.9656` | ✅ |
| 17 | `University_Studnet_WiFi` | `University_Student_WiFi` | `homoglyph_typo` | **EVIL_TWIN** | EVIL_TWIN | EVIL_TWIN | `0.9073` | ✅ |
| 18 | `University_Gue5t_Portal` | `University_Guest_Portal` | `homoglyph_typo` | **EVIL_TWIN** | EVIL_TWIN | EVIL_TWIN | `0.9626` | ✅ |
| 19 | `University_Guest_P0rtal` | `University_Guest_Portal` | `homoglyph_typo` | **EVIL_TWIN** | EVIL_TWIN | EVIL_TWIN | `0.9589` | ✅ |
| 20 | `eduroarn` | `eduroam` | `homoglyph_typo` | **EVIL_TWIN** | EVIL_TWIN | EVIL_TWIN | `0.9526` | ✅ |
| 21 | `edur0am` | `eduroam` | `homoglyph_typo` | **EVIL_TWIN** | EVIL_TWIN | EVIL_TWIN | `0.8507` | ✅ |
| 22 | `University_Campus_5G_Fast` | `University_Campus_5G` | `word_addition` | **EVIL_TWIN** | EVIL_TWIN | EVIL_TWIN | `0.9777` | ✅ |
| 23 | `Free_University_Campus_5G` | `University_Campus_5G` | `word_addition` | **EVIL_TWIN** | EVIL_TWIN | EVIL_TWIN | `0.9693` | ✅ |
| 24 | `Official_University_Campus_5G` | `University_Campus_5G` | `word_addition` | **EVIL_TWIN** | EVIL_TWIN | EVIL_TWIN | `0.9770` | ✅ |
| 25 | `University_Campus_5G_VIP` | `University_Campus_5G` | `word_addition` | **EVIL_TWIN** | EVIL_TWIN | EVIL_TWIN | `0.9724` | ✅ |
| 26 | `University_Staff_Secure_Login` | `University_Staff_Secure` | `word_addition` | **EVIL_TWIN** | EVIL_TWIN | EVIL_TWIN | `0.9777` | ✅ |
| 27 | `University_Staff_Secure_Verify` | `University_Staff_Secure` | `word_addition` | **EVIL_TWIN** | EVIL_TWIN | EVIL_TWIN | `0.9777` | ✅ |
| 28 | `Official_University_Staff_Secure` | `University_Staff_Secure` | `word_addition` | **EVIL_TWIN** | EVIL_TWIN | EVIL_TWIN | `0.9700` | ✅ |
| 29 | `University_Student_WiFi_Free` | `University_Student_WiFi` | `word_addition` | **EVIL_TWIN** | EVIL_TWIN | EVIL_TWIN | `0.9777` | ✅ |
| 30 | `University_Student_WiFi_Portal` | `University_Student_WiFi` | `word_addition` | **EVIL_TWIN** | EVIL_TWIN | EVIL_TWIN | `0.9777` | ✅ |
| 31 | `University_Student_WiFi_AutoConnect` | `University_Student_WiFi` | `word_addition` | **EVIL_TWIN** | EVIL_TWIN | EVIL_TWIN | `0.9825` | ✅ |
| 32 | `Free_University_Student_WiFi` | `University_Student_WiFi` | `word_addition` | **EVIL_TWIN** | EVIL_TWIN | EVIL_TWIN | `0.9733` | ✅ |
| 33 | `University_Guest_Portal_Free` | `University_Guest_Portal` | `word_addition` | **EVIL_TWIN** | EVIL_TWIN | EVIL_TWIN | `0.9777` | ✅ |
| 34 | `University_Guest_Portal_Login` | `University_Guest_Portal` | `word_addition` | **EVIL_TWIN** | EVIL_TWIN | EVIL_TWIN | `0.9777` | ✅ |
| 35 | `eduroam_AutoConnect` | `eduroam` | `word_addition` | **EVIL_TWIN** | EVIL_TWIN | EVIL_TWIN | `0.9321` | ✅ |
| 36 | `eduroam_Setup` | `eduroam` | `word_addition` | **EVIL_TWIN** | EVIL_TWIN | EVIL_TWIN | `0.9569` | ✅ |
| 37 | `University_Campus` | `University_Campus_5G` | `word_subtraction` | **EVIL_TWIN** | EVIL_TWIN | EVIL_TWIN | `0.9690` | ✅ |
| 38 | `Campus_5G` | `University_Campus_5G` | `word_subtraction` | **EVIL_TWIN** | EVIL_TWIN | EVIL_TWIN | `0.9464` | ✅ |
| 39 | `University_Staff` | `University_Staff_Secure` | `word_subtraction` | **EVIL_TWIN** | EVIL_TWIN | EVIL_TWIN | `0.9825` | ✅ |
| 40 | `Staff_Secure` | `University_Staff_Secure` | `word_subtraction` | **EVIL_TWIN** | EVIL_TWIN | EVIL_TWIN | `0.9522` | ✅ |
| 41 | `University_Student` | `University_Student_WiFi` | `word_subtraction` | **EVIL_TWIN** | EVIL_TWIN | EVIL_TWIN | `0.9777` | ✅ |
| 42 | `Student_WiFi` | `University_Student_WiFi` | `word_subtraction` | **EVIL_TWIN** | EVIL_TWIN | EVIL_TWIN | `0.9464` | ✅ |
| 43 | `University_Guest` | `University_Guest_Portal` | `word_subtraction` | **EVIL_TWIN** | EVIL_TWIN | EVIL_TWIN | `0.9825` | ✅ |
| 44 | `Guest_Portal` | `University_Guest_Portal` | `word_subtraction` | **EVIL_TWIN** | EVIL_TWIN | EVIL_TWIN | `0.9464` | ✅ |
| 45 | `University` | `University_Campus_5G` | `word_subtraction` | **EVIL_TWIN** | EVIL_TWIN | EVIL_TWIN | `0.9529` | ✅ |
| 46 | `Campus` | `University_Campus_5G` | `word_subtraction` | **EVIL_TWIN** | EVIL_TWIN | EVIL_TWIN | `0.9398` | ✅ |
| 47 | `Staff` | `University_Staff_Secure` | `word_subtraction` | **EVIL_TWIN** | EVIL_TWIN | EVIL_TWIN | `0.7972` | ✅ |
| 48 | `Student` | `University_Student_WiFi` | `word_subtraction` | **EVIL_TWIN** | EVIL_TWIN | EVIL_TWIN | `0.9374` | ✅ |
| 49 | `University-Campus-5G` | `University_Campus_5G` | `delimiter_case` | **EVIL_TWIN** | EVIL_TWIN | EVIL_TWIN | `0.9788` | ✅ |
| 50 | `university_campus_5g` | `University_Campus_5G` | `delimiter_case` | **EVIL_TWIN** | EVIL_TWIN | EVIL_TWIN | `0.9425` | ✅ |
| 51 | `University Campus 5G` | `University_Campus_5G` | `delimiter_case` | **EVIL_TWIN** | EVIL_TWIN | EVIL_TWIN | `0.9788` | ✅ |
| 52 | `University.Campus.5G` | `University_Campus_5G` | `delimiter_case` | **EVIL_TWIN** | EVIL_TWIN | EVIL_TWIN | `0.9788` | ✅ |
| 53 | `University-Staff-Secure` | `University_Staff_Secure` | `delimiter_case` | **EVIL_TWIN** | EVIL_TWIN | EVIL_TWIN | `0.9788` | ✅ |
| 54 | `university_staff_secure` | `University_Staff_Secure` | `delimiter_case` | **EVIL_TWIN** | EVIL_TWIN | EVIL_TWIN | `0.9474` | ✅ |
| 55 | `University Staff Secure` | `University_Staff_Secure` | `delimiter_case` | **EVIL_TWIN** | EVIL_TWIN | EVIL_TWIN | `0.9788` | ✅ |
| 56 | `University.Staff.Secure` | `University_Staff_Secure` | `delimiter_case` | **EVIL_TWIN** | EVIL_TWIN | EVIL_TWIN | `0.9788` | ✅ |
| 57 | `University-Student-WiFi` | `University_Student_WiFi` | `delimiter_case` | **EVIL_TWIN** | EVIL_TWIN | EVIL_TWIN | `0.9788` | ✅ |
| 58 | `University Student WiFi` | `University_Student_WiFi` | `delimiter_case` | **EVIL_TWIN** | EVIL_TWIN | EVIL_TWIN | `0.9788` | ✅ |
| 59 | `EDUROAM` | `eduroam` | `delimiter_case` | **EVIL_TWIN** | EVIL_TWIN | EVIL_TWIN | `0.8988` | ✅ |
| 60 | `Eduroam` | `eduroam` | `delimiter_case` | **EVIL_TWIN** | EVIL_TWIN | EVIL_TWIN | `0.9474` | ✅ |
| 61 | `College_Campus_5G` | `University_Campus_5G` | `semantic_relevant` | **BENIGN** | BENIGN | BENIGN | `0.0902` | ✅ |
| 62 | `Faculty_Staff_Secure` | `University_Staff_Secure` | `semantic_relevant` | **BENIGN** | BENIGN | BENIGN | `0.1479` | ✅ |
| 63 | `University_Academic_WiFi` | `University_Student_WiFi` | `semantic_relevant` | **BENIGN** | EVIL_TWIN | EVIL_TWIN | `0.6656` | ⚠️ |
| 64 | `University_Library_Guest` | `University_Guest_Portal` | `semantic_relevant` | **BENIGN** | BENIGN | BENIGN | `0.1744` | ✅ |
| 65 | `Campus_Research_Lab_5G` | `University_Campus_5G` | `semantic_relevant` | **BENIGN** | BENIGN | BENIGN | `0.0456` | ✅ |
| 66 | `Engineering_Faculty_Staff` | `University_Staff_Secure` | `semantic_relevant` | **BENIGN** | BENIGN | BENIGN | `0.0456` | ✅ |
| 67 | `University_Alumni_Portal` | `University_Guest_Portal` | `semantic_relevant` | **BENIGN** | BENIGN | BENIGN | `0.2802` | ✅ |
| 68 | `Medical_School_Staff_WLAN` | `University_Staff_Secure` | `semantic_relevant` | **BENIGN** | BENIGN | BENIGN | `0.0439` | ✅ |
| 69 | `Campus_Student_HighSpeed` | `University_Student_WiFi` | `semantic_relevant` | **BENIGN** | BENIGN | BENIGN | `0.0444` | ✅ |
| 70 | `Science_Complex_Guest` | `University_Guest_Portal` | `semantic_relevant` | **BENIGN** | BENIGN | BENIGN | `0.0459` | ✅ |
| 71 | `Uni_Campus_Net` | `University_Campus_5G` | `semantic_relevant` | **EVIL_TWIN** | EVIL_TWIN | EVIL_TWIN | `0.8734` | ✅ |
| 72 | `University_Intranet_Secure` | `University_Staff_Secure` | `semantic_relevant` | **EVIL_TWIN** | EVIL_TWIN | EVIL_TWIN | `0.8589` | ✅ |
| 73 | `University_Public_Access` | `University_Guest_Portal` | `semantic_relevant` | **EVIL_TWIN** | EVIL_TWIN | EVIL_TWIN | `0.6656` | ✅ |
| 74 | `Campus_Wide_Open_Net` | `University_Campus_5G` | `semantic_relevant` | **EVIL_TWIN** | EVIL_TWIN | EVIL_TWIN | `0.5075` | ✅ |
| 75 | `Cafe_Amazon_WiFi` | `University_Campus_5G` | `irrelevant_noise` | **BENIGN** | BENIGN | BENIGN | `0.0497` | ✅ |
| 76 | `Starbucks_Guest` | `University_Campus_5G` | `irrelevant_noise` | **BENIGN** | BENIGN | BENIGN | `0.0325` | ✅ |
| 77 | `AIS_SUPER_WiFi` | `University_Campus_5G` | `irrelevant_noise` | **BENIGN** | BENIGN | BENIGN | `0.1161` | ✅ |
| 78 | `TrueMove_H_WiFi` | `University_Campus_5G` | `irrelevant_noise` | **BENIGN** | BENIGN | BENIGN | `0.0648` | ✅ |
| 79 | `dtac_WiFi` | `University_Campus_5G` | `irrelevant_noise` | **BENIGN** | BENIGN | BENIGN | `0.1772` | ✅ |
| 80 | `7Eleven_Public` | `University_Campus_5G` | `irrelevant_noise` | **BENIGN** | BENIGN | BENIGN | `0.1161` | ✅ |
| 81 | `Dorm_Room_302_5G` | `University_Campus_5G` | `irrelevant_noise` | **BENIGN** | BENIGN | BENIGN | `0.0247` | ✅ |
| 82 | `iPhone_15_Hotspot` | `University_Campus_5G` | `irrelevant_noise` | **BENIGN** | BENIGN | BENIGN | `0.0472` | ✅ |
| 83 | `Galaxy_S24_MobileAP` | `University_Campus_5G` | `irrelevant_noise` | **BENIGN** | BENIGN | BENIGN | `0.0454` | ✅ |
| 84 | `HP_LaserJet_Direct_4B` | `University_Campus_5G` | `irrelevant_noise` | **BENIGN** | BENIGN | BENIGN | `0.0454` | ✅ |
| 85 | `Bangkok_Bank_Branch_WiFi` | `University_Campus_5G` | `irrelevant_noise` | **BENIGN** | BENIGN | BENIGN | `0.0472` | ✅ |
| 86 | `KFC_Guest_Free` | `University_Campus_5G` | `irrelevant_noise` | **BENIGN** | BENIGN | BENIGN | `0.0657` | ✅ |
| 87 | `Subway_Customers_WiFi` | `University_Campus_5G` | `irrelevant_noise` | **BENIGN** | BENIGN | BENIGN | `0.0484` | ✅ |
| 88 | `Campus_Bus_Transit_FreeWiFi` | `University_Campus_5G` | `irrelevant_noise` | **BENIGN** | BENIGN | BENIGN | `0.3417` | ✅ |
