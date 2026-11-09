#!/usr/bin/env python3
"""
University Wi-Fi SSID Feature Robustness Benchmark & Classifier
Includes pure Python CART Decision Tree (zero external dependencies).
"""

import os
import sys
import json
import math
from typing import List, Dict, Any, Tuple
from features import extract_features, find_best_whitelist_match

# Ensure UTF-8 output on Windows terminals
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

DEFAULT_WHITELIST = [
    "University Campus 5G",
    "University Staff Secure",
    "University Student WiFi",
    "University Guest Portal",
    "eduroam",
    "Siam Wifi",
    "SiamXP Wifi",
    "SIAM WIFI",
    "SIAM XP WIFI"
]

FEATURE_NAMES = [
    "f1_lev_ratio",
    "f2_dam_ratio",
    "f3_jaro_winkler",
    "f4_ngram2",
    "f5_ngram3",
    "f6_homoglyphs",
    "f7_len_abs_diff",
    "f8_len_ratio",
    "f9_token_jaccard",
    "f10_separator_delta",
    "f11_lure_flag",
    "f12_academic_role_collision",
    "f13_prefix_ratio"
]


class TreeNode:
    """Node in a binary decision tree."""
    def __init__(self, feature_idx=None, threshold=None, left=None, right=None, value=None):
        self.feature_idx = feature_idx
        self.threshold = threshold
        self.left = left
        self.right = right
        self.value = value  # Class prediction if leaf node


class PurePythonDecisionTree:
    """
    Lightweight, self-contained CART Decision Tree.
    Runs on any device without scikit-learn, numpy, or scipy.
    """
    def __init__(self, max_depth=3, min_samples_split=2):
        self.max_depth = max_depth
        self.min_samples_split = min_samples_split
        self.root = None
        self.feature_importances_ = {fn: 0.0 for fn in FEATURE_NAMES}

    def _gini(self, y: List[int]) -> float:
        if not y:
            return 0.0
        p1 = sum(y) / len(y)
        p0 = 1.0 - p1
        return 1.0 - (p0 ** 2 + p1 ** 2)

    def _split(self, X: List[List[float]], y: List[int], feat_idx: int, thresh: float):
        left_X, left_y, right_X, right_y = [], [], [], []
        for i, row in enumerate(X):
            if row[feat_idx] <= thresh:
                left_X.append(row)
                left_y.append(y[i])
            else:
                right_X.append(row)
                right_y.append(y[i])
        return left_X, left_y, right_X, right_y

    def _best_split(self, X: List[List[float]], y: List[int]):
        best_gain = -1.0
        best_feat = None
        best_thresh = None
        current_gini = self._gini(y)

        n_samples = len(y)
        n_features = len(X[0])

        for feat_idx in range(n_features):
            values = sorted(list(set(row[feat_idx] for row in X)))
            for i in range(len(values) - 1):
                thresh = (values[i] + values[i + 1]) / 2.0
                left_X, left_y, right_X, right_y = self._split(X, y, feat_idx, thresh)
                if not left_y or not right_y:
                    continue

                p_left = len(left_y) / n_samples
                p_right = len(right_y) / n_samples
                gain = current_gini - (p_left * self._gini(left_y) + p_right * self._gini(right_y))

                if gain > best_gain:
                    best_gain = gain
                    best_feat = feat_idx
                    best_thresh = thresh

        return best_feat, best_thresh, best_gain

    def _build_tree(self, X: List[List[float]], y: List[int], depth: int = 0) -> TreeNode:
        n_samples = len(y)
        n_pos = sum(y)
        n_neg = n_samples - n_pos

        # Leaf condition
        if depth >= self.max_depth or n_samples < self.min_samples_split or n_pos == 0 or n_neg == 0:
            majority = 1 if n_pos >= n_neg else 0
            return TreeNode(value=majority)

        feat_idx, thresh, gain = self._best_split(X, y)
        if feat_idx is None or gain <= 0.0:
            majority = 1 if n_pos >= n_neg else 0
            return TreeNode(value=majority)

        self.feature_importances_[FEATURE_NAMES[feat_idx]] += gain * n_samples

        left_X, left_y, right_X, right_y = self._split(X, y, feat_idx, thresh)
        left_child = self._build_tree(left_X, left_y, depth + 1)
        right_child = self._build_tree(right_X, right_y, depth + 1)

        return TreeNode(feature_idx=feat_idx, threshold=thresh, left=left_child, right=right_child)

    def fit(self, X: List[List[float]], y: List[int]):
        self.feature_importances_ = {fn: 0.0 for fn in FEATURE_NAMES}
        self.root = self._build_tree(X, y, depth=0)
        total_imp = sum(self.feature_importances_.values())
        if total_imp > 0:
            for k in self.feature_importances_:
                self.feature_importances_[k] = round(self.feature_importances_[k] / total_imp, 4)

    def _predict_one(self, node: TreeNode, row: List[float]) -> int:
        if node.value is not None:
            return node.value
        if row[node.feature_idx] <= node.threshold:
            return self._predict_one(node.left, row)
        return self._predict_one(node.right, row)

    def predict(self, X: List[List[float]]) -> List[int]:
        return [self._predict_one(self.root, row) for row in X]

    def export_ascii_tree(self, node: TreeNode = None, prefix: str = "", is_left: bool = True) -> str:
        if node is None:
            node = self.root
        lines = []
        if node.value is not None:
            label = "🚨 EVIL_TWIN" if node.value == 1 else "✅ BENIGN"
            lines.append(f"{prefix}└── [Verdict: {label}]")
        else:
            feat_name = FEATURE_NAMES[node.feature_idx]
            lines.append(f"{prefix}├── If {feat_name} <= {node.threshold:.3f}:")
            lines.append(self.export_ascii_tree(node.left, prefix + "│   ", is_left=True))
            lines.append(f"{prefix}└── Else ({feat_name} > {node.threshold:.3f}):")
            lines.append(self.export_ascii_tree(node.right, prefix + "    ", is_left=False))
        return "\n".join(lines)


def run_benchmark(dataset_path: str):
    """Executes feature extraction, category statistical analysis, and ML evaluation."""
    if not os.path.exists(dataset_path):
        print(f"Error: Dataset file not found at '{dataset_path}'")
        return

    with open(dataset_path, "r", encoding="utf-8") as f:
        samples = json.load(f)

    print(f"\n{'='*80}")
    print(f"  UNIVERSITY WI-FI SSID FEATURE BENCHMARK & ROBUSTNESS REPORT")
    print(f"  Total Test Cases: {len(samples)} samples")
    print(f"{'='*80}\n")

    # 1. Feature Extraction
    X, y, categories, detailed_rows = [], [], [], []
    for s in samples:
        obs = s["observed_ssid"]
        tgt = s.get("target_authorized_ssid") or DEFAULT_WHITELIST[0]
        label_int = 1 if s["ground_truth_label"] == "EVIL_TWIN" else 0
        cat = s["category"]

        feats = extract_features(obs, tgt)
        row = [feats[fn] for fn in FEATURE_NAMES]

        X.append(row)
        y.append(label_int)
        categories.append(cat)
        detailed_rows.append({
            "observed": obs,
            "target": tgt,
            "category": cat,
            "label": s["ground_truth_label"],
            "features": feats
        })

    # 2. Category Breakdown Analysis
    unique_cats = sorted(list(set(categories)))
    print("[1] FEATURE MEANS ACROSS ADVERSARIAL CATEGORIES:\n")
    header = f"{'Category':20s} | {'Count':5s} | {'Lev(f1)':7s} | {'JW(f3)':7s} | {'2Gram(f4)':9s} | {'Homo(f6)':8s} | {'Lure(f11)':9s} | {'Prefix(f13)':11s}"
    print(header)
    print("-" * len(header))

    for cat in unique_cats:
        cat_indices = [i for i, c in enumerate(categories) if c == cat]
        cnt = len(cat_indices)
        mean_f1 = sum(X[i][0] for i in cat_indices) / cnt
        mean_f3 = sum(X[i][2] for i in cat_indices) / cnt
        mean_f4 = sum(X[i][3] for i in cat_indices) / cnt
        mean_f6 = sum(X[i][5] for i in cat_indices) / cnt
        mean_f11 = sum(X[i][10] for i in cat_indices) / cnt
        mean_f13 = sum(X[i][12] for i in cat_indices) / cnt
        print(f"{cat:20s} | {cnt:5d} | {mean_f1:7.3f} | {mean_f3:7.3f} | {mean_f4:9.3f} | {mean_f6:8.2f} | {mean_f11:9.2f} | {mean_f13:11.3f}")

    # 3. Inter-Class Separability (Evil Twin vs Benign)
    evil_indices = [i for i, lbl in enumerate(y) if lbl == 1]
    benign_indices = [i for i, lbl in enumerate(y) if lbl == 0]

    print("\n" + "="*80)
    print("[2] FEATURE SEPARATION POWER (EVIL TWIN vs BENIGN NOISE):\n")
    sep_header = f"{'Feature':28s} | {'Evil Twin Mean':14s} | {'Benign Mean':12s} | {'Delta (|E - B|)':15s} | {'Discriminative Role'}"
    print(sep_header)
    print("-" * 95)

    roles = {
        "f1_lev_ratio": "Catches single-character typo mutations",
        "f2_dam_ratio": "Catches character transpositions",
        "f3_jaro_winkler": "Detects preserved prefix identity",
        "f4_ngram2": "Measures fine-grained token continuity",
        "f5_ngram3": "Strict structural word-stem overlap",
        "f6_homoglyphs": "Explicit typosquatting indicator",
        "f7_len_abs_diff": "Detects suffix inflation or truncation",
        "f8_len_ratio": "Length balance indicator",
        "f9_token_jaccard": "Word-level token preservation",
        "f10_separator_delta": "Delimiter evasion indicator",
        "f11_lure_flag": "Crucial: Catches +word captive lure additions",
        "f12_academic_role_collision": "Identifies campus role confusion",
        "f13_prefix_ratio": "Crucial: Detects brand preservation with added suffixes"
    }

    for idx, fn in enumerate(FEATURE_NAMES):
        mean_e = sum(X[i][idx] for i in evil_indices) / len(evil_indices)
        mean_b = sum(X[i][idx] for i in benign_indices) / len(benign_indices)
        delta = abs(mean_e - mean_b)
        print(f"{fn:28s} | {mean_e:14.3f} | {mean_b:12.3f} | {delta:15.3f} | {roles.get(fn, '')}")

    # 4. Train Pure Python Decision Tree Classifier
    print("\n" + "="*80)
    print("[3] PURE PYTHON DECISION TREE CLASSIFIER EVALUATION:\n")
    clf = PurePythonDecisionTree(max_depth=3, min_samples_split=2)
    clf.fit(X, y)
    preds = clf.predict(X)

    tp = sum(1 for p, act in zip(preds, y) if p == 1 and act == 1)
    tn = sum(1 for p, act in zip(preds, y) if p == 0 and act == 0)
    fp = sum(1 for p, act in zip(preds, y) if p == 1 and act == 0)
    fn = sum(1 for p, act in zip(preds, y) if p == 0 and act == 1)

    acc = (tp + tn) / len(y) if len(y) > 0 else 0
    prec = tp / (tp + fp) if (tp + fp) > 0 else 0
    rec = tp / (tp + fn) if (tp + fn) > 0 else 0
    f1 = 2 * prec * rec / (prec + rec) if (prec + rec) > 0 else 0

    print(f"  Accuracy           : {acc * 100:.2f}% ({tp+tn}/{len(y)})")
    print(f"  Precision          : {prec * 100:.2f}% (False Positive Rate: {fp}/{tn+fp})")
    print(f"  Recall (Detection) : {rec * 100:.2f}% (False Negative Rate: {fn}/{tp+fn})")
    print(f"  F1-Score           : {f1:.4f}\n")

    print("Top Feature Weights Learned by Decision Tree:")
    sorted_imps = sorted(clf.feature_importances_.items(), key=lambda item: item[1], reverse=True)
    for fn, imp in sorted_imps:
        if imp > 0.0:
            print(f"  - {fn:28s}: {imp * 100:5.2f}%")

    print("\n[+] Learned Decision Tree Logic (ASCII Architecture for Defense/Report):")
    print(clf.export_ascii_tree())
    print("\n" + "="*80)


if __name__ == "__main__":
    script_dir = os.path.dirname(os.path.abspath(__file__))
    dataset_file = os.path.join(script_dir, "test_cases.json")
    run_benchmark(dataset_file)
