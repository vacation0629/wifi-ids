#!/usr/bin/env python3
"""
Zero-Overlap Semantic Pretexting Experiment:
Testing Zero-Day Semantic Pretexting against:
1. Feature Extraction (f1 Levenshtein, f5 Trigram, f11 Lure, f12 Role)
2. XGBoost Classifier (Trained on baseline 88 samples)
3. Neural Semantic Embedding (BAAI/bge-small-en-v1.5 Cosine Similarity)
4. Nemotron-Mini-4B SLM (Tier 4 Local Vulkan Reasoning)
"""

import os
import sys
import json
import time
import requests
import numpy as np
from typing import List, Dict, Any

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from features import extract_features
from benchmark import FEATURE_NAMES, DEFAULT_WHITELIST
import xgboost as xgb
from fastembed import TextEmbedding

LM_STUDIO_CHAT_URL = "http://127.0.0.1:1234/v1/chat/completions"
LLM_MODEL_NAME = "nvidia/nemotron-mini-4b-instruct"

# Test cases representing Zero-Overlap Semantic Pretexting
ZERO_OVERLAP_CASES = [
    {
        "observed_ssid": "Complimentary Visitor Broadband",
        "target_authorized_ssid": "University Guest Portal",
        "ground_truth_label": "EVIL_TWIN",
        "description": "Deceptive visitor lure; uses 'Complimentary' and 'Broadband' (zero-day synonyms not in hardcoded 19 lure words)."
    },
    {
        "observed_ssid": "Campus Registration Desk",
        "target_authorized_ssid": "University Guest Portal",
        "ground_truth_label": "EVIL_TWIN",
        "description": "Onboarding captive portal phishing trap mimicking administrative registration desk."
    },
    {
        "observed_ssid": "Institutional Faculty WLAN",
        "target_authorized_ssid": "University Staff Secure",
        "ground_truth_label": "EVIL_TWIN",
        "description": "Academic synonym clone imitating faculty network ('Institutional', 'WLAN')."
    },
    {
        "observed_ssid": "Dormitory Instructional Net",
        "target_authorized_ssid": "University Student WiFi",
        "ground_truth_label": "EVIL_TWIN",
        "description": "Residential student trap mimicking academic subnet using 'Instructional'."
    },
    {
        "observed_ssid": "HighBandwidth Express Access",
        "target_authorized_ssid": "University Campus 5G",
        "ground_truth_label": "EVIL_TWIN",
        "description": "Speed lure exploiting zero-day terms 'HighBandwidth' and 'Express'."
    },
    {
        "observed_ssid": "Campus Portal Verification",
        "target_authorized_ssid": "University Guest Portal",
        "ground_truth_label": "EVIL_TWIN",
        "description": "Credential harvesting captive portal trap using 'Verification'."
    },
    {
        "observed_ssid": "Library Study Commons",
        "target_authorized_ssid": "University Campus 5G",
        "ground_truth_label": "BENIGN",
        "description": "Authentic departmental quiet study facility operated by university library."
    },
    {
        "observed_ssid": "Alumni Association Lounge",
        "target_authorized_ssid": "University Guest Portal",
        "ground_truth_label": "BENIGN",
        "description": "Authentic visitor hospitality network for campus alumni center."
    }
]


def cosine_sim(v1: np.ndarray, v2: np.ndarray) -> float:
    dot = np.dot(v1, v2)
    norm = np.linalg.norm(v1) * np.linalg.norm(v2)
    return float(dot / norm) if norm > 0 else 0.0


def query_nemotron(obs: str, tgt: str) -> Dict[str, str]:
    prompt = (
        f"You are a campus Wi-Fi security analyzer. Authorized campus networks are: {DEFAULT_WHITELIST}.\n"
        f"Analyze this observed SSID: '{obs}' claiming or appearing near target '{tgt}'.\n"
        f"Is this observed SSID a deceptive rogue AP/evil twin lure, or a benign campus network?\n"
        f"Respond in EXACTLY this format:\n"
        f"RISK: HIGH or LOW\n"
        f"REASON: one concise sentence explaining why."
    )
    payload = {
        "model": LLM_MODEL_NAME,
        "messages": [{"role": "user", "content": prompt}],
        "temperature": 0.1,
        "max_tokens": 60
    }
    try:
        r = requests.post(LM_STUDIO_CHAT_URL, json=payload, timeout=20)
        if r.status_code == 200:
            text = r.json()["choices"][0]["message"]["content"].strip()
            text_upper = text.upper()
            is_high = "RISK: HIGH" in text_upper or "HIGH RISK" in text_upper
            pred = "EVIL_TWIN" if is_high else "BENIGN"
            # Extract reason
            reason = text
            if "REASON:" in text:
                reason = text.split("REASON:")[1].strip()
            return {"pred": pred, "reason": reason.replace("\n", " ")[:120]}
        return {"pred": "ERROR", "reason": f"HTTP {r.status_code}"}
    except Exception as e:
        return {"pred": "ERROR", "reason": str(e)}


def main():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    dataset_file = os.path.join(script_dir, "test_cases.json")
    with open(dataset_file, "r", encoding="utf-8") as f:
        baseline_samples = json.load(f)

    print("=" * 95)
    print("  ZERO-OVERLAP SEMANTIC PRETEXTING EXPERIMENTAL BENCHMARK")
    print(f"  Training Baseline: {len(baseline_samples)} Samples | Test Cases: {len(ZERO_OVERLAP_CASES)} Novel Cases")
    print("=" * 95)

    # 1. Train XGBoost on Baseline Dataset
    X_train, y_train = [], []
    for s in baseline_samples:
        obs = s["observed_ssid"]
        tgt = s.get("target_authorized_ssid") or DEFAULT_WHITELIST[0]
        feats = extract_features(obs, tgt)
        X_train.append([feats[fn] for fn in FEATURE_NAMES])
        y_train.append(1 if s["ground_truth_label"] == "EVIL_TWIN" else 0)

    X_train = np.array(X_train, dtype=np.float32)
    y_train = np.array(y_train, dtype=np.int32)

    xgb_model = xgb.XGBClassifier(
        n_estimators=50,
        max_depth=3,
        learning_rate=0.1,
        subsample=0.8,
        colsample_bytree=0.8,
        reg_lambda=1.0,
        reg_alpha=0.1,
        eval_metric="logloss",
        random_state=42
    )
    xgb_model.fit(X_train, y_train)

    # 2. Initialize Neural Embedding Model
    print("[*] Initializing BAAI/bge-small-en-v1.5 embedding model...")
    embed_model = TextEmbedding("BAAI/bge-small-en-v1.5")

    # Pre-embed target whitelists
    whitelist_embeds = {}
    for wl in DEFAULT_WHITELIST:
        emb = list(embed_model.embed([wl.replace("_", " ")]))[0]
        whitelist_embeds[wl] = emb

    # 3. Evaluate Zero-Overlap Test Cases
    results = []
    print("\n" + "=" * 95)
    print(f"{'#':<3} {'Observed SSID':<32} {'Target Whitelist':<24} {'Actual':<10} {'XGB Prob':<10} {'XGB Pred':<10} {'Embed Cos':<10} {'Nemotron':<10}")
    print("=" * 95)

    for i, item in enumerate(ZERO_OVERLAP_CASES):
        obs = item["observed_ssid"]
        tgt = item["target_authorized_ssid"]
        actual = item["ground_truth_label"]

        # A. Feature extraction
        feats = extract_features(obs, tgt)
        x_vec = np.array([[feats[fn] for fn in FEATURE_NAMES]], dtype=np.float32)

        # B. XGBoost Prediction
        xgb_prob = float(xgb_model.predict_proba(x_vec)[0, 1])
        xgb_pred = "EVIL_TWIN" if xgb_prob >= 0.50 else "BENIGN"

        # C. Embedding Cosine Similarity
        obs_emb = list(embed_model.embed([obs.replace("_", " ")]))[0]
        tgt_emb = whitelist_embeds[tgt]
        cos_sim = cosine_sim(obs_emb, tgt_emb)

        # D. Nemotron SLM Reasoning
        slm_res = query_nemotron(obs, tgt)

        results.append({
            "idx": i + 1,
            "observed": obs,
            "target": tgt,
            "actual": actual,
            "features": {
                "f1_lev": feats["f1_lev_ratio"],
                "f5_3gram": feats["f5_ngram3"],
                "f11_lure": feats["f11_lure_flag"],
                "f12_role": feats["f12_academic_role_collision"]
            },
            "xgb_prob": round(xgb_prob, 4),
            "xgb_pred": xgb_pred,
            "xgb_correct": (xgb_pred == actual),
            "embed_cosine": round(cos_sim, 4),
            "nemotron_pred": slm_res["pred"],
            "nemotron_correct": (slm_res["pred"] == actual),
            "nemotron_reason": slm_res["reason"],
            "description": item["description"]
        })

        # Match indicator
        xgb_icon = "OK" if xgb_pred == actual else "FAIL"
        slm_icon = "OK" if slm_res["pred"] == actual else "FAIL"

        print(f"{i+1:<3} {obs:<32} {tgt:<24} {actual:<10} {xgb_prob:<10.4f} {xgb_pred:<10} {cos_sim:<10.4f} {slm_res['pred']:<10}")

    # Output detailed JSON
    out_file = os.path.join(script_dir, "zero_overlap_results.json")
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)

    print("\n" + "=" * 95)
    print(f"Results successfully saved to {out_file}")
    print("=" * 95)


if __name__ == "__main__":
    main()
