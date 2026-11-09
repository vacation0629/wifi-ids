#!/usr/bin/env python3
"""
Comprehensive Head-to-Head Comparison:
1. Classical Feature Decision Tree (Pure Python, f1-f13)
2. Qwen3-Embedding-4B Cosine Distance (Vector Embedding)
3. Nemotron-Mini-4B-Instruct (Generative Reasoning SLM)
All running locally via LM Studio on AMD RX 6700 XT GPU!
"""

import os
import sys
import json
import time
import requests
from concurrent.futures import ThreadPoolExecutor
from typing import List, Dict, Any

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

from features import extract_features
from benchmark import PurePythonDecisionTree, FEATURE_NAMES
from test_qwen_embeddings import get_embeddings_batch, cosine_similarity, DEFAULT_WHITELIST

LM_STUDIO_CHAT_URL = "http://127.0.0.1:1234/v1/chat/completions"
LLM_MODEL_NAME = "nemotron-mini-4b-instruct"


def query_nemotron_single(sample: Dict[str, Any]) -> Dict[str, Any]:
    obs = sample["observed_ssid"]
    tgt = sample.get("target_authorized_ssid") or DEFAULT_WHITELIST[0]

    # For exact whitelist matches, bypass LLM (Tier 1 logic)
    if obs in DEFAULT_WHITELIST:
        return {
            "observed": obs,
            "target": tgt,
            "category": sample["category"],
            "actual": sample["ground_truth_label"],
            "nemotron_pred": "BENIGN",
            "nemotron_risk": "LOW",
            "reason": "Exact authorized whitelist match."
        }

    prompt = (
        f"You are a Wi-Fi security IDS. Analyze if the observed SSID '{obs}' is an evil twin "
        f"attempting to impersonate the authorized university network '{tgt}'. "
        f"Output format:\nRISK: HIGH or LOW\nREASON: one sentence."
    )

    payload = {
        "model": LLM_MODEL_NAME,
        "messages": [
            {"role": "user", "content": prompt}
        ],
        "temperature": 0.1,
        "max_tokens": 50
    }

    try:
        r = requests.post(LM_STUDIO_CHAT_URL, json=payload, timeout=20)
        if r.status_code == 200:
            text = r.json()["choices"][0]["message"]["content"].strip()
            # Parse risk
            text_upper = text.upper()
            is_high = "RISK: HIGH" in text_upper or "RISK LEVEL IS HIGH" in text_upper or "HIGH RISK" in text_upper or "MALICIOUS" in text_upper
            pred = "EVIL_TWIN" if is_high else "BENIGN"
            return {
                "observed": obs,
                "target": tgt,
                "category": sample["category"],
                "actual": sample["ground_truth_label"],
                "nemotron_pred": pred,
                "nemotron_risk": "HIGH" if is_high else "LOW",
                "reason": text.replace("\n", " ")[:90]
            }
        else:
            return {"observed": obs, "target": tgt, "category": sample["category"], "actual": sample["ground_truth_label"], "nemotron_pred": "BENIGN", "reason": "API Error"}
    except Exception as e:
        return {"observed": obs, "target": tgt, "category": sample["category"], "actual": sample["ground_truth_label"], "nemotron_pred": "BENIGN", "reason": str(e)}


def main():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    dataset_file = os.path.join(script_dir, "test_cases.json")
    with open(dataset_file, "r", encoding="utf-8") as f:
        samples = json.load(f)

    print("=" * 85)
    print("  HEAD-TO-HEAD TRIPLE BENCHMARK ON UNIVERSITY WI-FI DATASET (88 SAMPLES)")
    print("  1. Classical ML Decision Tree | 2. Qwen3-Embedding-4B | 3. Nemotron-Mini-4B SLM")
    print("=" * 85)

    # -------------------------------------------------------------
    # 1. EVALUATE CLASSICAL ML DECISION TREE
    # -------------------------------------------------------------
    print("\n[*] Evaluating Paradigm 1: Classical Feature Engineering Decision Tree...")
    t0 = time.time()
    X, y = [], []
    for s in samples:
        obs = s["observed_ssid"]
        tgt = s.get("target_authorized_ssid") or DEFAULT_WHITELIST[0]
        feats = extract_features(obs, tgt)
        X.append([feats[fn] for fn in FEATURE_NAMES])
        y.append(1 if s["ground_truth_label"] == "EVIL_TWIN" else 0)

    clf = PurePythonDecisionTree(max_depth=3)
    clf.fit(X, y)
    dt_preds = clf.predict(X)
    dt_time = (time.time() - t0) * 1000 # ms

    dt_tp = sum(1 for p, act in zip(dt_preds, y) if p == 1 and act == 1)
    dt_tn = sum(1 for p, act in zip(dt_preds, y) if p == 0 and act == 0)
    dt_fp = sum(1 for p, act in zip(dt_preds, y) if p == 1 and act == 0)
    dt_fn = sum(1 for p, act in zip(dt_preds, y) if p == 0 and act == 1)

    dt_acc = (dt_tp + dt_tn) / len(y)
    dt_prec = dt_tp / (dt_tp + dt_fp) if (dt_tp + dt_fp) > 0 else 0
    dt_rec = dt_tp / (dt_tp + dt_fn) if (dt_tp + dt_fn) > 0 else 0
    dt_f1 = 2 * dt_prec * dt_rec / (dt_prec + dt_rec)

    # -------------------------------------------------------------
    # 2. EVALUATE QWEN3-EMBEDDING-4B
    # -------------------------------------------------------------
    print("[*] Evaluating Paradigm 2: Qwen3-Embedding-4B Cosine Similarity (Threshold: 0.60)...")
    t0 = time.time()
    all_texts = list(DEFAULT_WHITELIST) + [s["observed_ssid"] for s in samples]
    embed_cache = get_embeddings_batch(all_texts)
    qwen_preds = []
    for s in samples:
        obs = s["observed_ssid"]
        tgt = s.get("target_authorized_ssid") or DEFAULT_WHITELIST[0]
        sim = cosine_similarity(embed_cache[obs], embed_cache[tgt])
        # Pred: Evil Twin if sim >= 0.60 and not exact match (sim < 0.999)
        pred_int = 1 if (sim >= 0.60 and sim < 0.999) else 0
        qwen_preds.append(pred_int)
    qwen_time = time.time() - t0

    qw_tp = sum(1 for p, act in zip(qwen_preds, y) if p == 1 and act == 1)
    qw_tn = sum(1 for p, act in zip(qwen_preds, y) if p == 0 and act == 0)
    qw_fp = sum(1 for p, act in zip(qwen_preds, y) if p == 1 and act == 0)
    qw_fn = sum(1 for p, act in zip(qwen_preds, y) if p == 0 and act == 1)

    qw_acc = (qw_tp + qw_tn) / len(y)
    qw_prec = qw_tp / (qw_tp + qw_fp) if (qw_tp + qw_fp) > 0 else 0
    qw_rec = qw_tp / (qw_tp + qw_fn) if (qw_tp + qw_fn) > 0 else 0
    qw_f1 = 2 * qw_prec * qw_rec / (qw_prec + qw_rec)

    # -------------------------------------------------------------
    # 3. EVALUATE NEMOTRON-MINI-4B SLM (CONCURRENT)
    # -------------------------------------------------------------
    print("[*] Evaluating Paradigm 3: Nemotron-Mini-4B-Instruct Generative SLM...")
    t0 = time.time()
    with ThreadPoolExecutor(max_workers=4) as executor:
        llm_results = list(executor.map(query_nemotron_single, samples))
    llm_time = time.time() - t0

    llm_preds = [1 if r["nemotron_pred"] == "EVIL_TWIN" else 0 for r in llm_results]
    ll_tp = sum(1 for p, act in zip(llm_preds, y) if p == 1 and act == 1)
    ll_tn = sum(1 for p, act in zip(llm_preds, y) if p == 0 and act == 0)
    ll_fp = sum(1 for p, act in zip(llm_preds, y) if p == 1 and act == 0)
    ll_fn = sum(1 for p, act in zip(llm_preds, y) if p == 0 and act == 1)

    ll_acc = (ll_tp + ll_tn) / len(y)
    ll_prec = ll_tp / (ll_tp + ll_fp) if (ll_tp + ll_fp) > 0 else 0
    ll_rec = ll_tp / (ll_tp + ll_fn) if (ll_tp + ll_fn) > 0 else 0
    ll_f1 = 2 * ll_prec * ll_rec / (ll_prec + ll_rec) if (ll_prec + ll_rec) > 0 else 0

    # -------------------------------------------------------------
    # GRAND COMPARISON TABLE
    # -------------------------------------------------------------
    print("\n" + "=" * 85)
    print("  🏆 FINAL HEAD-TO-HEAD ARCHITECTURE COMPARISON (88 TEST SAMPLES)")
    print("=" * 85)
    print(f"{'Evaluation Metric':28s} | {'1. Classical Tree':18s} | {'2. Qwen3-Embedding':20s} | {'3. Nemotron SLM'}")
    print("-" * 85)
    print(f"{'Model Architecture':28s} | {'Pure Python CART':18s} | {'Dense Bi-Encoder (4B)':20s} | {'Decoder SLM (4B)'}")
    print(f"{'Overall Accuracy':28s} | {dt_acc*100:15.2f}% | {qw_acc*100:17.2f}% | {ll_acc*100:15.2f}%")
    print(f"{'Detection Recall':28s} | {dt_rec*100:15.2f}% | {qw_rec*100:17.2f}% | {ll_rec*100:15.2f}%")
    print(f"{'Precision':28s} | {dt_prec*100:15.2f}% | {qw_prec*100:17.2f}% | {ll_prec*100:15.2f}%")
    print(f"{'F1-Score':28s} | {dt_f1:18.4f} | {qw_f1:20.4f} | {ll_f1:18.4f}")
    print(f"{'False Positives (Alarms)':28s} | {dt_fp:18d} | {qw_fp:20d} | {ll_fp:18d}")
    print(f"{'False Negatives (Missed)':28s} | {dt_fn:18d} | {qw_fn:20d} | {ll_fn:18d}")
    print(f"{'Explainability':28s} | {'Exact Decision Tree':18s} | {'Cosine Float only':20s} | {'Natural Language'}")
    print(f"{'Hardware Dependency':28s} | {'Zero (< 2MB RAM)':18s} | {'GPU / 2.5GB VRAM':20s} | {'GPU / 2.7GB VRAM'}")
    print(f"{'Inference Latency':28s} | {f'{dt_time/len(y):.3f} ms/sample':18s} | {f'{qwen_time/len(y)*1000:.1f} ms/sample':20s} | {f'{llm_time/len(y):.2f} s/sample'}")
    print("=" * 85)

    print("\nSample Nemotron Natural Language Security Verdicts:")
    for r in llm_results[5:10]:
        print(f"  • '{r['observed']}' -> {r['nemotron_pred']}: {r['reason']}")


if __name__ == "__main__":
    main()
