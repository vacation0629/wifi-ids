#!/usr/bin/env python3
"""
Comprehensive Mega-Benchmark: Testing ALL Available Models Across 210+ SSID Samples
1. Single Decision Tree (CART)
2. XGBoost Classifier (50 Trees)
3. all-MiniLM-L6-v2 (80 MB, 384d)
4. BAAI/bge-small-en-v1.5 (67 MB, 384d)
5. snowflake-arctic-embed-s (130 MB, 384d)
6. BAAI/bge-base-en-v1.5 (210 MB, 768d)
7. nomic-embed-text-v1.5-Q (130 MB, 768d)
8. Qwen3-Embedding-4B (2.5 GB, 2560d GPU)
9. Nemotron-Mini-4B-Instruct (2.7 GB, SLM Generative Reasoning GPU)
"""

import os
import sys
import json
import time
import math
import requests
import numpy as np
from concurrent.futures import ThreadPoolExecutor
from typing import List, Dict, Any

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from features import extract_features
from benchmark import FEATURE_NAMES, DEFAULT_WHITELIST
import xgboost as xgb
from sklearn.tree import DecisionTreeClassifier
from fastembed import TextEmbedding

LM_STUDIO_EMBED_URL = "http://127.0.0.1:1234/v1/embeddings"
LM_STUDIO_CHAT_URL = "http://127.0.0.1:1234/v1/chat/completions"


def cosine_sim(v1: List[float], v2: List[float]) -> float:
    dot = sum(a * b for a, b in zip(v1, v2))
    n1 = math.sqrt(sum(a * a for a in v1))
    n2 = math.sqrt(sum(b * b for b in v2))
    return float(dot / (n1 * n2)) if (n1 > 0 and n2 > 0) else 0.0


def main():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    baseline_file = os.path.join(script_dir, "test_cases.json")
    extended_file = os.path.join(script_dir, "extended_200_test_cases.json")

    with open(baseline_file, "r", encoding="utf-8") as f:
        baseline_samples = json.load(f)

    with open(extended_file, "r", encoding="utf-8") as f:
        extended_samples = json.load(f)

    print("=" * 105)
    print("  MEGA BENCHMARK: TESTING ALL 9 AVAILABLE MODELS ACROSS 210 SAMPLES")
    print(f"  Training Baseline: {len(baseline_samples)} Samples | Test Cases: {len(extended_samples)} Samples")
    print("=" * 105)

    # -------------------------------------------------------------------------
    # 1. TRAIN CLASSICAL MODELS (Decision Tree & XGBoost)
    # -------------------------------------------------------------------------
    print("\n[*] Training Classical Models on 88 Baseline Samples...")
    X_train, y_train = [], []
    for s in baseline_samples:
        obs = s["observed_ssid"]
        tgt = s.get("target_authorized_ssid") or DEFAULT_WHITELIST[0]
        feats = extract_features(obs, tgt)
        X_train.append([feats[fn] for fn in FEATURE_NAMES])
        y_train.append(1 if s["ground_truth_label"] == "EVIL_TWIN" else 0)

    X_train = np.array(X_train, dtype=np.float32)
    y_train = np.array(y_train, dtype=np.int32)

    dt_model = DecisionTreeClassifier(max_depth=3, random_state=42)
    dt_model.fit(X_train, y_train)

    xgb_model = xgb.XGBClassifier(
        n_estimators=50, max_depth=3, learning_rate=0.1,
        subsample=0.8, colsample_bytree=0.8, reg_lambda=1.0, reg_alpha=0.1,
        eval_metric="logloss", random_state=42
    )
    xgb_model.fit(X_train, y_train)

    # -------------------------------------------------------------------------
    # 2. EVALUATE CLASSICAL MODELS
    # -------------------------------------------------------------------------
    print("[*] Evaluating Decision Tree and XGBoost on 210 samples...")
    dt_preds, xgb_preds, xgb_probs = [], [], []
    t_dt_start = time.perf_counter()
    for s in extended_samples:
        obs = s["observed_ssid"]
        tgt = s.get("target_authorized_ssid") or DEFAULT_WHITELIST[0]
        feats = extract_features(obs, tgt)
        x_vec = np.array([[feats[fn] for fn in FEATURE_NAMES]], dtype=np.float32)
        p_dt = int(dt_model.predict(x_vec)[0])
        p_xgb = float(xgb_model.predict_proba(x_vec)[0, 1])
        dt_preds.append("EVIL_TWIN" if p_dt == 1 else "BENIGN")
        xgb_probs.append(round(p_xgb, 4))
        xgb_preds.append("EVIL_TWIN" if p_xgb >= 0.50 else "BENIGN")

    # -------------------------------------------------------------------------
    # 3. EVALUATE 5 LIGHTWEIGHT FASTEMBED MODELS (CPU ONNX)
    # -------------------------------------------------------------------------
    all_texts = list(set(DEFAULT_WHITELIST + [s["observed_ssid"] for s in extended_samples]))
    
    fastembed_models = [
        ("MiniLM-L6-v2", "sentence-transformers/all-MiniLM-L6-v2"),
        ("BGE-Small-v1.5", "BAAI/bge-small-en-v1.5"),
        ("Arctic-Embed-S", "snowflake/snowflake-arctic-embed-s"),
        ("BGE-Base-v1.5", "BAAI/bge-base-en-v1.5"),
        ("Nomic-Embed-v1.5-Q", "nomic-ai/nomic-embed-text-v1.5-Q")
    ]

    embed_results = {}
    for label, m_id in fastembed_models:
        print(f"[*] Running FastEmbed Model: {label} ({m_id})...")
        t0 = time.perf_counter()
        m = TextEmbedding(m_id)
        # Pre-embed
        text_map = {t: [float(x) for x in emb] for t, emb in zip(all_texts, m.embed(all_texts))}
        lat_per_sample = (time.perf_counter() - t0) / len(all_texts) * 1000

        # Score per sample
        scores_tgt, scores_max, preds = [], [], []
        for s in extended_samples:
            obs = s["observed_ssid"]
            tgt = s.get("target_authorized_ssid") or DEFAULT_WHITELIST[0]
            sim_tgt = cosine_sim(text_map[obs], text_map[tgt])
            sim_max = max(cosine_sim(text_map[obs], text_map[wl]) for wl in DEFAULT_WHITELIST)
            scores_tgt.append(round(sim_tgt, 4))
            scores_max.append(round(sim_max, 4))
            # Embedding classification threshold: >= 0.60 is suspicious
            preds.append("EVIL_TWIN" if sim_max >= 0.60 else "BENIGN")

        embed_results[label] = {
            "scores_target": scores_tgt,
            "scores_max": scores_max,
            "preds": preds,
            "latency_ms": round(lat_per_sample, 2)
        }

    # -------------------------------------------------------------------------
    # 4. EVALUATE QWEN3-EMBEDDING-4B (If local server is running)
    # -------------------------------------------------------------------------
    print("[*] Checking for local Qwen3-Embedding-4B server on port 1234...")
    qwen_available = False
    qwen_scores_tgt, qwen_scores_max, qwen_preds = [], [], []
    try:
        r = requests.post(LM_STUDIO_EMBED_URL, json={"model": "text-embedding-qwen3-embedding-4b", "input": ["test"]}, timeout=3)
        if r.status_code == 200:
            qwen_available = True
            print("[+] Qwen3 server detected! Generating Qwen3 embeddings for all unique texts...")
            qwen_map = {}
            batch_size = 32
            for i in range(0, len(all_texts), batch_size):
                chunk = all_texts[i:i + batch_size]
                res = requests.post(LM_STUDIO_EMBED_URL, json={"model": "text-embedding-qwen3-embedding-4b", "input": chunk}, timeout=60).json()
                for item, txt in zip(res["data"], chunk):
                    qwen_map[txt] = item["embedding"]

            for s in extended_samples:
                obs = s["observed_ssid"]
                tgt = s.get("target_authorized_ssid") or DEFAULT_WHITELIST[0]
                sim_tgt = cosine_sim(qwen_map[obs], qwen_map[tgt])
                sim_max = max(cosine_sim(qwen_map[obs], qwen_map[wl]) for wl in DEFAULT_WHITELIST)
                qwen_scores_tgt.append(round(sim_tgt, 4))
                qwen_scores_max.append(round(sim_max, 4))
                qwen_preds.append("EVIL_TWIN" if sim_max >= 0.60 else "BENIGN")
    except Exception as e:
        print(f"[-] Qwen3 server not currently responding: {e}")

    # -------------------------------------------------------------------------
    # 5. EVALUATE NEMOTRON-MINI-4B SLM (If local server is running chat)
    # -------------------------------------------------------------------------
    print("[*] Checking for local Nemotron-Mini-4B server on port 1234...")
    nemotron_available = False
    nemotron_preds, nemotron_reasons = [], []
    try:
        r = requests.get("http://127.0.0.1:1234/v1/models", timeout=3)
        if r.status_code == 200 and "nemotron" in r.text.lower():
            nemotron_available = True
            print("[+] Nemotron SLM server detected! Querying 210 samples with 4 parallel worker threads...")

            def query_slm(sample):
                obs = sample["observed_ssid"]
                tgt = sample.get("target_authorized_ssid") or DEFAULT_WHITELIST[0]
                prompt = (
                    f"You are a campus Wi-Fi security analyzer. Authorized campus networks are: {DEFAULT_WHITELIST}.\n"
                    f"Analyze this observed SSID: '{obs}' claiming or appearing near target '{tgt}'.\n"
                    f"Is this observed SSID a deceptive rogue AP/evil twin lure, or a benign campus network?\n"
                    f"Respond in EXACTLY this format:\n"
                    f"RISK: HIGH or LOW\n"
                    f"REASON: one concise sentence explaining why."
                )
                try:
                    res = requests.post(LM_STUDIO_CHAT_URL, json={
                        "model": "nvidia/nemotron-mini-4b-instruct",
                        "messages": [{"role": "user", "content": prompt}],
                        "temperature": 0.1,
                        "max_tokens": 50
                    }, timeout=20)
                    if res.status_code == 200:
                        txt = res.json()["choices"][0]["message"]["content"].strip()
                        is_high = "RISK: HIGH" in txt.upper() or "HIGH RISK" in txt.upper()
                        pred = "EVIL_TWIN" if is_high else "BENIGN"
                        reason = txt.split("REASON:")[1].strip() if "REASON:" in txt else txt
                        return pred, reason.replace("\n", " ")[:90]
                    return "BENIGN", "API Error"
                except Exception as err:
                    return "BENIGN", str(err)

            with ThreadPoolExecutor(max_workers=4) as executor:
                slm_results = list(executor.map(query_slm, extended_samples))

            nemotron_preds = [r[0] for r in slm_results]
            nemotron_reasons = [r[1] for r in slm_results]
    except Exception as e:
        print(f"[-] Nemotron chat server not currently responding: {e}")

    # -------------------------------------------------------------------------
    # 6. COMPILE CONSOLIDATED RESULTS
    # -------------------------------------------------------------------------
    consolidated_data = []
    for i, s in enumerate(extended_samples):
        row = {
            "id": s["id"],
            "observed_ssid": s["observed_ssid"],
            "target_authorized_ssid": s.get("target_authorized_ssid") or DEFAULT_WHITELIST[0],
            "category": s["category"],
            "actual": s["ground_truth_label"],
            "dt_pred": dt_preds[i],
            "xgb_pred": xgb_preds[i],
            "xgb_prob": xgb_probs[i],
        }
        for label, _ in fastembed_models:
            row[f"{label}_max_cos"] = embed_results[label]["scores_max"][i]
            row[f"{label}_pred"] = embed_results[label]["preds"][i]
        
        if qwen_available:
            row["qwen3_max_cos"] = qwen_scores_max[i]
            row["qwen3_pred"] = qwen_preds[i]
        
        if nemotron_available:
            row["nemotron_pred"] = nemotron_preds[i]
            row["nemotron_reason"] = nemotron_reasons[i]

        consolidated_data.append(row)

    # Save to intermediate JSON
    out_file = os.path.join(script_dir, "all_models_eval_intermediate.json")
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(consolidated_data, f, indent=2)

    # Compute Category Metrics for available models
    models_to_report = ["Decision Tree", "XGBoost"] + [lbl for lbl, _ in fastembed_models]
    if qwen_available:
        models_to_report.append("Qwen3-Embedding-4B")
    if nemotron_available:
        models_to_report.append("Nemotron-Mini-4B")

    categories = ["zero_overlap_semantic_evil_twin", "classical_orthographic_evil_twin", "departmental_sister_benign", "ambient_environmental_noise"]

    print("\n" + "=" * 115)
    print("  PER-CATEGORY ACCURACY ACROSS ALL TESTED MODELS (210 SAMPLES)")
    print("=" * 115)
    header = f"{'Model':<26} | {'Zero-Overlap (70)':<18} | {'Orthographic (40)':<18} | {'Departmental (60)':<18} | {'Noise (40)':<12} | {'Overall (210)':<14}"
    print(header)
    print("-" * 115)

    def get_pred_key(m_name):
        if m_name == "Decision Tree": return "dt_pred"
        if m_name == "XGBoost": return "xgb_pred"
        if m_name == "Qwen3-Embedding-4B": return "qwen3_pred"
        if m_name == "Nemotron-Mini-4B": return "nemotron_pred"
        return f"{m_name}_pred"

    summary_stats = {}
    for m_name in models_to_report:
        pkey = get_pred_key(m_name)
        cat_accs = {}
        for cat in categories:
            cat_items = [r for r in consolidated_data if r["category"] == cat]
            corr = sum(1 for r in cat_items if r[pkey] == r["actual"])
            cat_accs[cat] = round((corr / len(cat_items)) * 100, 1)

        total_corr = sum(1 for r in consolidated_data if r[pkey] == r["actual"])
        total_acc = round((total_corr / len(consolidated_data)) * 100, 1)

        summary_stats[m_name] = {
            "cat_accs": cat_accs,
            "overall": total_acc
        }

        row_str = f"{m_name:<26} | {cat_accs['zero_overlap_semantic_evil_twin']:<16.1f}% | {cat_accs['classical_orthographic_evil_twin']:<16.1f}% | {cat_accs['departmental_sister_benign']:<16.1f}% | {cat_accs['ambient_environmental_noise']:<10.1f}% | {total_acc:<12.1f}%"
        print(row_str)

    print("=" * 115)
    return summary_stats, consolidated_data


if __name__ == "__main__":
    main()
