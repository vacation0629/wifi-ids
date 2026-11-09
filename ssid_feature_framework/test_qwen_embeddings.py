#!/usr/bin/env python3
"""
Benchmark Qwen3-Embedding-4B (Running in LM Studio) on University Wi-Fi Dataset
Compares pure embedding cosine similarity vs. morphological feature engineering.
"""

import os
import sys
import json
import math
import time
import requests
from typing import List, Dict, Any, Tuple

# Ensure UTF-8 output on Windows
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

LM_STUDIO_EMBED_URL = "http://127.0.0.1:1234/v1/embeddings"
MODEL_NAME = "text-embedding-qwen3-embedding-4b"

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


def cosine_similarity(v1: List[float], v2: List[float]) -> float:
    """Computes cosine similarity between two float vectors."""
    dot = sum(a * b for a, b in zip(v1, v2))
    norm1 = math.sqrt(sum(a * a for a in v1))
    norm2 = math.sqrt(sum(b * b for b in v2))
    if norm1 == 0 or norm2 == 0:
        return 0.0
    return dot / (norm1 * norm2)


def get_embeddings_batch(texts: List[str], batch_size: int = 16) -> Dict[str, List[float]]:
    """Fetches embeddings from LM Studio in batches and caches by text."""
    unique_texts = list(set(texts))
    embedding_cache = {}

    print(f"[*] Fetching embeddings from LM Studio ({MODEL_NAME})...")
    print(f"    Total unique texts to embed: {len(unique_texts)}")

    for i in range(0, len(unique_texts), batch_size):
        chunk = unique_texts[i:i + batch_size]
        payload = {
            "model": MODEL_NAME,
            "input": chunk
        }
        try:
            resp = requests.post(LM_STUDIO_EMBED_URL, json=payload, timeout=30)
            if resp.status_code != 200:
                print(f"[!] Error {resp.status_code}: {resp.text}")
                continue
            data = resp.json()["data"]
            for idx, item in enumerate(data):
                embedding_cache[chunk[idx]] = item["embedding"]
            print(f"    Processed {min(i + batch_size, len(unique_texts))}/{len(unique_texts)} texts...")
        except Exception as e:
            print(f"[!] Request failed: {e}")

    return embedding_cache


def run_qwen_benchmark(dataset_path: str):
    if not os.path.exists(dataset_path):
        print(f"Error: {dataset_path} not found")
        return

    with open(dataset_path, "r", encoding="utf-8") as f:
        samples = json.load(f)

    # Collect all needed texts
    all_texts = list(DEFAULT_WHITELIST)
    for s in samples:
        all_texts.append(s["observed_ssid"])
        if s.get("target_authorized_ssid"):
            all_texts.append(s["target_authorized_ssid"])

    t0 = time.time()
    cache = get_embeddings_batch(all_texts)
    duration = time.time() - t0
    print(f"[+] All embeddings generated in {duration:.2f} seconds!\n")

    # Evaluate each sample
    results = []
    category_scores = {}

    for s in samples:
        obs = s["observed_ssid"]
        tgt = s.get("target_authorized_ssid") or DEFAULT_WHITELIST[0]
        cat = s["category"]
        ground_truth = s["ground_truth_label"]

        vec_obs = cache.get(obs)
        vec_tgt = cache.get(tgt)

        if not vec_obs or not vec_tgt:
            continue

        sim = round(cosine_similarity(vec_obs, vec_tgt), 4)

        # Also find best match across the entire whitelist
        best_wl_sim = -1.0
        best_wl_name = ""
        for wl in DEFAULT_WHITELIST:
            vec_wl = cache.get(wl)
            if vec_wl:
                curr_sim = cosine_similarity(vec_obs, vec_wl)
                if curr_sim > best_wl_sim:
                    best_wl_sim = curr_sim
                    best_wl_name = wl

        results.append({
            "observed": obs,
            "target": tgt,
            "category": cat,
            "label": ground_truth,
            "sim_to_target": sim,
            "sim_to_best_wl": round(best_wl_sim, 4),
            "best_wl_name": best_wl_name
        })

        if cat not in category_scores:
            category_scores[cat] = []
        category_scores[cat].append(sim)

    # 1. Print Category Breakdown
    print("=" * 80)
    print("  QWEN3-EMBEDDING-4B: MEAN COSINE SIMILARITY ACROSS CATEGORIES")
    print("=" * 80)
    print(f"{'Category':20s} | {'Count':5s} | {'Mean Sim':9s} | {'Min Sim':8s} | {'Max Sim':8s} | {'Std Dev'}")
    print("-" * 70)

    for cat in sorted(category_scores.keys()):
        scores = category_scores[cat]
        cnt = len(scores)
        mean_s = sum(scores) / cnt
        variance = sum((x - mean_s) ** 2 for x in scores) / cnt
        std_s = math.sqrt(variance)
        print(f"{cat:20s} | {cnt:5d} | {mean_s:9.4f} | {min(scores):8.4f} | {max(scores):8.4f} | {std_s:7.4f}")

    # 2. Threshold Sweep Analysis
    print("\n" + "=" * 80)
    print("  STANDALONE COSINE THRESHOLD ANALYSIS (CAN EMBEDDING ALONE DETECT EVIL TWINS?)")
    print("=" * 80)
    print(f"{'Threshold':10s} | {'Accuracy':10s} | {'Precision':10s} | {'Recall':10s} | {'F1-Score':10s} | {'False Positives':16s} | {'False Negatives'}")
    print("-" * 88)

    best_thresh = 0.70
    best_f1 = 0.0

    # Test thresholds from 0.50 to 0.95
    # Note: Exact matches (sim=1.0) are Whitelist (Benign).
    # Evil Twin detection logic for embedding:
    # IF sim >= threshold AND sim < 0.9999 -> EVIL_TWIN, ELSE BENIGN
    for th in [0.55, 0.60, 0.65, 0.70, 0.75, 0.80, 0.85, 0.90]:
        tp, tn, fp, fn = 0, 0, 0, 0
        for r in results:
            actual = r["label"]
            sim = r["sim_to_target"]
            # Predicted Evil Twin if similar to target but not exact
            pred = "EVIL_TWIN" if (sim >= th and sim < 0.999) else "BENIGN"

            if pred == "EVIL_TWIN" and actual == "EVIL_TWIN":
                tp += 1
            elif pred == "BENIGN" and actual == "BENIGN":
                tn += 1
            elif pred == "EVIL_TWIN" and actual == "BENIGN":
                fp += 1
            elif pred == "BENIGN" and actual == "EVIL_TWIN":
                fn += 1

        total = len(results)
        acc = (tp + tn) / total
        prec = tp / (tp + fp) if (tp + fp) > 0 else 0
        rec = tp / (tp + fn) if (tp + fn) > 0 else 0
        f1 = 2 * prec * rec / (prec + rec) if (prec + rec) > 0 else 0

        if f1 > best_f1:
            best_f1 = f1
            best_thresh = th

        print(f"{th:10.2f} | {acc * 100:9.2f}% | {prec * 100:9.2f}% | {rec * 100:9.2f}% | {f1:10.4f} | {fp:16d} | {fn:14d}")

    print(f"\n[+] Optimal standalone threshold: {best_thresh:.2f} (F1: {best_f1:.4f})")

    # 3. Drill down into specific strengths and failure modes of Qwen3
    print("\n" + "=" * 80)
    print("  DEEP DIVE: NOTABLE SUCCESSES & BLIND SPOTS OF QWEN3-EMBEDDING-4B")
    print("=" * 80)

    print("\n[A] Homoglyph & Typo Behavior:")
    for r in results:
        if r["category"] == "homoglyph_typo" and r["observed"] in ["Un1versity_Campus_5G", "University_Carnpus_5G", "edur0am", "Unviersity_Campus_5G"]:
            print(f"  • '{r['observed']:26s}' vs '{r['target']:22s}' -> Cosine Sim: {r['sim_to_target']:.4f}")

    print("\n[B] +Word Lure Attacks (e.g. _Free, _Login):")
    for r in results:
        if r["category"] == "word_addition" and r["observed"] in ["University_Campus_5G_Free", "University_Staff_Secure_Login", "eduroam_Fast_5G"]:
            print(f"  • '{r['observed']:30s}' vs '{r['target']:22s}' -> Cosine Sim: {r['sim_to_target']:.4f}")

    print("\n[C] Departmental & Semantic Variations (Benign but similar):")
    for r in results:
        if r["category"] == "semantic_relevant" and r["observed"] in ["College_Campus_5G", "Faculty_Staff_Secure", "University_Academic_WiFi"]:
            print(f"  • '{r['observed']:26s}' vs '{r['target']:22s}' -> Cosine Sim: {r['sim_to_target']:.4f} (Actual: {r['label']})")

    print("\n[D] Irrelevant Noise (Unrelated campus Wi-Fi):")
    for r in results:
        if r["category"] == "irrelevant_noise" and r["observed"] in ["Cafe_Amazon_WiFi", "Starbucks_Guest", "AIS_SUPER_WiFi", "Dorm_Room_302_5G"]:
            print(f"  • '{r['observed']:26s}' vs Best Whitelist '{r['best_wl_name']:22s}' -> Cosine Sim: {r['sim_to_best_wl']:.4f}")

    print("\n" + "=" * 80)


if __name__ == "__main__":
    script_dir = os.path.dirname(os.path.abspath(__file__))
    dataset_file = os.path.join(script_dir, "test_cases.json")
    run_qwen_benchmark(dataset_file)
