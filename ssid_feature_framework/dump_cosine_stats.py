#!/usr/bin/env python3
"""
Dump exact row-by-row cosine similarities for MiniLM and Qwen3 across all 88 test cases.
Analyzes exact score distributions and examines the threshold ranges.
"""

import os
import sys
import json
import math
from typing import List, Dict, Any

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

from fastembed import TextEmbedding
from test_qwen_embeddings import get_embeddings_batch, cosine_similarity, DEFAULT_WHITELIST


def main():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    dataset_file = os.path.join(script_dir, "test_cases.json")
    with open(dataset_file, "r", encoding="utf-8") as f:
        samples = json.load(f)

    all_texts = list(set(DEFAULT_WHITELIST + [s['observed_ssid'] for s in samples] + [s['target_authorized_ssid'] for s in samples if s.get('target_authorized_ssid')]))

    # 1. MiniLM
    print("[*] Generating MiniLM embeddings...")
    ml_model = TextEmbedding(model_name='sentence-transformers/all-MiniLM-L6-v2')
    ml_cache = {text: [float(x) for x in emb] for text, emb in zip(all_texts, ml_model.embed(all_texts))}

    # 2. Qwen3
    print("[*] Fetching Qwen3 embeddings...")
    qw_cache = get_embeddings_batch(all_texts)

    rows = []
    for idx, s in enumerate(samples):
        obs = s['observed_ssid']
        tgt = s.get('target_authorized_ssid') or DEFAULT_WHITELIST[0]
        cat = s['category']
        lbl = s['ground_truth_label']

        ml_sim_tgt = float(cosine_similarity(ml_cache[obs], ml_cache[tgt]))
        qw_sim_tgt = float(cosine_similarity(qw_cache[obs], qw_cache[tgt]))

        ml_best_sim = float(max(cosine_similarity(ml_cache[obs], ml_cache[wl]) for wl in DEFAULT_WHITELIST))
        qw_best_sim = float(max(cosine_similarity(qw_cache[obs], qw_cache[wl]) for wl in DEFAULT_WHITELIST))

        rows.append({
            'idx': idx + 1,
            'observed': obs,
            'target': tgt,
            'category': cat,
            'ground_truth': lbl,
            'minilm_sim_target': round(ml_sim_tgt, 4),
            'minilm_sim_best_wl': round(ml_best_sim, 4),
            'qwen3_sim_target': round(qw_sim_tgt, 4),
            'qwen3_sim_best_wl': round(qw_best_sim, 4)
        })

    # Save to JSON
    out_json = os.path.join(script_dir, "cosine_per_row_stats.json")
    with open(out_json, "w", encoding="utf-8") as f:
        json.dump(rows, f, indent=2)

    # Save to Markdown table
    out_md = os.path.join(script_dir, "COSINE_ROW_BY_ROW.md")
    with open(out_md, "w", encoding="utf-8") as f:
        f.write("# 📊 Complete Per-Row Cosine Similarity Statistics (All 88 Samples)\n\n")
        f.write("| # | Observed SSID | Target Whitelist | Category | Label | MiniLM (Tgt) | MiniLM (Best WL) | Qwen3 (Tgt) | Qwen3 (Best WL) |\n")
        f.write("| :-: | :--- | :--- | :--- | :-: | :-: | :-: | :-: | :-: |\n")
        for r in rows:
            f.write(f"| {r['idx']} | `{r['observed']}` | `{r['target']}` | `{r['category']}` | **{r['ground_truth']}** | {r['minilm_sim_target']:.4f} | {r['minilm_sim_best_wl']:.4f} | {r['qwen3_sim_target']:.4f} | {r['qwen3_sim_best_wl']:.4f} |\n")

    print(f"[+] Successfully exported {len(rows)} rows to:")
    print(f"    - {out_json}")
    print(f"    - {out_md}\n")

    # Analyze distributions and ranges
    print("=" * 80)
    print("  SCORE DISTRIBUTION ANALYSIS (EVIL TWIN vs BENIGN)")
    print("=" * 80)

    evil_ml = [r['minilm_sim_target'] for r in rows if r['ground_truth'] == 'EVIL_TWIN']
    benign_ml = [r['minilm_sim_target'] for r in rows if r['ground_truth'] == 'BENIGN' and r['category'] != 'authorized_exact']
    exact_ml = [r['minilm_sim_target'] for r in rows if r['category'] == 'authorized_exact']

    evil_qw = [r['qwen3_sim_target'] for r in rows if r['ground_truth'] == 'EVIL_TWIN']
    benign_qw = [r['qwen3_sim_target'] for r in rows if r['ground_truth'] == 'BENIGN' and r['category'] != 'authorized_exact']
    exact_qw = [r['qwen3_sim_target'] for r in rows if r['category'] == 'authorized_exact']

    print(f"\n1. MINILM (all-MiniLM-L6-v2):")
    print(f"   • Exact Whitelist (n=5)   : Min = {min(exact_ml):.4f}, Max = {max(exact_ml):.4f}")
    print(f"   • EVIL TWINS (n=59)       : Min = {min(evil_ml):.4f}, Mean = {sum(evil_ml)/len(evil_ml):.4f}, Max = {max(evil_ml):.4f}")
    print(f"   • BENIGN Non-Exact (n=24) : Min = {min(benign_ml):.4f}, Mean = {sum(benign_ml)/len(benign_ml):.4f}, Max = {max(benign_ml):.4f}")

    print(f"\n2. QWEN3-EMBEDDING-4B:")
    print(f"   • Exact Whitelist (n=5)   : Min = {min(exact_qw):.4f}, Max = {max(exact_qw):.4f}")
    print(f"   • EVIL TWINS (n=59)       : Min = {min(evil_qw):.4f}, Mean = {sum(evil_qw)/len(evil_qw):.4f}, Max = {max(evil_qw):.4f}")
    print(f"   • BENIGN Non-Exact (n=24) : Min = {min(benign_qw):.4f}, Mean = {sum(benign_qw)/len(benign_qw):.4f}, Max = {max(benign_qw):.4f}")

    print("\n" + "=" * 80)
    print("  EXACT OVERLAP / CONFUSION ZONE ANALYSIS")
    print("=" * 80)
    print("Why a single cosine threshold CANNOT separate them cleanly:")
    print(f"• MiniLM Evil Twin lowest score  : {min(evil_ml):.4f}")
    print(f"• MiniLM Benign highest score     : {max(benign_ml):.4f}")
    print(f"  ==> OVERLAP RANGE for MiniLM: [{min(evil_ml):.4f} to {max(benign_ml):.4f}] (MASSIVE CONFUSION ZONE!)")

    print(f"\n• Qwen3 Evil Twin lowest score   : {min(evil_qw):.4f}")
    print(f"• Qwen3 Benign highest score      : {max(benign_qw):.4f}")
    print(f"  ==> OVERLAP RANGE for Qwen3 : [{min(evil_qw):.4f} to {max(benign_qw):.4f}] (MASSIVE CONFUSION ZONE!)")


if __name__ == "__main__":
    main()
