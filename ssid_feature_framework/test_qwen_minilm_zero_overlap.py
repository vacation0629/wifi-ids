#!/usr/bin/env python3
"""
Evaluate Qwen3-Embedding-4B and all-MiniLM-L6-v2 on Zero-Overlap Semantic Pretexting cases.
Compares cosine similarities against the authorized whitelist baseline.
"""

import os
import sys
import json
import math
import requests
import numpy as np
from typing import List, Dict, Any

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

from fastembed import TextEmbedding

LM_STUDIO_EMBED_URL = "http://127.0.0.1:1234/v1/embeddings"
QWEN_MODEL_NAME = "text-embedding-qwen3-embedding-4b"

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

ZERO_OVERLAP_CASES = [
    {
        "idx": 1,
        "observed_ssid": "Complimentary Visitor Broadband",
        "target_authorized_ssid": "University Guest Portal",
        "ground_truth_label": "EVIL_TWIN",
        "description": "Deceptive visitor lure using 'Complimentary' and 'Broadband'."
    },
    {
        "idx": 2,
        "observed_ssid": "Campus Registration Desk",
        "target_authorized_ssid": "University Guest Portal",
        "ground_truth_label": "EVIL_TWIN",
        "description": "Onboarding captive portal phishing trap."
    },
    {
        "idx": 3,
        "observed_ssid": "Institutional Faculty WLAN",
        "target_authorized_ssid": "University Staff Secure",
        "ground_truth_label": "EVIL_TWIN",
        "description": "Academic synonym clone imitating faculty network."
    },
    {
        "idx": 4,
        "observed_ssid": "Dormitory Instructional Net",
        "target_authorized_ssid": "University Student WiFi",
        "ground_truth_label": "EVIL_TWIN",
        "description": "Residential student trap mimicking academic subnet."
    },
    {
        "idx": 5,
        "observed_ssid": "HighBandwidth Express Access",
        "target_authorized_ssid": "University Campus 5G",
        "ground_truth_label": "EVIL_TWIN",
        "description": "Speed lure exploiting zero-day terms 'HighBandwidth' and 'Express'."
    },
    {
        "idx": 6,
        "observed_ssid": "Campus Portal Verification",
        "target_authorized_ssid": "University Guest Portal",
        "ground_truth_label": "EVIL_TWIN",
        "description": "Credential harvesting captive portal trap using 'Verification'."
    },
    {
        "idx": 7,
        "observed_ssid": "Library Study Commons",
        "target_authorized_ssid": "University Campus 5G",
        "ground_truth_label": "BENIGN",
        "description": "Authentic departmental quiet study facility operated by library."
    },
    {
        "idx": 8,
        "observed_ssid": "Alumni Association Lounge",
        "target_authorized_ssid": "University Guest Portal",
        "ground_truth_label": "BENIGN",
        "description": "Authentic visitor hospitality network for campus alumni center."
    }
]


def cosine_sim(v1: List[float], v2: List[float]) -> float:
    dot = sum(a * b for a, b in zip(v1, v2))
    n1 = math.sqrt(sum(a * a for a in v1))
    n2 = math.sqrt(sum(b * b for b in v2))
    return float(dot / (n1 * n2)) if (n1 > 0 and n2 > 0) else 0.0


def get_qwen_embeddings(texts: List[str]) -> Dict[str, List[float]]:
    payload = {
        "model": QWEN_MODEL_NAME,
        "input": texts
    }
    r = requests.post(LM_STUDIO_EMBED_URL, json=payload, timeout=30)
    if r.status_code != 200:
        raise RuntimeError(f"Qwen API error: {r.status_code} {r.text}")
    res = {}
    for item, txt in zip(r.json()["data"], texts):
        res[txt] = item["embedding"]
    return res


def main():
    print("=" * 95)
    print("  EVALUATING MINI-LM AND QWEN3-EMBEDDING-4B ON ZERO-OVERLAP TEST CASES")
    print("=" * 95)

    all_texts = list(set(DEFAULT_WHITELIST + [c["observed_ssid"] for c in ZERO_OVERLAP_CASES]))

    # 1. MiniLM
    print("[*] Generating all-MiniLM-L6-v2 embeddings (384-dim)...")
    ml_model = TextEmbedding("sentence-transformers/all-MiniLM-L6-v2")
    ml_embeds = {txt: [float(x) for x in emb] for txt, emb in zip(all_texts, ml_model.embed(all_texts))}

    # 2. Qwen3-Embedding-4B
    print("[*] Fetching Qwen3-Embedding-4B embeddings (2560-dim) via local server...")
    qw_embeds = get_qwen_embeddings(all_texts)

    results = []
    print("\n" + "=" * 95)
    print(f"{'#':<3} {'Observed SSID':<32} {'Target Whitelist':<24} {'Actual':<10} {'MiniLM (Tgt)':<14} {'MiniLM (Max)':<14} {'Qwen3 (Tgt)':<14} {'Qwen3 (Max)':<14}")
    print("=" * 95)

    for c in ZERO_OVERLAP_CASES:
        obs = c["observed_ssid"]
        tgt = c["target_authorized_ssid"]
        act = c["ground_truth_label"]

        # MiniLM
        ml_tgt = cosine_sim(ml_embeds[obs], ml_embeds[tgt])
        ml_max = max(cosine_sim(ml_embeds[obs], ml_embeds[wl]) for wl in DEFAULT_WHITELIST)

        # Qwen3
        qw_tgt = cosine_sim(qw_embeds[obs], qw_embeds[tgt])
        qw_max = max(cosine_sim(qw_embeds[obs], qw_embeds[wl]) for wl in DEFAULT_WHITELIST)

        results.append({
            "idx": c["idx"],
            "observed": obs,
            "target": tgt,
            "actual": act,
            "minilm_target_cos": round(ml_tgt, 4),
            "minilm_max_whitelist_cos": round(ml_max, 4),
            "qwen3_target_cos": round(qw_tgt, 4),
            "qwen3_max_whitelist_cos": round(qw_max, 4),
            "description": c["description"]
        })

        print(f"{c['idx']:<3} {obs:<32} {tgt:<24} {act:<10} {ml_tgt:<14.4f} {ml_max:<14.4f} {qw_tgt:<14.4f} {qw_max:<14.4f}")

    # Save to JSON
    script_dir = os.path.dirname(os.path.abspath(__file__))
    out_file = os.path.join(script_dir, "qwen_minilm_zero_overlap_results.json")
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)

    print("\n" + "=" * 95)
    print(f"Results saved to {out_file}")
    print("=" * 95)


if __name__ == "__main__":
    main()
