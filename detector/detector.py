#!/usr/bin/env python3
"""
Rogue WiFi / Evil Twin SSID Similarity Detector
Designed for Raspberry Pi 4 / Pi 5 (ARM64) & Kali Linux.
Optimized for ultra-low RAM usage (< 30 MB).
Offloads embedding / Nemotron inference to Hugging Face Cloud API.
"""

import os
import sys
import re
import json
import math
import time
import requests
import sqlite3
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(line_buffering=True)

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
WHITELIST_FILE = os.getenv("WHITELIST_FILE", os.path.join(SCRIPT_DIR, "whitelist.json"))
DB_FILE = os.getenv("DB_FILE", os.path.join(SCRIPT_DIR, "wifi_records.db"))
HF_API_TOKEN = os.getenv("HF_API_TOKEN", "")
# Default embedding model on Hugging Face Serverless API (fast, lightweight embeddings)
HF_EMBEDDING_MODEL = os.getenv("HF_EMBEDDING_MODEL", "sentence-transformers/all-MiniLM-L6-v2")
# Nemotron model endpoint on Hugging Face
HF_NEMOTRON_MODEL = os.getenv("HF_NEMOTRON_MODEL", "nvidia/nemotron-mini-4b-instruct")

# Local LM Studio / OpenAI-compatible endpoint (runs locally on host with AMD GPU Vulkan acceleration)
LOCAL_LLM_URL = os.getenv("LOCAL_LLM_URL", "http://host.docker.internal:1234/v1")
LOCAL_LLM_MODEL = os.getenv("LOCAL_LLM_MODEL", "nvidia/nemotron-mini-4b-instruct")
USE_LOCAL_LLM = os.getenv("USE_LOCAL_LLM", "true").lower() in ("true", "1", "yes")

def init_db():
    """Initializes SQLite database table for detected access points."""
    conn = sqlite3.connect(DB_FILE)
    with conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS detected_aps (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                bssid TEXT UNIQUE,
                ssid TEXT,
                similarity REAL,
                status TEXT,
                matched_whitelist TEXT,
                nemotron_verdict TEXT DEFAULT '',
                count INTEGER DEFAULT 1,
                last_seen TEXT
            )
        """)
        # Safe migration if table existed before without column
        try:
            conn.execute("ALTER TABLE detected_aps ADD COLUMN nemotron_verdict TEXT DEFAULT ''")
        except Exception:
            pass
    conn.close()

def save_to_db(bssid, ssid, similarity, status, matched, nemotron_verdict=""):
    """Inserts or updates a detected AP in SQLite database."""
    try:
        conn = sqlite3.connect(DB_FILE)
        with conn:
            conn.execute("""
                INSERT INTO detected_aps (bssid, ssid, similarity, status, matched_whitelist, nemotron_verdict, count, last_seen)
                VALUES (?, ?, ?, ?, ?, ?, 1, datetime('now', 'localtime'))
                ON CONFLICT(bssid) DO UPDATE SET
                    ssid = excluded.ssid,
                    similarity = excluded.similarity,
                    status = excluded.status,
                    matched_whitelist = excluded.matched_whitelist,
                    nemotron_verdict = CASE WHEN excluded.nemotron_verdict != '' THEN excluded.nemotron_verdict ELSE nemotron_verdict END,
                    count = count + 1,
                    last_seen = datetime('now', 'localtime')
            """, (bssid, ssid, similarity, status, matched, nemotron_verdict))
        conn.close()
    except Exception as e:
        print(f"[!] DB Error: {e}")

# Cosine similarity alert threshold (e.g. 0.70 to 0.99)
SIMILARITY_THRESHOLD = float(os.getenv("SIMILARITY_THRESHOLD", "0.75"))

def get_memory_usage_mb():
    """Returns the current process RSS memory in MB."""
    try:
        with open("/proc/self/status", "r") as f:
            for line in f:
                if line.startswith("VmRSS:"):
                    return float(line.split()[1]) / 1024.0
    except Exception:
        return 0.0

def load_whitelist(filepath):
    """Loads the authorized SSID whitelist from a JSON file."""
    if not os.path.exists(filepath):
        print(f"[-] Whitelist file '{filepath}' not found. Using default fallback.")
        return [
            "Siam Wifi",
            "SiamXP Wifi",
            "SIAM WIFI",
            "SIAM XP WIFI",
            "eduroam",
            "University Campus 5G",
            "University Staff Secure",
            "University Student WiFi",
            "University Guest Portal"
        ]
    with open(filepath, "r", encoding="utf-8") as f:
        return json.load(f)

def cosine_similarity(vec_a, vec_b):
    """
    Computes cosine similarity between two 1D float vectors in pure Python.
    Avoids loading heavy libraries like numpy/scipy to save RAM.
    """
    dot = sum(a * b for a, b in zip(vec_a, vec_b))
    norm_a = math.sqrt(sum(a * a for a in vec_a))
    norm_b = math.sqrt(sum(b * b for b in vec_b))
    if norm_a == 0 or norm_b == 0:
        return 0.0
    return dot / (norm_a * norm_b)

def get_hf_embeddings(texts, model=HF_EMBEDDING_MODEL, token=HF_API_TOKEN):
    """
    Fetches text embeddings from Hugging Face Serverless Inference API.
    """
    if not token:
        return None

    api_url = f"https://api-inference.huggingface.co/pipeline/feature-extraction/{model}"
    headers = {"Authorization": f"Bearer {token}"}
    payload = {"inputs": texts, "options": {"wait_for_model": True}}

    try:
        response = requests.post(api_url, headers=headers, json=payload, timeout=15)
        if response.status_code == 200:
            return response.json()
        else:
            print(f"[!] HF API Error ({response.status_code}): {response.text[:150]}")
            return None
    except Exception as e:
        print(f"[!] Request to Hugging Face failed: {e}")
        return None

def query_nemotron_classification(ssid, whitelisted_ssid, token=HF_API_TOKEN):
    """
    Queries local LM Studio (Vulkan accelerated) or Hugging Face Nemotron model
    to assess whether an SSID is an evil twin/phishing clone.
    """
    prompt = (
        f"You are a wireless network security analyst. Analyze if the detected SSID '{ssid}' is an evil twin "
        f"attempting to impersonate the authorized SSID '{whitelisted_ssid}'. "
        f"Reply concisely with RISK LEVEL (HIGH/MEDIUM/LOW) and one sentence explanation."
    )

    # 1. Try Local LM Studio (OpenAI-compatible endpoint with AMD GPU Vulkan acceleration)
    if USE_LOCAL_LLM and LOCAL_LLM_URL:
        try:
            api_url = f"{LOCAL_LLM_URL.rstrip('/')}/chat/completions"
            payload = {
                "model": LOCAL_LLM_MODEL,
                "messages": [
                    {"role": "system", "content": "You are a wireless network security analyst specializing in Rogue Wi-Fi and Evil Twin AP detection."},
                    {"role": "user", "content": prompt}
                ],
                "temperature": 0.2,
                "max_tokens": 100
            }
            response = requests.post(api_url, json=payload, timeout=8)
            if response.status_code == 200:
                res_json = response.json()
                choices = res_json.get("choices", [])
                if choices and "message" in choices[0]:
                    content = choices[0]["message"].get("content", "").strip()
                    if content:
                        return f"[Local LM Studio] {content}"
        except Exception:
            pass  # Fall through to HF Cloud fallback

    # 2. Fallback to Hugging Face Cloud if token available
    if token:
        api_url = f"https://api-inference.huggingface.co/models/{HF_NEMOTRON_MODEL}"
        headers = {"Authorization": f"Bearer {token}"}
        payload = {
            "inputs": prompt,
            "parameters": {"max_new_tokens": 80, "temperature": 0.2}
        }
        try:
            response = requests.post(api_url, headers=headers, json=payload, timeout=15)
            if response.status_code == 200:
                res_json = response.json()
                if isinstance(res_json, list) and len(res_json) > 0:
                    return f"[HF Cloud] " + res_json[0].get("generated_text", "").replace(prompt, "").strip()
                return str(res_json)
        except Exception as e:
            return f"Nemotron query error: {e}"

    return "No LLM response (Start LM Studio local server on port 1234 or set HF_API_TOKEN)"

def _fold_homoglyphs(s):
    """Folds visual homoglyphs and leet-speak mutations to base Latin characters."""
    t = s.lower()
    t = re.sub(r"[-_\.\s]+", " ", t).strip()
    t = t.replace("1", "i").replace("0", "o").replace("5", "s")
    cyr_map = {
        '\u0430': 'a', '\u0435': 'e', '\u043e': 'o', '\u0440': 'p', '\u0441': 'c',
        '\u0443': 'y', '\u0445': 'x', '\u0456': 'i', '\u0458': 'j', '\u0455': 's',
    }
    for k, v in cyr_map.items():
        t = t.replace(k, v)
    greek_map = {'\u03BF': 'o', '\u03B1': 'a', '\u03B9': 'i'}
    for k, v in greek_map.items():
        t = t.replace(k, v)
    return t

def fallback_character_similarity(s1, s2):
    """
    N-gram & Levenshtein hybrid similarity fallback when running offline without cloud API.
    Handles typos, delimiters (- _ . space), homoglyphs (1 for i/l, 0 for O, Cyrillic, Greek),
    and brand-embedded captive portal lure additions.
    """
    if not s1 or not s2:
        return 0.0

    if s1.lower().strip() == s2.lower().strip():
        return 0.99

    s1_norm = re.sub(r"[-_\.\s]+", " ", s1.lower()).strip()
    s2_norm = re.sub(r"[-_\.\s]+", " ", s2.lower()).strip()
    if s1_norm == s2_norm:
        return 0.95

    f1 = _fold_homoglyphs(s1)
    f2 = _fold_homoglyphs(s2)
    if f1 == f2:
        return 0.95

    # Check brand containment (e.g. "Free Siam Wifi" containing "Siam Wifi")
    tokens1 = set(s1_norm.split())
    tokens2 = set(s2_norm.split())
    sub_sim = 0.80 if (tokens2 and tokens2.issubset(tokens1) and len(tokens1) - len(tokens2) <= 2) else 0.0

    # 2-gram sets (raw)
    n = 2
    ngrams1 = set([s1[i:i+n] for i in range(len(s1)-n+1)]) or {s1}
    ngrams2 = set([s2[i:i+n] for i in range(len(s2)-n+1)]) or {s2}
    intersection = len(ngrams1.intersection(ngrams2))
    union = len(ngrams1.union(ngrams2))
    jaccard = intersection / union if union > 0 else 0.0

    # Normalized & homoglyph-folded 2-grams
    ngrams1_norm = set([f1[i:i+n] for i in range(len(f1)-n+1)]) or {f1}
    ngrams2_norm = set([f2[i:i+n] for i in range(len(f2)-n+1)]) or {f2}
    inter_norm = len(ngrams1_norm.intersection(ngrams2_norm))
    union_norm = len(ngrams1_norm.union(ngrams2_norm))
    jaccard_norm = inter_norm / union_norm if union_norm > 0 else 0.0

    return max(jaccard, jaccard_norm, sub_sim)

def analyze_ssid(observed_ssid, whitelist, whitelist_embeddings=None):
    """
    Compares an observed SSID against the whitelist.
    Flags high-similarity non-exact matches as potential Rogue / Evil Twin APs.
    """
    # 1. Exact match check
    if observed_ssid in whitelist:
        return {
            "ssid": observed_ssid,
            "status": "AUTHORIZED",
            "matched_whitelist": observed_ssid,
            "similarity": 1.0,
            "details": "Exact match with authorized whitelist."
        }

    # 2. Embedding Cosine Similarity via Hugging Face Cloud
    best_match = None
    highest_sim = 0.0

    if HF_API_TOKEN and whitelist_embeddings:
        obs_emb = get_hf_embeddings([observed_ssid])
        if obs_emb and len(obs_emb) > 0:
            obs_vec = obs_emb[0]
            for idx, authorized_ssid in enumerate(whitelist):
                sim = cosine_similarity(obs_vec, whitelist_embeddings[idx])
                if sim > highest_sim:
                    highest_sim = sim
                    best_match = authorized_ssid
    else:
        # Fallback character similarity if no HF token is supplied
        for authorized_ssid in whitelist:
            sim = fallback_character_similarity(observed_ssid, authorized_ssid)
            if sim > highest_sim:
                highest_sim = sim
                best_match = authorized_ssid

    # Evaluate risk
    is_evil_twin = (highest_sim >= SIMILARITY_THRESHOLD)
    nemotron_opinion = ""
    if is_evil_twin and (USE_LOCAL_LLM or HF_API_TOKEN):
        nemotron_opinion = query_nemotron_classification(observed_ssid, best_match)

    return {
        "ssid": observed_ssid,
        "status": "SUSPICIOUS_EVIL_TWIN" if is_evil_twin else "UNRELATED_OR_BENIGN",
        "matched_whitelist": best_match,
        "similarity": round(highest_sim, 4),
        "nemotron_analysis": nemotron_opinion,
        "details": f"{'Probable Evil Twin / Typosquatting AP!' if is_evil_twin else 'Normal unrelated network.'}"
    }

def extract_ssid_from_80211(raw_bytes):
    """
    Parses IEEE 802.11 frame bytes (with optional RadioTap header)
    Extracts SSID and BSSID. Works in pure Python without needing Scapy in memory.
    """
    try:
        data = raw_bytes
        # Check for RadioTap header
        if len(data) > 4 and data[0] == 0x00 and data[1] == 0x00:
            radiotap_len = int.from_bytes(data[2:4], "little")
            data = data[radiotap_len:]

        if len(data) < 24:
            return None, None

        fc = data[0]
        frame_type = (fc >> 2) & 0x03
        frame_subtype = (fc >> 4) & 0x0F

        # Management frames: Beacon (subtype 8) or Probe Request (subtype 4)
        if frame_type != 0 or frame_subtype not in (4, 8):
            return None, None

        bssid_bytes = data[10:16]
        bssid = ":".join(f"{b:02x}" for b in bssid_bytes)

        # Body offset: 36 for Beacon (24 header + 12 fixed params), 24 for Probe Req
        offset = 36 if frame_subtype == 8 else 24

        while offset + 2 <= len(data):
            eid = data[offset]
            elen = data[offset + 1]
            if offset + 2 + elen > len(data):
                break
            if eid == 0:  # Element ID 0 is SSID
                ssid_bytes = data[offset + 2 : offset + 2 + elen]
                ssid = ssid_bytes.decode("utf-8", errors="ignore")
                return ssid, bssid
            offset += 2 + elen

        return None, bssid
    except Exception as e:
        return None, None

HTML_DASHBOARD = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Rogue WiFi / Evil Twin Live Dashboard</title>
<style>
  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0f172a; color: #f8fafc; margin: 0; padding: 24px; }
  h1 { margin-top: 0; color: #38bdf8; display: flex; align-items: center; gap: 12px; }
  .badge { padding: 4px 10px; border-radius: 9999px; font-size: 11px; font-weight: bold; }
  .badge-rogue { background: #ef4444; color: #fff; }
  .badge-safe { background: #22c55e; color: #fff; }
  .badge-unrelated { background: #475569; color: #cbd5e1; }
  table { width: 100%; border-collapse: collapse; margin-top: 16px; background: #1e293b; border-radius: 8px; overflow: hidden; box-shadow: 0 4px 6px -1px rgba(0,0,0,0.3); }
  th, td { padding: 12px 16px; text-align: left; border-bottom: 1px solid #334155; }
  th { background: #0b1329; color: #94a3b8; font-size: 12px; text-transform: uppercase; letter-spacing: 0.05em; }
  tr:hover { background: #283548; }
  .stats { display: flex; gap: 16px; margin-bottom: 20px; }
  .card { background: #1e293b; padding: 16px 20px; border-radius: 8px; flex: 1; border-left: 4px solid #38bdf8; box-shadow: 0 4px 6px -1px rgba(0,0,0,0.3); }
  .card-rogue { border-left-color: #ef4444; }
  .card-safe { border-left-color: #22c55e; }
  .card h3 { margin: 0 0 6px 0; font-size: 13px; color: #94a3b8; }
  .card p { margin: 0; font-size: 26px; font-weight: bold; }
  code { background: #0f172a; padding: 2px 6px; border-radius: 4px; font-family: monospace; color: #38bdf8; }
</style>
</head>
<body>
  <h1>📡 Rogue WiFi & Evil Twin Live Monitor</h1>
  <div class="stats">
    <div class="card card-rogue"><h3>Rogue AP Alerts</h3><p id="cnt-rogue">0</p></div>
    <div class="card card-safe"><h3>Whitelisted APs</h3><p id="cnt-safe">0</p></div>
    <div class="card"><h3>Total APs Monitored</h3><p id="cnt-total">0</p></div>
  </div>
  <table>
    <thead>
      <tr>
        <th>BSSID (MAC)</th>
        <th>SSID (Network Name)</th>
        <th>Status</th>
        <th>Similarity</th>
        <th>Target Whitelist</th>
        <th>Nemotron AI Verdict</th>
        <th>Beacons</th>
        <th>Last Seen</th>
      </tr>
    </thead>
    <tbody id="table-body"></tbody>
  </table>
  <script>
    async function refreshData() {
      try {
        const res = await fetch('/api/aps');
        const data = await res.json();
        let rogue = 0, safe = 0;
        const tbody = document.getElementById('table-body');
        tbody.innerHTML = '';
        data.forEach(ap => {
          if (ap.status === 'SUSPICIOUS_EVIL_TWIN') rogue++;
          else if (ap.status === 'AUTHORIZED') safe++;
          const tr = document.createElement('tr');
          let bClass = 'badge-unrelated';
          let bText = 'Normal';
          if (ap.status === 'SUSPICIOUS_EVIL_TWIN') { bClass = 'badge-rogue'; bText = 'ROGUE / EVIL TWIN'; }
          else if (ap.status === 'AUTHORIZED') { bClass = 'badge-safe'; bText = 'AUTHORIZED'; }
          tr.innerHTML = `
            <td><code>${ap.bssid}</code></td>
            <td><strong>${ap.ssid}</strong></td>
            <td><span class="badge ${bClass}">${bText}</span></td>
            <td>${(ap.similarity * 100).toFixed(1)}%</td>
            <td>${ap.matched_whitelist || '-'}</td>
            <td style="font-size:12px; color:#93c5fd; max-width:280px;">${ap.nemotron_verdict || (ap.status === 'SUSPICIOUS_EVIL_TWIN' ? 'Typo / Homoglyph imitation' : '-')}</td>
            <td>${ap.count}</td>
            <td>${ap.last_seen}</td>
          `;
          tbody.appendChild(tr);
        });
        document.getElementById('cnt-rogue').innerText = rogue;
        document.getElementById('cnt-safe').innerText = safe;
        document.getElementById('cnt-total').innerText = data.length;
      } catch(e) {}
    }
    refreshData();
    setInterval(refreshData, 2000);
  </script>
</body>
</html>"""

class DashboardHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass  # Suppress HTTP request logs to keep terminal output clean

    def do_GET(self):
        if self.path == "/api/aps":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            try:
                conn = sqlite3.connect(DB_FILE)
                conn.row_factory = sqlite3.Row
                rows = conn.execute("SELECT * FROM detected_aps ORDER BY last_seen DESC").fetchall()
                conn.close()
                data = [dict(r) for r in rows]
                self.wfile.write(json.dumps(data).encode("utf-8"))
            except Exception as e:
                self.wfile.write(json.dumps([]).encode("utf-8"))
        else:
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(HTML_DASHBOARD.encode("utf-8"))

def start_web_server(port=8080):
    """Starts the embedded zero-overhead HTTP dashboard in a background thread."""
    server = HTTPServer(("0.0.0.0", port), DashboardHandler)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    print(f"[+] Web Dashboard & SQLite DB live on port {port}")

def run_listener_mode(whitelist, whitelist_embeddings, listen_port=5555):
    """
    Listens for live 802.11 frames over virtual airwaves (UDP) or raw socket.
    Evaluates incoming SSIDs against whitelist in real-time.
    """
    import socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", listen_port))
    print(f"[+] 802.11 Frame Listener active on port {listen_port} (Listening for live frames...)")

    analyzed_cache = {}  # Cache SSID results to minimize cloud API quota

    while True:
        try:
            data, addr = sock.recvfrom(4096)
            ssid, bssid = extract_ssid_from_80211(data)
            if not ssid:
                continue

            # Check cache to prevent duplicate alerts for continuous beacons
            now = time.time()
            if ssid in analyzed_cache and (now - analyzed_cache[ssid]["time"]) < 30.0:
                res = analyzed_cache[ssid]["res"]
                save_to_db(bssid, ssid, res["similarity"], res["status"], res["matched_whitelist"], res.get("nemotron_analysis", ""))
                continue

            res = analyze_ssid(ssid, whitelist, whitelist_embeddings)
            analyzed_cache[ssid] = {"res": res, "time": now}

            status = res["status"]
            sim = res["similarity"]
            match = res["matched_whitelist"]
            nemotron_verdict = res.get("nemotron_analysis", "")

            # Save record to SQLite Database
            save_to_db(bssid, ssid, sim, status, match, nemotron_verdict)

            if status == "AUTHORIZED":
                print(f"[SAFE]   [{bssid}] '{ssid}' -> Whitelisted Network")
            elif status == "SUSPICIOUS_EVIL_TWIN":
                print(f"\n" + "!" * 70)
                print(f"[ALERT]  [{bssid}] POTENTIAL ROGUE / EVIL TWIN DETECTED!")
                print(f"         Broadcasted SSID : '{ssid}'")
                print(f"         Target Whitelist : '{match}'")
                print(f"         Cosine Similarity: {sim:.2%}")
                if res.get("nemotron_analysis"):
                    print(f"         Nemotron Verdict : {res['nemotron_analysis']}")
                print("!" * 70 + "\n")
            else:
                print(f"[INFO]   [{bssid}] '{ssid}' -> Normal / Unrelated (Sim: {sim:.2%})")

        except KeyboardInterrupt:
            print("\n[-] Stopping listener.")
            break
        except Exception as e:
            print(f"[!] Listener error: {e}")

def main():
    print("=" * 65)
    print("  Rogue WiFi / Evil Twin Detector (Low-RAM Pi 4/5 Edition)")
    print(f"  Target Architecture : ARM64 (aarch64)")
    print(f"  Local LLM Endpoint   : {LOCAL_LLM_URL if USE_LOCAL_LLM else 'Disabled'} (LM Studio / Vulkan)")
    print(f"  Cloud Fallback       : Hugging Face ({HF_NEMOTRON_MODEL})")
    print(f"  Threshold            : {SIMILARITY_THRESHOLD * 100:.1f}% Similarity Threshold")
    print("=" * 65)

    whitelist = load_whitelist(WHITELIST_FILE)
    print(f"[+] Loaded {len(whitelist)} whitelisted SSIDs: {whitelist}")

    whitelist_embeddings = None
    if HF_API_TOKEN:
        print("[+] Requesting initial embeddings for whitelist from Hugging Face...")
        whitelist_embeddings = get_hf_embeddings(whitelist)
        if whitelist_embeddings:
            print("[+] Successfully cached whitelist embeddings in memory.")
    else:
        print("[+] Using local hybrid N-gram & homoglyph similarity analyzer.")
        if USE_LOCAL_LLM:
            print(f"[+] Local LLM verification enabled -> {LOCAL_LLM_URL}")

    init_db()
    web_port = int(os.getenv("WEB_PORT", "8080"))
    start_web_server(port=web_port)

    mode = os.getenv("RUN_MODE", "listen" if "--listen" in sys.argv or len(sys.argv) == 1 else "test")
    if "--test" in sys.argv:
        mode = "test"

    if mode == "listen":
        port = int(os.getenv("LISTEN_PORT", "5555"))
        run_listener_mode(whitelist, whitelist_embeddings, listen_port=port)
    else:
        # Test suite: simulate scanning airwaves for various SSIDs
        test_scanned_ssids = [
            "Siam Wifi",                # Exact match
            "Siam_Wifi",                # Evil twin (delimiter mutation)
            "Siam W1f1",                # Evil twin (homoglyph: 1 for i)
            "Free Siam Wifi",           # Phishing / captive lure variant
            "CoffeeShop_Public_Net",    # Unrelated AP
            "Neighbor_Home_Router"      # Unrelated AP
        ]

        print("\n[*] Commencing SSID Security Scan...\n")

        for ssid in test_scanned_ssids:
            res = analyze_ssid(ssid, whitelist, whitelist_embeddings)
            status = res["status"]
            sim = res["similarity"]
            match = res["matched_whitelist"]

            if status == "AUTHORIZED":
                print(f"[SAFE]  '{ssid}' -> Whitelisted Network (100% Match)")
            elif status == "SUSPICIOUS_EVIL_TWIN":
                print(f"[ALERT] '{ssid}' -> POTENTIAL ROGUE / EVIL TWIN!")
                print(f"        Closest Whitelist: '{match}' (Cosine Similarity: {sim:.2%})")
                if res.get("nemotron_analysis"):
                    print(f"        Nemotron Cloud Verdict: {res['nemotron_analysis']}")
            else:
                print(f"[INFO]  '{ssid}' -> Unrelated SSID (Closest: '{match}' at {sim:.2%})")

            time.sleep(0.5)

        current_ram = get_memory_usage_mb()
        if current_ram > 0:
            print(f"\n[+] Memory footprint on device: {current_ram:.2f} MB RSS")
        print("[+] Scan complete.\n")

if __name__ == "__main__":
    main()
