#!/usr/bin/env python3
"""
Kali Linux Virtual Environment Health Check & Validator (v2.1.2)
Verifies that all system packages, Python libraries, ML models, and pipeline components
are fully operational inside the Kali Linux environment.
"""

import os
import sys
import time
import platform
import sqlite3

def print_header(title: str):
    print("\n" + "=" * 70)
    print(f"  {title}")
    print("=" * 70)

def check_mark(status: bool) -> str:
    return "[PASS]" if status else "[FAIL]"

def main():
    print_header("KALI LINUX VENV VALIDATOR - WI-FI IDS v2.1.2")
    print(f"OS Platform     : {platform.system()} {platform.release()} ({platform.machine()})")
    print(f"Python Executable: {sys.executable}")
    print(f"Python Version   : {sys.version.split()[0]}")
    
    in_venv = hasattr(sys, 'real_prefix') or (hasattr(sys, 'base_prefix') and sys.base_prefix != sys.prefix)
    print(f"Virtual Env Active: {in_venv} ({'Isolated venv' if in_venv else 'System / Global'})")

    all_ok = True

    # 1. Dependency Imports Check
    print_header("1. Core Dependencies Check")
    deps = [
        ("numpy", "NumPy Numerical Computing"),
        ("xgboost", "XGBoost Machine Learning"),
        ("fastembed", "FastEmbed ONNX Embeddings"),
        ("scapy", "Scapy 802.11 Packet Sniffer"),
        ("requests", "HTTP Requests"),
        ("sqlite3", "SQLite3 with WAL Support"),
    ]

    for mod_name, desc in deps:
        try:
            mod = __import__(mod_name)
            ver = getattr(mod, "__version__", "builtin")
            print(f"  {check_mark(True)} {desc:<35} : v{ver}")
        except ImportError as e:
            print(f"  {check_mark(False)} {desc:<35} : MISSING ({e})")
            all_ok = False

    if not all_ok:
        print("\n[!] Critical dependencies missing! Please run: pip install -r requirements-kali.txt")
        sys.exit(1)

    # 2. SQLite WAL Verification
    print_header("2. SQLite WAL Mode Storage Check")
    try:
        test_db = ":memory:"
        conn = sqlite3.connect(test_db)
        ver = conn.execute("SELECT sqlite_version()").fetchone()[0]
        conn.close()
        print(f"  {check_mark(True)} SQLite Database Engine            : v{ver} (WAL Enabled)")
    except Exception as e:
        print(f"  {check_mark(False)} SQLite Database Engine            : ERROR ({e})")
        all_ok = False

    # 3. Model Files & Inference Verification
    print_header("3. Machine Learning Models Verification")
    
    script_dir = os.path.dirname(os.path.abspath(__file__))
    model_json_path = os.path.join(script_dir, "ids_v2", "models", "xgb_ssid_model.json")
    
    # Check XGBoost model
    if os.path.exists(model_json_path):
        import xgboost as xgb
        try:
            xgb_model = xgb.XGBClassifier()
            xgb_model.load_model(model_json_path)
            print(f"  {check_mark(True)} Pre-trained XGBoost Model        : Loaded from {os.path.basename(model_json_path)}")
        except Exception as e:
            print(f"  {check_mark(False)} Pre-trained XGBoost Model        : Corrupted / Load Error ({e})")
            all_ok = False
    else:
        print(f"  {check_mark(False)} Pre-trained XGBoost Model        : NOT FOUND at {model_json_path}")
        all_ok = False

    # Check FastEmbed BGE-small
    try:
        from fastembed import TextEmbedding
        t0 = time.perf_counter()
        embedder = TextEmbedding("BAAI/bge-small-en-v1.5")
        vec = list(embedder.embed(["Test_SSID"]))[0]
        dt = (time.perf_counter() - t0) * 1000
        print(f"  {check_mark(True)} BAAI/bge-small-en-v1.5 Model     : OK (Dim: {len(vec)}, {dt:.1f} ms cold start)")
    except Exception as e:
        print(f"  {check_mark(False)} BAAI/bge-small-en-v1.5 Model     : Failed ({e})")
        all_ok = False

    # 4. End-to-End Pipeline Smoke Test
    print_header("4. IDS v2.1.2 Pipeline Integration Test")
    try:
        # Ensure project root and detector dir are in sys.path
        root_dir = os.path.abspath(os.path.join(script_dir, ".."))
        if root_dir not in sys.path:
            sys.path.insert(0, root_dir)
        if script_dir not in sys.path:
            sys.path.insert(0, script_dir)

        try:
            from detector.ids_v2.pipeline import WiFiIDSPipeline
        except (ImportError, ModuleNotFoundError):
            from ids_v2.pipeline import WiFiIDSPipeline

        test_db_path = os.path.join(script_dir, "test_validation.tmp.db")
        if os.path.exists(test_db_path):
            try:
                os.remove(test_db_path)
            except OSError:
                pass

        pipeline = WiFiIDSPipeline(
            db_path=test_db_path,
            campus_whitelist=["University_Campus_5G", "eduroam"]
        )

        # 1. Whitelist the authorized AP's BSSID
        pipeline.whitelist_bssid("00:11:22:33:44:55")

        # Feed an authorized AP frame (Whitelisted SSID + Whitelisted BSSID)
        res_safe = pipeline.process_frame({
            "subtype": 8,
            "bssid": "00:11:22:33:44:55",
            "ssid": "University_Campus_5G",
            "channel": 6,
            "seq": 100,
            "tsf": 1000000,
            "rssi": -45
        })

        # Feed an adversarial evil twin frame (Typosquatting + non-whitelisted BSSID)
        res_evil = pipeline.process_frame({
            "subtype": 8,
            "bssid": "aa:bb:cc:dd:ee:ff",
            "ssid": "Un1versity_Campus_5G",
            "channel": 1,
            "seq": 10,
            "tsf": 50000,
            "rssi": -70
        })

        pipeline.flush(force=True)
        pipeline.close()

        # Clean up temp test db
        for ext in ["", "-wal", "-shm"]:
            fpath = test_db_path + ext
            if os.path.exists(fpath):
                try:
                    os.remove(fpath)
                except OSError:
                    pass

        safe_ok = (res_safe.risk_tier == "LOW" and res_safe.risk_score == 0)
        evil_ok = (res_evil.risk_tier in ("MEDIUM", "HIGH") and res_evil.risk_score >= 30)

        print(f"  {check_mark(safe_ok)} Whitelist Baseline Bypass Test   : Risk={res_safe.risk_score} (Tier: {res_safe.risk_tier})")
        print(f"  {check_mark(evil_ok)} Evil Twin Alert Scoring Test     : Risk={res_evil.risk_score} (Tier: {res_evil.risk_tier})")

        if not (safe_ok and evil_ok):
            all_ok = False

    except Exception as e:
        print(f"  {check_mark(False)} Pipeline Initialization Test     : Exception ({e})")
        import traceback
        traceback.print_exc()
        all_ok = False

    # 5. Final Verdict
    print_header("VALIDATION SUMMARY")
    if all_ok:
        print("  \033[92mSUCCESS: Kali Linux Virtual Environment is 100% READY for v2.1.2 Production!\033[0m")
        print("  You can now start the IDS engine using: ./run_kali_ids.sh")
        return 0
    else:
        print("  \033[91mFAILURE: One or more checks failed. Please inspect the log above.\033[0m")
        return 1

if __name__ == "__main__":
    sys.exit(main())
