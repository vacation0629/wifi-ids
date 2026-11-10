#!/usr/bin/env python3
"""
Edge Wi-Fi Evil Twin Detection Framework (v2.1.2)
Production Service Daemon for Kali Linux
Supports:
1. UDP Socket Listener (Port 5555) for Virtual / Docker Simulation Labs
2. Live Raw 802.11 Monitor Mode Sniffer (Scapy) on physical interfaces (wlan0mon)
3. Zero-Overhead Live Alert Web Dashboard (Port 8080)
4. Graceful WAL commit on shutdown
"""

import os
import sys
import time
import json
import sqlite3
import signal
import socket
import argparse
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
from typing import Optional, List

# Ensure module path resolution
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(SCRIPT_DIR, ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)
if SCRIPT_DIR not in sys.path:
    sys.path.insert(0, SCRIPT_DIR)

try:
    from detector.ids_v2.pipeline import WiFiIDSPipeline
    from detector.ids_v2.config import DEFAULT_CAMPUS_WHITELIST, DEFAULT_DB_PATH
    from detector.kismet_connector import KismetBridge
    from detector.dashboard_server import HTML_STANDALONE_DASHBOARD
except (ImportError, ModuleNotFoundError):
    from ids_v2.pipeline import WiFiIDSPipeline
    from ids_v2.config import DEFAULT_CAMPUS_WHITELIST, DEFAULT_DB_PATH
    from kismet_connector import KismetBridge
    from dashboard_server import HTML_STANDALONE_DASHBOARD

# Global daemon reference for signal handling
DAEMON_INSTANCE = None


class IDSWebHandler(BaseHTTPRequestHandler):
    """Zero-overhead HTTP REST & Live UI Dashboard (Pulls 100% from SQLite Database)."""

    def log_message(self, format, *args):
        pass  # Suppress HTTP request logs for clean terminal output

    def get_db(self) -> sqlite3.Connection:
        db_path = DAEMON_INSTANCE.db_path if DAEMON_INSTANCE else DEFAULT_DB_PATH
        if DAEMON_INSTANCE and DAEMON_INSTANCE.pipeline:
            try:
                DAEMON_INSTANCE.pipeline.flush(force=False)
            except Exception:
                pass
        conn = sqlite3.connect(db_path, timeout=5.0)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL;")
        return conn

    def do_GET(self):
        pipeline = DAEMON_INSTANCE.pipeline if DAEMON_INSTANCE else None

        if self.path == "/api/aps":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()

            data = []
            try:
                conn = self.get_db()
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT b.bssid, b.current_ssid, b.is_whitelisted, b.risk_tier,
                           b.current_risk_score, b.is_mutated, b.encryption_type,
                           b.first_seen_ts, b.last_seen_ts, b.primary_channel, b.last_rssi,
                           s.matched_whitelist_ssid, s.xgb_prob, s.bge_cos_clean
                    FROM bssid_devices b
                    LEFT JOIN ssid_catalog s ON b.current_ssid = s.ssid_text
                    ORDER BY b.current_risk_score DESC, b.last_seen_ts DESC
                    LIMIT 200
                """)
                for r in cursor.fetchall():
                    data.append({
                        "bssid": r["bssid"],
                        "ssid": r["current_ssid"] or "[Hidden SSID]",
                        "is_whitelisted": bool(r["is_whitelisted"]),
                        "risk_tier": r["risk_tier"] or "LOW",
                        "risk_score": r["current_risk_score"] or 0,
                        "is_mutated": bool(r["is_mutated"]),
                        "encryption": r["encryption_type"] or "OPEN",
                        "channel": r["primary_channel"] or 1,
                        "rssi": r["last_rssi"] or -65,
                        "first_seen": r["first_seen_ts"],
                        "last_seen": r["last_seen_ts"],
                        "target_whitelist": r["matched_whitelist_ssid"] or "-",
                        "xgb_prob": round(r["xgb_prob"] or 0.0, 4),
                        "bge_cos": round(r["bge_cos_clean"] or 0.0, 4),
                    })
                conn.close()
            except Exception as e:
                data = [{"error": str(e)}]

            self.wfile.write(json.dumps(data).encode("utf-8"))

        elif self.path == "/api/status":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()

            db_path = DAEMON_INSTANCE.db_path if DAEMON_INSTANCE else DEFAULT_DB_PATH
            status = {
                "running": True,
                "version": "2.1.2",
                "mode": DAEMON_INSTANCE.mode if DAEMON_INSTANCE else "unknown",
                "interface": DAEMON_INSTANCE.interface if DAEMON_INSTANCE else "none",
                "db_path": db_path,
                "db_connected": False,
                "high_threats": 0,
                "medium_threats": 0,
                "authorized_aps": 0,
                "total_aps": 0,
                "cataloged_ssids": 0,
                "behavior_logs_count": 0,
            }

            try:
                conn = self.get_db()
                cur = conn.cursor()
                cur.execute("SELECT count(*) FROM bssid_devices WHERE risk_tier = 'HIGH'")
                status["high_threats"] = cur.fetchone()[0]
                cur.execute("SELECT count(*) FROM bssid_devices WHERE risk_tier = 'MEDIUM'")
                status["medium_threats"] = cur.fetchone()[0]
                cur.execute("SELECT count(*) FROM bssid_devices WHERE is_whitelisted = 1")
                status["authorized_aps"] = cur.fetchone()[0]
                cur.execute("SELECT count(*) FROM bssid_devices")
                status["total_aps"] = cur.fetchone()[0]
                cur.execute("SELECT count(*) FROM ssid_catalog")
                status["cataloged_ssids"] = cur.fetchone()[0]
                try:
                    cur.execute("SELECT count(*) FROM beacon_behavior_logs")
                    status["behavior_logs_count"] = cur.fetchone()[0]
                except Exception:
                    pass
                conn.close()
                status["db_connected"] = True
            except Exception as e:
                status["error"] = str(e)

            self.wfile.write(json.dumps(status).encode("utf-8"))

        elif self.path == "/api/logs":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()

            logs = []
            try:
                conn = self.get_db()
                cur = conn.cursor()
                cur.execute("""
                    SELECT id, bssid, timestamp, channel_anomaly_type, deauth_count_1m,
                           jitter_ms, ssid_mutated, raw_ie_fingerprint
                    FROM beacon_behavior_logs
                    ORDER BY id DESC
                    LIMIT 50
                """)
                for r in cur.fetchall():
                    logs.append({
                        "id": r["id"],
                        "bssid": r["bssid"],
                        "timestamp": r["timestamp"],
                        "anomaly_type": r["channel_anomaly_type"],
                        "deauth_count": r["deauth_count_1m"],
                        "jitter_ms": round(r["jitter_ms"] or 0.0, 2),
                        "mutated": bool(r["ssid_mutated"]),
                        "fingerprint": r["raw_ie_fingerprint"][:16] if r["raw_ie_fingerprint"] else "-"
                    })
                conn.close()
            except Exception:
                logs = []

            self.wfile.write(json.dumps(logs).encode("utf-8"))

        else:
            # HTML Dashboard UI
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(HTML_STANDALONE_DASHBOARD.encode("utf-8"))

    def do_POST(self):
        pipeline = DAEMON_INSTANCE.pipeline if DAEMON_INSTANCE else None
        if not pipeline:
            self.send_response(500)
            self.end_headers()
            return

        if self.path == "/api/whitelist/add":
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length).decode("utf-8")
            try:
                payload = json.loads(body)
                bssid = payload.get("bssid", "").strip()
                if bssid:
                    pipeline.whitelist_bssid(bssid)
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    self.wfile.write(json.dumps({"status": "ok", "bssid": bssid, "action": "added"}).encode("utf-8"))
                    return
            except Exception as e:
                pass
            self.send_response(400)
            self.end_headers()

        elif self.path == "/api/whitelist/remove":
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length).decode("utf-8")
            try:
                payload = json.loads(body)
                bssid = payload.get("bssid", "").strip()
                if bssid:
                    pipeline.unwhitelist_bssid(bssid)
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    self.wfile.write(json.dumps({"status": "ok", "bssid": bssid, "action": "removed"}).encode("utf-8"))
                    return
            except Exception as e:
                pass
            self.send_response(400)
            self.end_headers()


HTML_DASHBOARD = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Wi-Fi IDS v2.1.2 - Kali Live SOC Dashboard</title>
<style>
  :root {
    --bg: #090d16;
    --card: #131b2e;
    --border: #23314d;
    --text: #e2e8f0;
    --muted: #8e9bb0;
    --cyan: #06b6d4;
    --green: #10b981;
    --amber: #f59e0b;
    --rose: #f43f5e;
  }
  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: var(--bg); color: var(--text); margin: 0; padding: 24px; }
  h1 { margin: 0 0 4px 0; color: #38bdf8; font-size: 24px; display: flex; align-items: center; gap: 12px; }
  .subtitle { color: var(--muted); font-size: 13px; margin-bottom: 24px; }
  .metrics { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 16px; margin-bottom: 24px; }
  .card { background: var(--card); border: 1px solid var(--border); border-radius: 10px; padding: 18px 20px; box-shadow: 0 4px 12px rgba(0,0,0,0.3); }
  .card h3 { margin: 0 0 6px 0; font-size: 12px; color: var(--muted); text-transform: uppercase; letter-spacing: 0.05em; }
  .card .val { font-size: 28px; font-weight: bold; margin: 0; }
  .card.rose { border-left: 4px solid var(--rose); }
  .card.amber { border-left: 4px solid var(--amber); }
  .card.green { border-left: 4px solid var(--green); }
  .card.cyan { border-left: 4px solid var(--cyan); }
  table { width: 100%; border-collapse: collapse; background: var(--card); border-radius: 10px; overflow: hidden; border: 1px solid var(--border); font-size: 13px; }
  th, td { padding: 12px 16px; text-align: left; border-bottom: 1px solid var(--border); }
  th { background: #0c1322; color: var(--muted); font-weight: 600; text-transform: uppercase; font-size: 11px; letter-spacing: 0.05em; }
  tr:hover { background: #1a253d; }
  .badge { padding: 4px 8px; border-radius: 6px; font-size: 11px; font-weight: bold; text-transform: uppercase; display: inline-block; }
  .badge-HIGH { background: rgba(244, 63, 94, 0.2); color: #fb7185; border: 1px solid #f43f5e; }
  .badge-MEDIUM { background: rgba(245, 158, 11, 0.2); color: #fbbf24; border: 1px solid #f59e0b; }
  .badge-LOW { background: rgba(16, 185, 129, 0.2); color: #34d399; border: 1px solid #10b981; }
  .score-bar { width: 70px; height: 8px; background: #23314d; border-radius: 4px; overflow: hidden; display: inline-block; vertical-align: middle; margin-right: 8px; }
  .score-fill { height: 100%; }
  .btn { padding: 4px 8px; border-radius: 4px; border: none; font-size: 11px; cursor: pointer; font-weight: 600; }
  .btn-auth { background: #0284c7; color: #fff; }
  .btn-auth:hover { background: #0369a1; }
  code { font-family: monospace; color: #38bdf8; background: #090d16; padding: 2px 6px; border-radius: 4px; }
</style>
</head>
<body>
  <h1>🛡️ Wi-Fi IDS v2.1.2 - Kali SOC Monitor</h1>
  <div class="subtitle">Edge Wi-Fi Evil Twin & Rogue AP Real-Time Behavioral Threat Detection</div>

  <div class="metrics">
    <div class="card rose">
      <h3>Active High Threats</h3>
      <p class="val" id="cnt-high" style="color: var(--rose);">0</p>
    </div>
    <div class="card amber">
      <h3>Suspicious APs (Medium)</h3>
      <p class="val" id="cnt-med" style="color: var(--amber);">0</p>
    </div>
    <div class="card green">
      <h3>Authorized APs</h3>
      <p class="val" id="cnt-auth" style="color: var(--green);">0</p>
    </div>
    <div class="card cyan">
      <h3>Frames Analyzed</h3>
      <p class="val" id="cnt-frames" style="color: var(--cyan);">0</p>
    </div>
  </div>

  <table>
    <thead>
      <tr>
        <th>BSSID (MAC)</th>
        <th>SSID (Network Name)</th>
        <th>Risk Score</th>
        <th>Threat Tier</th>
        <th>Target Whitelist</th>
        <th>AI Metrics</th>
        <th>Auth Status</th>
        <th>Actions</th>
      </tr>
    </thead>
    <tbody id="ap-table-body">
      <tr><td colspan="8" style="text-align: center; color: var(--muted); padding: 30px;">Listening for live 802.11 frames...</td></tr>
    </tbody>
  </table>

  <script>
    async function updateDashboard() {
      try {
        const [resStatus, resAps] = await Promise.all([
          fetch('/api/status').then(r => r.json()),
          fetch('/api/aps').then(r => r.json())
        ]);

        document.getElementById('cnt-frames').innerText = resStatus.frames_processed || 0;

        let high = 0, med = 0, auth = 0;
        const tbody = document.getElementById('ap-table-body');

        if (resAps.length > 0) {
          tbody.innerHTML = '';
          resAps.forEach(ap => {
            if (ap.risk_tier === 'HIGH') high++;
            else if (ap.risk_tier === 'MEDIUM') med++;
            if (ap.is_whitelisted) auth++;

            const tr = document.createElement('tr');
            const scoreColor = ap.risk_score >= 70 ? 'var(--rose)' : (ap.risk_score >= 30 ? 'var(--amber)' : 'var(--green)');

            tr.innerHTML = `
              <td><code>${ap.bssid}</code></td>
              <td><strong>${ap.ssid || '<em>[Hidden SSID]</em>'}</strong> ${ap.is_mutated ? '⚠️ <span style=\"font-size:10px; color:#fb7185;\">Mutated</span>' : ''}</td>
              <td>
                <div class="score-bar"><div class="score-fill" style="width: ${ap.risk_score}%; background: ${scoreColor};"></div></div>
                <strong>${ap.risk_score}</strong>
              </td>
              <td><span class="badge badge-${ap.risk_tier}">${ap.risk_tier}</span></td>
              <td>${ap.target_whitelist}</td>
              <td style="font-size: 11px; color: var(--muted);">XGB: ${(ap.xgb_prob * 100).toFixed(0)}% | BGE: ${ap.bge_cos.toFixed(2)}</td>
              <td>${ap.is_whitelisted ? '<span style=\"color:var(--green); font-weight:600;\">✓ Authorized</span>' : '<span style=\"color:var(--muted);\">Unknown</span>'}</td>
              <td>
                ${ap.is_whitelisted 
                  ? `<button class="btn" style="background:#475569; color:#fff;" onclick="toggleWhitelist('${ap.bssid}', false)">Revoke</button>` 
                  : `<button class="btn btn-auth" onclick="toggleWhitelist('${ap.bssid}', true)">+ Authorize</button>`}
              </td>
            `;
            tbody.appendChild(tr);
          });
        }
        document.getElementById('cnt-high').innerText = high;
        document.getElementById('cnt-med').innerText = med;
        document.getElementById('cnt-auth').innerText = auth;
      } catch (e) {
        console.error("Dashboard poll error:", e);
      }
    }

    async function toggleWhitelist(bssid, add) {
      const endpoint = add ? '/api/whitelist/add' : '/api/whitelist/remove';
      await fetch(endpoint, {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({bssid: bssid})
      });
      updateDashboard();
    }

    setInterval(updateDashboard, 2000);
    updateDashboard();
  </script>
</body>
</html>
"""


class KaliIDSDaemon:
    """Master Controller orchestrating Pipeline, Capture Engine, and HTTP Dashboard."""

    def __init__(
        self,
        mode: str = "udp",
        interface: Optional[str] = None,
        listen_port: int = 5555,
        web_port: int = 8080,
        whitelist_file: Optional[str] = None,
        db_path: Optional[str] = None,
        kismet_url: str = "http://127.0.0.1:2501",
        kismet_key: Optional[str] = None,
        kismet_user: Optional[str] = None,
        kismet_pass: Optional[str] = None,
        kismet_interval: float = 1.5,
    ):
        self.mode = mode
        self.interface = interface
        self.listen_port = listen_port
        self.web_port = web_port
        self.kismet_url = kismet_url
        self.kismet_key = kismet_key
        self.kismet_user = kismet_user
        self.kismet_pass = kismet_pass
        self.kismet_interval = kismet_interval
        self.kismet_bridge = None
        self.running = False
        self.frames_count = 0
        self.alerts_high = 0
        self.alerts_medium = 0

        # Load Whitelist
        whitelist = list(DEFAULT_CAMPUS_WHITELIST)
        if whitelist_file and os.path.exists(whitelist_file):
            try:
                with open(whitelist_file, "r", encoding="utf-8") as f:
                    custom_wl = json.load(f)
                    if isinstance(custom_wl, list) and custom_wl:
                        whitelist = custom_wl
            except Exception as e:
                print(f"[!] Warning: Could not parse whitelist file: {e}")

        # Initialize Pipeline
        self.db_path = db_path or os.path.join(SCRIPT_DIR, "wifi_ids_v2.db")
        print(f"[*] Initializing Wi-Fi IDS v2.1.2 Pipeline...")
        print(f"    SQLite Database : {self.db_path}")
        print(f"    Whitelist Size  : {len(whitelist)} authorized SSIDs")

        self.pipeline = WiFiIDSPipeline(
            db_path=self.db_path,
            campus_whitelist=whitelist
        )

        # HTTP Server
        self.server = None

    def start_web_server(self):
        try:
            self.server = HTTPServer(("0.0.0.0", self.web_port), IDSWebHandler)
            t = threading.Thread(target=self.server.serve_forever, daemon=True, name="DashboardServer")
            t.start()
            print(f"[+] Live Alert Dashboard active at: http://0.0.0.0:{self.web_port}")
        except Exception as e:
            print(f"[!] Warning: Could not bind dashboard on port {self.web_port}: {e}")

    def run_udp_listener(self):
        """Mode A: Listens on UDP port 5555 for virtual lab / forwarded IEEE 802.11 frames."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(("0.0.0.0", self.listen_port))
        print(f"[+] UDP Frame Receiver listening on 0.0.0.0:{self.listen_port}...")

        while self.running:
            try:
                data, addr = sock.recvfrom(4096)
                if not data:
                    continue
                self.process_incoming_packet(data)
            except socket.error as e:
                if self.running:
                    print(f"[!] UDP Socket Error: {e}")
                break

    def run_live_sniffer(self):
        """Mode B: Captures live IEEE 802.11 frames using Scapy monitor mode."""
        try:
            from scapy.all import sniff  # type: ignore
        except ImportError:
            print("[!] ERROR: Scapy is required for live monitor sniffing. Please install scapy.")
            return

        if not self.interface:
            print("[!] ERROR: Monitor interface not specified. Use --interface wlan0mon")
            return

        print(f"[+] Commencing Live 802.11 Sniffing on {self.interface} (Monitor Mode)...")
        bpf_filter = "type mgt subtype beacon or subtype probe-resp or subtype deauth or subtype disas"

        try:
            sniff(
                iface=self.interface,
                prn=self.process_incoming_packet,
                filter=bpf_filter,
                store=False,
                stop_filter=lambda x: not self.running
            )
        except Exception as e:
            print(f"[!] Live sniffing terminated with error: {e}")

    def process_incoming_packet(self, frame_or_bytes):
        """Processes frame through v2.1.2 Pipeline and updates telemetry."""
        self.frames_count += 1
        try:
            res = self.pipeline.process_frame(frame_or_bytes)
            if res.risk_tier == "HIGH":
                self.alerts_high += 1
                print(f"\n🚨 [CRITICAL ALERT] [{res.bssid}] '{res.ssid}' | Risk: {res.risk_score} (HIGH)")
                if res.track_4a_result and res.track_4a_result.is_anomaly:
                    print(f"   ↳ Track 4A Anomaly: {res.track_4a_result.reason}")
                if res.track_4b_result and res.track_4b_result.is_anomaly:
                    print(f"   ↳ Track 4B Anomaly: {res.track_4b_result.reason}")
            elif res.risk_tier == "MEDIUM":
                self.alerts_medium += 1
                print(f"⚠️  [SUSPICIOUS AP]  [{res.bssid}] '{res.ssid}' | Risk: {res.risk_score} (MEDIUM)")
            elif self.frames_count % 50 == 0:
                print(f"[*] Processed {self.frames_count} frames... ({self.alerts_high} High, {self.alerts_medium} Med)")
        except Exception as e:
            print(f"[!] Frame processing exception: {e}")

    def start(self):
        self.running = True
        self.start_web_server()

        if self.mode == "udp":
            self.run_udp_listener()
        elif self.mode == "live":
            self.run_live_sniffer()
        elif self.mode == "kismet":
            self.run_kismet_bridge()
        elif self.mode == "dashboard":
            print(f"[+] Running in Standalone Dashboard Mode (Pulling strictly from DB: {self.db_path})")
            print(f"[+] Web UI live at: http://0.0.0.0:{self.web_port}")
            while self.running:
                time.sleep(1.0)
        elif self.mode == "test":
            self.run_demo_test()

    def run_kismet_bridge(self):
        """Mode Kismet: Connects to running Kismet server via REST API."""
        print(f"[*] Initializing Kismet Live Bridge...")
        print(f"    Kismet URL : {self.kismet_url}")
        self.kismet_bridge = KismetBridge(
            pipeline=self.pipeline,
            kismet_url=self.kismet_url,
            api_key=self.kismet_key,
            username=self.kismet_user,
            password=self.kismet_pass,
            poll_interval=self.kismet_interval,
        )
        ok, msg = self.kismet_bridge.check_connection()
        if not ok:
            print(f"[!] Kismet connection notice: {msg}")
            print(f"    Ensure Kismet is started: 'kismet' or 'sudo systemctl start kismet'")
            print(f"    Bridge will automatically poll and connect when Kismet becomes available...")
        else:
            print(f"[+] {msg}")

        self.kismet_bridge.start()
        print(f"[+] Kismet Bridge active! Polling every {self.kismet_interval}s...")
        print(f"[+] Live Alert Dashboard: http://localhost:{self.web_port}")
        while self.running:
            time.sleep(1.0)

    def run_demo_test(self):
        """Mode C: Synthetic demonstration test frames."""
        print("[*] Generating synthetic test frames...")
        test_samples = [
            {"subtype": 8, "bssid": "00:14:6c:aa:bb:cc", "ssid": "University_Campus_5G", "channel": 6, "seq": 100, "tsf": 1000},
            {"subtype": 8, "bssid": "aa:bb:cc:11:22:33", "ssid": "Un1versity_Campus_5G", "channel": 1, "seq": 10, "tsf": 500},
            {"subtype": 8, "bssid": "aa:bb:cc:44:55:66", "ssid": "Free_University_5G", "channel": 6, "seq": 20, "tsf": 800},
            {"subtype": 12, "bssid": "ff:ee:dd:33:22:11", "channel": 6},  # Deauth flood
        ]
        for s in test_samples:
            self.process_incoming_packet(s)
            time.sleep(1.0)
        print("[+] Demo completed. Keeping dashboard alive (Press Ctrl+C to stop)...")
        while self.running:
            time.sleep(1.0)

    def stop(self):
        print("\n[*] Stopping IDS Service gracefully...")
        self.running = False
        if self.kismet_bridge:
            self.kismet_bridge.stop()
        if self.pipeline:
            self.pipeline.flush(force=True)
            self.pipeline.close()
        print("[+] SQLite WAL flushed and closed cleanly.")


def handle_signals(signum, frame):
    if DAEMON_INSTANCE:
        DAEMON_INSTANCE.stop()
    sys.exit(0)


def main():
    global DAEMON_INSTANCE

    parser = argparse.ArgumentParser(description="Wi-Fi IDS v2.1.2 Production Service Daemon for Kali Linux")
    parser.add_argument("--mode", choices=["udp", "live", "kismet", "dashboard", "test"], default="udp", help="Operation mode: 'udp' (port 5555), 'live' (monitor card), 'kismet' (Kismet REST), 'dashboard' (DB pull only), 'test'")
    parser.add_argument("--interface", "-i", type=str, default=None, help="Monitor interface name for live mode (e.g. wlan0mon)")
    parser.add_argument("--port", "-p", type=int, default=5555, help="UDP listening port (default: 5555)")
    parser.add_argument("--web-port", "-w", type=int, default=8080, help="Web dashboard port (default: 8080)")
    parser.add_argument("--whitelist", type=str, default=None, help="Path to whitelist.json")
    parser.add_argument("--db", type=str, default=None, help="Path to SQLite database file")

    # Kismet specific options
    parser.add_argument("--kismet-url", type=str, default="http://127.0.0.1:2501", help="Kismet server URL (default: http://127.0.0.1:2501)")
    parser.add_argument("--kismet-key", type=str, default=None, help="Kismet API key (optional)")
    parser.add_argument("--kismet-user", type=str, default=None, help="Kismet HTTP auth username")
    parser.add_argument("--kismet-pass", type=str, default=None, help="Kismet HTTP auth password")
    parser.add_argument("--kismet-interval", type=float, default=1.5, help="Kismet polling interval in seconds (default: 1.5)")

    args = parser.parse_args()

    signal.signal(signal.SIGINT, handle_signals)
    signal.signal(signal.SIGTERM, handle_signals)

    DAEMON_INSTANCE = KaliIDSDaemon(
        mode=args.mode,
        interface=args.interface,
        listen_port=args.port,
        web_port=args.web_port,
        whitelist_file=args.whitelist,
        db_path=args.db,
        kismet_url=args.kismet_url,
        kismet_key=args.kismet_key,
        kismet_user=args.kismet_user,
        kismet_pass=args.kismet_pass,
        kismet_interval=args.kismet_interval,
    )
    DAEMON_INSTANCE.start()


if __name__ == "__main__":
    main()
