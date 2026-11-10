#!/usr/bin/env python3
"""
Wi-Fi IDS v2.1.2 - Standalone Decoupled SOC Dashboard Server
Pulls 100% of telemetry, alerts, and access point catalogs directly from SQLite WAL Database.
Completely decoupled from packet capture engines (Kismet, Scapy, UDP).

Architecture:
  [Capture Engine (Kismet / Scapy / UDP)] ---> [IDS Pipeline & Risk Engine]
                                                       │
                                                       ▼
                                            [SQLite WAL Database]
                                                       │
                                                       ▼ (Pulls ONLY from DB)
                                            [Dashboard Server :8080]
"""

import os
import sys
import time
import json
import sqlite3
import argparse
from http.server import HTTPServer, BaseHTTPRequestHandler
from typing import Dict, Any, List

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_DB_FILE = os.path.join(SCRIPT_DIR, "wifi_ids_v2.db")
GLOBAL_DB_PATH = DEFAULT_DB_FILE


def get_db_connection(db_path: str) -> sqlite3.Connection:
    """Opens a thread-safe connection to the SQLite database with WAL pragma."""
    conn = sqlite3.connect(db_path, timeout=5.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL;")
    return conn


class StandaloneDashboardHandler(BaseHTTPRequestHandler):
    """HTTP Request Handler reading strictly from SQLite Database."""

    def log_message(self, format, *args):
        pass  # Suppress HTTP access logs for clean console

    def do_GET(self):
        db_path = GLOBAL_DB_PATH

        if self.path == "/api/status":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()

            status = {
                "db_path": db_path,
                "db_connected": False,
                "high_threats": 0,
                "medium_threats": 0,
                "authorized_aps": 0,
                "total_aps": 0,
                "cataloged_ssids": 0,
                "behavior_logs_count": 0,
            }

            if os.path.exists(db_path):
                try:
                    conn = get_db_connection(db_path)
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
                    except sqlite3.OperationalError:
                        status["behavior_logs_count"] = 0
                    conn.close()
                    status["db_connected"] = True
                except Exception as e:
                    status["error"] = str(e)

            self.wfile.write(json.dumps(status).encode("utf-8"))

        elif self.path == "/api/aps":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()

            data = []
            if os.path.exists(db_path):
                try:
                    conn = get_db_connection(db_path)
                    cur = conn.cursor()
                    cur.execute("""
                        SELECT b.bssid, b.current_ssid, b.is_whitelisted, b.risk_tier,
                               b.current_risk_score, b.is_mutated, b.encryption_type,
                               b.first_seen_ts, b.last_seen_ts, b.primary_channel, b.last_rssi,
                               s.matched_whitelist_ssid, s.xgb_prob, s.bge_cos_clean
                        FROM bssid_devices b
                        LEFT JOIN ssid_catalog s ON b.current_ssid = s.ssid_text
                        ORDER BY b.current_risk_score DESC, b.last_seen_ts DESC
                        LIMIT 200
                    """)
                    for r in cur.fetchall():
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

        elif self.path == "/api/logs":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()

            logs = []
            if os.path.exists(db_path):
                try:
                    conn = get_db_connection(db_path)
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
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(HTML_STANDALONE_DASHBOARD.encode("utf-8"))

    def do_POST(self):
        db_path = GLOBAL_DB_PATH
        if self.path in ("/api/whitelist/add", "/api/whitelist/remove"):
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length).decode("utf-8")
            try:
                payload = json.loads(body)
                bssid = payload.get("bssid", "").strip()
                add_to_wl = (self.path == "/api/whitelist/add")

                if bssid and os.path.exists(db_path):
                    conn = get_db_connection(db_path)
                    with conn:
                        val = 1 if add_to_wl else 0
                        tier = "LOW" if add_to_wl else "MEDIUM"
                        score = 0 if add_to_wl else 30
                        conn.execute("""
                            UPDATE bssid_devices
                            SET is_whitelisted = ?, risk_tier = ?, current_risk_score = ?
                            WHERE bssid = ?
                        """, (val, tier, score, bssid))
                    conn.close()
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    self.wfile.write(json.dumps({"status": "ok", "bssid": bssid, "whitelisted": val}).encode("utf-8"))
                    return
            except Exception as e:
                pass

        self.send_response(400)
        self.end_headers()


HTML_STANDALONE_DASHBOARD = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Wi-Fi IDS v2.1.2 - Live SOC Database Monitor</title>
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
    --input-bg: #0b1322;
  }
  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: var(--bg); color: var(--text); margin: 0; padding: 24px; }
  header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; flex-wrap: wrap; gap: 12px; }
  h1 { margin: 0; color: #38bdf8; font-size: 22px; display: flex; align-items: center; gap: 10px; }
  .db-badge { font-size: 11px; background: rgba(6, 182, 212, 0.15); border: 1px solid var(--cyan); color: var(--cyan); padding: 4px 12px; border-radius: 9999px; font-weight: 500; }
  
  .metrics { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 14px; margin-bottom: 24px; }
  .card { background: var(--card); border: 1px solid var(--border); border-radius: 8px; padding: 14px 18px; box-shadow: 0 4px 12px rgba(0,0,0,0.3); }
  .card h3 { margin: 0 0 4px 0; font-size: 11px; color: var(--muted); text-transform: uppercase; letter-spacing: 0.05em; }
  .card .val { font-size: 26px; font-weight: bold; margin: 0; }
  .card.rose { border-left: 4px solid var(--rose); }
  .card.amber { border-left: 4px solid var(--amber); }
  .card.green { border-left: 4px solid var(--green); }
  .card.cyan { border-left: 4px solid var(--cyan); }
  .card.muted { border-left: 4px solid var(--muted); }
  
  /* Toolbar: Search, Filters, Sorting */
  .toolbar {
    background: var(--card);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 14px 18px;
    margin-bottom: 16px;
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 12px;
    box-shadow: 0 4px 12px rgba(0,0,0,0.25);
  }
  .search-box {
    position: relative;
    flex: 1 1 260px;
    min-width: 240px;
  }
  .search-box input {
    width: 100%;
    box-sizing: border-box;
    background: var(--input-bg);
    border: 1px solid var(--border);
    color: var(--text);
    padding: 8px 32px 8px 36px;
    border-radius: 6px;
    font-size: 13px;
    outline: none;
    transition: border-color 0.2s, box-shadow 0.2s;
  }
  .search-box input:focus {
    border-color: var(--cyan);
    box-shadow: 0 0 0 2px rgba(6, 182, 212, 0.2);
  }
  .search-icon {
    position: absolute;
    left: 10px;
    top: 50%;
    transform: translateY(-50%);
    color: var(--muted);
    font-size: 14px;
    pointer-events: none;
  }
  .clear-btn {
    position: absolute;
    right: 8px;
    top: 50%;
    transform: translateY(-50%);
    background: transparent;
    border: none;
    color: var(--muted);
    cursor: pointer;
    font-size: 14px;
    padding: 2px 6px;
    border-radius: 4px;
  }
  .clear-btn:hover { color: var(--text); background: rgba(255,255,255,0.1); }
  
  .filter-group {
    display: flex;
    align-items: center;
    gap: 6px;
    font-size: 12px;
    color: var(--muted);
  }
  .filter-group select {
    background: var(--input-bg);
    border: 1px solid var(--border);
    color: var(--text);
    padding: 7px 10px;
    border-radius: 6px;
    font-size: 12px;
    outline: none;
    cursor: pointer;
  }
  .filter-group select:focus {
    border-color: var(--cyan);
  }
  .table-meta {
    margin-left: auto;
    font-size: 12px;
    color: var(--cyan);
    background: rgba(6, 182, 212, 0.1);
    padding: 4px 10px;
    border-radius: 6px;
    border: 1px solid rgba(6, 182, 212, 0.25);
    white-space: nowrap;
  }

  /* Tables */
  table { width: 100%; border-collapse: collapse; background: var(--card); border-radius: 8px; overflow: hidden; border: 1px solid var(--border); font-size: 13px; margin-bottom: 28px; }
  th, td { padding: 10px 14px; text-align: left; border-bottom: 1px solid var(--border); }
  th {
    background: #0c1322;
    color: var(--muted);
    font-weight: 600;
    text-transform: uppercase;
    font-size: 11px;
    letter-spacing: 0.05em;
    user-select: none;
    cursor: pointer;
    transition: background 0.15s, color 0.15s;
  }
  th:hover {
    background: #141f36;
    color: var(--cyan);
  }
  th.sorted {
    color: var(--cyan);
    background: #141f36;
  }
  th .sort-arrow {
    display: inline-block;
    margin-left: 4px;
    font-size: 10px;
    color: var(--cyan);
  }
  tr:hover { background: #1a253d; }
  
  .badge { padding: 3px 8px; border-radius: 4px; font-size: 11px; font-weight: bold; text-transform: uppercase; display: inline-block; }
  .badge-HIGH { background: rgba(244, 63, 94, 0.2); color: #fb7185; border: 1px solid #f43f5e; }
  .badge-MEDIUM { background: rgba(245, 158, 11, 0.2); color: #fbbf24; border: 1px solid #f59e0b; }
  .badge-LOW { background: rgba(16, 185, 129, 0.2); color: #34d399; border: 1px solid #10b981; }
  
  .score-bar { width: 60px; height: 7px; background: #23314d; border-radius: 4px; overflow: hidden; display: inline-block; vertical-align: middle; margin-right: 6px; }
  .score-fill { height: 100%; }
  .btn { padding: 4px 8px; border-radius: 4px; border: none; font-size: 11px; cursor: pointer; font-weight: 600; transition: opacity 0.15s; }
  .btn:hover { opacity: 0.85; }
  .btn-auth { background: #0284c7; color: #fff; }
  code { font-family: monospace; color: #38bdf8; background: #090d16; padding: 2px 6px; border-radius: 4px; }
  h2 { font-size: 14px; color: var(--muted); margin: 0 0 10px 0; text-transform: uppercase; letter-spacing: 0.05em; display: flex; align-items: center; justify-content: space-between; }
</style>
</head>
<body>
  <header>
    <div>
      <h1>🛡️ Wi-Fi IDS v2.1.2 - Live SOC Database Monitor</h1>
      <div style="color: var(--muted); font-size: 12px; margin-top: 4px;">Data Source: Persistent SQLite WAL Database (Pull Model)</div>
    </div>
    <div class="db-badge" id="db-badge">Connecting to SQLite WAL...</div>
  </header>

  <div class="metrics">
    <div class="card rose">
      <h3>Active High Threats (DB)</h3>
      <p class="val" id="cnt-high" style="color: var(--rose);">0</p>
    </div>
    <div class="card amber">
      <h3>Suspicious APs (DB)</h3>
      <p class="val" id="cnt-med" style="color: var(--amber);">0</p>
    </div>
    <div class="card green">
      <h3>Whitelisted APs (DB)</h3>
      <p class="val" id="cnt-auth" style="color: var(--green);">0</p>
    </div>
    <div class="card cyan">
      <h3>Total APs in DB</h3>
      <p class="val" id="cnt-total" style="color: var(--cyan);">0</p>
    </div>
    <div class="card muted">
      <h3>Cached SSIDs (DB)</h3>
      <p class="val" id="cnt-ssids" style="color: var(--muted);">0</p>
    </div>
  </div>

  <h2>
    <span>1. Monitored Access Points (Pulled from <code>bssid_devices</code>)</span>
  </h2>

  <!-- Interactive Controls: Search Bar, Filter By, Sorting -->
  <div class="toolbar">
    <div class="search-box">
      <span class="search-icon">🔍</span>
      <input type="text" id="search-input" placeholder="Search SSID, BSSID MAC, Target..." oninput="handleSearch(this.value)">
      <button class="clear-btn" id="clear-search" onclick="clearSearch()" style="display:none;" title="Clear search">✕</button>
    </div>

    <div class="filter-group">
      <label for="filter-tier">Tier:</label>
      <select id="filter-tier" onchange="handleFilterTier(this.value)">
        <option value="ALL">All Tiers</option>
        <option value="HIGH">🚨 High Risk (>=70)</option>
        <option value="MEDIUM">⚠️ Medium (>=30)</option>
        <option value="LOW">✓ Low Risk (Safe)</option>
      </select>
    </div>

    <div class="filter-group">
      <label for="filter-auth">Auth:</label>
      <select id="filter-auth" onchange="handleFilterAuth(this.value)">
        <option value="ALL">All Status</option>
        <option value="AUTH">✓ Authorized</option>
        <option value="UNAUTH">⚠️ Unauthorized</option>
      </select>
    </div>

    <div class="filter-group">
      <label for="filter-mutation">Mutation:</label>
      <select id="filter-mutation" onchange="handleFilterMutation(this.value)">
        <option value="ALL">All APs</option>
        <option value="MUTATED">⚠️ Mutated Only</option>
      </select>
    </div>

    <div class="filter-group">
      <label for="sort-select">Sort By:</label>
      <select id="sort-select" onchange="handleSortSelect(this.value)">
        <option value="risk_score_desc">Risk: High → Low</option>
        <option value="risk_score_asc">Risk: Low → High</option>
        <option value="ssid_asc">SSID: A → Z</option>
        <option value="ssid_desc">SSID: Z → A</option>
        <option value="bssid_asc">BSSID MAC</option>
        <option value="rssi_desc">Signal: Strongest</option>
        <option value="last_seen_desc">Most Recent</option>
      </select>
    </div>

    <div class="table-meta" id="table-count-badge">Showing 0 of 0 APs</div>
  </div>

  <table>
    <thead>
      <tr>
        <th onclick="toggleSort('bssid')" id="th-bssid">BSSID (MAC) <span class="sort-arrow"></span></th>
        <th onclick="toggleSort('ssid')" id="th-ssid">SSID (Network Name) <span class="sort-arrow"></span></th>
        <th onclick="toggleSort('risk_score')" id="th-risk_score" class="sorted">Risk Score <span class="sort-arrow">▼</span></th>
        <th onclick="toggleSort('risk_tier')" id="th-risk_tier">Threat Tier <span class="sort-arrow"></span></th>
        <th onclick="toggleSort('target_whitelist')" id="th-target_whitelist">Target Whitelist <span class="sort-arrow"></span></th>
        <th>AI Detection Metrics</th>
        <th onclick="toggleSort('channel')" id="th-channel">Channel / RSSI <span class="sort-arrow"></span></th>
        <th onclick="toggleSort('is_whitelisted')" id="th-is_whitelisted">Auth Status <span class="sort-arrow"></span></th>
        <th>Action</th>
      </tr>
    </thead>
    <tbody id="ap-table-body">
      <tr><td colspan="9" style="text-align: center; color: var(--muted); padding: 24px;">Querying database records...</td></tr>
    </tbody>
  </table>

  <h2>2. Threat Behavioral Event Logs (Pulled from <code>beacon_behavior_logs</code>)</h2>
  <table>
    <thead>
      <tr>
        <th>Log ID</th>
        <th>BSSID</th>
        <th>Timestamp</th>
        <th>Channel Anomaly</th>
        <th>Deauth 1m</th>
        <th>Timing Jitter</th>
        <th>Mutation</th>
        <th>IE Fingerprint</th>
      </tr>
    </thead>
    <tbody id="logs-table-body">
      <tr><td colspan="8" style="text-align: center; color: var(--muted); padding: 18px;">No behavioral anomaly logs found in DB.</td></tr>
    </tbody>
  </table>

  <script>
    // Global State for UI Controls (Preserved across auto-poll refreshes)
    let rawApsList = [];
    let searchQuery = "";
    let filterTier = "ALL";
    let filterAuth = "ALL";
    let filterMutation = "ALL";
    let sortColumn = "risk_score";
    let sortAscending = false;

    // Search input handler
    function handleSearch(val) {
      searchQuery = (val || "").trim().toLowerCase();
      document.getElementById('clear-search').style.display = searchQuery ? 'block' : 'none';
      renderApTable();
    }

    function clearSearch() {
      document.getElementById('search-input').value = '';
      searchQuery = '';
      document.getElementById('clear-search').style.display = 'none';
      renderApTable();
    }

    // Filter handlers
    function handleFilterTier(val) {
      filterTier = val;
      renderApTable();
    }

    function handleFilterAuth(val) {
      filterAuth = val;
      renderApTable();
    }

    function handleFilterMutation(val) {
      filterMutation = val;
      renderApTable();
    }

    // Quick Sort Select dropdown handler
    function handleSortSelect(val) {
      const parts = val.split('_');
      const dir = parts.pop();
      const col = parts.join('_');
      sortColumn = col;
      sortAscending = (dir === 'asc');
      updateHeaderSortIndicators();
      renderApTable();
    }

    // Interactive Column Header Click Sort Toggle
    function toggleSort(col) {
      if (sortColumn === col) {
        sortAscending = !sortAscending;
      } else {
        sortColumn = col;
        sortAscending = (col === 'ssid' || col === 'bssid');
      }

      // Sync the sort-select dropdown value if matching
      const sel = document.getElementById('sort-select');
      const candidateVal = `${col}_${sortAscending ? 'asc' : 'desc'}`;
      for (let opt of sel.options) {
        if (opt.value === candidateVal) {
          sel.value = candidateVal;
          break;
        }
      }

      updateHeaderSortIndicators();
      renderApTable();
    }

    function updateHeaderSortIndicators() {
      const sortableCols = ['bssid', 'ssid', 'risk_score', 'risk_tier', 'target_whitelist', 'channel', 'is_whitelisted'];
      sortableCols.forEach(col => {
        const th = document.getElementById(`th-${col}`);
        if (!th) return;
        const arrow = th.querySelector('.sort-arrow');
        if (sortColumn === col) {
          th.classList.add('sorted');
          if (arrow) arrow.innerText = sortAscending ? '▲' : '▼';
        } else {
          th.classList.remove('sorted');
          if (arrow) arrow.innerText = '';
        }
      });
    }

    // Pure Filter & Sort Pipeline
    function filterAndSortAps(list) {
      const tierRank = { 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1 };

      // 1. Filtering Phase
      let filtered = list.filter(ap => {
        // Search Query (SSID, BSSID, Target Whitelist)
        if (searchQuery) {
          const matchSsid = (ap.ssid || '').toLowerCase().includes(searchQuery);
          const matchBssid = (ap.bssid || '').toLowerCase().includes(searchQuery);
          const matchTarget = (ap.target_whitelist || '').toLowerCase().includes(searchQuery);
          if (!matchSsid && !matchBssid && !matchTarget) return false;
        }

        // Tier Filter
        if (filterTier !== 'ALL' && ap.risk_tier !== filterTier) return false;

        // Auth Filter
        if (filterAuth === 'AUTH' && !ap.is_whitelisted) return false;
        if (filterAuth === 'UNAUTH' && ap.is_whitelisted) return false;

        // Mutation Filter
        if (filterMutation === 'MUTATED' && !ap.is_mutated) return false;

        return true;
      });

      // 2. Sorting Phase
      filtered.sort((a, b) => {
        let valA = a[sortColumn];
        let valB = b[sortColumn];

        if (sortColumn === 'risk_tier') {
          valA = tierRank[valA] || 0;
          valB = tierRank[valB] || 0;
        } else if (sortColumn === 'risk_score' || sortColumn === 'channel' || sortColumn === 'rssi' || sortColumn === 'last_seen') {
          valA = Number(valA) || 0;
          valB = Number(valB) || 0;
        } else if (typeof valA === 'string') {
          valA = (valA || '').toLowerCase();
          valB = (valB || '').toLowerCase();
        }

        if (valA < valB) return sortAscending ? -1 : 1;
        if (valA > valB) return sortAscending ? 1 : -1;
        return 0;
      });

      return filtered;
    }

    // Render AP Table
    function renderApTable() {
      const tbody = document.getElementById('ap-table-body');
      const filtered = filterAndSortAps(rawApsList);

      document.getElementById('table-count-badge').innerText = `Showing ${filtered.length} of ${rawApsList.length} APs`;

      if (filtered.length === 0) {
        tbody.innerHTML = `<tr><td colspan="9" style="text-align: center; color: var(--muted); padding: 32px;">No matching access points found for current filter/search.</td></tr>`;
        return;
      }

      tbody.innerHTML = '';
      filtered.forEach(ap => {
        const tr = document.createElement('tr');
        const scoreColor = ap.risk_score >= 70 ? 'var(--rose)' : (ap.risk_score >= 30 ? 'var(--amber)' : 'var(--green)');

        tr.innerHTML = `
          <td><code>${ap.bssid}</code></td>
          <td><strong>${ap.ssid}</strong> ${ap.is_mutated ? '⚠️ <span style=\"font-size:10px; color:#fb7185;\">Mutated</span>' : ''}</td>
          <td>
            <div class="score-bar"><div class="score-fill" style="width: ${ap.risk_score}%; background: ${scoreColor};"></div></div>
            <strong>${ap.risk_score}</strong>
          </td>
          <td><span class="badge badge-${ap.risk_tier}">${ap.risk_tier}</span></td>
          <td>${ap.target_whitelist}</td>
          <td style="font-size: 11px; color: var(--muted);">XGB: ${(ap.xgb_prob * 100).toFixed(0)}% | BGE: ${ap.bge_cos.toFixed(2)}</td>
          <td>Ch ${ap.channel} (${ap.rssi} dBm)</td>
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

    async function updateDashboard() {
      try {
        const [resStatus, resAps, resLogs] = await Promise.all([
          fetch('/api/status').then(r => r.json()),
          fetch('/api/aps').then(r => r.json()),
          fetch('/api/logs').then(r => r.json()).catch(() => [])
        ]);

        const badge = document.getElementById('db-badge');
        if (resStatus.db_connected) {
          badge.innerText = `● DB Connected: ${resStatus.db_path.split(/[\\\\/]/).pop()}`;
          badge.style.borderColor = 'var(--green)';
          badge.style.color = 'var(--green)';
        } else {
          badge.innerText = `⚠ DB Disconnected`;
          badge.style.borderColor = 'var(--rose)';
          badge.style.color = 'var(--rose)';
        }

        // Metrics directly from DB queries
        document.getElementById('cnt-high').innerText = resStatus.high_threats || 0;
        document.getElementById('cnt-med').innerText = resStatus.medium_threats || 0;
        document.getElementById('cnt-auth').innerText = resStatus.authorized_aps || 0;
        document.getElementById('cnt-total').innerText = resStatus.total_aps || 0;
        document.getElementById('cnt-ssids').innerText = resStatus.cataloged_ssids || 0;

        // Update Global AP List & Re-render (Preserves active search/filter/sort)
        if (Array.isArray(resAps)) {
          rawApsList = resAps;
          renderApTable();
        }

        // Logs Table from DB
        const logsBody = document.getElementById('logs-table-body');
        if (Array.isArray(resLogs) && resLogs.length > 0) {
          logsBody.innerHTML = '';
          resLogs.forEach(lg => {
            const tr = document.createElement('tr');
            tr.innerHTML = `
              <td>#${lg.id}</td>
              <td><code>${lg.bssid}</code></td>
              <td>${new Date(lg.timestamp * 1000).toLocaleTimeString()}</td>
              <td><span class=\"badge badge-${lg.anomaly_type !== 'NONE' ? 'HIGH' : 'LOW'}\">${lg.anomaly_type}</span></td>
              <td>${lg.deauth_count}</td>
              <td>${lg.jitter_ms} ms</td>
              <td>${lg.mutated ? 'Yes' : 'No'}</td>
              <td><code>${lg.fingerprint}</code></td>
            `;
            logsBody.appendChild(tr);
          });
        }

      } catch (e) {
        console.error("Database poll error:", e);
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


def main():
    global GLOBAL_DB_PATH

    parser = argparse.ArgumentParser(description="Wi-Fi IDS v2.1.2 - Decoupled SOC Dashboard Server (Pulls directly from DB)")
    parser.add_argument("--db", type=str, default=DEFAULT_DB_FILE, help="Path to SQLite database file")
    parser.add_argument("--port", "-p", type=int, default=8080, help="Web server port (default: 8080)")

    args = parser.parse_args()
    GLOBAL_DB_PATH = os.path.abspath(args.db)

    print("=" * 70)
    print("  🛡️ Wi-Fi IDS v2.1.2 - Standalone SOC Dashboard Server")
    print("=" * 70)
    print(f"  Target Database : {GLOBAL_DB_PATH}")
    print(f"  Database Exists : {os.path.exists(GLOBAL_DB_PATH)}")
    print(f"  Dashboard Port  : {args.port}")
    print("=" * 70)

    server = HTTPServer(("0.0.0.0", args.port), StandaloneDashboardHandler)
    print(f"[+] Dashboard Server active: http://0.0.0.0:{args.port}")
    print(f"[+] Pulling all metrics strictly from SQLite WAL. Press Ctrl+C to stop.")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Stopping Dashboard Server...")
        server.server_close()


if __name__ == "__main__":
    main()
