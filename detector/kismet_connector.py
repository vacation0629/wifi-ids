#!/usr/bin/env python3
"""
Edge Wi-Fi Evil Twin Detection Framework (v2.1.2)
Kismet REST & Streaming Live Bridge for Kali Linux
Connects Kismet wireless capture server to Wi-Fi IDS v2.1.2 Pipeline:
- Subscribes to live dot11 AP devices via Kismet REST API
- Parses BSSID, SSID, Beacon IEs, Channels, RSSI, Sequence, TSF, Encryption
- Detects Deauth flood bursts tracked by Kismet
- Translates Kismet telemetry into v2.1.2 pipeline frames in real-time
"""

import os
import sys
import time
import json
import logging
import threading
from typing import Any, Dict, List, Optional, Tuple, Union

try:
    import requests
    from requests.auth import HTTPBasicAuth
except ImportError:
    requests = None
    HTTPBasicAuth = None

logger = logging.getLogger(__name__)


class KismetBridge:
    """
    Bridge connecting a running Kismet server to WiFiIDSPipeline (v2.1.2).
    """

    def __init__(
        self,
        pipeline: Any,
        kismet_url: str = "http://127.0.0.1:2501",
        api_key: Optional[str] = None,
        username: Optional[str] = None,
        password: Optional[str] = None,
        poll_interval: float = 1.5,
    ):
        self.pipeline = pipeline
        self.kismet_url = kismet_url.rstrip("/")
        self.api_key = api_key
        self.username = username
        self.password = password
        self.poll_interval = poll_interval
        self.running = False
        self._thread: Optional[threading.Thread] = None

        # Tracking state for incremental updates
        self.last_poll_ts = 0
        self.device_deauth_cache: Dict[str, int] = {}
        self.processed_devices_count = 0
        self.alerts_count = 0

    def get_auth_headers(self) -> Dict[str, str]:
        headers = {"Accept": "application/json"}
        if self.api_key:
            headers["KISMET-API-KEY"] = self.api_key
        return headers

    def get_auth(self) -> Optional[Any]:
        if self.username and self.password and HTTPBasicAuth:
            return HTTPBasicAuth(self.username, self.password)
        return None

    def check_connection(self) -> Tuple[bool, str]:
        """Verifies connectivity to Kismet server."""
        if requests is None:
            return False, "requests library not installed in Python environment"

        url = f"{self.kismet_url}/system/status.json"
        try:
            r = requests.get(
                url,
                headers=self.get_auth_headers(),
                auth=self.get_auth(),
                timeout=3.0
            )
            if r.status_code == 200:
                data = r.json()
                version = data.get("kismet.system.version", "unknown")
                timestamp = data.get("kismet.system.timestamp.sec", 0)
                return True, f"Kismet v{version} online (Server Time: {timestamp})"
            elif r.status_code in (401, 403):
                return False, f"HTTP {r.status_code}: Kismet Authentication required. Provide --kismet-key or --kismet-user/--kismet-pass"
            else:
                return False, f"HTTP {r.status_code}: {r.text[:100]}"
        except Exception as e:
            return False, f"Connection failed: {e}"

    def map_kismet_device_to_frame(self, device: Dict[str, Any]) -> Tuple[Dict[str, Any], int]:
        """
        Maps a Kismet phy-IEEE802.11 device dictionary into a v2.1.2 pipeline frame dict.
        Returns: (frame_dict, deauth_delta)
        """
        bssid = device.get("kismet.device.base.macaddr", "").strip()
        
        # SSID Resolution (Kismet stores advertised SSIDs in dot11 sub-dictionary)
        ssid = device.get("kismet.device.base.name", "")
        dot11 = device.get("dot11.device", {})
        
        adv_ssid_map = dot11.get("dot11.device.advertised_ssid_map", [])
        if isinstance(adv_ssid_map, list) and adv_ssid_map:
            # First advertised SSID
            first_entry = adv_ssid_map[0]
            if isinstance(first_entry, dict) and "dot11.advertisedssid.ssid" in first_entry:
                candidate_ssid = first_entry["dot11.advertisedssid.ssid"]
                if candidate_ssid:
                    ssid = candidate_ssid
        elif isinstance(adv_ssid_map, dict) and adv_ssid_map:
            for _, val in adv_ssid_map.items():
                if isinstance(val, dict) and "dot11.advertisedssid.ssid" in val:
                    candidate_ssid = val["dot11.advertisedssid.ssid"]
                    if candidate_ssid:
                        ssid = candidate_ssid
                        break

        # Radio channel vs Tag 3 beacon declared channel
        radio_channel = device.get("kismet.device.base.channel", 1)
        try:
            radio_channel = int(radio_channel)
        except (ValueError, TypeError):
            radio_channel = 1

        beacon_channel = dot11.get("dot11.device.beacon_channel", radio_channel)
        try:
            tag3_channel = int(beacon_channel)
        except (ValueError, TypeError):
            tag3_channel = radio_channel

        # Signal RSSI
        signal_data = device.get("kismet.device.base.signal", {})
        rssi = signal_data.get("kismet.common.signal.last_signal_dbm", -65)
        try:
            rssi = int(rssi)
        except (ValueError, TypeError):
            rssi = -65

        # Sequence and Timestamp
        seq_num = dot11.get("dot11.device.last_seq", 0)
        tsf_timestamp = dot11.get("dot11.device.last_beacon_timestamp", 0)

        # Encryption Type
        crypt = device.get("kismet.device.base.crypt", "")
        enc_type = "OPEN"
        if "WPA3" in crypt:
            enc_type = "WPA3-SAE"
        elif "WPA2" in crypt:
            enc_type = "WPA2-ENTERPRISE" if "EAP" in crypt or "Enterprise" in crypt else "WPA2-PSK"
        elif "WPA" in crypt:
            enc_type = "WPA-PSK"
        elif "WEP" in crypt:
            enc_type = "WEP"

        # Deauth Delta Detection
        deauth_count = dot11.get("dot11.device.num_deauth_packets", 0)
        last_deauth = self.device_deauth_cache.get(bssid, deauth_count)
        deauth_delta = max(0, deauth_count - last_deauth)
        self.device_deauth_cache[bssid] = deauth_count

        frame = {
            "subtype": 8,  # Beacon
            "bssid": bssid,
            "ssid": ssid,
            "channel": radio_channel,
            "radio_channel": radio_channel,
            "tag3_channel": tag3_channel,
            "seq_num": int(seq_num) & 0x0FFF,
            "tsf_timestamp": int(tsf_timestamp),
            "rssi": rssi,
            "encryption_type": enc_type,
        }
        return frame, deauth_delta

    def poll_kismet_devices(self) -> int:
        """
        Polls Kismet REST API for updated 802.11 APs and feeds them into v2.1.2 Pipeline.
        """
        if requests is None:
            return 0

        # Endpoint 1: Incremental updates via /devices/last-time/{ts}/devices.json
        # Endpoint 2: Complete AP view via /devices/views/phydot11_access_points.json
        if self.last_poll_ts > 0:
            url = f"{self.kismet_url}/devices/last-time/{self.last_poll_ts}/devices.json"
        else:
            url = f"{self.kismet_url}/devices/views/phydot11_access_points.json"

        try:
            now_ts = int(time.time())
            r = requests.get(
                url,
                headers=self.get_auth_headers(),
                auth=self.get_auth(),
                timeout=5.0
            )
            if r.status_code != 200:
                logger.warning(f"Kismet API returned status {r.status_code}: {r.text[:80]}")
                return 0

            devices = r.json()
            if not isinstance(devices, list):
                if isinstance(devices, dict) and "kismet.device.list" in devices:
                    devices = devices["kismet.device.list"]
                else:
                    devices = []

            count = 0
            for d in devices:
                # Filter strictly for 802.11 Wi-Fi devices
                phy = d.get("kismet.device.base.phyname", "")
                if phy and "802.11" not in phy and "IEEE802.11" not in phy:
                    continue

                frame_meta, deauth_delta = self.map_kismet_device_to_frame(d)
                if not frame_meta["bssid"]:
                    continue

                # 1. If deauth burst occurred, feed deauth frames first
                if deauth_delta > 0:
                    for _ in range(min(deauth_delta, 16)):
                        self.pipeline.process_frame({
                            "subtype": 0x0C,
                            "bssid": frame_meta["bssid"],
                            "channel": frame_meta["radio_channel"]
                        })

                # 2. Feed AP beacon frame into v2.1.2 Pipeline
                res = self.pipeline.process_frame(frame_meta)
                count += 1
                self.processed_devices_count += 1

                if res.risk_tier in ("HIGH", "MEDIUM"):
                    self.alerts_count += 1
                    symbol = "🚨" if res.risk_tier == "HIGH" else "⚠️"
                    print(f"{symbol} [{res.risk_tier}] AP: '{res.ssid}' ({res.bssid}) | Score: {res.risk_score} | Kismet Ch: {frame_meta['radio_channel']}")

            self.last_poll_ts = now_ts
            return count

        except Exception as e:
            logger.error(f"Error communicating with Kismet server: {e}")
            return 0

    def _worker_loop(self):
        """Continuous polling background thread."""
        logger.info(f"Kismet Bridge connected. Listening to {self.kismet_url}...")
        while self.running:
            try:
                self.poll_kismet_devices()
            except Exception as e:
                logger.error(f"Kismet bridge loop error: {e}")
            time.sleep(self.poll_interval)

    def start(self):
        """Starts background Kismet polling thread."""
        self.running = True
        self._thread = threading.Thread(target=self._worker_loop, daemon=True, name="KismetBridgeThread")
        self._thread.start()

    def stop(self):
        """Stops bridge gracefully."""
        self.running = False
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=2.0)
