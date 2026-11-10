#!/usr/bin/env python3
"""
Lightweight 802.11 Wi-Fi Frame Generator (Alpine Linux)
Constructs real IEEE 802.11 Beacon and Probe frames using Scapy.
Broadcasts them across virtual airwaves (Docker bridge) for testing Rogue AP detectors.
"""

import os
import sys
import time
import socket
import random
from scapy.layers.dot11 import RadioTap, Dot11, Dot11Beacon, Dot11ProbeReq, Dot11Elt

CLIENT_NAME = os.getenv("CLIENT_NAME", "wifi-node")
TARGET_HOST = os.getenv("TARGET_HOST", "10.10.0.5")  # Kali detector IP or broadcast
TARGET_PORT = int(os.getenv("TARGET_PORT", "5555"))
MODE = os.getenv("FRAME_MODE", "evil_twin")  # 'evil_twin', 'authorized', or 'mixed'
INTERVAL_SEC = float(os.getenv("INTERVAL_SEC", "3.0"))

# Pre-defined test SSIDs by role
AUTHORIZED_SSIDS = [
    "Siam Wifi",
    "SiamXP Wifi",
    "SIAM WIFI",
    "SIAM XP WIFI",
    "University Campus 5G",
    "University Staff Secure",
    "University Student WiFi",
    "University Guest Portal",
    "eduroam"
]

EVIL_TWIN_SSIDS = [
    "Siam_Wifi",                # Delimiter mutation (underscore)
    "Siam-Wifi",                # Delimiter mutation (hyphen)
    "Siam W1f1",                # Homoglyph (1 for i)
    "S\u0456am Wifi",           # Cyrillic lookalike
    "Free Siam Wifi",           # Captive portal lure
    "SiamXP_Wifi",              # Delimiter mutation
    "University_Campus_5G",     # Delimiter mutation
    "Un1versity Campus 5G",     # Homoglyph (1 for i)
    "Free University Campus 5G" # Lure keyword addition
]

BENIGN_SSIDS = [
    "Cafe Amazon WiFi",
    "Starbucks Guest",
    "AIS SUPER WiFi",
    "TrueMove H WiFi",
    "Local Printer Direct"
]

def generate_mac():
    """Generates a random MAC address string."""
    return ":".join(f"{random.randint(0x00, 0xfe):02x}" for _ in range(6))

def build_80211_beacon(ssid: str, bssid: str, channel: int = 6):
    """
    Constructs a valid IEEE 802.11 Beacon frame.
    RadioTap() / Dot11(subtype=8) / Dot11Beacon() / Dot11Elt(SSID) / Dot11Elt(Rates) / Dot11Elt(DSset)
    """
    # 802.11 Header: Management Frame (type 0), Subtype 8 (Beacon)
    # addr1 = Destination (Broadcast: ff:ff:ff:ff:ff:ff)
    # addr2 = Source / Transmitter MAC (BSSID)
    # addr3 = BSSID (Access Point MAC)
    dot11 = Dot11(
        subtype=8,
        type=0,
        proto=0,
        addr1="ff:ff:ff:ff:ff:ff",
        addr2=bssid,
        addr3=bssid
    )

    beacon = Dot11Beacon(cap="ESS+privacy")
    
    # Information Elements (IEs)
    ie_ssid = Dot11Elt(ID=0, info=ssid.encode("utf-8"))
    ie_rates = Dot11Elt(ID=1, info=b"\x82\x84\x8b\x96\x0c\x12\x18\x24")
    ie_channel = Dot11Elt(ID=3, info=bytes([channel]))

    # Prepend RadioTap header (standard 802.11 capture format)
    frame = RadioTap() / dot11 / beacon / ie_ssid / ie_rates / ie_channel
    return frame

def build_80211_probe_req(ssid: str, client_mac: str):
    """Constructs a valid IEEE 802.11 Probe Request frame (subtype 4)."""
    dot11 = Dot11(
        subtype=4,
        type=0,
        addr1="ff:ff:ff:ff:ff:ff",
        addr2=client_mac,
        addr3="ff:ff:ff:ff:ff:ff"
    )
    probe = Dot11ProbeReq()
    ie_ssid = Dot11Elt(ID=0, info=ssid.encode("utf-8"))
    return RadioTap() / dot11 / probe / ie_ssid

def main():
    print(f"[{CLIENT_NAME}] Initializing lightweight 802.11 Wi-Fi Frame Generator", flush=True)
    print(f"[{CLIENT_NAME}] Mode: {MODE} | Target: {TARGET_HOST}:{TARGET_PORT} | Interval: {INTERVAL_SEC}s", flush=True)

    # Select SSID pool based on mode
    if MODE == "evil_twin":
        ssid_pool = EVIL_TWIN_SSIDS
    elif MODE == "authorized":
        ssid_pool = AUTHORIZED_SSIDS
    else:
        ssid_pool = AUTHORIZED_SSIDS + EVIL_TWIN_SSIDS + BENIGN_SSIDS

    bssid = generate_mac()
    print(f"[{CLIENT_NAME}] Simulated Radio BSSID: {bssid}", flush=True)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

    seq = 0
    while True:
        seq += 1
        ssid = random.choice(ssid_pool)
        channel = random.choice([1, 6, 11])

        # 80% Beacons, 20% Probe Requests
        if random.random() < 0.8:
            frame = build_80211_beacon(ssid, bssid, channel)
            frame_type = "BEACON"
        else:
            frame = build_80211_probe_req(ssid, bssid)
            frame_type = "PROBE_REQ"

        raw_bytes = bytes(frame)

        try:
            sock.sendto(raw_bytes, (TARGET_HOST, TARGET_PORT))
            print(f"[{CLIENT_NAME}] #{seq:03d} Sent 802.11 {frame_type} | SSID: '{ssid}' | Ch: {channel} | Size: {len(raw_bytes)}B", flush=True)
        except Exception as e:
            print(f"[{CLIENT_NAME}] Send error: {e}", flush=True)

        # Sleep with slight jitter
        jitter = random.uniform(-0.5, 0.5)
        time.sleep(max(1.0, INTERVAL_SEC + jitter))

if __name__ == "__main__":
    main()
