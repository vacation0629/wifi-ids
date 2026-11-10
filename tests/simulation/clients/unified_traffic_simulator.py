#!/usr/bin/env python3
"""
Unified Multi-Threaded Wi-Fi Traffic Simulator (Consolidated Client Unit)
Consolidates 4 separate client containers into a single lightweight container:
- Thread 1: Authorized AP Beacon Generator (Interval 5.0s)
- Thread 2: Stationary Evil Twin AP Generator (Interval 4.0s)
- Thread 3: Fast Roaming Evil Twin AP Generator (Interval 2.0s)
- Thread 4: Client Station Probe Request Generator (Interval 3.5s)
"""

import os
import sys
import time
import socket
import random
import threading
from scapy.layers.dot11 import RadioTap, Dot11, Dot11Beacon, Dot11ProbeReq, Dot11Elt

TARGET_HOST = os.getenv("TARGET_HOST", "10.10.0.5")
TARGET_PORT = int(os.getenv("TARGET_PORT", "5555"))

AUTHORIZED_SSIDS = [
    "University_Campus_5G",
    "University_Staff_Secure",
    "University_Student_WiFi",
    "University_Guest_Portal",
    "eduroam",
    "Siam_Wifi",
    "SiamXP_Wifi",
]

EVIL_TWIN_SSIDS = [
    "Un1versity_Campus_5G",       # Homoglyph
    "Free_University_Campus_5G",  # Captive lure
    "University Campus 5G",       # Delimiter mutation (space)
    "University-Campus-5G",       # Delimiter mutation (hyphen)
    "Siam_W1f1",                  # Homoglyph
    "Complimentary_Patron_Broadband", # Zero-overlap semantic lure
    "Colloquium_Wireless",
]

BENIGN_SSIDS = [
    "Cafe_Amazon_WiFi",
    "Starbucks_WiFi",
    "Costa_Coffee_Guest",
    "TrueMove_H_WiFi",
]

def generate_mac():
    return ":".join(f"{random.randint(0x00, 0xfe):02x}" for _ in range(6))

def build_beacon(ssid: str, bssid: str, channel: int = 6):
    dot11 = Dot11(subtype=8, type=0, proto=0, addr1="ff:ff:ff:ff:ff:ff", addr2=bssid, addr3=bssid)
    beacon = Dot11Beacon(cap="ESS+privacy")
    ie_ssid = Dot11Elt(ID=0, info=ssid.encode("utf-8"))
    ie_rates = Dot11Elt(ID=1, info=b"\x82\x84\x8b\x96\x0c\x12\x18\x24")
    ie_channel = Dot11Elt(ID=3, info=bytes([channel]))
    return RadioTap() / dot11 / beacon / ie_ssid / ie_rates / ie_channel

def build_probe_req(ssid: str, client_mac: str):
    dot11 = Dot11(subtype=4, type=0, addr1="ff:ff:ff:ff:ff:ff", addr2=client_mac, addr3="ff:ff:ff:ff:ff:ff")
    return RadioTap() / dot11 / Dot11ProbeReq() / Dot11Elt(ID=0, info=ssid.encode("utf-8"))

def send_frame(sock, frame_bytes):
    try:
        sock.sendto(frame_bytes, (TARGET_HOST, TARGET_PORT))
    except Exception as e:
        print(f"[!] Error sending frame to {TARGET_HOST}:{TARGET_PORT}: {e}")

# Thread 1: Authorized AP Loop
def run_authorized_ap(sock):
    bssids = {ssid: generate_mac() for ssid in AUTHORIZED_SSIDS}
    print("[+] Thread 1: Authorized AP generator started (5.0s interval)")
    while True:
        for ssid in AUTHORIZED_SSIDS:
            frame = build_beacon(ssid, bssids[ssid], channel=6)
            send_frame(sock, bytes(frame))
        time.sleep(5.0)

# Thread 2: Stationary Evil Twin Loop
def run_evil_twin_ap(sock):
    bssids = {ssid: generate_mac() for ssid in EVIL_TWIN_SSIDS}
    print("[+] Thread 2: Stationary Evil Twin generator started (4.0s interval)")
    while True:
        ssid = random.choice(EVIL_TWIN_SSIDS)
        frame = build_beacon(ssid, bssids[ssid], channel=6)
        send_frame(sock, bytes(frame))
        time.sleep(4.0)

# Thread 3: Fast Roaming / Channel Hop Clone Loop
def run_fast_roaming_ap(sock):
    bssid = generate_mac()
    print("[+] Thread 3: Fast Roaming Clone generator started (2.0s interval, ping-pong ch 1/6)")
    channels = [1, 6]
    ch_idx = 0
    while True:
        ch = channels[ch_idx % len(channels)]
        frame = build_beacon("Un1versity_Campus_5G", bssid, channel=ch)
        send_frame(sock, bytes(frame))
        ch_idx += 1
        time.sleep(2.0)

# Thread 4: Client Probe Request Loop
def run_probe_clients(sock):
    client_mac = generate_mac()
    print("[+] Thread 4: Client Station Probe generator started (3.5s interval)")
    while True:
        target = random.choice(AUTHORIZED_SSIDS + BENIGN_SSIDS)
        frame = build_probe_req(target, client_mac)
        send_frame(sock, bytes(frame))
        time.sleep(3.5)

def main():
    print(f"=== Unified Wi-Fi Traffic Simulator ===")
    print(f"Target Detector: {TARGET_HOST}:{TARGET_PORT}")
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    
    threads = [
        threading.Thread(target=run_authorized_ap, args=(sock,), daemon=True, name="AuthorizedAP"),
        threading.Thread(target=run_evil_twin_ap, args=(sock,), daemon=True, name="EvilTwinAP"),
        threading.Thread(target=run_fast_roaming_ap, args=(sock,), daemon=True, name="FastRoamingAP"),
        threading.Thread(target=run_probe_clients, args=(sock,), daemon=True, name="ProbeStation"),
    ]
    
    for t in threads:
        t.start()
        
    print("[*] All 4 simulator threads active in 1 consolidated container. Running indefinitely...")
    try:
        while True:
            time.sleep(1.0)
    except KeyboardInterrupt:
        print("[*] Stopping simulator...")

if __name__ == "__main__":
    main()
