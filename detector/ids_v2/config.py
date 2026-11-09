"""
Edge Wi-Fi Evil Twin Detection Framework (v2.1.2)
Configuration & Global Constants
"""

import os
from typing import List, Dict

# Main Whitelisted SSIDs (Campus Baseline)
WHITELISTED_SSIDS: List[str] = [
    'University Campus 5G',
    'University Staff Secure',
    'University Student WiFi',
    'University Guest Portal',
    'eduroam',
    'Siam Wifi',
    'SiamXP Wifi',
    'SIAM WIFI',
    'SIAM XP WIFI'
]

# Protected 5-SSID Campus Baseline Whitelist (M=5)
DEFAULT_CAMPUS_WHITELIST: List[str] = [
    'University Campus 5G',
    'University Staff Secure',
    'University Student WiFi',
    'University Guest Portal',
    'eduroam'
]

# Database & RAM Cache Limits
DEFAULT_DB_PATH: str = os.getenv("WIFI_IDS_DB_PATH", "detector/wifi_ids_v2.db")
MAX_RAM_ENTRIES: int = 4096

# Timing Thresholds (Seconds)
FLUSH_INTERVAL_SEC: float = 3.0          # Routine deduplicated batch flush
MIN_FORCE_COOLDOWN_SEC: float = 0.25     # Coalesced Instant Alert Bypass cooldown (caps forced commits at <= 4/sec)
OFFLINE_RESET_SEC: float = 3600.0        # 1-hour offline gap resets 24h probation timer
CHANNEL_WINDOW_SEC: float = 15.0         # Sliding window for IE Tag 3/61 channel tracking

# Jitter & Beacon Timing (Milliseconds)
BEACON_INTERVAL_MS: float = 102.4        # Standard 100 TU beacon interval
JITTER_THRESHOLD_MS: float = 20.0        # Strict un-diluted jitter threshold

# Tech Stopwords for SSID Sanitization
TECH_STOPWORDS: List[str] = ['wifi', '5g', 'wlan', 'net', 'broadband']
ENABLE_STOPWORD_STRIP: bool = True

# Risk Scoring Thresholds & Floors
SCORE_THRESHOLD_MEDIUM: int = 30
SCORE_THRESHOLD_HIGH: int = 70
TIER_RANK: Dict[str, int] = {
    "LOW": 0,
    "MEDIUM": 1,
    "HIGH": 2
}

# Deauth / Disassoc Flood Detection Thresholds (Frames)
DEAUTH_THRESHOLD_10S: int = 15
DEAUTH_THRESHOLD_60S: int = 30

# Adaptive AI Inference Batching
AI_QUEUE_MAX_BATCH: int = 32
XGB_SUSPICIOUS_THRESHOLD: float = 0.50
BGE_SUSPICIOUS_THRESHOLD: float = 0.60
PSK_WEIGHT_MULTIPLIER: float = 0.50
