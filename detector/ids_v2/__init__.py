"""
Edge Wi-Fi Evil Twin Detection Framework (v2.1.2)
Core Modular Package
"""

from detector.ids_v2.config import (
    WHITELISTED_SSIDS,
    DEFAULT_DB_PATH,
    FLUSH_INTERVAL_SEC,
    MIN_FORCE_COOLDOWN_SEC,
    OFFLINE_RESET_SEC,
    CHANNEL_WINDOW_SEC,
    MAX_RAM_ENTRIES,
    BEACON_INTERVAL_MS,
    JITTER_THRESHOLD_MS,
    TECH_STOPWORDS,
    ENABLE_STOPWORD_STRIP,
    SCORE_THRESHOLD_MEDIUM,
    SCORE_THRESHOLD_HIGH,
    TIER_RANK,
    AI_QUEUE_MAX_BATCH,
    XGB_SUSPICIOUS_THRESHOLD,
    BGE_SUSPICIOUS_THRESHOLD,
    PSK_WEIGHT_MULTIPLIER,
)
from detector.ids_v2.db_manager import (
    BatchDatabaseManager,
    SSIDRecord,
    BSSIDState,
    CampusIEProfile,
    BeaconBehaviorLog,
)
from detector.ids_v2.name_screener import (
    CampusNameScreener,
    Stage25Result,
    WorkConservingAIQueue,
    strip_tech_stopwords,
    FEATURE_NAMES,
    DEFAULT_CAMPUS_WHITELIST,
)

__all__ = [
    "WHITELISTED_SSIDS",
    "DEFAULT_DB_PATH",
    "FLUSH_INTERVAL_SEC",
    "MIN_FORCE_COOLDOWN_SEC",
    "OFFLINE_RESET_SEC",
    "CHANNEL_WINDOW_SEC",
    "MAX_RAM_ENTRIES",
    "BEACON_INTERVAL_MS",
    "JITTER_THRESHOLD_MS",
    "TECH_STOPWORDS",
    "ENABLE_STOPWORD_STRIP",
    "SCORE_THRESHOLD_MEDIUM",
    "SCORE_THRESHOLD_HIGH",
    "TIER_RANK",
    "AI_QUEUE_MAX_BATCH",
    "XGB_SUSPICIOUS_THRESHOLD",
    "BGE_SUSPICIOUS_THRESHOLD",
    "PSK_WEIGHT_MULTIPLIER",
    "BatchDatabaseManager",
    "SSIDRecord",
    "BSSIDState",
    "CampusIEProfile",
    "BeaconBehaviorLog",
    "CampusNameScreener",
    "Stage25Result",
    "WorkConservingAIQueue",
    "strip_tech_stopwords",
    "FEATURE_NAMES",
    "DEFAULT_CAMPUS_WHITELIST",
]
