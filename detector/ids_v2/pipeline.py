"""
Edge Wi-Fi Evil Twin Detection Framework (v2.1.2)
Pipeline: Unified Two-Group Wi-Fi Evil Twin Sniffer Pipeline
"""

import logging
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple, Union

from detector.ids_v2.config import (
    DEFAULT_CAMPUS_WHITELIST,
    DEFAULT_DB_PATH,
    MIN_FORCE_COOLDOWN_SEC,
    SCORE_THRESHOLD_HIGH,
    SCORE_THRESHOLD_MEDIUM,
)
from detector.ids_v2.db_manager import (
    BatchDatabaseManager,
    BSSIDState,
    CampusIEProfile,
    SSIDRecord,
)
from detector.ids_v2.name_screener import (
    CampusNameScreener,
    Stage25Result,
)
from detector.ids_v2.risk_engine import (
    HybridRiskEngine,
    RiskAssessment,
)
from detector.ids_v2.track_4a_state import (
    extract_tag3_or_61_channel,
    Track4AResult,
    Track4AStateTracker,
)
from detector.ids_v2.track_4b_beacon import (
    extract_beacon_features,
    Track4BBeaconAnalyzer,
    Track4BResult,
)

logger = logging.getLogger(__name__)


@dataclass
class PipelineResult:
    """Unified result for a single processed 802.11 management frame."""
    frame_type: str                          # "BEACON", "PROBE_RESP", "DEAUTH", "DISASSOC", "UNKNOWN"
    bssid: str
    ssid: str
    stage_reached: str                       # "PRE_STAGE_0_DEMUX", "STAGE_0_WHITELISTED", "STAGE_2_5_BENIGN", "STAGE_5_SCORING"
    is_suspicious_name: bool = False
    is_anomaly: bool = False
    risk_score: int = 0
    risk_tier: str = "LOW"
    track_4a_result: Optional[Track4AResult] = None
    track_4b_result: Optional[Track4BResult] = None
    stage25_result: Optional[Stage25Result] = None
    risk_assessment: Optional[RiskAssessment] = None
    flushed: bool = False
    details: Dict[str, Any] = field(default_factory=dict)

    @property
    def current_risk_score(self) -> int:
        return self.risk_score


class WiFiIDSPipeline:
    """
    Unified Two-Group Wi-Fi Evil Twin Sniffer Pipeline (v2.1.2).

    Coordinates:
      - Pre-Stage-0 Frame Subtype Demux (0x0C / 0x0A direct to Track 4A)
      - Stage 0: ram_bssids lookup & Whitelisted Integrity Check (skips AI, runs 4A)
      - Stage 1: ram_ssids cache lookup / Adaptive AI Worker (1xM vs NxM)
      - Stage 2.5: Dynamic PSK Gate (eff_bge = 0.5 * bge_cos if PSK)
      - Parallel Tracks 4A & 4B behavioral checks
      - Stage 5: Hybrid Risk Scoring & Coalesced Flush
    """

    def __init__(
        self,
        db_manager: Optional[BatchDatabaseManager] = None,
        campus_whitelist: Optional[List[str]] = None,
        db_path: Optional[str] = None,
        auto_train_xgb: bool = True,
        profile_name: str = "campus_default",
    ):
        self.campus_whitelist = (
            list(campus_whitelist) if campus_whitelist is not None else list(DEFAULT_CAMPUS_WHITELIST)
        )
        self.profile_name = profile_name

        # 1. Database & Cache Manager
        if db_manager is not None:
            self.db_manager = db_manager
        else:
            self.db_manager = BatchDatabaseManager(db_path or DEFAULT_DB_PATH)

        # 2. Stage 1 & 2 AI Name Screener
        self.screener = CampusNameScreener(
            db_manager=self.db_manager,
            whitelist=self.campus_whitelist,
            auto_train_xgb=auto_train_xgb,
        )

        # 3. Track 4A Active RF & Ingress Router
        self.track_4a = Track4AStateTracker(
            db_manager=self.db_manager,
            screener=self.screener,
        )

        # 4. Track 4B Deep Beacon IE & Strict Jitter Analyzer
        self.track_4b = Track4BBeaconAnalyzer(
            db_manager=self.db_manager,
            campus_whitelist=self.campus_whitelist,
            profile_name=self.profile_name,
        )

        # 5. Stage 5 Master Hybrid Risk Scoring Engine
        self.risk_engine = HybridRiskEngine(
            db_manager=self.db_manager,
            campus_whitelist=self.campus_whitelist,
        )

        self._lock = threading.RLock()

    def _normalize_bssid(self, bssid: str) -> str:
        return bssid.strip().lower()

    def _extract_frame_metadata(self, frame: Any) -> Dict[str, Any]:
        """
        Extracts subtype, BSSID, SSID, channels, seq, tsf, and RSSI from:
        1. Scapy Dot11 packets
        2. Dictionaries
        3. Custom Mock objects
        """
        meta: Dict[str, Any] = {
            "subtype": 0x08,
            "bssid": "00:00:00:00:00:00",
            "ssid": "",
            "tag3_channel": 1,
            "radio_channel": 1,
            "seq_num": 0,
            "tsf_timestamp": 0,
            "rssi": -60,
            "encryption_type": "OPEN",
            "raw_features": {},
        }

        if frame is None:
            return meta

        # ---------------------------------------------------------------------
        # Case A: Dictionary representation
        # ---------------------------------------------------------------------
        if isinstance(frame, dict):
            # Subtype
            sub = frame.get("subtype")
            if isinstance(sub, str):
                s_lower = sub.lower()
                if "deauth" in s_lower:
                    meta["subtype"] = 0x0C
                elif "disas" in s_lower:
                    meta["subtype"] = 0x0A
                elif "probe" in s_lower:
                    meta["subtype"] = 0x05
                elif "beacon" in s_lower:
                    meta["subtype"] = 0x08
                else:
                    try:
                        meta["subtype"] = int(sub, 16 if sub.startswith("0x") else 10)
                    except ValueError:
                        meta["subtype"] = 0x08
            elif sub is not None:
                meta["subtype"] = int(sub)
            elif "deauth" in frame or frame.get("type") == "deauth":
                meta["subtype"] = 0x0C
            elif "disassoc" in frame or frame.get("type") == "disassoc":
                meta["subtype"] = 0x0A
            else:
                meta["subtype"] = 0x08

            # BSSID
            for k in ("bssid", "addr3", "addr2", "ap_mac"):
                if k in frame and frame[k]:
                    meta["bssid"] = str(frame[k]).strip()
                    break

            # SSID
            for k in ("ssid", "observed_ssid"):
                if k in frame and frame[k] is not None:
                    raw_s = frame[k]
                    if isinstance(raw_s, (bytes, bytearray)):
                        try:
                            meta["ssid"] = raw_s.decode("utf-8", errors="replace").replace("\x00", "")
                        except Exception:
                            meta["ssid"] = raw_s.decode("latin-1", errors="ignore").replace("\x00", "")
                    else:
                        meta["ssid"] = str(raw_s).replace("\x00", "")
                    break

            # Declared Tag 3 / Tag 61 Channel
            meta["tag3_channel"] = extract_tag3_or_61_channel(frame) or 1

            # Radio Channel
            for k in ("radio_channel", "channel", "operating_channel"):
                if k in frame and frame[k] is not None:
                    try:
                        meta["radio_channel"] = int(frame[k])
                        break
                    except (ValueError, TypeError):
                        pass
            if not meta.get("radio_channel"):
                meta["radio_channel"] = meta["tag3_channel"]

            # Sequence Number
            for k in ("seq", "seq_num", "sc"):
                if k in frame and frame[k] is not None:
                    try:
                        meta["seq_num"] = int(frame[k]) & 0x0FFF
                        break
                    except (ValueError, TypeError):
                        pass

            # TSF
            for k in ("tsf", "tsf_timestamp", "timestamp"):
                if k in frame and frame[k] is not None:
                    try:
                        meta["tsf_timestamp"] = int(frame[k])
                        break
                    except (ValueError, TypeError):
                        pass

            # RSSI
            for k in ("rssi", "signal", "dBm_AntSignal"):
                if k in frame and frame[k] is not None:
                    try:
                        meta["rssi"] = int(frame[k])
                        break
                    except (ValueError, TypeError):
                        pass

            # Extract full beacon features if beacon
            if meta["subtype"] in (0x08, 0x05):
                feats = extract_beacon_features(frame)
                meta["raw_features"] = feats
                if not meta["ssid"] and feats.get("ssid"):
                    meta["ssid"] = feats["ssid"]
                meta["encryption_type"] = feats.get("encryption_type", "OPEN")
            return meta

        # ---------------------------------------------------------------------
        # Case B: Scapy Packet
        # ---------------------------------------------------------------------
        if hasattr(frame, "haslayer"):
            try:
                from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11Deauth, Dot11Disas, Dot11ProbeResp, RadioTap  # type: ignore

                if frame.haslayer(Dot11Deauth):
                    meta["subtype"] = 0x0C
                elif frame.haslayer(Dot11Disas):
                    meta["subtype"] = 0x0A
                elif frame.haslayer(Dot11ProbeResp):
                    meta["subtype"] = 0x05
                elif frame.haslayer(Dot11Beacon):
                    meta["subtype"] = 0x08
                elif frame.haslayer(Dot11):
                    meta["subtype"] = getattr(frame[Dot11], "subtype", 0x08)

                if frame.haslayer(Dot11):
                    dot11 = frame[Dot11]
                    meta["bssid"] = str(dot11.addr3 or dot11.addr2 or "00:00:00:00:00:00").strip()
                    sc = getattr(dot11, "SC", 0)
                    meta["seq_num"] = (sc >> 4) & 0x0FFF if sc else getattr(dot11, "seq", 0)

                if frame.haslayer(RadioTap):
                    rt = frame[RadioTap]
                    if hasattr(rt, "dBm_AntSignal") and rt.dBm_AntSignal is not None:
                        meta["rssi"] = int(rt.dBm_AntSignal)
                    if hasattr(rt, "ChannelFrequency") and rt.ChannelFrequency:
                        freq = rt.ChannelFrequency
                        if 2412 <= freq <= 2484:
                            meta["radio_channel"] = 14 if freq == 2484 else (freq - 2407) // 5
                        elif 5000 <= freq <= 5900:
                            meta["radio_channel"] = (freq - 5000) // 5

                meta["tag3_channel"] = extract_tag3_or_61_channel(frame) or 1
                if not meta.get("radio_channel"):
                    meta["radio_channel"] = meta["tag3_channel"]

                feats = extract_beacon_features(frame)
                meta["raw_features"] = feats
                meta["ssid"] = feats.get("ssid", "")
                meta["tsf_timestamp"] = feats.get("tsf_timestamp", 0)
                meta["encryption_type"] = feats.get("encryption_type", "OPEN")
                return meta
            except ImportError:
                pass
            except Exception as e:
                logger.debug(f"Scapy frame parsing error: {e}")

        # ---------------------------------------------------------------------
        # Case C: Generic Mock Object
        # ---------------------------------------------------------------------
        meta["subtype"] = getattr(frame, "subtype", 0x08)
        raw_mock_ssid = getattr(frame, "ssid", "")
        if isinstance(raw_mock_ssid, (bytes, bytearray)):
            try:
                meta["ssid"] = raw_mock_ssid.decode("utf-8", errors="replace").replace("\x00", "")
            except Exception:
                meta["ssid"] = raw_mock_ssid.decode("latin-1", errors="ignore").replace("\x00", "")
        else:
            meta["ssid"] = str(raw_mock_ssid).replace("\x00", "")
        meta["tag3_channel"] = getattr(frame, "tag3_channel", getattr(frame, "channel", 1))
        meta["radio_channel"] = getattr(frame, "radio_channel", meta["tag3_channel"])
        meta["seq_num"] = getattr(frame, "seq_num", getattr(frame, "seq", 0))
        meta["tsf_timestamp"] = getattr(frame, "tsf_timestamp", getattr(frame, "tsf", 0))
        meta["rssi"] = getattr(frame, "rssi", -60)
        feats = extract_beacon_features(frame)
        meta["raw_features"] = feats
        meta["encryption_type"] = feats.get("encryption_type", getattr(frame, "encryption_type", "OPEN"))
        return meta

    def process_frame(
        self,
        frame: Any,
        now_ts: Optional[float] = None,
    ) -> PipelineResult:
        """
        Unified end-to-end frame processing entry point.

        Steps:
          1. Metadata extraction (Scapy / dict / mock)
          2. Pre-Stage-0 Management Demux:
             Subtypes 0x0C (Deauth) & 0x0A (Disassoc) route directly by BSSID to Track 4A.
          3. Stage 0: ram_bssids cache lookup & Whitelisted AP Integrity Check.
             - Whitelisted BSSIDs skip AI (Stage 1 & 2), but run Track 4A for collision/clone check.
             - Option M2: BSSID Name Mutation triggers +45 pts and forces full evaluation.
          4. Stage 1 & 2: Encryption-agnostic AI screener (ram_ssids cache or adaptive worker).
          5. Stage 2.5: Dynamic PSK Gate: eff_bge = 0.5 * bge_cos if PSK else bge_cos.
             - If Benign: Brief Logging (3.0s periodic buffer).
             - If Suspicious: Route to Parallel Tracks 4A & 4B.
          6. Stage 5: Hybrid Risk Scoring Engine & Coalesced Instant Alert Bypass.
        """
        if now_ts is None:
            now_ts = time.time()

        with self._lock:
            self.db_manager.check_and_sync_data_version()
            commits_start = self.db_manager.commit_count
            meta = self._extract_frame_metadata(frame)
            subtype = meta["subtype"]
            bssid = meta["bssid"]
            ssid = meta["ssid"]
            tag3_ch = meta["tag3_channel"]
            radio_ch = meta["radio_channel"]
            seq = meta["seq_num"]
            tsf = meta["tsf_timestamp"]
            rssi = meta["rssi"]
            enc_type = meta["encryption_type"]

            # Capture initial tier before frame processing begins
            existing_bssid_state = self.db_manager.get_bssid(bssid)
            prev_tier_before_frame = existing_bssid_state.risk_tier if existing_bssid_state else "LOW"

            # =================================================================
            # Step 1: Pre-Stage-0 Ingress Router (Deauth / Disassoc Subtype 0x0C / 0x0A)
            # =================================================================
            if subtype in (0x0C, 0x0A, 12, 10):
                track_4a_res = self.track_4a.process_deauth_frame(bssid=bssid, now_ts=now_ts)
                existing_state = self.db_manager.get_bssid(bssid)
                current_ssid = existing_state.current_ssid if existing_state else ""

                if track_4a_res.is_anomaly:
                    # Deauth storm detected (>=15/10s or >=30/60s) -> evaluate and escalate to Floor HIGH (75 pts)
                    risk_assessment = self.risk_engine.evaluate_and_update(
                        bssid=bssid,
                        ssid=current_ssid,
                        bssid_state=existing_state,
                        track_4a_result=track_4a_res,
                        track_4b_result=None,
                        now_ts=now_ts,
                        is_suspicious_name=False,
                        prev_tier=prev_tier_before_frame,
                    )
                else:
                    # Non-storm deauth frame: deauth frames carry no SSID, do not trigger probation
                    curr_score = existing_state.current_risk_score if existing_state else 0
                    curr_tier = existing_state.risk_tier if existing_state else "LOW"
                    risk_assessment = RiskAssessment(
                        bssid=bssid,
                        ssid=current_ssid,
                        risk_score=curr_score,
                        risk_tier=curr_tier,
                        prev_risk_tier=prev_tier_before_frame,
                        is_escalation=False,
                        triggered_instant_flush=False,
                        bssid_state=existing_state,
                    )

                frame_label = "DEAUTH" if subtype in (0x0C, 12) else "DISASSOC"
                return PipelineResult(
                    frame_type=frame_label,
                    bssid=bssid,
                    ssid=current_ssid,
                    stage_reached="PRE_STAGE_0_DEMUX",
                    is_suspicious_name=False,
                    is_anomaly=track_4a_res.is_anomaly,
                    risk_score=risk_assessment.risk_score,
                    risk_tier=risk_assessment.risk_tier,
                    track_4a_result=track_4a_res,
                    track_4b_result=None,
                    risk_assessment=risk_assessment,
                    flushed=bool(self.db_manager.commit_count > commits_start or risk_assessment.triggered_instant_flush),
                    details={
                        "deauth_10s": track_4a_res.deauth_count_10s,
                        "deauth_60s": track_4a_res.deauth_count_60s,
                    },
                )

            # =================================================================
            # Step 2: Beacon / Probe Response Processing
            # =================================================================
            bssid_state = self.db_manager.get_bssid(bssid)
            is_wl = self.track_4a._is_bssid_whitelisted(bssid, bssid_state)

            is_mutated = False
            if bssid_state is None:
                # Stage 0: Brand New BSSID
                bssid_state = BSSIDState(
                    bssid=bssid,
                    current_ssid=ssid,
                    is_whitelisted=1 if is_wl else 0,
                    is_mutated=0,
                    first_seen_ts=now_ts,
                    last_seen_ts=now_ts,
                    primary_channel=tag3_ch,
                    encryption_type=enc_type,
                    active_channels_map={tag3_ch: now_ts},
                )
                self.db_manager.put_bssid(bssid_state)
            else:
                if is_wl:
                    bssid_state.is_whitelisted = 1
                bssid_state.last_seen_ts = now_ts
                bssid_state.encryption_type = enc_type

                # Option M2: BSSID Name Mutation Check
                if bssid_state.current_ssid and bssid_state.current_ssid != ssid:
                    is_mutated = True
                    bssid_state.is_mutated = 1
                    bssid_state.current_ssid = ssid
                    self.db_manager.put_bssid(bssid_state)
                else:
                    is_mutated = bool(bssid_state.is_mutated)
                    if not bssid_state.current_ssid:
                        bssid_state.current_ssid = ssid

            # =================================================================
            # Step 3: Stage 0 Whitelisted AP Integrity Check (Point 1 Fix)
            # =================================================================
            if bssid_state.is_whitelisted == 1 and not is_mutated:
                # Whitelisted BSSIDs skip AI (Stage 1 & 2) to save CPU,
                # but MUST run Track 4A to verify collision & multi-channel clone integrity!
                track_4a_res = self.track_4a.process_beacon_frame(
                    bssid=bssid,
                    observed_ssid=ssid,
                    tag3_channel=tag3_ch,
                    seq_num=seq,
                    tsf_timestamp=tsf,
                    now_ts=now_ts,
                )

                risk_assessment = self.risk_engine.evaluate_and_update(
                    bssid=bssid,
                    ssid=ssid,
                    bssid_state=bssid_state,
                    track_4a_result=track_4a_res,
                    track_4b_result=None,
                    is_mutated=False,
                    now_ts=now_ts,
                    is_whitelisted=True,
                    is_suspicious_name=False,
                    prev_tier=prev_tier_before_frame,
                )

                return PipelineResult(
                    frame_type="BEACON",
                    bssid=bssid,
                    ssid=ssid,
                    stage_reached="STAGE_0_WHITELISTED",
                    is_suspicious_name=False,
                    is_anomaly=track_4a_res.is_anomaly,
                    risk_score=risk_assessment.risk_score,
                    risk_tier=risk_assessment.risk_tier,
                    track_4a_result=track_4a_res,
                    track_4b_result=None,
                    risk_assessment=risk_assessment,
                    flushed=bool(self.db_manager.commit_count > commits_start or risk_assessment.triggered_instant_flush),
                    details={"is_whitelisted": True},
                )

            # =================================================================
            # Step 4: Group 1 — AI Name Screening (Stage 1, 2, 2.5)
            # =================================================================
            # Stage 1: Check ram_ssids LRU cache or evaluate via Adaptive AI Worker
            record = self.screener.screen_ssid(ssid)

            # Stage 2.5: Dynamic PSK-Weighted Suspicious Name Gatekeeper
            is_suspicious_name, eff_bge, base_bge = self.screener.evaluate_stage_2_5(
                record=record,
                bssid_state=bssid_state,
            )

            # Construct Stage25Result
            stage25_res = Stage25Result(
                bssid=bssid,
                ssid=ssid,
                is_suspicious_name=is_suspicious_name,
                eff_bge=eff_bge,
                base_bge=base_bge,
                xgb_prob=record.xgb_prob,
                is_mutated=is_mutated,
                is_whitelisted=bool(bssid_state.is_whitelisted),
                record=record,
                bssid_state=bssid_state,
            )

            # =================================================================
            # Step 5: Route to Benign Brief Logging vs Group 2 (Parallel 4A & 4B)
            # =================================================================
            if not is_suspicious_name:
                # Stage 2.5 = False (Benign Name):
                # Update Track 4A RF tracking (channels and timestamps)
                track_4a_res = self.track_4a.process_beacon_frame(
                    bssid=bssid,
                    observed_ssid=ssid,
                    tag3_channel=tag3_ch,
                    seq_num=seq,
                    tsf_timestamp=tsf,
                    now_ts=now_ts,
                )

                risk_assessment = self.risk_engine.evaluate_and_update(
                    bssid=bssid,
                    ssid=ssid,
                    bssid_state=bssid_state,
                    track_4a_result=track_4a_res,
                    track_4b_result=None,
                    is_mutated=is_mutated,
                    now_ts=now_ts,
                    is_suspicious_name=False,
                    prev_tier=prev_tier_before_frame,
                )

                return PipelineResult(
                    frame_type="BEACON",
                    bssid=bssid,
                    ssid=ssid,
                    stage_reached="STAGE_2_5_BENIGN",
                    is_suspicious_name=False,
                    is_anomaly=track_4a_res.is_anomaly,
                    risk_score=risk_assessment.risk_score,
                    risk_tier=risk_assessment.risk_tier,
                    track_4a_result=track_4a_res,
                    track_4b_result=None,
                    stage25_result=stage25_res,
                    risk_assessment=risk_assessment,
                    flushed=bool(self.db_manager.commit_count > commits_start or risk_assessment.triggered_instant_flush),
                    details={"eff_bge": eff_bge, "xgb_prob": record.xgb_prob},
                )

            # Stage 2.5 = True (Suspicious Name or Mutated):
            # Route to Parallel Tracks 4A & 4B
            track_4a_res = self.track_4a.process_beacon_frame(
                bssid=bssid,
                observed_ssid=ssid,
                tag3_channel=tag3_ch,
                seq_num=seq,
                tsf_timestamp=tsf,
                now_ts=now_ts,
            )

            track_4b_res = self.track_4b.analyze_beacon(
                bssid=bssid,
                frame=frame,
                radio_channel=radio_ch,
                rssi=rssi,
                now_ts=now_ts,
                ssid=ssid,
                update_db_state=False,
            )

            # =================================================================
            # Step 6: Stage 5 Hybrid Risk Scoring & Coalesced Flush
            # =================================================================
            risk_assessment = self.risk_engine.evaluate_and_update(
                bssid=bssid,
                ssid=ssid,
                bssid_state=bssid_state,
                track_4a_result=track_4a_res,
                track_4b_result=track_4b_res,
                is_mutated=is_mutated,
                now_ts=now_ts,
                is_suspicious_name=True,
                prev_tier=prev_tier_before_frame,
            )

            is_any_anomaly = bool(
                track_4a_res.is_anomaly or track_4b_res.is_anomaly or risk_assessment.risk_score >= SCORE_THRESHOLD_MEDIUM
            )

            return PipelineResult(
                frame_type="BEACON",
                bssid=bssid,
                ssid=ssid,
                stage_reached="STAGE_5_SCORING",
                is_suspicious_name=True,
                is_anomaly=is_any_anomaly,
                risk_score=risk_assessment.risk_score,
                risk_tier=risk_assessment.risk_tier,
                track_4a_result=track_4a_res,
                track_4b_result=track_4b_res,
                stage25_result=stage25_res,
                risk_assessment=risk_assessment,
                flushed=bool(self.db_manager.commit_count > commits_start or risk_assessment.triggered_instant_flush),
                details={
                    "eff_bge": eff_bge,
                    "xgb_prob": record.xgb_prob,
                    "ie_match_status": track_4b_res.ie_match_status,
                },
            )

    def learn_baseline(self, frames_or_dicts: List[Any]) -> CampusIEProfile:
        """
        Locks the Campus IE Blueprint profile in SQLite WAL (--learn-baseline).
        Leaves bssid_devices.is_whitelisted = 0 for all APs (Check 4.2 Point 5 rule).
        """
        return self.track_4b.learn_baseline(frames_or_dicts)

    def whitelist_bssid(self, bssid: str) -> None:
        """Manually marks a BSSID as authorized via Dashboard UI [+ Add to Whitelist]."""
        with self._lock:
            b_norm = self._normalize_bssid(bssid)
            self.db_manager.whitelisted_bssids.add(b_norm)
            state = self.db_manager.get_bssid(bssid)
            if state is not None:
                state.is_whitelisted = 1
                state.risk_tier = "LOW"
                state.current_risk_score = 0
                self.db_manager.put_bssid(state)
            self.db_manager.flush_to_sqlite(force=True)

    def unwhitelist_bssid(self, bssid: str) -> None:
        """Removes a BSSID from the manual whitelist."""
        with self._lock:
            b_norm = self._normalize_bssid(bssid)
            self.db_manager.whitelisted_bssids.discard(b_norm)
            state = self.db_manager.get_bssid(bssid)
            if state is not None:
                state.is_whitelisted = 0
                self.db_manager.put_bssid(state)
            self.db_manager.flush_to_sqlite(force=True)

    def flush(self, force: bool = True) -> bool:
        """Forces immediate SQLite WAL batch flush."""
        return self.db_manager.flush_to_sqlite(force=force)

    def close(self) -> None:
        """Flushes dirty records and closes the underlying database connection."""
        self.db_manager.close()
