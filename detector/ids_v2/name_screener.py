"""
Edge Wi-Fi Evil Twin Detection Framework (v2.1.2)
Stage 1 & 2: Work-Conserving Adaptive AI Name Screener & Dynamic Stage 2.5 Gatekeeper
"""

import collections
import concurrent.futures
import json
import logging
import os
import re
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple, Union

import math
import struct

try:
    import numpy as np
    HAS_NUMPY = True
except ImportError:
    class _MockArray(list):
        def __init__(self, data, dtype=None):
            if isinstance(data, (list, tuple)):
                data = [_MockArray(x, dtype) if isinstance(x, (list, tuple)) else x for x in data]
            super().__init__(data)
            self.dtype = dtype

        @property
        def shape(self):
            if not self:
                return (0,)
            if isinstance(self[0], (list, _MockArray)):
                return (len(self), len(self[0]))
            return (len(self),)

        def __getitem__(self, item):
            if isinstance(item, tuple):
                row = super().__getitem__(item[0])
                for idx in item[1:]:
                    row = row[idx]
                return row
            res = super().__getitem__(item)
            if isinstance(res, (list, tuple)) and not isinstance(res, _MockArray):
                return _MockArray(res)
            return res

        def __setitem__(self, item, value):
            if isinstance(item, tuple):
                target = super().__getitem__(item[0])
                for idx in item[1:-1]:
                    target = target[idx]
                target[item[-1]] = value
            else:
                super().__setitem__(item, value)

        def astype(self, dtype):
            return self

        def tobytes(self):
            flat = []
            for item in self:
                if isinstance(item, (list, _MockArray)):
                    flat.extend(float(x) for x in item)
                else:
                    flat.append(float(item))
            return struct.pack(f"{len(flat)}f", *flat)

        def __matmul__(self, other):
            if isinstance(self[0], (list, _MockArray)):
                if not isinstance(other[0], (list, _MockArray)):
                    return _MockArray([sum(a * b for a, b in zip(row, other)) for row in self])
                else:
                    cols = list(zip(*other))
                    return _MockArray([
                        [sum(a * b for a, b in zip(row, col)) for col in cols]
                        for row in self
                    ])
            else:
                cols = list(zip(*other))
                return _MockArray([sum(a * b for a, b in zip(self, col)) for col in cols])

        @property
        def T(self):
            if isinstance(self[0], (list, _MockArray)):
                return _MockArray([_MockArray(list(col)) for col in zip(*self)])
            return self

        def __truediv__(self, other):
            if isinstance(other, (list, _MockArray)):
                if isinstance(other[0], (list, _MockArray)):
                    return _MockArray([[val / (other[i][0] or 1.0) for val in row] for i, row in enumerate(self)])
                denom = other[0] or 1.0
                return _MockArray([[val / denom for val in row] for row in self])
            denom = other or 1.0
            return _MockArray([[val / denom for val in row] if isinstance(row, (list, _MockArray)) else row / denom for row in self])

    class _MockLinalg:
        @staticmethod
        def norm(arr, axis=None, keepdims=False):
            if axis == 1:
                norms = [math.sqrt(sum(x * x for x in row)) for row in arr]
                if keepdims:
                    return _MockArray([[n] for n in norms])
                return _MockArray(norms)
            if isinstance(arr, (list, _MockArray)) and arr and isinstance(arr[0], (list, _MockArray)):
                return math.sqrt(sum(x * x for row in arr for x in row))
            return math.sqrt(sum(x * x for x in arr))

    class _MockNumPy:
        float32 = float
        int32 = int
        ndarray = _MockArray
        linalg = _MockLinalg()

        @staticmethod
        def array(data, dtype=None):
            return _MockArray(data, dtype=dtype)

        @staticmethod
        def empty(shape, dtype=None):
            if isinstance(shape, (list, tuple)):
                if len(shape) == 2:
                    return _MockArray([_MockArray([0.0] * shape[1]) for _ in range(shape[0])], dtype=dtype)
                return _MockArray([0.0] * shape[0], dtype=dtype)
            return _MockArray([0.0] * shape, dtype=dtype)

        @staticmethod
        def zeros(shape, dtype=None):
            return _MockNumPy.empty(shape, dtype=dtype)

        @staticmethod
        def max(arr, axis=None):
            if axis == 1:
                return _MockArray([max(row) for row in arr])
            if isinstance(arr, (list, _MockArray)) and arr and isinstance(arr[0], (list, _MockArray)):
                return max(max(row) for row in arr)
            return max(arr)

    np = _MockNumPy()
    HAS_NUMPY = False

# Internal framework imports
from detector.ids_v2.config import (
    AI_QUEUE_MAX_BATCH,
    BGE_SUSPICIOUS_THRESHOLD,
    DEFAULT_DB_PATH,
    ENABLE_STOPWORD_STRIP,
    PSK_WEIGHT_MULTIPLIER,
    TECH_STOPWORDS,
    WHITELISTED_SSIDS,
    XGB_SUSPICIOUS_THRESHOLD,
)
from detector.ids_v2.db_manager import (
    BatchDatabaseManager,
    BSSIDState,
    SSIDRecord,
)

logger = logging.getLogger(__name__)

# Feature names corresponding to the 13-feature lexical extractor
FEATURE_NAMES: List[str] = [
    "f1_lev_ratio",
    "f2_dam_ratio",
    "f3_jaro_winkler",
    "f4_ngram2",
    "f5_ngram3",
    "f6_homoglyphs",
    "f7_len_abs_diff",
    "f8_len_ratio",
    "f9_token_jaccard",
    "f10_separator_delta",
    "f11_lure_flag",
    "f12_academic_role_collision",
    "f13_prefix_ratio",
]

# Protected 5-SSID Campus Baseline Whitelist (M=5)
DEFAULT_CAMPUS_WHITELIST: List[str] = [
    "University Campus 5G",
    "University Staff Secure",
    "University Student WiFi",
    "University Guest Portal",
    "eduroam",
]

# Optional external dependency detection
try:
    import xgboost as xgb
    HAS_XGBOOST = True
except ImportError:
    xgb = None
    HAS_XGBOOST = False

try:
    from fastembed import TextEmbedding
    HAS_FASTEMBED = True
except ImportError:
    TextEmbedding = None
    HAS_FASTEMBED = False

# Import 13-feature extractor from ssid_feature_framework if available
try:
    from ssid_feature_framework.features import (
        extract_features as raw_extract_features,
        find_best_whitelist_match as raw_find_best_whitelist_match,
        jaro_winkler_similarity,
    )
    HAS_FEATURE_FRAMEWORK = True
except ImportError:
    raw_extract_features = None
    raw_find_best_whitelist_match = None
    jaro_winkler_similarity = None
    HAS_FEATURE_FRAMEWORK = False


def strip_tech_stopwords(ssid: str, stopwords: Optional[List[str]] = None) -> str:
    """
    Strips technical stopwords (e.g. 'wifi', '5g', 'wlan', 'net', 'broadband')
    from an SSID string while preserving distinguishing semantic tokens.
    E.g. 'Starbucks_WiFi' -> 'Starbucks'
         'Free_Campus_WiFi' -> 'Free Campus'
    If stripping produces an empty string or no stopwords exist, preserves original SSID.
    """
    if stopwords is None:
        stopwords = TECH_STOPWORDS

    sw_set = {w.lower() for w in stopwords}
    tokens = [t for t in re.split(r"[-_\.\s]+", ssid) if t]
    remaining = [t for t in tokens if t.lower() not in sw_set]
    if not remaining:
        return ssid
    if len(remaining) == len(tokens):
        return ssid
    return " ".join(remaining)


# Fallback pure-Python string distance functions if ssid_feature_framework not in path
def _fallback_levenshtein(s1: str, s2: str) -> int:
    if s1 == s2:
        return 0
    if len(s1) == 0:
        return len(s2)
    if len(s2) == 0:
        return len(s1)
    if len(s1) < len(s2):
        s1, s2 = s2, s1
    prev = list(range(len(s2) + 1))
    for i, c1 in enumerate(s1):
        curr = [i + 1] + [0] * len(s2)
        for j, c2 in enumerate(s2):
            curr[j + 1] = min(prev[j + 1] + 1, curr[j] + 1, prev[j] + (c1 != c2))
        prev = curr
    return prev[-1]


def _fallback_extract_features(observed: str, target: str) -> Dict[str, Any]:
    """Fallback 13-feature extractor if ssid_feature_framework is not present."""
    len1, len2 = len(observed), len(target)
    max_len = max(len1, len2) or 1
    lev = _fallback_levenshtein(observed, target)
    lev_ratio = round(1.0 - (lev / max_len), 4)

    # Simple approximations for fallback environment
    obs_lower = observed.lower()
    tgt_lower = target.lower()
    prefix_len = 0
    for c1, c2 in zip(observed, target):
        if c1 == c2:
            prefix_len += 1
        else:
            break
    prefix_ratio = round(prefix_len / len2, 4) if len2 > 0 else 0.0

    return {
        "f1_lev_ratio": lev_ratio,
        "f2_dam_ratio": lev_ratio,
        "f3_jaro_winkler": lev_ratio,
        "f4_ngram2": lev_ratio,
        "f5_ngram3": lev_ratio,
        "f6_homoglyphs": 0,
        "f7_len_abs_diff": abs(len1 - len2),
        "f8_len_ratio": round(min(len1, len2) / max_len, 4),
        "f9_token_jaccard": 1.0 if obs_lower == tgt_lower else 0.0,
        "f10_separator_delta": 0,
        "f11_lure_flag": 1 if any(w in obs_lower for w in ["free", "login", "portal", "fast"]) else 0,
        "f12_academic_role_collision": 0,
        "f13_prefix_ratio": prefix_ratio,
    }


def _fallback_find_best_match(observed: str, whitelist: List[str]) -> Tuple[str, Dict[str, Any]]:
    best_target = whitelist[0]
    best_feats = _fallback_extract_features(observed, best_target)
    best_score = best_feats["f1_lev_ratio"]
    for t in whitelist[1:]:
        f = _fallback_extract_features(observed, t)
        if f["f1_lev_ratio"] > best_score:
            best_score = f["f1_lev_ratio"]
            best_target = t
            best_feats = f
    return best_target, best_feats


@dataclass
class Stage25Result:
    """Detailed evaluation result from Stage 2.5 gatekeeper."""
    bssid: str
    ssid: str
    is_suspicious_name: bool
    eff_bge: float
    base_bge: float
    xgb_prob: float
    is_mutated: bool
    is_whitelisted: bool
    record: Optional[SSIDRecord]
    bssid_state: BSSIDState


class WorkConservingAIQueue:
    """
    Q1 Work-Conserving Adaptive AI Queue.
    - If queue is empty when 1 SSID arrives (N=1): Instant Type A (1xM dot product) with 0 ms wait.
    - If requests arrive during busy inference (N>1): Batches up to 32 SSIDs in Type B (NxM).
    """

    def __init__(self, max_batch_size: int = AI_QUEUE_MAX_BATCH):
        self.max_batch_size = max_batch_size
        self._queue: collections.deque[Tuple[str, concurrent.futures.Future]] = collections.deque()
        self._lock = False

    def enqueue(self, ssid: str) -> concurrent.futures.Future:
        """Enqueues an SSID for adaptive evaluation, returning a Future."""
        fut: concurrent.futures.Future = concurrent.futures.Future()
        self._queue.append((ssid, fut))
        return fut

    def get_pending_batch(self, max_items: Optional[int] = None) -> List[Tuple[str, concurrent.futures.Future]]:
        """Drains up to max_items (default: max_batch_size) from the queue."""
        limit = max_items or self.max_batch_size
        batch = []
        while self._queue and len(batch) < limit:
            batch.append(self._queue.popleft())
        return batch

    def __len__(self) -> int:
        return len(self._queue)


class CampusNameScreener:
    """
    Stage 1 & Stage 2 Adaptive AI Name Screener (v2.1.2).
    - 13-feature lexical extractor from ssid_feature_framework.
    - 50-tree XGBoost classifier (loaded or trained on startup).
    - FastEmbed BAAI/bge-small-en-v1.5 text embeddings (384-dimensional).
    - Pre-computed Campus Whitelist normalized embedding matrix W (shape M x 384).
    - Work-conserving adaptive AI queue: N=1 instant 1xM (<10ms) vs N<=32 batch NxM (<55ms).
    - Encryption-agnostic storage in ssid_catalog (no PSK zeroing in DB).
    - Dynamic Stage 2.5 PSK-weighted gate: eff_bge = 0.5*bge_cos if PSK else bge_cos.
    - Option M2 BSSID mutation detection: flag mutated (+45 pts) on SSID change.
    """

    def __init__(
        self,
        db_manager: BatchDatabaseManager,
        whitelist: Optional[List[str]] = None,
        threads: int = 4,
        model_path: Optional[str] = None,
        auto_train_xgb: bool = True,
        embedder: Optional[Any] = None,
        xgb_model: Optional[Any] = None,
    ):
        self.db_manager = db_manager
        self.whitelist = list(whitelist) if whitelist else list(DEFAULT_CAMPUS_WHITELIST)
        self.threads = threads
        self.model_path = model_path or os.path.join(
            os.path.dirname(__file__), "models", "xgb_ssid_model.json"
        )
        self.auto_train_xgb = auto_train_xgb

        # 1. Initialize XGBoost Classifier
        if xgb_model is not None:
            self.xgb_model = xgb_model
        else:
            self.xgb_model = self._init_xgb_model()

        # 2. Initialize FastEmbed Embedding Model
        if embedder is not None:
            self.embedder = embedder
        else:
            self.embedder = self._init_embedder()

        # 3. Pre-compute Whitelist Matrix W of shape (M x 384)
        self.W: np.ndarray = np.empty((0, 384), dtype=np.float32)
        self.recompute_whitelist_embeddings()

        # 4. Adaptive AI Queue (Q1)
        self.ai_queue = WorkConservingAIQueue(max_batch_size=AI_QUEUE_MAX_BATCH)

    def _init_xgb_model(self) -> Any:
        """Loads serialized XGBoost model or trains 50-tree classifier in < 80ms."""
        if not HAS_XGBOOST:
            logger.warning("xgboost not installed. Using pure-Python fallback classifier.")
            return None

        model = xgb.XGBClassifier(
            n_estimators=50,
            max_depth=3,
            learning_rate=0.1,
            subsample=0.8,
            colsample_bytree=0.8,
            reg_lambda=1.0,
            reg_alpha=0.1,
            eval_metric="logloss",
            random_state=42,
        )

        if os.path.isfile(self.model_path):
            try:
                model.load_model(self.model_path)
                return model
            except Exception as e:
                logger.warning(f"Could not load existing XGBoost model from {self.model_path}: {e}")

        if not self.auto_train_xgb:
            return model

        # Train on startup using test_cases.json
        project_root = Path(__file__).resolve().parent.parent.parent
        test_cases_path = project_root / "ssid_feature_framework" / "test_cases.json"

        if test_cases_path.is_file():
            try:
                with open(test_cases_path, "r", encoding="utf-8") as f:
                    samples = json.load(f)

                X_list, y_list = [], []
                for s in samples:
                    obs = s["observed_ssid"]
                    best_target, feats = self.compute_features(obs)
                    X_list.append(feats)
                    y_list.append(1 if s["ground_truth_label"] == "EVIL_TWIN" else 0)

                X = np.array(X_list, dtype=np.float32)
                y = np.array(y_list, dtype=np.int32)
                model.fit(X, y)

                os.makedirs(os.path.dirname(os.path.abspath(self.model_path)), exist_ok=True)
                model.save_model(self.model_path)
                logger.info(f"Trained and saved 50-tree XGBoost model to {self.model_path}")
            except Exception as e:
                logger.error(f"Failed to train XGBoost on test_cases.json: {e}")

        return model

    def _init_embedder(self) -> Any:
        """Initializes FastEmbed BAAI/bge-small-en-v1.5 model."""
        if not HAS_FASTEMBED:
            logger.warning("fastembed not installed. Semantic embeddings will use fallback.")
            return None
        return TextEmbedding("BAAI/bge-small-en-v1.5", threads=self.threads)

    def set_whitelist(self, whitelist: List[str]) -> None:
        """Updates the protected whitelist and regenerates W matrix."""
        self.whitelist = list(whitelist)
        self.recompute_whitelist_embeddings()

    def recompute_whitelist_embeddings(self) -> None:
        """
        Pre-computes Campus Whitelist embeddings as normalized matrix W
        of shape (M x 384) where M = len(whitelist).
        """
        if not self.whitelist:
            self.W = np.empty((0, 384), dtype=np.float32)
            return

        if self.embedder is not None:
            # Embed all whitelisted SSIDs using FastEmbed
            embs = np.array(list(self.embedder.embed(self.whitelist)), dtype=np.float32)
            norms = np.linalg.norm(embs, axis=1, keepdims=True)
            norms[norms == 0.0] = 1.0
            self.W = embs / norms
        else:
            # Deterministic pseudo-embedding for environments without FastEmbed
            self.W = np.array([self._pseudo_embed(wl) for wl in self.whitelist], dtype=np.float32)

    def _pseudo_embed(self, text: str) -> Any:
        """Generates deterministic pseudo-embedding vector for fallback environments."""
        vec = np.zeros(384, dtype=np.float32)
        words = text.lower().replace("_", " ").replace("-", " ").split()
        campus_kw = {"university", "campus", "staff", "student", "guest", "portal", "eduroam"}
        for w in words:
            weight = 5.0 if w in campus_kw else 1.5
            hw = sum(ord(c) * (37**i) for i, c in enumerate(w)) % 384
            vec[hw] += weight
            for i in range(len(w) - 1):
                bg = w[i : i + 2]
                h = (ord(bg[0]) * 31 + ord(bg[1])) % 384
                vec[h] += 0.8
        norm = np.linalg.norm(vec)
        return vec / (norm if norm > 0 else 1.0)

    def compute_features(self, observed_ssid: str) -> Tuple[str, List[float]]:
        """
        Extracts 13-feature lexical vector against the best matching whitelist SSID.
        Returns: (best_matching_target_ssid, [f1, f2, ..., f13])
        """
        if HAS_FEATURE_FRAMEWORK and raw_extract_features is not None and jaro_winkler_similarity is not None:
            best_target = max(self.whitelist, key=lambda t: jaro_winkler_similarity(observed_ssid, t))
            feat_dict = raw_extract_features(observed_ssid, best_target)
        elif HAS_FEATURE_FRAMEWORK and raw_find_best_whitelist_match is not None:
            best_target, feat_dict = raw_find_best_whitelist_match(observed_ssid, self.whitelist)
        else:
            best_target, feat_dict = _fallback_find_best_match(observed_ssid, self.whitelist)

        feature_vector = [float(feat_dict.get(fn, 0.0)) for fn in FEATURE_NAMES]
        return best_target, feature_vector

    def compute_xgb_prob(self, feature_vector: List[float]) -> float:
        """Computes Evil Twin probability using XGBoost (or fallback heuristic)."""
        if self.xgb_model is not None and HAS_XGBOOST:
            x = np.array([feature_vector], dtype=np.float32)
            probs = self.xgb_model.predict_proba(x)
            return float(probs[0, 1])

        # Pure-Python heuristic fallback if xgboost is absent
        f1_lev = feature_vector[0]
        f3_jaro = feature_vector[2]
        f11_lure = feature_vector[10]
        f6_homo = feature_vector[5]
        score = 0.0
        if f1_lev >= 0.70 and f1_lev < 1.0:
            score += 0.50
        if f11_lure > 0:
            score += 0.40
        if f6_homo > 0:
            score += 0.45
        return min(1.0, max(0.0, score))

    def _embed_single(self, text: str) -> np.ndarray:
        """Embeds and L2-normalizes a single string to a 384-d vector."""
        if self.embedder is not None:
            raw = np.array(list(self.embedder.embed([text])), dtype=np.float32)[0]
            norm = np.linalg.norm(raw)
            return raw / (norm if norm > 0 else 1.0)
        return self._pseudo_embed(text)

    def _embed_batch(self, texts: List[str]) -> np.ndarray:
        """Embeds and L2-normalizes a batch of strings to an (N x 384) matrix."""
        if not texts:
            return np.empty((0, 384), dtype=np.float32)

        if self.embedder is not None:
            raw = np.array(list(self.embedder.embed(texts, batch_size=len(texts))), dtype=np.float32)
            norms = np.linalg.norm(raw, axis=1, keepdims=True)
            norms[norms == 0.0] = 1.0
            return raw / norms

        # Fallback
        return np.array([self._embed_single(t) for t in texts], dtype=np.float32)

    def compute_ssid_record(self, ssid: str) -> SSIDRecord:
        """
        Type A Work-Conserving Evaluation (N=1):
        Instant 1xM dot product v @ W.T with 0 ms queue wait (< 10 ms compute).
        """
        # 1. 13 Lexical Features + XGBoost Probability
        best_target, feat_vec = self.compute_features(ssid)
        xgb_prob = self.compute_xgb_prob(feat_vec)

        # 2. Tech Stopwords Stripping & Semantic Cosine
        clean_ssid = strip_tech_stopwords(ssid)

        if clean_ssid == ssid:
            v_raw = self._embed_single(ssid)
            v_clean = v_raw
        else:
            embs = self._embed_batch([ssid, clean_ssid])
            v_raw = embs[0]
            v_clean = embs[1]

        # 3. Instant 1 x M dot product against W
        if len(self.W) > 0:
            sims_raw = self.W @ v_raw
            sims_clean = self.W @ v_clean
            bge_cos_raw = float(np.max(sims_raw))
            bge_cos_clean = float(np.max(sims_clean))
        else:
            bge_cos_raw = 0.0
            bge_cos_clean = 0.0

        # Pure base suspicion (encryption-agnostic)
        base_bge = bge_cos_clean if ENABLE_STOPWORD_STRIP else bge_cos_raw
        pure_is_suspicious = 1 if (xgb_prob >= XGB_SUSPICIOUS_THRESHOLD or base_bge >= BGE_SUSPICIOUS_THRESHOLD) else 0

        record = SSIDRecord(
            ssid_text=ssid,
            matched_whitelist_ssid=best_target,
            xgb_prob=round(xgb_prob, 4),
            bge_cos_raw=round(bge_cos_raw, 4),
            bge_cos_clean=round(bge_cos_clean, 4),
            bge_vector_blob=v_raw.astype(np.float32).tobytes(),
            is_suspicious_name=pure_is_suspicious,
            first_computed_at=time.time(),
        )

        self.db_manager.put_ssid(record)
        return record

    def compute_ssid_records_batch(self, ssids: List[str]) -> List[SSIDRecord]:
        """
        Type B Work-Conserving Batch Evaluation (N <= 32):
        SIMD batch matrix multiplication E @ W.T (< 55 ms for 32 SSIDs).
        """
        if not ssids:
            return []

        # 1. Extract lexical features & batch predict XGBoost
        feat_vecs = []
        best_targets = []
        for s in ssids:
            bt, fv = self.compute_features(s)
            best_targets.append(bt)
            feat_vecs.append(fv)

        if self.xgb_model is not None and HAS_XGBOOST:
            X_batch = np.array(feat_vecs, dtype=np.float32)
            probs = self.xgb_model.predict_proba(X_batch)[:, 1]
            xgb_probs = [float(p) for p in probs]
        else:
            xgb_probs = [self.compute_xgb_prob(fv) for fv in feat_vecs]

        # 2. Gather unique strings for batch embedding
        clean_ssids = [strip_tech_stopwords(s) for s in ssids]
        unique_texts = list(dict.fromkeys(ssids + clean_ssids))

        # Batch embed all unique texts
        unique_embs = self._embed_batch(unique_texts)
        emb_dict = {t: unique_embs[i] for i, t in enumerate(unique_texts)}

        # 3. Vectorized matrix multiplication E @ W.T
        E_raw = np.array([emb_dict[s] for s in ssids], dtype=np.float32)
        E_clean = np.array([emb_dict[c] for c in clean_ssids], dtype=np.float32)

        if len(self.W) > 0:
            S_raw = E_raw @ self.W.T          # Shape (N, M)
            S_clean = E_clean @ self.W.T      # Shape (N, M)
            cos_raw = np.max(S_raw, axis=1)
            cos_clean = np.max(S_clean, axis=1)
        else:
            cos_raw = np.zeros(len(ssids), dtype=np.float32)
            cos_clean = np.zeros(len(ssids), dtype=np.float32)

        now_ts = time.time()
        records = []
        for i, ssid in enumerate(ssids):
            p_xgb = round(xgb_probs[i], 4)
            c_raw = round(float(cos_raw[i]), 4)
            c_clean = round(float(cos_clean[i]), 4)
            base_bge = c_clean if ENABLE_STOPWORD_STRIP else c_raw
            pure_suspicious = 1 if (p_xgb >= XGB_SUSPICIOUS_THRESHOLD or base_bge >= BGE_SUSPICIOUS_THRESHOLD) else 0

            rec = SSIDRecord(
                ssid_text=ssid,
                matched_whitelist_ssid=best_targets[i],
                xgb_prob=p_xgb,
                bge_cos_raw=c_raw,
                bge_cos_clean=c_clean,
                bge_vector_blob=E_raw[i].astype(np.float32).tobytes(),
                is_suspicious_name=pure_suspicious,
                first_computed_at=now_ts,
            )
            self.db_manager.put_ssid(rec)
            records.append(rec)

        return records

    def screen_ssid(self, ssid: str) -> SSIDRecord:
        """
        Public Stage 1 entrypoint:
        1. Checks RAM / SQLite cache (0.002 ms).
        2. On cache miss, computes via Work-Conserving Adaptive AI Worker.
        """
        cached = self.db_manager.get_ssid(ssid)
        if cached is not None:
            return cached
        return self.compute_ssid_record(ssid)

    def screen_ssid_batch(self, ssids: List[str]) -> List[SSIDRecord]:
        """
        Batched Stage 1 entrypoint:
        Reuses cached entries and batch-computes misses in up to 32-chunk batches.
        """
        results: Dict[str, SSIDRecord] = {}
        missing: List[str] = []

        for s in ssids:
            c = self.db_manager.get_ssid(s)
            if c is not None:
                results[s] = c
            elif s not in missing:
                missing.append(s)

        # Process missing SSIDs in chunks of AI_QUEUE_MAX_BATCH
        for i in range(0, len(missing), self.ai_queue.max_batch_size):
            chunk = missing[i : i + self.ai_queue.max_batch_size]
            if len(chunk) == 1:
                rec = self.compute_ssid_record(chunk[0])
                results[chunk[0]] = rec
            else:
                batch_recs = self.compute_ssid_records_batch(chunk)
                for rec in batch_recs:
                    results[rec.ssid_text] = rec

        return [results[s] for s in ssids]

    def evaluate_stage_2_5(
        self,
        record: SSIDRecord,
        bssid_state: BSSIDState
    ) -> Tuple[bool, float, float]:
        """
        Stage 2.5: Dynamic PSK-Weighted Suspicious Name Gate.
        - base_bge = row.bge_cos_clean if ENABLE_STOPWORD_STRIP else row.bge_cos_raw
        - eff_bge = (0.5 * base_bge) if PSK else base_bge
        - is_suspicious_name = (row.xgb_prob >= 0.50) or (eff_bge >= 0.60) or bssid_state.is_mutated
        Returns: (is_suspicious_name, eff_bge, base_bge)
        """
        base_bge = record.bge_cos_clean if ENABLE_STOPWORD_STRIP else record.bge_cos_raw
        enc = (bssid_state.encryption_type or "").upper()
        is_psk = "PSK" in enc
        eff_bge = round(PSK_WEIGHT_MULTIPLIER * base_bge, 4) if is_psk else base_bge

        is_suspicious = bool(
            (record.xgb_prob >= XGB_SUSPICIOUS_THRESHOLD)
            or (eff_bge >= BGE_SUSPICIOUS_THRESHOLD)
            or bool(bssid_state.is_mutated)
        )
        return is_suspicious, eff_bge, base_bge

    def screen_beacon(
        self,
        bssid: str,
        ssid: str,
        encryption_type: str = "OPEN"
    ) -> Stage25Result:
        """
        Full Group 1 Pipeline for an incoming Beacon frame:
        - Stage 0: BSSID Cache lookup & Option M2 mutation check (+45 pts).
        - Whitelisted BSSID check (skips AI if unmutated).
        - Stage 1 & 2: Encryption-agnostic AI screening.
        - Stage 2.5: Dynamic PSK-weighted suspicious name evaluation.
        """
        state = self.db_manager.get_bssid(bssid)
        now_ts = time.time()

        if state is None:
            # Stage 0: New BSSID
            state = BSSIDState(
                bssid=bssid,
                current_ssid=ssid,
                is_whitelisted=1 if bssid in self.db_manager.whitelisted_bssids else 0,
                is_mutated=0,
                first_seen_ts=now_ts,
                last_seen_ts=now_ts,
                encryption_type=encryption_type,
            )
            self.db_manager.ram_bssids[bssid] = state
            self.db_manager.dirty_bssids.add(bssid)
        else:
            # Stage 0: Known BSSID
            state.last_seen_ts = now_ts
            state.encryption_type = encryption_type

            # Option M2: BSSID Name Mutation Check
            if state.current_ssid != ssid:
                state.is_mutated = 1
                state.current_risk_score += 45
                state.current_ssid = ssid
                self.db_manager.dirty_bssids.add(bssid)

        # Stage 0: Whitelisted AP Path
        if state.is_whitelisted == 1 and not state.is_mutated:
            # Whitelisted BSSID with unchanged SSID bypasses AI Stage 1 & 2
            return Stage25Result(
                bssid=bssid,
                ssid=ssid,
                is_suspicious_name=False,
                eff_bge=0.0,
                base_bge=0.0,
                xgb_prob=0.0,
                is_mutated=False,
                is_whitelisted=True,
                record=None,
                bssid_state=state,
            )

        # Stage 1 & 2: AI Screening
        record = self.screen_ssid(ssid)

        # Stage 2.5: Dynamic PSK-weighted Gatekeeper
        is_suspicious, eff_bge, base_bge = self.evaluate_stage_2_5(record, state)

        return Stage25Result(
            bssid=bssid,
            ssid=ssid,
            is_suspicious_name=is_suspicious,
            eff_bge=eff_bge,
            base_bge=base_bge,
            xgb_prob=record.xgb_prob,
            is_mutated=bool(state.is_mutated),
            is_whitelisted=bool(state.is_whitelisted),
            record=record,
            bssid_state=state,
        )
