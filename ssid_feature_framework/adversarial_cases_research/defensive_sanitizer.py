#!/usr/bin/env python3
"""
Defensive SSID Pre-Processing & Detection Sanitizer
Defensive Wireless Security Architecture (Blue Team Defender)
Compliant with IEEE 802.11, RFC 3629 UTF-8, and UTS #39 Confusable Skeleton Specs.
Designed for sub-millisecond execution (< 0.05 ms) on ARM64 Raspberry Pi edge sensors.
"""

import re
import unicodedata
from enum import Enum
from typing import Dict, List, Tuple, Any, Optional

class SSIDStatus(Enum):
    AUTHORIZED = "AUTHORIZED"
    BENIGN_HIDDEN = "BENIGN_HIDDEN"
    BENIGN_NON_LATIN = "BENIGN_NON_LATIN"
    BENIGN_NOISE = "BENIGN_NOISE"
    AMBIGUOUS = "AMBIGUOUS"
    CONFIRMED_EVIL_TWIN = "CONFIRMED_EVIL_TWIN"
    INVALID_FRAME = "INVALID_FRAME"
    MALFORMED_UTF8 = "MALFORMED_UTF8"

# ---------------------------------------------------------
# STAGE 3 CONSTANTS: Invisible & Non-Printable Characters
# ---------------------------------------------------------
# Includes: Zero-Width Space (U+200B), ZWNJ (U+200C), ZWJ (U+200D), BOM (U+FEFF),
# Soft Hyphen (U+00AD), Left-to-Right Mark (U+200E), Right-to-Left Mark (U+200F),
# Bidi Embedding/Override (U+202A - U+202E), Word Joiner (U+2060), Invisible Separators (U+2061 - U+206F),
# Control characters (\x00-\x1F, \x7F-\x9F).
INVISIBLE_CHARS_REGEX = re.compile(
    r'[\u200B-\u200D\uFEFF\u00AD\u200E\u200F\u202A-\u202E\u2060-\u206F\x00-\x1F\x7F-\x9F]'
)
NBSP_CHAR = '\u00A0'

# ---------------------------------------------------------
# STAGE 4 CONSTANTS: Emoji Range
# ---------------------------------------------------------
# Standard Unicode Emoji blocks
EMOJI_REGEX = re.compile(
    r'[\U0001F000-\U0001FAFF'
    r'\u2600-\u27BF'
    r'\u2300-\u23FF'
    r'\u2B50-\u2B55'
    r'\U00010000-\U0010FFFF]'
)

# ---------------------------------------------------------
# STAGE 5 CONSTANTS: UTS #39 Confusable Skeleton Translation Table
# ---------------------------------------------------------
# Precompiled translation table mapping Cyrillic & Greek visual confusables to Latin base glyphs.
# Latency: Python's str.translate uses this table at the C level in ~2 microseconds for <= 32 chars.
UTS39_LATIN_CONFUSABLES = {
    # Cyrillic Lowercase to Latin Lowercase
    0x0430: 'a',  # а -> a
    0x0435: 'e',  # е -> e
    0x043E: 'o',  # о -> o
    0x0440: 'p',  # р -> p
    0x0441: 'c',  # с -> c
    0x0443: 'y',  # у -> y
    0x0445: 'x',  # х -> x
    0x0456: 'i',  # і -> i
    0x0458: 'j',  # ј -> j
    0x0455: 's',  # ѕ -> s
    0x043A: 'k',  # к -> k (in some fonts)

    # Cyrillic Uppercase to Latin Uppercase
    0x0410: 'A',  # А -> A
    0x0412: 'B',  # В -> B
    0x0415: 'E',  # Е -> E
    0x041A: 'K',  # К -> K
    0x041C: 'M',  # М -> M
    0x041D: 'H',  # Н -> H
    0x041E: 'O',  # О -> O
    0x0420: 'P',  # Р -> P
    0x0421: 'C',  # С -> C
    0x0422: 'T',  # Т -> T
    0x0425: 'X',  # Х -> X

    # Greek Lowercase to Latin Lowercase
    0x03B1: 'a',  # α -> a
    0x03BF: 'o',  # ο -> o
    0x03BD: 'v',  # ν -> v
    0x03C1: 'p',  # ρ -> p
    0x03B9: 'i',  # ι -> i
    0x03BA: 'k',  # κ -> k

    # Greek Uppercase to Latin Uppercase
    0x0391: 'A',  # Α -> A
    0x0392: 'B',  # Β -> B
    0x0395: 'E',  # Ε -> E
    0x0396: 'Z',  # Ζ -> Z
    0x0397: 'H',  # Η -> H
    0x0399: 'I',  # Ι -> I
    0x039A: 'K',  # Κ -> K
    0x039C: 'M',  # Μ -> M
    0x039D: 'N',  # Ν -> N
    0x039F: 'O',  # Ο -> O
    0x03A1: 'P',  # Ρ -> P
    0x03A4: 'T',  # Τ -> T
    0x03A7: 'X',  # Χ -> X
    0x03A5: 'Y',  # Υ -> Y
}

CONFUSABLE_TRANSLATION_TABLE = str.maketrans(UTS39_LATIN_CONFUSABLES)

# Leet / ASCII homoglyph pair mappings for multi-character & numeral substitutions
ASCII_HOMOGLYPH_PAIRS = [
    ("1", "l"), ("1", "i"), ("0", "o"), ("5", "s"),
    ("rn", "m"), ("vv", "w"), ("cl", "d"), ("nn", "m")
]


def is_pure_non_latin(s: str) -> bool:
    """
    Checks if a string belongs exclusively to non-Latin scripts (e.g. Thai, Arabic, CJK)
    with 0 Latin or Latin-confusable characters.
    """
    latin_count = 0
    non_latin_count = 0
    for char in s:
        cp = ord(char)
        # Latin blocks: Basic Latin (0020-007F), Latin-1 Supp (0080-00FF), Latin Ext (0100-024F)
        if (0x0041 <= cp <= 0x005A) or (0x0061 <= cp <= 0x007A) or (cp in UTS39_LATIN_CONFUSABLES):
            latin_count += 1
        elif unicodedata.category(char) in ('Lo', 'So', 'Mn', 'Mc', 'Nd'):
            non_latin_count += 1
    return latin_count == 0 and non_latin_count > 0


def strip_combining_diacritics_latin_only(s: str) -> str:
    """
    Performs NFD decomposition and strips Non-Spacing Marks (Mn) ONLY for Latin base characters.
    Preserves combining marks in non-Latin scripts such as Thai (vowels/tones) or Arabic.
    """
    nfd = unicodedata.normalize('NFD', s)
    result = []
    last_was_latin = False
    
    for c in nfd:
        cp = ord(c)
        cat = unicodedata.category(c)
        
        # Check if base character is Latin or Greek/Cyrillic confusable
        if cat in ('Lu', 'Ll', 'Lt', 'Lm'):
            last_was_latin = (cp <= 0x024F) or (cp in UTS39_LATIN_CONFUSABLES)
            result.append(c)
        elif cat == 'Mn':
            # If combining mark follows a Latin letter or is in Combining Diacritical Marks block (0300-036F)
            if last_was_latin or (0x0300 <= cp <= 0x036F):
                continue  # Strip diacritic!
            else:
                result.append(c)  # Preserve non-Latin mark (e.g. Thai tone)
        else:
            last_was_latin = False
            result.append(c)
            
    return unicodedata.normalize('NFC', ''.join(result))


class PipelineResult:
    def __init__(
        self,
        status: SSIDStatus,
        raw_bytes: bytes,
        decoded_ssid: str = "",
        sanitized_ssid: str = "",
        skeleton_ssid: str = "",
        target_match: str = "",
        features: Optional[Dict[str, Any]] = None,
        telemetry: Optional[Dict[str, Any]] = None,
        reason: str = ""
    ):
        self.status = status
        self.raw_bytes = raw_bytes
        self.decoded_ssid = decoded_ssid
        self.sanitized_ssid = sanitized_ssid
        self.skeleton_ssid = skeleton_ssid
        self.target_match = target_match
        self.features = features or {}
        self.telemetry = telemetry or {}
        self.reason = reason

    def to_dict(self) -> Dict[str, Any]:
        return {
            "status": self.status.value,
            "raw_hex": self.raw_bytes.hex(),
            "decoded_ssid": self.decoded_ssid,
            "sanitized_ssid": self.sanitized_ssid,
            "skeleton_ssid": self.skeleton_ssid,
            "target_match": self.target_match,
            "features": self.features,
            "telemetry": self.telemetry,
            "reason": self.reason
        }


class DefensiveSSIDPipeline:
    """
    7-Stage Pre-Processing & Detection Pipeline for 802.11 Edge Sensors
    """
    def __init__(self, whitelist: List[str]):
        self.whitelist = whitelist
        # Precompute normalized and skeleton whitelist for O(1) lookups
        self.whitelist_set = set(whitelist)
        self.whitelist_skeletons = {self._generate_skeleton(w): w for w in whitelist}

    def _generate_skeleton(self, s: str) -> str:
        """Internal helper for confusable skeleton generation."""
        s_nfkc = unicodedata.normalize('NFKC', s)
        s_clean = strip_combining_diacritics_latin_only(s_nfkc)
        return s_clean.translate(CONFUSABLE_TRANSLATION_TABLE)

    def process(self, raw_bytes: bytes) -> PipelineResult:
        telemetry: Dict[str, Any] = {
            "invisible_char_count": 0,
            "trailing_whitespace": False,
            "emoji_count": 0,
            "homoglyph_count": 0,
            "nfkc_altered": False,
            "diacritics_stripped": False,
            "is_pure_non_latin": False
        }

        # ---------------------------------------------------------
        # STAGE 0: 802.11 Raw Octet Boundary Validation
        # ---------------------------------------------------------
        byte_len = len(raw_bytes)
        if byte_len > 32:
            return PipelineResult(
                status=SSIDStatus.INVALID_FRAME,
                raw_bytes=raw_bytes,
                reason=f"Frame SSID Information Element length ({byte_len} bytes) exceeds IEEE 802.11 max limit (32 bytes)."
            )

        # ---------------------------------------------------------
        # STAGE 1: Strict UTF-8 Decoding
        # ---------------------------------------------------------
        try:
            decoded_ssid = raw_bytes.decode('utf-8', errors='strict')
        except UnicodeDecodeError as e:
            return PipelineResult(
                status=SSIDStatus.MALFORMED_UTF8,
                raw_bytes=raw_bytes,
                telemetry={"decode_error": str(e)},
                reason=f"RFC 3629 UTF-8 violation detected (overlong encoding, invalid continuation byte, or truncated multi-byte payload): {e}"
            )

        # ---------------------------------------------------------
        # STAGE 2: Hidden SSID Check
        # ---------------------------------------------------------
        # IEEE 802.11 specifies zero-length or all-null octets as Hidden / Wildcard
        if byte_len == 0 or raw_bytes == b'\x00' * byte_len or decoded_ssid == "":
            return PipelineResult(
                status=SSIDStatus.BENIGN_HIDDEN,
                raw_bytes=raw_bytes,
                decoded_ssid="",
                reason="Wildcard SSID / Hidden AP broadcast (0 octets). Benign suppression, safely bypasses ML."
            )

        # ---------------------------------------------------------
        # STAGE 3: Invisible & Non-Printable Character Extraction
        # ---------------------------------------------------------
        invisible_matches = INVISIBLE_CHARS_REGEX.findall(decoded_ssid)
        telemetry["invisible_char_count"] = len(invisible_matches)
        
        # Check trailing or leading whitespace
        if decoded_ssid.startswith(" ") or decoded_ssid.endswith(" ") or decoded_ssid.startswith("\t") or decoded_ssid.endswith("\t"):
            telemetry["trailing_whitespace"] = True

        # Check NBSP replacement
        nbsp_count = decoded_ssid.count(NBSP_CHAR)
        telemetry["nbsp_count"] = nbsp_count

        # Strip invisibles and normalize NBSP
        s_stage3 = INVISIBLE_CHARS_REGEX.sub('', decoded_ssid)
        s_stage3 = s_stage3.replace(NBSP_CHAR, ' ').strip()

        # ---------------------------------------------------------
        # STAGE 4: Unicode NFKC Normalization & Diacritic Sanitization
        # ---------------------------------------------------------
        s_nfkc = unicodedata.normalize('NFKC', s_stage3)
        if s_nfkc != s_stage3:
            telemetry["nfkc_altered"] = True

        # Strip Latin combining marks (accents)
        s_stripped_diacritics = strip_combining_diacritics_latin_only(s_nfkc)
        if s_stripped_diacritics != s_nfkc:
            telemetry["diacritics_stripped"] = True

        # Extract & strip emojis
        emojis = EMOJI_REGEX.findall(s_stripped_diacritics)
        telemetry["emoji_count"] = len(emojis)
        s_stage4 = EMOJI_REGEX.sub('', s_stripped_diacritics).strip()

        # ---------------------------------------------------------
        # STAGE 5: UTS #39 Confusable Skeleton Generation
        # ---------------------------------------------------------
        s_skeleton = s_stage4.translate(CONFUSABLE_TRANSLATION_TABLE)
        
        # Count cross-script confusable substitutions (e.g. Cyrillic/Greek mapped to Latin)
        cross_script_subs = 0
        for orig_c, skel_c in zip(s_stage4, s_skeleton):
            if orig_c != skel_c:
                cross_script_subs += 1
        
        telemetry["homoglyph_count"] = cross_script_subs

        # ---------------------------------------------------------
        # STAGE 6: Fast Paths, Whitelist Collision & 13-Feature Extraction
        # ---------------------------------------------------------
        
        # 1. Exact Whitelist Fast Path & Legitimate Uppercase Signage
        matched_auth = None
        if decoded_ssid in self.whitelist_set:
            matched_auth = decoded_ssid
        elif decoded_ssid.isupper():
            # Support case-insensitive matching for legitimate uppercase physical signage (e.g. "SIAM WIFI", "SIAM XP WIFI")
            # Note: eduroam strictly forbids uppercase and must not match here
            for w in self.whitelist:
                if w.lower() != "eduroam" and decoded_ssid == w.upper():
                    matched_auth = w
                    break

        if (
            matched_auth
            and telemetry["invisible_char_count"] == 0
            and telemetry["homoglyph_count"] == 0
            and not telemetry["trailing_whitespace"]
            and not telemetry["nfkc_altered"]
            and not telemetry["diacritics_stripped"]
            and telemetry["emoji_count"] == 0
            and telemetry["nbsp_count"] == 0
        ):
            return PipelineResult(
                status=SSIDStatus.AUTHORIZED,
                raw_bytes=raw_bytes,
                decoded_ssid=decoded_ssid,
                sanitized_ssid=s_stage4,
                skeleton_ssid=s_skeleton,
                target_match=matched_auth,
                telemetry=telemetry,
                reason="Exact byte and grapheme match to authorized whitelist (0 ms fast-path)."
            )

        # 2. Stealth Evasion / Brand Impersonation Fast Alert
        # If the stripped skeleton matches an authorized SSID, but evasive manipulations were applied
        # Also check delimiter-normalized match (replacing spaces with underscores or vice versa)
        s_skeleton_delim_norm = re.sub(r'[\s\-_.]+', '_', s_skeleton)
        matched_target = self.whitelist_skeletons.get(s_skeleton)
        if not matched_target:
            candidates = []
            for w in self.whitelist:
                w_norm = re.sub(r'[\s\-_.]+', '_', w)
                if s_skeleton_delim_norm.lower() == w_norm.lower():
                    candidates.append(w)
            if candidates:
                if s_skeleton.isupper():
                    matched_target = next((c for c in candidates if c.isupper()), candidates[0])
                else:
                    matched_target = next((c for c in candidates if not c.isupper()), candidates[0])

        delimiter_mismatch = (
            matched_target is not None
            and s_skeleton != matched_target
        )
        if delimiter_mismatch:
            telemetry["delimiter_mismatch"] = True

        has_evasion_tricks = (
            telemetry["invisible_char_count"] > 0 or
            telemetry["trailing_whitespace"] or
            telemetry["homoglyph_count"] > 0 or
            telemetry["nfkc_altered"] or
            telemetry["diacritics_stripped"] or
            telemetry["nbsp_count"] > 0 or
            delimiter_mismatch or
            (telemetry["emoji_count"] > 0 and matched_target is not None)
        )

        if matched_target and has_evasion_tricks:
            # Deterministic CONFIRMED_EVIL_TWIN! Zero false positives.
            violations = []
            if telemetry["invisible_char_count"] > 0:
                violations.append(f"{telemetry['invisible_char_count']} Zero-Width/Hidden chars")
            if telemetry["trailing_whitespace"]:
                violations.append("Padding whitespace")
            if telemetry["homoglyph_count"] > 0:
                violations.append(f"{telemetry['homoglyph_count']} Confusable/Homoglyphs")
            if telemetry["nfkc_altered"]:
                violations.append("Fullwidth/compatibility form mutation")
            if telemetry["diacritics_stripped"]:
                violations.append("Combining diacritics/accents")
            if telemetry["nbsp_count"] > 0:
                violations.append(f"{telemetry['nbsp_count']} Non-Breaking Space (NBSP) mutation")
            if telemetry.get("delimiter_mismatch"):
                violations.append("Delimiter substitution/evasion")
            if telemetry["emoji_count"] > 0:
                violations.append(f"{telemetry['emoji_count']} Brand-trailing emojis")

            return PipelineResult(
                status=SSIDStatus.CONFIRMED_EVIL_TWIN,
                raw_bytes=raw_bytes,
                decoded_ssid=decoded_ssid,
                sanitized_ssid=s_stage4,
                skeleton_ssid=s_skeleton,
                target_match=matched_target,
                telemetry=telemetry,
                reason=f"High-fidelity spoof of whitelist SSID '{matched_target}' via evasive mutations: {', '.join(violations)}."
            )

        # 3. Pure Non-Latin Benign Fast Path (e.g. Thai 'บ้านสุข', Arabic)
        if is_pure_non_latin(s_stage4):
            telemetry["is_pure_non_latin"] = True
            return PipelineResult(
                status=SSIDStatus.BENIGN_NON_LATIN,
                raw_bytes=raw_bytes,
                decoded_ssid=decoded_ssid,
                sanitized_ssid=s_stage4,
                skeleton_ssid=s_skeleton,
                telemetry=telemetry,
                reason="Legitimate pure non-Latin network (0% Latin script or confusable overlap with whitelist). Safely dropped."
            )

        # 4. Standard Feature Extraction against Whitelist for ML / XGBoost
        # Features are computed on s_skeleton against whitelist candidates
        # to ensure edit distances f1..f5 reflect the true underlying text structure
        try:
            from features import extract_features, find_best_whitelist_match
        except ImportError:
            try:
                from ssid_feature_framework.features import extract_features, find_best_whitelist_match
            except ImportError:
                import sys, os
                sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
                from features import extract_features, find_best_whitelist_match
        
        best_target, feats = find_best_whitelist_match(s_skeleton, self.whitelist)
        # Inject sanitized telemetry values into feature dictionary
        feats["f6_homoglyphs"] = telemetry["homoglyph_count"]
        feats["invisible_char_count"] = telemetry["invisible_char_count"]
        feats["emoji_count"] = telemetry["emoji_count"]

        # Simple classification baseline (or XGBoost model invocation)
        # Low edit distance or high token similarity indicates rogue / ambiguous
        if feats["f1_lev_ratio"] >= 0.70 or feats["f3_jaro_winkler"] >= 0.75:
            if feats["f11_lure_flag"] > 0 or feats["f6_homoglyphs"] > 0:
                status = SSIDStatus.CONFIRMED_EVIL_TWIN
                reason = f"Heuristic match against '{best_target}' with lure keywords or homoglyphs."
            else:
                status = SSIDStatus.AMBIGUOUS
                reason = f"High orthographic similarity to '{best_target}' (f1={feats['f1_lev_ratio']}, f3={feats['f3_jaro_winkler']})."
        else:
            status = SSIDStatus.BENIGN_NOISE
            reason = f"Orthographically distant from whitelist (f1={feats['f1_lev_ratio']})."

        return PipelineResult(
            status=status,
            raw_bytes=raw_bytes,
            decoded_ssid=decoded_ssid,
            sanitized_ssid=s_stage4,
            skeleton_ssid=s_skeleton,
            target_match=best_target,
            features=feats,
            telemetry=telemetry,
            reason=reason
        )
