#!/usr/bin/env python3
"""
University Wi-Fi SSID Feature Extraction Module (f1 to f13)
Pure Python implementation optimized for ultra-low latency (< 0.05 ms) on edge sensors.
"""

import re
import math
from typing import Dict, List, Tuple, Any

# Common lure keywords used in Rogue AP / Evil Twin social engineering
LURE_KEYWORDS = {
    "login", "portal", "free", "fast", "vip", "verify", "5g", "autoconnect",
    "auth", "secure", "official", "guest", "visitor", "speed", "highspeed",
    "public", "connect", "signin", "wifi", "internet"
}

# Academic / University role keywords
ACADEMIC_ROLES = {
    "staff", "student", "faculty", "guest", "campus", "dorm", "library",
    "eduroam", "alumni", "lab", "research", "academy", "college", "admin"
}

DEFAULT_WHITELIST = [
    "University Campus 5G",
    "University Staff Secure",
    "University Student WiFi",
    "University Guest Portal",
    "eduroam",
    "Siam Wifi",
    "SiamXP Wifi",
    "SIAM WIFI",
    "SIAM XP WIFI"
]

# Homoglyph lookup pairs (visual look-alikes)
HOMOGLYPH_PAIRS = [
    ("1", "l"), ("1", "i"), ("0", "o"), ("5", "s"),
    ("rn", "m"), ("vv", "w"), ("cl", "d"), ("nn", "m"),
    # Cyrillic lookalikes
    ("\u0430", "a"),  # Cyrillic small 'а'
    ("\u0435", "e"),  # Cyrillic small 'е'
    ("\u043e", "o"),  # Cyrillic small 'о'
    ("\u0440", "p"),  # Cyrillic small 'р'
    ("\u0441", "c"),  # Cyrillic small 'с'
    ("\u0443", "y"),  # Cyrillic small 'у'
    ("\u0445", "x"),  # Cyrillic small 'х'
    ("\u0456", "i"),  # Cyrillic small 'і'
    ("\u0458", "j"),  # Cyrillic small 'ј'
    ("\u0455", "s"),  # Cyrillic small 'ѕ'
    # Greek lookalikes
    ("\u03BF", "o"),  # Greek small 'ο'
    ("\u03B1", "a"),  # Greek small 'α'
    ("\u03B9", "i"),  # Greek small 'ι'
    ("\u03BD", "v"),  # Greek small 'ν'
    ("\u03C1", "p"),  # Greek small 'ρ'
    ("\u03BA", "k"),  # Greek small 'κ'
]

DELIMITERS_REGEX = re.compile(r"[-_\.\s]+")


def levenshtein_distance(s1: str, s2: str) -> int:
    """Computes standard Levenshtein edit distance in O(min(m, n)) space."""
    if s1 == s2:
        return 0
    if len(s1) == 0:
        return len(s2)
    if len(s2) == 0:
        return len(s1)

    if len(s1) < len(s2):
        s1, s2 = s2, s1

    previous_row = list(range(len(s2) + 1))
    for i, c1 in enumerate(s1):
        current_row = [i + 1] + [0] * len(s2)
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row[j + 1] = min(insertions, deletions, substitutions)
        previous_row = current_row

    return previous_row[-1]


def damerau_levenshtein_distance(s1: str, s2: str) -> int:
    """Computes Damerau-Levenshtein distance accounting for adjacent transpositions."""
    d = {}
    len1, len2 = len(s1), len(s2)
    for i in range(-1, len1 + 1):
        d[(i, -1)] = i + 1
    for j in range(-1, len2 + 1):
        d[(-1, j)] = j + 1

    for i in range(len1):
        for j in range(len2):
            cost = 0 if s1[i] == s2[j] else 1
            d[(i, j)] = min(
                d[(i - 1, j)] + 1,       # deletion
                d[(i, j - 1)] + 1,       # insertion
                d[(i - 1, j - 1)] + cost # substitution
            )
            if i > 0 and j > 0 and s1[i] == s2[j - 1] and s1[i - 1] == s2[j]:
                d[(i, j)] = min(d[(i, j)], d[(i - 2, j - 2)] + 1) # transposition

    return d[(len1 - 1, len2 - 1)]


def jaro_winkler_similarity(s1: str, s2: str, prefix_scaling: float = 0.1) -> float:
    """Computes Jaro-Winkler similarity with prefix bonus."""
    if s1 == s2:
        return 1.0
    len1, len2 = len(s1), len(s2)
    if len1 == 0 or len2 == 0:
        return 0.0

    match_distance = max(len1, len2) // 2 - 1
    s1_matches = [False] * len1
    s2_matches = [False] * len2
    matches = 0
    transpositions = 0

    for i in range(len1):
        start = max(0, i - match_distance)
        end = min(i + match_distance + 1, len2)
        for j in range(start, end):
            if s2_matches[j] or s1[i] != s2[j]:
                continue
            s1_matches[i] = True
            s2_matches[j] = True
            matches += 1
            break

    if matches == 0:
        return 0.0

    k = 0
    for i in range(len1):
        if not s1_matches[i]:
            continue
        while not s2_matches[k]:
            k += 1
        if s1[i] != s2[k]:
            transpositions += 1
        k += 1

    jaro = (
        (matches / len1) +
        (matches / len2) +
        ((matches - transpositions / 2) / matches)
    ) / 3.0

    # Prefix match up to 4 characters
    prefix_len = 0
    for i in range(min(4, min(len1, len2))):
        if s1[i] == s2[i]:
            prefix_len += 1
        else:
            break

    return jaro + prefix_len * prefix_scaling * (1.0 - jaro)


def ngram_jaccard(s1: str, s2: str, n: int = 2) -> float:
    """Computes n-gram Jaccard index between two strings."""
    s1_lower = s1.lower()
    s2_lower = s2.lower()
    if len(s1_lower) < n or len(s2_lower) < n:
        return 1.0 if s1_lower == s2_lower else 0.0

    ngrams1 = set(s1_lower[i:i+n] for i in range(len(s1_lower) - n + 1))
    ngrams2 = set(s2_lower[i:i+n] for i in range(len(s2_lower) - n + 1))

    intersection = len(ngrams1 & ngrams2)
    union = len(ngrams1 | ngrams2)
    return intersection / union if union > 0 else 0.0


def count_homoglyphs(observed: str, target: str) -> int:
    """Counts visual character look-alike replacements."""
    obs_lower = observed.lower()
    tgt_lower = target.lower()
    count = 0
    for char_fake, char_real in HOMOGLYPH_PAIRS:
        # Check if fake character exists in observed where real character existed in target
        if char_fake in obs_lower and char_real in tgt_lower:
            extra = obs_lower.count(char_fake) - tgt_lower.count(char_fake)
            if extra > 0:
                count += extra
    return count


def extract_tokens(s: str) -> List[str]:
    """Splits an SSID into lowercase word tokens, handling delimiters, camelCase, and compounds (e.g. 'SiamXP' -> ['siam', 'xp'])."""
    tokens = []
    for part in DELIMITERS_REGEX.split(s):
        if not part:
            continue
        if part.lower() == "wifi":
            tokens.append("wifi")
            continue
        # Split specific SiamXP compound case-insensitively
        split_part = re.sub(r'(siam)(xp)', r'\1 \2', part, flags=re.IGNORECASE)
        # Standard camelCase splitting
        split_part = re.sub(r'([a-z])([A-Z])', r'\1 \2', split_part)
        split_part = re.sub(r'([A-Z]+)([A-Z][a-z])', r'\1 \2', split_part)
        for t in split_part.split():
            tokens.append(t.lower())
    return tokens


def extract_features(observed_ssid: str, target_authorized_ssid: str) -> Dict[str, Any]:
    """
    Extracts complete 13-feature vector between an observed SSID and an authorized target.
    Returns a dictionary of named features and raw numeric values.
    """
    s1, s2 = observed_ssid, target_authorized_ssid
    len1, len2 = len(s1), len(s2)
    max_len = max(len1, len2) or 1

    # f1: Levenshtein Ratio
    lev_dist = levenshtein_distance(s1, s2)
    f1_lev_ratio = round(1.0 - (lev_dist / max_len), 4)

    # f2: Damerau-Levenshtein Ratio
    dam_dist = damerau_levenshtein_distance(s1, s2)
    f2_dam_ratio = round(1.0 - (dam_dist / max_len), 4)

    # f3: Jaro-Winkler Similarity
    f3_jaro_winkler = round(jaro_winkler_similarity(s1, s2), 4)

    # f4: 2-Gram Jaccard
    f4_ngram2 = round(ngram_jaccard(s1, s2, n=2), 4)

    # f5: 3-Gram Jaccard
    f5_ngram3 = round(ngram_jaccard(s1, s2, n=3), 4)

    # f6: Homoglyph Count
    f6_homoglyphs = count_homoglyphs(s1, s2)

    # f7: Length Absolute Difference
    f7_len_abs_diff = abs(len1 - len2)

    # f8: Length Ratio (min / max)
    min_len = min(len1, len2)
    f8_len_ratio = round(min_len / max_len, 4) if max_len > 0 else 1.0

    # Token-level analysis
    tokens1 = extract_tokens(s1)
    tokens2 = extract_tokens(s2)
    set1, set2 = set(tokens1), set(tokens2)

    # f9: Token Overlap Jaccard
    token_inter = len(set1 & set2)
    token_union = len(set1 | set2)
    f9_token_jaccard = round(token_inter / token_union, 4) if token_union > 0 else 0.0

    # f10: Separator Mutation Delta
    seps1 = set(re.findall(r"[-_\.\s]", s1))
    seps2 = set(re.findall(r"[-_\.\s]", s2))
    f10_separator_delta = len(seps1 ^ seps2)

    # f11: Lure Keyword Score (count of lures added to s1 that were not in s2)
    lures_in_s1 = [t for t in tokens1 if t in LURE_KEYWORDS]
    lures_in_s2 = [t for t in tokens2 if t in LURE_KEYWORDS]
    f11_lure_flag = max(0, len(lures_in_s1) - len(lures_in_s2))

    # f12: Academic Role Collision
    roles_in_s1 = set(t for t in tokens1 if t in ACADEMIC_ROLES)
    roles_in_s2 = set(t for t in tokens2 if t in ACADEMIC_ROLES)
    f12_academic_role_collision = 1 if (roles_in_s1 != roles_in_s2 and len(roles_in_s1) > 0 and len(roles_in_s2) > 0) else 0

    # f13: Prefix Match Ratio
    common_prefix_len = 0
    for c1, c2 in zip(s1, s2):
        if c1 == c2:
            common_prefix_len += 1
        else:
            break
    f13_prefix_ratio = round(common_prefix_len / len2, 4) if len2 > 0 else 0.0

    return {
        "f1_lev_ratio": f1_lev_ratio,
        "f2_dam_ratio": f2_dam_ratio,
        "f3_jaro_winkler": f3_jaro_winkler,
        "f4_ngram2": f4_ngram2,
        "f5_ngram3": f5_ngram3,
        "f6_homoglyphs": f6_homoglyphs,
        "f7_len_abs_diff": f7_len_abs_diff,
        "f8_len_ratio": f8_len_ratio,
        "f9_token_jaccard": f9_token_jaccard,
        "f10_separator_delta": f10_separator_delta,
        "f11_lure_flag": f11_lure_flag,
        "f12_academic_role_collision": f12_academic_role_collision,
        "f13_prefix_ratio": f13_prefix_ratio
    }


def find_best_whitelist_match(observed_ssid: str, whitelist: List[str]) -> Tuple[str, Dict[str, Any]]:
    """
    Compares an observed SSID against all whitelisted targets and returns
    the best matching authorized SSID along with its extracted feature vector.
    """
    best_target = whitelist[0]
    best_features = extract_features(observed_ssid, best_target)
    highest_score = best_features["f3_jaro_winkler"]

    for target in whitelist[1:]:
        feat = extract_features(observed_ssid, target)
        if feat["f3_jaro_winkler"] > highest_score:
            highest_score = feat["f3_jaro_winkler"]
            best_target = target
            best_features = feat

    return best_target, best_features


if __name__ == "__main__":
    # Smoke test with University samples
    test_obs = "University_Campus_5G_Free"
    test_auth = "University_Campus_5G"
    feats = extract_features(test_obs, test_auth)
    print(f"Features for '{test_obs}' vs '{test_auth}':")
    for k, v in feats.items():
        print(f"  {k:30s}: {v}")
