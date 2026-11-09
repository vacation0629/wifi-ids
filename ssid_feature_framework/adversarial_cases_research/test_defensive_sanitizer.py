#!/usr/bin/env python3
"""
Unit Test Suite for Defensive SSID Sanitization Pipeline (Blue Team Defender)
Validates all Adversarial Evasion Case Groups including Siam Wifi & SiamXP Wifi
"""

import sys
import os
import time

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from defensive_sanitizer import DefensiveSSIDPipeline, SSIDStatus

WHITELIST = [
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

def run_tests():
    pipeline = DefensiveSSIDPipeline(WHITELIST)
    passed = 0
    total = 0

    test_cases = [
        # ----------------------------------------------------
        # Group 1: Cross-Script Homoglyphs
        # ----------------------------------------------------
        {
            "group": "Group 1: Cross-Script Homoglyphs",
            "name": "Cyrillic Small Letter Ie (\\u0435) in University",
            "raw": "Univ\u0435rsity Campus 5G".encode('utf-8'),
            "expected_status": SSIDStatus.CONFIRMED_EVIL_TWIN,
            "check": lambda res: res.telemetry["homoglyph_count"] >= 1 and res.skeleton_ssid == "University Campus 5G"
        },
        {
            "group": "Group 1: Cross-Script Homoglyphs",
            "name": "Greek Small Letter Omicron (\\u03BF) in eduroam",
            "raw": "edur\u03BFam".encode('utf-8'),
            "expected_status": SSIDStatus.CONFIRMED_EVIL_TWIN,
            "check": lambda res: res.telemetry["homoglyph_count"] >= 1 and res.skeleton_ssid == "eduroam"
        },
        {
            "group": "Group 1: Cross-Script Homoglyphs",
            "name": "Multi-script Cyrillic (e, a) in University Campus 5G",
            "raw": "Univ\u0435rsity C\u0430mpus 5G".encode('utf-8'),
            "expected_status": SSIDStatus.CONFIRMED_EVIL_TWIN,
            "check": lambda res: res.telemetry["homoglyph_count"] >= 2 and res.skeleton_ssid == "University Campus 5G"
        },
        {
            "group": "Group 1: Cross-Script Homoglyphs",
            "name": "Cyrillic Small Letter Byelorussian-Ukrainian I (\\u0456) in Siam Wifi",
            "raw": "S\u0456am Wifi".encode('utf-8'),
            "expected_status": SSIDStatus.CONFIRMED_EVIL_TWIN,
            "check": lambda res: res.telemetry["homoglyph_count"] >= 1 and res.skeleton_ssid == "Siam Wifi"
        },
        {
            "group": "Group 1: Cross-Script Homoglyphs",
            "name": "Cyrillic Small Letter Byelorussian-Ukrainian I (\\u0456) in SiamXP Wifi",
            "raw": "S\u0456amXP Wifi".encode('utf-8'),
            "expected_status": SSIDStatus.CONFIRMED_EVIL_TWIN,
            "check": lambda res: res.telemetry["homoglyph_count"] >= 1 and res.skeleton_ssid == "SiamXP Wifi"
        },

        # ----------------------------------------------------
        # Group 2: Invisible or Whitespace Manipulations
        # ----------------------------------------------------
        {
            "group": "Group 2: Invisible / Whitespace",
            "name": "Zero-Width Space (U+200B) at end of University Campus 5G",
            "raw": "University Campus 5G\u200B".encode('utf-8'),
            "expected_status": SSIDStatus.CONFIRMED_EVIL_TWIN,
            "check": lambda res: res.telemetry["invisible_char_count"] == 1 and res.skeleton_ssid == "University Campus 5G"
        },
        {
            "group": "Group 2: Invisible / Whitespace",
            "name": "Zero-Width Space (U+200B) at end of Siam Wifi",
            "raw": "Siam Wifi\u200B".encode('utf-8'),
            "expected_status": SSIDStatus.CONFIRMED_EVIL_TWIN,
            "check": lambda res: res.telemetry["invisible_char_count"] == 1 and res.skeleton_ssid == "Siam Wifi"
        },
        {
            "group": "Group 2: Invisible / Whitespace",
            "name": "Byte Order Mark (U+FEFF) prepended",
            "raw": "\uFEFFUniversity Campus 5G".encode('utf-8'),
            "expected_status": SSIDStatus.CONFIRMED_EVIL_TWIN,
            "check": lambda res: res.telemetry["invisible_char_count"] == 1 and res.skeleton_ssid == "University Campus 5G"
        },
        {
            "group": "Group 2: Invisible / Whitespace",
            "name": "Trailing ASCII Space padding",
            "raw": "University Campus 5G ".encode('utf-8'),
            "expected_status": SSIDStatus.CONFIRMED_EVIL_TWIN,
            "check": lambda res: res.telemetry["trailing_whitespace"] is True and res.skeleton_ssid == "University Campus 5G"
        },
        {
            "group": "Group 2: Invisible / Whitespace",
            "name": "Non-Breaking Space (U+00A0) delimiter replacement",
            "raw": "University\u00A0Campus\u00A05G".encode('utf-8'),
            "expected_status": SSIDStatus.CONFIRMED_EVIL_TWIN,
            "check": lambda res: res.skeleton_ssid == "University Campus 5G"
        },

        # ----------------------------------------------------
        # Group 3: Unicode Normalization & Combining Accents
        # ----------------------------------------------------
        {
            "group": "Group 3: Normalization & Diacritics",
            "name": "Fullwidth Latin U (\\uFF35)",
            "raw": "\uFF35niversity Campus 5G".encode('utf-8'),
            "expected_status": SSIDStatus.CONFIRMED_EVIL_TWIN,
            "check": lambda res: res.telemetry["nfkc_altered"] is True and res.skeleton_ssid == "University Campus 5G"
        },
        {
            "group": "Group 3: Normalization & Diacritics",
            "name": "Decomposed Combining Acute Accent (\\u0065\\u0301)",
            "raw": "Univ\u0065\u0301rsity Campus 5G".encode('utf-8'),
            "expected_status": SSIDStatus.CONFIRMED_EVIL_TWIN,
            "check": lambda res: res.telemetry["diacritics_stripped"] is True and res.skeleton_ssid == "University Campus 5G"
        },

        # ----------------------------------------------------
        # Group 4: Emoji & Non-Latin Benign
        # ----------------------------------------------------
        {
            "group": "Group 4: Emoji & Non-Latin",
            "name": "University Brand with Appended Emoji (University Campus 5G📶)",
            "raw": "University Campus 5G📶".encode('utf-8'),
            "expected_status": SSIDStatus.CONFIRMED_EVIL_TWIN,
            "check": lambda res: res.telemetry["emoji_count"] == 1 and res.skeleton_ssid == "University Campus 5G"
        },
        {
            "group": "Group 4: Emoji & Non-Latin",
            "name": "Siam Wifi Brand with Appended Emoji (Siam Wifi📶)",
            "raw": "Siam Wifi📶".encode('utf-8'),
            "expected_status": SSIDStatus.CONFIRMED_EVIL_TWIN,
            "check": lambda res: res.telemetry["emoji_count"] == 1 and res.skeleton_ssid == "Siam Wifi"
        },
        {
            "group": "Group 4: Emoji & Non-Latin",
            "name": "Standalone Benign Network with Emoji (Home📶)",
            "raw": "Home📶".encode('utf-8'),
            "expected_status": SSIDStatus.BENIGN_NOISE,
            "check": lambda res: res.telemetry["emoji_count"] == 1 and res.skeleton_ssid == "Home"
        },
        {
            "group": "Group 4: Emoji & Non-Latin",
            "name": "Legitimate Non-Latin Thai Network (บ้านสุข - 21 bytes)",
            "raw": "บ้านสุข".encode('utf-8'),
            "expected_status": SSIDStatus.BENIGN_NON_LATIN,
            "check": lambda res: res.telemetry["is_pure_non_latin"] is True and res.decoded_ssid == "บ้านสุข"
        },

        # ----------------------------------------------------
        # Group 5: Byte-level Breakage & 802.11 Compliance
        # ----------------------------------------------------
        {
            "group": "Group 5: Byte Breakage & 802.11 Spec",
            "name": "Oversized SSID Frame (33 octets > 32 max)",
            "raw": b"A" * 33,
            "expected_status": SSIDStatus.INVALID_FRAME,
            "check": lambda res: "exceeds IEEE 802.11" in res.reason
        },
        {
            "group": "Group 5: Byte Breakage & 802.11 Spec",
            "name": "Overlong UTF-8 Sequence (\\xc1\\xa1)",
            "raw": b"\xc1\xa1_test",
            "expected_status": SSIDStatus.MALFORMED_UTF8,
            "check": lambda res: "RFC 3629" in res.reason
        },
        {
            "group": "Group 5: Byte Breakage & 802.11 Spec",
            "name": "Truncated Multi-Byte Sequence (\\xe0\\xb8 missing 3rd byte)",
            "raw": b"\xe0\xb8",
            "expected_status": SSIDStatus.MALFORMED_UTF8,
            "check": lambda res: "unexpected end of data" in res.telemetry.get("decode_error", "")
        },
        {
            "group": "Group 5: Byte Breakage & 802.11 Spec",
            "name": "Zero-Length Hidden SSID (0 octets)",
            "raw": b"",
            "expected_status": SSIDStatus.BENIGN_HIDDEN,
            "check": lambda res: res.decoded_ssid == ""
        },
        {
            "group": "Group 5: Byte Breakage & 802.11 Spec",
            "name": "All-Null Octet Hidden SSID (\\x00*6)",
            "raw": b"\x00" * 6,
            "expected_status": SSIDStatus.BENIGN_HIDDEN,
            "check": lambda res: "Hidden AP" in res.reason
        },

        # ----------------------------------------------------
        # Group 6: Delimiter Substitution & Evasion
        # ----------------------------------------------------
        {
            "group": "Group 6: Delimiter Evasion",
            "name": "Underscore Delimiter Spoofing (Siam_Wifi targeting Siam Wifi)",
            "raw": "Siam_Wifi".encode('utf-8'),
            "expected_status": SSIDStatus.CONFIRMED_EVIL_TWIN,
            "check": lambda res: res.target_match == "Siam Wifi" and res.telemetry.get("delimiter_mismatch") is True
        },
        {
            "group": "Group 6: Delimiter Evasion",
            "name": "Hyphen Delimiter Spoofing (Siam-Wifi targeting Siam Wifi)",
            "raw": "Siam-Wifi".encode('utf-8'),
            "expected_status": SSIDStatus.CONFIRMED_EVIL_TWIN,
            "check": lambda res: res.target_match == "Siam Wifi" and res.telemetry.get("delimiter_mismatch") is True
        },
        {
            "group": "Group 6: Delimiter Evasion",
            "name": "Underscore Delimiter Spoofing (SiamXP_Wifi targeting SiamXP Wifi)",
            "raw": "SiamXP_Wifi".encode('utf-8'),
            "expected_status": SSIDStatus.CONFIRMED_EVIL_TWIN,
            "check": lambda res: res.target_match == "SiamXP Wifi" and res.telemetry.get("delimiter_mismatch") is True
        },
        {
            "group": "Group 6: Delimiter Evasion",
            "name": "Underscore Delimiter Spoofing (University_Campus_5G targeting University Campus 5G)",
            "raw": "University_Campus_5G".encode('utf-8'),
            "expected_status": SSIDStatus.CONFIRMED_EVIL_TWIN,
            "check": lambda res: res.target_match == "University Campus 5G" and res.telemetry.get("delimiter_mismatch") is True
        },
        {
            "group": "Group 6: Delimiter Evasion",
            "name": "Double Space Delimiter Injection (Siam  Wifi targeting Siam Wifi)",
            "raw": "Siam  Wifi".encode('utf-8'),
            "expected_status": SSIDStatus.CONFIRMED_EVIL_TWIN,
            "check": lambda res: res.target_match == "Siam Wifi" and res.telemetry.get("delimiter_mismatch") is True
        },
        {
            "group": "Group 6: Delimiter Evasion",
            "name": "Uppercase Delimiter Mutation (SIAM_WIFI targeting Siam Wifi)",
            "raw": "SIAM_WIFI".encode('utf-8'),
            "expected_status": SSIDStatus.CONFIRMED_EVIL_TWIN,
            "check": lambda res: res.target_match in ("Siam Wifi", "SIAM WIFI") and res.telemetry.get("delimiter_mismatch") is True
        },
        {
            "group": "Group 6: Delimiter Evasion",
            "name": "Lowercase Case Anomaly (university campus 5g targeting University Campus 5G)",
            "raw": "university campus 5g".encode('utf-8'),
            "expected_status": SSIDStatus.CONFIRMED_EVIL_TWIN,
            "check": lambda res: res.target_match == "University Campus 5G" and res.telemetry.get("delimiter_mismatch") is True
        },
        {
            "group": "Group 6: Delimiter Evasion",
            "name": "Uppercase Eduroam Spoofing (EDUROAM targeting eduroam)",
            "raw": "EDUROAM".encode('utf-8'),
            "expected_status": SSIDStatus.CONFIRMED_EVIL_TWIN,
            "check": lambda res: res.target_match == "eduroam" and res.telemetry.get("delimiter_mismatch") is True
        },

        # ----------------------------------------------------
        # Group 7: Combined Evasion Tricks
        # ----------------------------------------------------
        {
            "group": "Group 7: Combined Tricks",
            "name": "Fullwidth + Cyrillic + Zero-Width + Emoji (\\u200B\\uFF35niv\\u0435rsity Campus 5G📶 )",
            "raw": "\u200B\uFF35niv\u0435rsity Campus 5G📶 ".encode('utf-8'),
            "expected_status": SSIDStatus.CONFIRMED_EVIL_TWIN,
            "check": lambda res: (
                res.skeleton_ssid == "University Campus 5G" and
                res.telemetry["invisible_char_count"] == 1 and
                res.telemetry["nfkc_altered"] is True and
                res.telemetry["homoglyph_count"] >= 1 and
                res.telemetry["emoji_count"] == 1 and
                res.telemetry["trailing_whitespace"] is True
            )
        },

        # ----------------------------------------------------
        # Group 8: Authorized Baseline Matches
        # ----------------------------------------------------
        {
            "group": "Baseline",
            "name": "Authorized Exact Whitelist (University Campus 5G)",
            "raw": "University Campus 5G".encode('utf-8'),
            "expected_status": SSIDStatus.AUTHORIZED,
            "check": lambda res: res.target_match == "University Campus 5G"
        },
        {
            "group": "Baseline",
            "name": "Authorized Exact Whitelist (Siam Wifi)",
            "raw": "Siam Wifi".encode('utf-8'),
            "expected_status": SSIDStatus.AUTHORIZED,
            "check": lambda res: res.target_match == "Siam Wifi"
        },
        {
            "group": "Baseline",
            "name": "Authorized Uppercase Physical Signage (SIAM WIFI)",
            "raw": "SIAM WIFI".encode('utf-8'),
            "expected_status": SSIDStatus.AUTHORIZED,
            "check": lambda res: res.target_match in ("SIAM WIFI", "Siam Wifi")
        },
        {
            "group": "Baseline",
            "name": "Authorized Exact Whitelist (SiamXP Wifi)",
            "raw": "SiamXP Wifi".encode('utf-8'),
            "expected_status": SSIDStatus.AUTHORIZED,
            "check": lambda res: res.target_match == "SiamXP Wifi"
        },
        {
            "group": "Baseline",
            "name": "Authorized Uppercase Physical Signage (SIAM XP WIFI)",
            "raw": "SIAM XP WIFI".encode('utf-8'),
            "expected_status": SSIDStatus.AUTHORIZED,
            "check": lambda res: res.target_match in ("SIAM XP WIFI", "SiamXP Wifi")
        },
        {
            "group": "Baseline",
            "name": "Authorized Exact Whitelist (eduroam)",
            "raw": "eduroam".encode('utf-8'),
            "expected_status": SSIDStatus.AUTHORIZED,
            "check": lambda res: res.target_match == "eduroam"
        }
    ]

    print("=" * 80)
    print("RUNNING DEFENSIVE SSID PIPELINE VERIFICATION SUITE")
    print("=" * 80)

    for tc in test_cases:
        total += 1
        res = pipeline.process(tc["raw"])
        status_match = (res.status == tc["expected_status"])
        custom_check = tc["check"](res)
        is_ok = status_match and custom_check

        if is_ok:
            passed += 1
            print(f" [PASS] {tc['group']} :: {tc['name']}")
        else:
            print(f" [FAIL] {tc['group']} :: {tc['name']}")
            print(f"        Expected: {tc['expected_status'].value}, Got: {res.status.value}")
            print(f"        Skeleton: {repr(res.skeleton_ssid)}")
            print(f"        Telemetry: {res.telemetry}")
            print(f"        Reason: {res.reason}")

    print("=" * 80)
    print(f"RESULTS: {passed} / {total} tests passed ({passed/total*100:.1f}%)")
    print("=" * 80)

    # Latency Benchmark
    benchmark_payload = "\u200B\uFF35niv\u0435rsity Campus 5G📶 ".encode('utf-8')
    iterations = 20000
    t0 = time.perf_counter()
    for _ in range(iterations):
        pipeline.process(benchmark_payload)
    t1 = time.perf_counter()
    avg_latency_ms = ((t1 - t0) / iterations) * 1000
    print(f"BENCHMARK: 7-Stage Pipeline Average Latency: {avg_latency_ms:.5f} ms per frame")
    print(f"THROUGHPUT: {iterations / (t1 - t0):.1f} frames/second")
    print("=" * 80)

if __name__ == "__main__":
    run_tests()
