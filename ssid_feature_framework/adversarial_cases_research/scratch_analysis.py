import unicodedata
import binascii
import sys
import os

sys.stdout.reconfigure(encoding="utf-8")
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
import features


baseline = [
    "University_Campus_5G",
    "University_Staff_Secure",
    "University_Student_WiFi",
    "University_Guest_Portal",
    "eduroam"
]

auth = "University_Campus_5G"
print(f"Baseline Target: {auth}")
print(f"Auth chars: {len(auth)}, bytes: {len(auth.encode('utf-8'))}, hex: {auth.encode('utf-8').hex(' ')}")
print("="*60)

cases = [
    ("Group 1: Cross-Script Homoglyph (Cyrillic e)", "Univ\u0435rsity_Campus_5G"),
    ("Group 1: Cross-Script Homoglyph (Cyrillic a)", "University_C\u0430mpus_5G"),
    ("Group 1: Cross-Script Homoglyph (Greek omicron)", "University_Camp\u03bfs_5G"),
    ("Group 2: Invisible / Whitespace (Zero-Width Space)", "University_Campus_5G\u200b"),
    ("Group 2: Invisible / Whitespace (Trailing ASCII Space)", "University_Campus_5G "),
    ("Group 2: Invisible (ZWNJ U+200C)", "University_Campus_5G\u200c"),
    ("Group 2: Invisible (ZWJ U+200D)", "University_Campus_5G\u200d"),
    ("Group 2: Invisible (BOM U+FEFF)", "\ufeffUniversity_Campus_5G"),
    ("Group 2: Invisible (NBSP U+00A0)", "University\u00a0Campus_5G"),
    ("Group 3: Fullwidth Latin U (U+FF35)", "\uff35niversity_Campus_5G"),
    ("Group 3: Combining Acute Accent (e + U+0301)", "Univ\u0065\u0301rsity_Campus_5G"),
    ("Group 4: Emoji Antenna Bars (Evil Twin)", "University_Campus_5G\U0001f4f6"),
    ("Group 4: Benign Emoji", "Home\U0001f4f6"),
    ("Group 4: Benign Thai script", "บ้านสุข"),
    ("Group 6: Combined Tricks", "Free_Un1v\u0435rsity_Campus_5G"),
]

for label, s in cases:
    raw_utf8 = s.encode("utf-8")
    hex_str = raw_utf8.hex(" ")
    nfc = unicodedata.normalize("NFC", s)
    nfd = unicodedata.normalize("NFD", s)
    nfkc = unicodedata.normalize("NFKC", s)
    nfkd = unicodedata.normalize("NFKD", s)
    
    # Calculate Levenshtein with target
    # Character level
    def lev(s1, s2):
        if len(s1) < len(s2):
            s1, s2 = s2, s1
        prev = list(range(len(s2) + 1))
        for i, c1 in enumerate(s1):
            curr = [i + 1] + [0] * len(s2)
            for j, c2 in enumerate(s2):
                curr[j + 1] = min(prev[j + 1] + 1, curr[j] + 1, prev[j] + (c1 != c2))
            prev = curr
        return prev[-1]
    
    char_lev = lev(s, auth)
    char_sim = 1.0 - (char_lev / max(len(s), len(auth)))
    
    # Byte level Levenshtein
    auth_bytes = auth.encode("utf-8")
    byte_lev = lev(raw_utf8, auth_bytes)
    byte_sim = 1.0 - (byte_lev / max(len(raw_utf8), len(auth_bytes)))

    print(f"[{label}]")
    print(f"  String: {repr(s)}")
    print(f"  Chars: {len(s)} | Bytes: {len(raw_utf8)}")
    print(f"  Hex: {hex_str}")
    print(f"  Char Levenshtein: dist={char_lev}, sim={char_sim:.4f}")
    print(f"  Byte Levenshtein: dist={byte_lev}, sim={byte_sim:.4f}")
    print(f"  NFC == target?  {nfc == auth} (repr: {repr(nfc)})")
    print(f"  NFD == target?  {nfd == auth}")
    print(f"  NFKC == target? {nfkc == auth} (repr: {repr(nfkc)})")
    print(f"  NFKD == target? {nfkd == auth}")
    feat = features.extract_features(s, auth)
    print(f"  Features: f1={feat['f1_lev_ratio']}, f2={feat['f2_dam_ratio']}, f3={feat['f3_jaro_winkler']}, f4={feat['f4_ngram2']}, f5={feat['f5_ngram3']}, f6={feat['f6_homoglyphs']}, f7={feat['f7_len_abs_diff']}, f11={feat['f11_lure_flag']}, f13={feat['f13_prefix_ratio']}")
    print()

print("="*60)
print("GROUP 5: BYTE-LEVEL BREAKAGE & 802.11 COMPLIANCE")
print("="*60)

# Case 1: 33 x 'A'
b1 = b"A" * 33
print(f"[Group 5: 33 x 'A']")
print(f"  Byte length: {len(b1)} octets (IEEE 802.11 limit: 32)")
print(f"  Raw Hex: {b1[:10].hex(' ')} ... ({len(b1)} bytes total)")

# Case 2: Overlong UTF-8 \xc1\xa1
b2 = b"\xc1\xa1"
print(f"[Group 5: Overlong UTF-8 0xC1 0xA1]")
print(f"  Raw Hex: {b2.hex(' ')}")
try:
    s2 = b2.decode("utf-8")
    print(f"  Strict decode: {s2}")
except UnicodeDecodeError as e:
    print(f"  Strict decode failed: {e}")
print(f"  Replace decode: {repr(b2.decode('utf-8', errors='replace'))}")
print(f"  Ignore decode: {repr(b2.decode('utf-8', errors='ignore'))}")

# Case 3: Truncated multi-byte (30 x 'A' + \xe0\xb8)
b3 = b"A" * 30 + b"\xe0\xb8"
print(f"[Group 5: Truncated Multi-byte 30 x 'A' + 0xE0 0xB8]")
print(f"  Byte length: {len(b3)} octets")
print(f"  Raw Hex: {b3.hex(' ')}")
try:
    s3 = b3.decode("utf-8")
    print(f"  Strict decode: {s3}")
except UnicodeDecodeError as e:
    print(f"  Strict decode failed: {e}")
s3_rep = b3.decode("utf-8", errors="replace")
print(f"  Replace decode: {repr(s3_rep)} (char count={len(s3_rep)})")

# Case 4: Empty SSID
b4 = b""
print(f"[Group 5: Empty SSID (0 octets)]")
print(f"  Byte length: {len(b4)} octets")
print(f"  Hex: (empty)")


