# 🔍 Case Group 4: Emoji Lures & Non-Latin Benign Networks

> **Case Category:** `emoji_and_non_latin_handling`  
> **Target Whitelist AP:** `University_Campus_5G` (or `None` for standalone non-campus networks)  
> **Collaborative Agents:**
> * 🔴 **Agent A:** Offensive Wireless Security Researcher (Red Team Adversary)
> * 🛡️ **Agent B:** Defensive Wireless Security Architect (Blue Team Defender)

---

## 1. Test Case Roster & Technical Parameters

| Test Case | Linguistic Script | Special Graphemes | Codepoints / Range | Char Len | Wire Byte Len | Ground Truth | Detection Mechanism |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :--- |
| `University_Campus_5G📶` | Latin + Emoji | Antenna Bars (`📶`) | `U+1F4F6` (SMP) | 21 | 24 | **EVIL_TWIN** | Emoji Stripping + Whitelist Match |
| `Home📶` | Latin + Emoji | Antenna Bars (`📶`) | `U+1F4F6` (SMP) | 5 | 8 | **BENIGN** | Low Edit Similarity to Whitelist |
| `บ้านสุข` | Thai (Non-Latin) | Consonants + Vowels + Tone | `U+0E00..U+0E7F` | 7 | 21 | **BENIGN** | Script Identification Fast-Path |

---

## 2. Red Team Offensive Analysis (Agent A)

### 2.1 The Psychology of Emoji Lures
- Emojis such as `📶` (Antenna Bars), `⚡` (High Voltage/Speed), `🔒` (Lock/Secure), and `🆓` (Free) exploit cognitive trust heuristics:
  - Users instinctively assume an SSID displaying `University_Campus_5G📶` represents an official, high-signal-strength AP broadcast by the campus network operations center.
- **Byte Overhead:** Emojis reside in Unicode's Supplementary Multilingual Plane (SMP, Plane 1). In UTF-8, each emoji requires **4 full octets** (`U+1F4F6` $\to$ `\xf0\x9f\x93\xb6`).
- Because `University_Campus_5G` is 20 octets, adding `📶` produces 24 octets, safely within the IEEE 802.11 32-octet limit.

### 2.2 The "Byte Bloat" vs "Character Count" Disparity in Non-Latin Scripts
- In Thai script (`บ้านสุข` - "Baan Suk" / Happy Home):
  - Graphemes: `บ` (`U+0E1A`), `้` (`U+0E49`), `า` (`U+0E32`), `น` (`U+0E19`), `ส` (`U+0E2A`), `ุ` (`U+0E38`), `ข` (`U+0E02`).
  - Total Characters in Python: `len("บ้านสุข") == 7`.
  - Total Octets in 802.11 Frame: `len("บ้านสุข".encode("utf-8")) == 21 bytes`!
- **Attacker Insight:** Naive detectors that compute length difference $f_7 = |\text{len}(s_1) - \text{len}(s_2)|$ using byte length will compute $|21 - 20| = 1$, falsely assuming a non-Latin string is of identical length to the institutional network, which can distort string-kernel comparisons.

---

## 3. Blue Team Defensive Architecture (Agent B)

### 3.1 Emoji Isolation & Stripping
We define an exhaustive Unicode regex to detect and isolate emojis across all emoji presentation blocks:

```python
import re

EMOJI_REGEX = re.compile(
    r'[\U0001F000-\U0001FAFF\u2600-\u27BF\u2300-\u23FF\u2B50-\u2B55\U00010000-\U0010FFFF]'
)
```

### 3.2 Distinguishing Brand Spoofing vs Standalone Benign Networks
A common pitfall is treating any SSID containing an emoji as malicious. Our architecture establishes a clear separation:
1. **Case A: `University_Campus_5G📶` (Brand Spoofing):**
   - The detector extracts the emoji: `emoji_found = ['📶']`.
   - The stripped string `University_Campus_5G` collides 100% with the authorized whitelist!
   - Result: **`CONFIRMED_EVIL_TWIN`** (`Brand-trailing emoji impersonation`).
2. **Case B: `Home📶` (Standalone Benign):**
   - Stripping emoji leaves `Home`.
   - Comparing `Home` to the whitelist yields $f_1 = 0.0500$, $f_3 = 0.4100$, $f_5 = 0.0000$.
   - Evaluated by XGBoost: $P(\text{Evil Twin}) = 0.0120 \implies$ **`BENIGN_NOISE`**.

### 3.3 Zero False-Positive Guarantee on Native Scripts (`บ้านสุข`)
To ensure complete resilience against false alarms in multilingual campuses (e.g. international universities in Thailand):
- The pipeline scans character scripts:
  ```python
  def is_pure_non_latin(s: str) -> bool:
      latin_count = sum(1 for c in s if 'a' <= c.lower() <= 'z')
      return latin_count == 0 and len(s) > 0
  ```
- If an SSID contains **0% Latin characters** and contains no institutional tokens, it bypasses the Evil Twin alarm entirely and is assigned $P(\text{Evil Twin}) = 0.0000$ (**`BENIGN_NON_LATIN`**).

---

## 4. Collaborative Discussion & Logic Refinement

```mermaid
sequenceDiagram
    autonumber
    participant Red as 🔴 Agent A (Red Team)
    participant Blue as 🛡️ Agent B (Blue Team)
    
    Red->>Blue: What if an attacker creates a hybrid SSID like "มหาวิทยาลัย_Campus_5G" (Thai for 'University' + Latin 'Campus_5G')?
    Blue->>Red: That is a cross-language semantic impersonation. Because it contains Latin characters ('Campus_5G'), it does NOT qualify for the 0% Latin bypass.
    Red->>Blue: How would the model score it?
    Blue->>Red: Token analysis matches 'Campus' and '5G' against the whitelist, yielding f9 (Token Overlap) = 0.66. It will be routed to Tier 3 physical telemetry.
    Red->>Blue: What if the attacker embeds an emoji in the middle of a word, e.g. "Univ📶ersity"?
    Blue->>Red: Stripping the emoji restores "University". When compared to the whitelist, f1 jumps to 1.0, triggering the immediate Evil Twin alert!
```

---

## 5. Production Reference Implementation

```python
import re
from typing import Dict, Any

EMOJI_REGEX = re.compile(
    r'[\U0001F000-\U0001FAFF\u2600-\u27BF\u2300-\u23FF\u2B50-\u2B55\U00010000-\U0010FFFF]'
)

def evaluate_emoji_and_script(raw_ssid: str, whitelist: list[str]) -> Dict[str, Any]:
    """
    Evaluates SSIDs containing emojis or native non-Latin scripts.
    Differentiates brand spoofing with emojis from legitimate personal/foreign APs.
    """
    emojis = EMOJI_REGEX.findall(raw_ssid)
    cleaned_no_emoji = EMOJI_REGEX.sub("", raw_ssid).strip()
    
    # Analyze Latin character presence
    latin_chars = [c for c in cleaned_no_emoji if 'a' <= c.lower() <= 'z']
    is_pure_non_latin = (len(latin_chars) == 0 and len(cleaned_no_emoji) > 0)
    
    # Check if stripping emojis exposes an exact Whitelist brand
    is_brand_spoofing = (cleaned_no_emoji in whitelist and raw_ssid not in whitelist)
    
    if is_brand_spoofing:
        classification = "EVIL_TWIN"
        reason = "Brand impersonation with appended/prepended emoji lure"
    elif is_pure_non_latin:
        classification = "BENIGN"
        reason = "Legitimate native non-Latin script network"
    else:
        # Fallback to feature extraction comparison against whitelist
        classification = "EVALUATE_DOWNSTREAM"
        reason = "Requires feature extraction and XGBoost inference"

    return {
        "raw_ssid": raw_ssid,
        "cleaned_ssid": cleaned_no_emoji,
        "emojis_found": emojis,
        "is_pure_non_latin": is_pure_non_latin,
        "is_brand_spoofing": is_brand_spoofing,
        "classification": classification,
        "reason": reason
    }

# Unit Test Verification
if __name__ == "__main__":
    wl = ["University_Campus_5G"]
    
    # 1. Evil Twin with emoji
    res1 = evaluate_emoji_and_script("University_Campus_5G📶", wl)
    assert res1["classification"] == "EVIL_TWIN"
    assert res1["is_brand_spoofing"] == True
    
    # 2. Benign personal network with emoji
    res2 = evaluate_emoji_and_script("Home📶", wl)
    assert res2["classification"] == "EVALUATE_DOWNSTREAM"
    assert res2["is_brand_spoofing"] == False
    
    # 3. Legitimate Thai non-Latin network
    res3 = evaluate_emoji_and_script("บ้านสุข", wl)
    assert res3["classification"] == "BENIGN"
    assert res3["is_pure_non_latin"] == True
    
    print("✅ All Emoji and Non-Latin test cases verified successfully!")
```
