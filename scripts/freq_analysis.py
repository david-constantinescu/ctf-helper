#!/usr/bin/env python3
"""
freq_analysis.py — letter frequency analysis for substitution cipher cracking
Shows frequency table, chi-squared fit vs English, and suggests single-letter mappings.
Optionally applies a manual substitution key to partially/fully decode.
"""

import sys
import re
import math
import argparse
from pathlib import Path
from collections import Counter

# English letter frequencies (percent) — Brown corpus
ENGLISH_FREQ = {
    'E':12.70,'T':9.06,'A':8.17,'O':7.51,'I':6.97,'N':6.75,'S':6.33,'H':6.09,
    'R':5.99,'D':4.25,'L':4.03,'C':2.78,'U':2.76,'M':2.41,'W':2.36,'F':2.23,
    'G':2.02,'Y':1.97,'P':1.93,'B':1.29,'V':0.98,'K':0.77,'J':0.15,'X':0.15,
    'Q':0.10,'Z':0.07,
}
ENGLISH_ORDER = "ETAOINSHRDLCUMWFGYPBVKJXQZ"
ENGLISH_DIGRAPHS = ["TH","HE","IN","ER","AN","RE","ON","EN","AT","OU","ND","ST","ES"]
ENGLISH_TRIGRAPHS = ["THE","AND","ING","ION","ENT","FOR","TIO","ERE"]

def letter_freq(text: str) -> dict[str, float]:
    letters = [c.upper() for c in text if c.isalpha()]
    if not letters:
        return {}
    counts = Counter(letters)
    total = len(letters)
    return {c: counts.get(c, 0) / total * 100 for c in "ABCDEFGHIJKLMNOPQRSTUVWXYZ"}

def chi_squared(observed: dict[str, float], expected: dict[str, float]) -> float:
    total = 0.0
    for c in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
        e = expected.get(c, 0)
        o = observed.get(c, 0)
        if e > 0:
            total += (o - e) ** 2 / e
    return total

def index_of_coincidence(text: str) -> float:
    letters = [c.upper() for c in text if c.isalpha()]
    n = len(letters)
    if n < 2:
        return 0.0
    counts = Counter(letters)
    return sum(c * (c - 1) for c in counts.values()) / (n * (n - 1))

def ngrams(text: str, n: int) -> Counter:
    letters = "".join(c.upper() for c in text if c.isalpha())
    return Counter(letters[i:i+n] for i in range(len(letters) - n + 1))

def suggest_mapping(cipher_order: str) -> dict[str, str]:
    """Map most-frequent cipher letter -> most-frequent English letter."""
    mapping = {}
    for i, c in enumerate(cipher_order):
        if i < len(ENGLISH_ORDER):
            mapping[c] = ENGLISH_ORDER[i]
    return mapping

def apply_key(text: str, key: dict[str, str]) -> str:
    """Apply a substitution key. key maps CIPHER -> PLAIN (uppercase)."""
    out = []
    for c in text:
        u = c.upper()
        if u in key:
            plain = key[u]
            out.append(plain.lower() if c.islower() else plain)
        else:
            out.append(c)
    return "".join(out)

def bar(value: float, max_val: float, width: int = 20) -> str:
    filled = int(value / max_val * width) if max_val > 0 else 0
    return "#" * filled + "." * (width - filled)

def parse_key(key_str: str) -> dict[str, str]:
    """Parse key string like 'A=E,B=T,C=A' or 'ETAOIN...' (positional for A-Z)."""
    key = {}
    if "=" in key_str:
        for pair in key_str.split(","):
            pair = pair.strip()
            if "=" in pair:
                cipher, plain = pair.split("=", 1)
                key[cipher.strip().upper()] = plain.strip().upper()
    elif len(key_str) == 26 and key_str.isalpha():
        # Positional: position i = plain for cipher letter chr(65+i)
        for i, p in enumerate(key_str.upper()):
            key[chr(65 + i)] = p
    return key

def main():
    parser = argparse.ArgumentParser(
        description="Letter frequency analysis for substitution cipher cracking"
    )
    parser.add_argument("input", nargs="?", help="Ciphertext string or file path")
    parser.add_argument("-f", "--file", help="Read ciphertext from file")
    parser.add_argument("-k", "--key", default=None,
                        help="Substitution key to apply, e.g. 'A=E,B=T' or 26-char positional string")
    parser.add_argument("--no-suggest", action="store_true",
                        help="Don't auto-suggest a mapping based on frequency")
    parser.add_argument("--digraphs", action="store_true",
                        help="Show top digraph and trigraph frequencies")
    parser.add_argument("--ioc", action="store_true",
                        help="Show Index of Coincidence (helps distinguish mono vs poly substitution)")
    args = parser.parse_args()

    if args.file:
        text = Path(args.file).read_text(encoding="utf-8", errors="replace")
    elif args.input:
        p = Path(args.input)
        text = p.read_text(encoding="utf-8", errors="replace") if p.exists() else args.input
    elif not sys.stdin.isatty():
        text = sys.stdin.read()
    else:
        parser.print_help()
        sys.exit(1)

    letters_only = "".join(c for c in text if c.isalpha())
    total_letters = len(letters_only)
    if total_letters < 20:
        print(f"[!] Warning: only {total_letters} letters — analysis may be inaccurate.")

    print(f"[*] Text length: {len(text)} chars, {total_letters} letters\n")

    freq = letter_freq(text)
    max_freq = max(freq.values()) if freq else 1

    # Frequency table
    print(f"{'Letter':<8} {'Count':>6} {'%':>7}  {'Bar (cipher)':20}  {'English %':>9}  {'Bar (english)':20}")
    print("-" * 80)
    cipher_order = sorted(freq, key=lambda c: freq[c], reverse=True)
    for c in cipher_order:
        f = freq[c]
        e = ENGLISH_FREQ.get(c, 0)
        count = sum(1 for ch in text.upper() if ch == c)
        print(f"  {c:<6} {count:>6} {f:>6.2f}%  {bar(f, max_freq):<20}  {e:>8.2f}%  {bar(e, max_freq):<20}")

    # Chi-squared
    chi = chi_squared(freq, ENGLISH_FREQ)
    print(f"\n[*] Chi-squared vs English: {chi:.2f}  (lower = closer to English; <100 usually good)")

    # IoC
    ioc = index_of_coincidence(text)
    print(f"[*] Index of Coincidence: {ioc:.4f}  (English≈0.065, random≈0.038)")
    if ioc > 0.060:
        print("    -> Likely monoalphabetic substitution (high IoC)")
    elif ioc < 0.045:
        print("    -> Likely polyalphabetic / Vigenere (low IoC)")
    else:
        print("    -> Possibly polyalphabetic with short key")

    # Digraphs / trigraphs
    if args.digraphs:
        print(f"\n[*] Top 10 digraphs (cipher):")
        for dg, cnt in ngrams(text, 2).most_common(10):
            print(f"    {dg}  ({cnt})")
        print(f"\n[*] Top 10 trigraphs (cipher):")
        for tg, cnt in ngrams(text, 3).most_common(10):
            print(f"    {tg}  ({cnt})")
        print(f"\n[*] Common English digraphs:  {' '.join(ENGLISH_DIGRAPHS[:8])}")
        print(f"[*] Common English trigraphs: {' '.join(ENGLISH_TRIGRAPHS[:6])}")

    # Suggested mapping
    if not args.no_suggest:
        suggested = suggest_mapping("".join(cipher_order))
        print(f"\n[*] Suggested mapping (by frequency rank):")
        print(f"    {'Cipher':<8} -> {'Plain'}")
        for c in cipher_order:
            print(f"    {c:<8} -> {suggested.get(c,'?')}")
        print(f"\n    Apply with: --key '{','.join(f'{c}={suggested[c]}' for c in cipher_order if c in suggested)}'")

    # Apply user key
    key = {}
    if args.key:
        key = parse_key(args.key)
    elif not args.no_suggest:
        key = suggest_mapping("".join(cipher_order))

    if key:
        decoded = apply_key(text, key)
        print(f"\n{'='*60}")
        print(f"[*] {'Applied key' if args.key else 'Frequency-suggested decode'}:")
        print(decoded[:500] + ("..." if len(decoded) > 500 else ""))

        import re as _re
        flags = _re.findall(r'[A-Za-z0-9_]{2,10}\{[^}]+\}', decoded)
        if flags:
            print(f"\n[!!!] FLAG PATTERNS:")
            for f in flags:
                print(f"  >>> {f}")

if __name__ == "__main__":
    main()
