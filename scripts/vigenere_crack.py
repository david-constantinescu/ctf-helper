#!/usr/bin/env python3
"""
vigenere_crack.py — crack Vigenere cipher without knowing the key
Uses Kasiski examination + Index of Coincidence to find key length,
then frequency analysis on each column to recover the key.
"""

import sys
import re
import math
import argparse
from pathlib import Path
from collections import Counter

ENGLISH_FREQ = {
    'A':8.17,'B':1.29,'C':2.78,'D':4.25,'E':12.70,'F':2.23,'G':2.02,
    'H':6.09,'I':6.97,'J':0.15,'K':0.77,'L':4.03,'M':2.41,'N':6.75,
    'O':7.51,'P':1.93,'Q':0.10,'R':5.99,'S':6.33,'T':9.06,'U':2.76,
    'V':0.98,'W':2.36,'X':0.15,'Y':1.97,'Z':0.07,
}
ENGLISH_IC = 0.0654
RANDOM_IC  = 0.0385

# ── Utilities ─────────────────────────────────────────────────────────────────

def strip_to_alpha(text: str) -> str:
    return "".join(c.upper() for c in text if c.isalpha())

def ioc(text: str) -> float:
    n = len(text)
    if n < 2:
        return 0.0
    counts = Counter(text)
    return sum(c * (c - 1) for c in counts.values()) / (n * (n - 1))

def chi_squared_shift(ciphertext: str, shift: int) -> float:
    """Chi-squared score for a Caesar shift on a column."""
    total = len(ciphertext)
    if total == 0:
        return float("inf")
    shifted = [chr((ord(c) - ord('A') - shift) % 26 + ord('A')) for c in ciphertext]
    counts = Counter(shifted)
    score = 0.0
    for c in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
        observed = counts.get(c, 0) / total * 100
        expected = ENGLISH_FREQ[c]
        score += (observed - expected) ** 2 / expected
    return score

# ── Kasiski examination ───────────────────────────────────────────────────────

def kasiski(text: str, min_len: int = 3, max_len: int = 5) -> list[int]:
    """Find repeated n-gram spacings and compute GCDs to suggest key lengths."""
    spacings = []
    for n in range(min_len, max_len + 1):
        seen = {}
        for i in range(len(text) - n):
            gram = text[i:i+n]
            if gram in seen:
                spacings.append(i - seen[gram])
            else:
                seen[gram] = i

    if not spacings:
        return []

    # Count GCDs of all spacing pairs
    from math import gcd
    factor_counts = Counter()
    for s in spacings:
        for f in range(2, min(s + 1, 30)):
            if s % f == 0:
                factor_counts[f] += 1

    # Return top candidates sorted by count
    return [k for k, _ in factor_counts.most_common(8)]

# ── IoC key-length test ───────────────────────────────────────────────────────

def ioc_keylen(text: str, max_keylen: int = 20) -> list[tuple[int, float]]:
    """For each candidate key length, compute average IoC of columns."""
    scores = []
    for kl in range(1, max_keylen + 1):
        columns = ["".join(text[i] for i in range(j, len(text), kl)) for j in range(kl)]
        avg_ioc = sum(ioc(col) for col in columns) / kl
        scores.append((kl, avg_ioc))
    # Sort by closeness to English IoC
    scores.sort(key=lambda x: abs(x[1] - ENGLISH_IC))
    return scores

# ── Key recovery ──────────────────────────────────────────────────────────────

def crack_key(text: str, keylen: int) -> str:
    """Recover key by finding best Caesar shift for each column."""
    key = []
    for j in range(keylen):
        column = "".join(text[i] for i in range(j, len(text), keylen))
        best_shift = min(range(26), key=lambda s: chi_squared_shift(column, s))
        key.append(chr(best_shift + ord('A')))
    return "".join(key)

# ── Decryption ────────────────────────────────────────────────────────────────

def vigenere_decrypt(ciphertext: str, key: str) -> str:
    key = key.upper()
    key_len = len(key)
    result = []
    ki = 0
    for c in ciphertext:
        if c.isalpha():
            shift = ord(key[ki % key_len]) - ord('A')
            base = ord('A') if c.isupper() else ord('a')
            result.append(chr((ord(c.upper()) - ord('A') - shift) % 26 + base))
            ki += 1
        else:
            result.append(c)
    return "".join(result)

def score_text(text: str) -> float:
    """Score decrypted text by English letter frequency fit."""
    letters = "".join(c for c in text.upper() if c.isalpha())
    if not letters:
        return 0.0
    total = len(letters)
    counts = Counter(letters)
    score = 0.0
    for c, exp in ENGLISH_FREQ.items():
        obs = counts.get(c, 0) / total * 100
        score -= (obs - exp) ** 2 / exp
    return score

# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Crack Vigenere cipher using Kasiski + IoC (no key required)"
    )
    parser.add_argument("input", nargs="?", help="Ciphertext string or file path")
    parser.add_argument("-f", "--file", help="Read ciphertext from file")
    parser.add_argument("-k", "--key", default=None,
                        help="Known key — just decrypt, skip cracking")
    parser.add_argument("--max-keylen", type=int, default=20,
                        help="Maximum key length to test (default: 20)")
    parser.add_argument("--top", type=int, default=3,
                        help="Show top N key-length candidates (default: 3)")
    parser.add_argument("--try-all", action="store_true",
                        help="Try all key lengths up to --max-keylen and rank by readability")
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

    clean = strip_to_alpha(text)
    print(f"[*] Ciphertext: {len(text)} chars, {len(clean)} letters\n")
    print(f"[*] Ciphertext (first 80): {text.strip()[:80]}\n")

    if len(clean) < 20:
        print("[!] Text too short for reliable Kasiski/IoC analysis.")

    # Direct decryption with known key
    if args.key:
        decrypted = vigenere_decrypt(text, args.key)
        print(f"[*] Key: {args.key.upper()}")
        print(f"\n[Decrypted]\n{decrypted}")
        flags = re.findall(r'[A-Za-z0-9_]{2,10}\{[^}]+\}', decrypted)
        if flags:
            print(f"\n[!!!] FLAG: {', '.join(flags)}")
        return

    # ── Step 1: Kasiski ──
    kasiski_candidates = kasiski(clean)
    print(f"[*] Kasiski candidates: {kasiski_candidates[:8] or 'none found'}")

    # ── Step 2: IoC per key length ──
    ioc_scores = ioc_keylen(clean, args.max_keylen)
    print(f"\n[*] IoC by key length (top {args.max_keylen}):")
    print(f"    {'KeyLen':<8} {'Avg IoC':<10} {'Distance to English IoC'}")
    for kl, avg in sorted(ioc_scores, key=lambda x: x[0])[:args.max_keylen]:
        dist = abs(avg - ENGLISH_IC)
        bar = "#" * int((1 - min(dist / 0.03, 1)) * 20)
        marker = " <-- likely" if dist < 0.005 else ""
        print(f"    {kl:<8} {avg:.5f}    {dist:.5f}  {bar}{marker}")

    # ── Step 3: Combine Kasiski + IoC to pick best candidates ──
    ioc_sorted = [kl for kl, _ in ioc_scores[:args.top]]
    combined = list(dict.fromkeys(kasiski_candidates[:args.top] + ioc_sorted))[:args.top * 2]
    print(f"\n[*] Combined key-length candidates: {combined[:8]}")

    # ── Step 4: Crack each candidate ──
    results = []
    for kl in combined:
        key = crack_key(clean, kl)
        decrypted = vigenere_decrypt(text, key)
        sc = score_text(decrypted)
        results.append((kl, key, decrypted, sc))

    if args.try_all:
        for kl in range(1, args.max_keylen + 1):
            if kl in combined:
                continue
            key = crack_key(clean, kl)
            decrypted = vigenere_decrypt(text, key)
            sc = score_text(decrypted)
            results.append((kl, key, decrypted, sc))

    results.sort(key=lambda x: x[3], reverse=True)

    # ── Step 5: Output ──
    SEP = "=" * 70
    print(f"\n{SEP}")
    print(f"  TOP RESULTS")
    print(SEP)

    flag_re = re.compile(r'[A-Za-z0-9_]{2,10}\{[^}]+\}', re.IGNORECASE)
    for kl, key, decrypted, sc in results[:args.top * 2]:
        flags = flag_re.findall(decrypted)
        flag_str = f"  <<< FLAG: {', '.join(flags)}" if flags else ""
        print(f"\n  KeyLen={kl}  Key={key}  score={sc:.1f}{flag_str}")
        print(f"  {decrypted[:200]}{'...' if len(decrypted)>200 else ''}")

    # Best result
    best_kl, best_key, best_dec, best_sc = results[0]
    print(f"\n{SEP}")
    print(f"  BEST GUESS: key length={best_kl}  key={best_key}")
    print(SEP)
    print(best_dec)

    flags = flag_re.findall(best_dec)
    if flags:
        print(f"\n[!!!] FLAGS FOUND:")
        for f in flags:
            print(f"  >>> {f}")

if __name__ == "__main__":
    main()
