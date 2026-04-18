#!/usr/bin/env python3
"""
brute_rot.py — try all ROT-N variants on text (ROT-1 through ROT-25)
Also handles ROT-47 (printable ASCII range).
"""

import sys
import argparse
import re
from pathlib import Path

COMMON_WORDS = {
    "the", "and", "for", "are", "but", "not", "you", "all", "can", "was",
    "one", "our", "out", "had", "has", "his", "her", "she", "they", "from",
    "this", "that", "with", "have", "flag", "ctf", "key", "secret", "pass",
    "password", "hidden", "encode", "cipher", "solve", "challenge",
}

def rot_n(text: str, n: int) -> str:
    result = []
    for c in text:
        if 'a' <= c <= 'z':
            result.append(chr((ord(c) - ord('a') + n) % 26 + ord('a')))
        elif 'A' <= c <= 'Z':
            result.append(chr((ord(c) - ord('A') + n) % 26 + ord('A')))
        else:
            result.append(c)
    return "".join(result)

def rot47(text: str) -> str:
    result = []
    for c in text:
        if '!' <= c <= '~':
            result.append(chr((ord(c) - 33 + 47) % 94 + 33))
        else:
            result.append(c)
    return "".join(result)

def score(text: str) -> int:
    words = re.findall(r'[a-zA-Z]+', text.lower())
    return sum(1 for w in words if w in COMMON_WORDS)

def check_flag(text: str) -> list[str]:
    return re.findall(r'[A-Za-z0-9_]{2,10}\{[^}]+\}', text)

def main():
    parser = argparse.ArgumentParser(description="Brute-force all ROT-N variants of input text")
    parser.add_argument("input", nargs="?", help="Input text or file path")
    parser.add_argument("-f", "--file", help="Read input from file")
    parser.add_argument("--rot47", action="store_true", help="Also try ROT-47 (printable ASCII)")
    parser.add_argument("--all", action="store_true", help="Print all 25 variants (default: scored/flagged only)")
    parser.add_argument("-n", "--rot", type=int, default=None, help="Only apply this specific ROT value")
    args = parser.parse_args()

    if args.file:
        text = Path(args.file).read_text(encoding="utf-8", errors="replace").strip()
    elif args.input:
        p = Path(args.input)
        if p.exists():
            text = p.read_text(encoding="utf-8", errors="replace").strip()
        else:
            text = args.input
    elif not sys.stdin.isatty():
        text = sys.stdin.read().strip()
    else:
        parser.print_help()
        sys.exit(1)

    print(f"[*] Input ({len(text)} chars): {text[:80]}{'...' if len(text)>80 else ''}\n")

    results = []

    if args.rot is not None:
        rotations = [args.rot]
    else:
        rotations = range(1, 26)

    for n in rotations:
        decoded = rot_n(text, n)
        s = score(decoded)
        flags = check_flag(decoded)
        results.append((n, decoded, s, flags))

    if args.rot47 or args.rot is None:
        decoded47 = rot47(text)
        s = score(decoded47)
        flags = check_flag(decoded47)
        results.append(("47", decoded47, s, flags))

    # Sort by score descending
    results.sort(key=lambda x: x[2], reverse=True)

    print(f"{'ROT':<6} {'Score':<7} {'Flags':<8}  Output")
    print("-" * 70)
    for n, decoded, s, flags in results:
        flag_str = " ".join(flags) if flags else ""
        marker = "  <<< FLAG!" if flags else ("  <<< likely" if s >= 3 else "")
        if args.all or flags or s >= 2:
            label = f"ROT-{n:<4}"
            preview = decoded[:80] + ("..." if len(decoded) > 80 else "")
            print(f"{label:<6} {s:<7} {flag_str or '-':<8}  {preview}{marker}")

    # Best guess
    best = max(results, key=lambda x: x[2])
    if best[2] > 0:
        print(f"\n[*] Best guess: ROT-{best[0]}  (score={best[2]})")
        print(f"    {best[1]}")
    flags_all = [(n, f) for n, _, _, flags in results for f in flags]
    if flags_all:
        print(f"\n[!!!] Flags found:")
        for n, f in flags_all:
            print(f"  ROT-{n}: {f}")

if __name__ == "__main__":
    main()
