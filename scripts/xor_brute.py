#!/usr/bin/env python3
"""
xor_brute.py — brute-force single/multi-byte XOR keys against a ciphertext file
"""

import sys
import re
import math
import argparse
import itertools
from pathlib import Path

COMMON_WORDS = {
    b"the", b"and", b"for", b"are", b"not", b"you", b"all", b"can",
    b"was", b"his", b"they", b"from", b"this", b"that", b"with", b"have",
    b"flag", b"ctf", b"key", b"secret", b"pass", b"hidden",
}

def score_bytes(data: bytes) -> float:
    """Score based on printable ASCII and common words."""
    printable = sum(1 for b in data if 0x20 <= b <= 0x7e or b in (0x09, 0x0a, 0x0d))
    s = printable / len(data) if data else 0
    lower = data.lower()
    for w in COMMON_WORDS:
        s += lower.count(w) * 0.5
    return s

def check_flag(data: bytes) -> list[str]:
    try:
        text = data.decode("utf-8", errors="replace")
    except Exception:
        return []
    return re.findall(r'[A-Za-z0-9_]{2,10}\{[^}]+\}', text)

def xor_key(data: bytes, key: bytes) -> bytes:
    key_len = len(key)
    return bytes(b ^ key[i % key_len] for i, b in enumerate(data))

def index_of_coincidence(data: bytes) -> float:
    n = len(data)
    if n < 2:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    return sum(c * (c - 1) for c in counts) / (n * (n - 1))

def guess_keylen(data: bytes, max_len: int = 16) -> list[int]:
    """Guess key length using index of coincidence on every Nth byte."""
    scores = []
    for kl in range(1, max_len + 1):
        ioc_sum = 0.0
        for offset in range(kl):
            stream = bytes(data[i] for i in range(offset, len(data), kl))
            ioc_sum += index_of_coincidence(stream)
        scores.append((ioc_sum / kl, kl))
    scores.sort(reverse=True)
    return [kl for _, kl in scores[:5]]

def crack_single(data: bytes) -> list[tuple[int, float, bytes]]:
    results = []
    for key in range(256):
        decrypted = xor_key(data, bytes([key]))
        s = score_bytes(decrypted)
        results.append((key, s, decrypted))
    results.sort(key=lambda x: x[1], reverse=True)
    return results

def crack_multi(data: bytes, keylen: int) -> tuple[bytes, bytes]:
    """Crack multi-byte key by treating each byte position independently."""
    key = []
    for offset in range(keylen):
        stream = bytes(data[i] for i in range(offset, len(data), keylen))
        best_key, best_score, _ = crack_single(stream)[0]
        key.append(best_key)
    key_bytes = bytes(key)
    return key_bytes, xor_key(data, key_bytes)

def main():
    parser = argparse.ArgumentParser(description="Brute-force XOR keys against a ciphertext")
    parser.add_argument("input", help="Ciphertext file")
    parser.add_argument("-k", "--keylen", type=int, default=None,
                        help="Key length to try (default: auto-detect 1-16)")
    parser.add_argument("--max-keylen", type=int, default=16,
                        help="Max key length for auto-detection (default: 16)")
    parser.add_argument("--single", action="store_true",
                        help="Force single-byte XOR only")
    parser.add_argument("--top", type=int, default=5,
                        help="Show top N results for single-byte (default: 5)")
    parser.add_argument("-o", "--output", default=None,
                        help="Write best decryption to file")
    args = parser.parse_args()

    in_path = Path(args.input)
    if not in_path.exists():
        print(f"[!] File not found: {in_path}")
        sys.exit(1)

    data = in_path.read_bytes()
    print(f"[*] Ciphertext: {in_path}  ({len(data):,} bytes)\n")

    best_overall = None

    if args.single or args.keylen == 1:
        print("[*] Single-byte XOR brute force:")
        results = crack_single(data)
        for key, s, dec in results[:args.top]:
            flags = check_flag(dec)
            preview = dec[:60].decode("utf-8", errors="replace").replace("\n", "\\n")
            flag_str = "  <<< FLAG: " + " ".join(flags) if flags else ""
            print(f"  Key=0x{key:02x} ({chr(key) if 0x20<=key<=0x7e else '?'})  score={s:.2f}  {preview!r}{flag_str}")
        best_overall = (bytes([results[0][0]]), results[0][2])
    else:
        keylens = [args.keylen] if args.keylen else guess_keylen(data, args.max_keylen)
        print(f"[*] Guessed key lengths (IoC): {keylens}\n")

        all_results = []
        for kl in keylens:
            if kl == 1:
                top = crack_single(data)
                key_b = bytes([top[0][0]])
                dec = top[0][2]
            else:
                key_b, dec = crack_multi(data, kl)
            s = score_bytes(dec)
            flags = check_flag(dec)
            all_results.append((kl, key_b, s, dec, flags))
            flag_str = "  <<< FLAG: " + " ".join(flags) if flags else ""
            key_hex = key_b.hex()
            key_repr = key_b.decode("latin-1", errors="replace")
            preview = dec[:60].decode("utf-8", errors="replace").replace("\n", "\\n")
            print(f"  KeyLen={kl}  Key=0x{key_hex} ({key_repr!r})  score={s:.2f}")
            print(f"    {preview!r}{flag_str}\n")

        all_results.sort(key=lambda x: x[2], reverse=True)
        best = all_results[0]
        best_overall = (best[1], best[3])
        print(f"[*] Best result: KeyLen={best[0]}  Key=0x{best[1].hex()} ({best[1].decode('latin-1', errors='replace')!r})")

        # Report all flags found
        all_flags = [(kl, f) for kl, _, _, _, flags in all_results for f in flags]
        if all_flags:
            print(f"\n[!!!] Flags found:")
            for kl, f in all_flags:
                print(f"  KeyLen={kl}: {f}")

    if args.output and best_overall:
        out_path = Path(args.output)
        out_path.write_bytes(best_overall[1])
        print(f"\n[*] Best decryption saved to {out_path}")

if __name__ == "__main__":
    main()
