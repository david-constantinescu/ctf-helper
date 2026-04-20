#!/usr/bin/env python3
"""
base_decoder.py — auto-detect and decode Base16/32/58/64/85 (and variants)
Tries every encoding, scores results, and shows the best matches.
"""

import sys
import re
import base64
import argparse
from pathlib import Path

# ── Charset definitions ───────────────────────────────────────────────────────

B16_RE  = re.compile(r'^[0-9A-Fa-f\s]+$')
B32_RE  = re.compile(r'^[A-Z2-7=\s]+$', re.IGNORECASE)
B32HEX_RE = re.compile(r'^[0-9A-V=\s]+$', re.IGNORECASE)
B58_CHARS = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
B64_RE  = re.compile(r'^[A-Za-z0-9+/=\s]+$')
B64URL_RE = re.compile(r'^[A-Za-z0-9_\-=\s]+$')
B85_CHARS = set("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!#$%&()*+-;<=>?@^_`{|}~")
A85_CHARS = set(chr(c) for c in range(33, 118))  # ASCII 85

FLAG_RE = re.compile(r'[A-Za-z0-9_]{2,10}\{[^}]+\}')

# ── Scoring ───────────────────────────────────────────────────────────────────

def is_printable(b: bytes, threshold: float = 0.80) -> bool:
    if not b:
        return False
    return sum(1 for x in b if 0x20 <= x <= 0x7e or x in (9, 10, 13)) / len(b) >= threshold

def decode_to_str(b: bytes) -> str:
    for enc in ("utf-8", "latin-1"):
        try:
            return b.decode(enc)
        except Exception:
            pass
    return b.decode("latin-1", errors="replace")

def result_score(b: bytes) -> int:
    s = 0
    if is_printable(b):         s += 10
    text = decode_to_str(b)
    if FLAG_RE.search(text):    s += 100
    return s

# ── Decoders ──────────────────────────────────────────────────────────────────

def pad(s: str, block: int) -> str:
    r = len(s) % block
    return s + "=" * ((block - r) % block) if r else s

def try_base16(s: str) -> tuple[str, bytes] | None:
    c = re.sub(r'\s', '', s).upper()
    if not B16_RE.match(c) or len(c) % 2:
        return None
    try:
        return "Base16 / Hex", base64.b16decode(c)
    except Exception:
        return None

def try_base32(s: str) -> list[tuple[str, bytes]]:
    results = []
    c = re.sub(r'\s', '', s).upper()
    if not B32_RE.match(c):
        return results
    for label, candidate in [
        ("Base32 (standard)", pad(c, 8)),
        ("Base32 (no-pad)",   c),
    ]:
        try:
            dec = base64.b32decode(candidate, casefold=True)
            results.append((label, dec))
        except Exception:
            pass
    # Base32 hex
    c2 = re.sub(r'\s', '', s).upper()
    if B32HEX_RE.match(c2):
        try:
            dec = base64.b32hexdecode(pad(c2, 8), casefold=True)
            results.append(("Base32-Hex", dec))
        except Exception:
            pass
    return results

def try_base64(s: str) -> list[tuple[str, bytes]]:
    results = []
    c = re.sub(r'\s|\n|\r', '', s)
    for label, candidate, urlsafe in [
        ("Base64 (standard)", pad(c, 4), False),
        ("Base64-URL",        pad(c.replace('+','-').replace('/','_'), 4), True),
        ("Base64 (no-pad)",   c, False),
    ]:
        try:
            dec = base64.urlsafe_b64decode(candidate) if urlsafe else base64.b64decode(candidate, validate=False)
            results.append((label, dec))
        except Exception:
            pass
    # Double base64
    if results:
        first = results[0][1]
        try:
            first_str = first.decode("ascii").strip()
            dec2 = base64.b64decode(pad(re.sub(r'\s', '', first_str), 4), validate=False)
            results.append(("Base64 (double)", dec2))
        except Exception:
            pass
    return results

def try_base58(s: str) -> tuple[str, bytes] | None:
    c = re.sub(r'\s', '', s)
    if not all(ch in B58_CHARS for ch in c):
        return None
    try:
        n = 0
        for ch in c:
            n = n * 58 + B58_CHARS.index(ch)
        leading = len(c) - len(c.lstrip('1'))
        dec = b'\x00' * leading + n.to_bytes(max(1, (n.bit_length() + 7) // 8), 'big')
        return "Base58", dec
    except Exception:
        return None

def try_base85(s: str) -> list[tuple[str, bytes]]:
    results = []
    c = re.sub(r'\s', '', s)
    # RFC 1924 / Python b85
    try:
        dec = base64.b85decode(c)
        results.append(("Base85 (RFC1924/b85)", dec))
    except Exception:
        pass
    # ASCII85 / a85
    try:
        dec = base64.a85decode(c, adobe=False, ignorechars=b' \t\n\r\v')
        results.append(("Base85 (ASCII85/a85)", dec))
    except Exception:
        pass
    # Adobe ASCII85 (<~ ... ~>)
    try:
        wrapped = c if c.startswith("<~") else f"<~{c}~>"
        dec = base64.a85decode(wrapped, adobe=True, ignorechars=b' \t\n\r\v')
        results.append(("Base85 (Adobe a85)", dec))
    except Exception:
        pass
    return results

def try_base36(s: str) -> tuple[str, bytes] | None:
    c = re.sub(r'\s', '', s)
    if not re.fullmatch(r'[0-9A-Za-z]+', c):
        return None
    try:
        n = int(c, 36)
        dec = n.to_bytes(max(1, (n.bit_length() + 7) // 8), 'big')
        return "Base36", dec
    except Exception:
        return None

def try_base62(s: str) -> tuple[str, bytes] | None:
    CHARS = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
    c = re.sub(r'\s', '', s)
    if not all(ch in CHARS for ch in c):
        return None
    try:
        n = 0
        for ch in c:
            n = n * 62 + CHARS.index(ch)
        dec = n.to_bytes(max(1, (n.bit_length() + 7) // 8), 'big')
        return "Base62", dec
    except Exception:
        return None

# ── Confidence heuristic ──────────────────────────────────────────────────────

def detect_likely(s: str) -> list[str]:
    c = re.sub(r'\s', '', s)
    hints = []
    if B16_RE.match(c) and len(c) % 2 == 0:
        hints.append("Base16/Hex")
    if B32_RE.match(c.upper()) and len(c) % 8 == 0:
        hints.append("Base32")
    if B64_RE.match(c) and len(c) % 4 == 0:
        hints.append("Base64")
    if B64URL_RE.match(c):
        hints.append("Base64-URL")
    if all(ch in B58_CHARS for ch in c):
        hints.append("Base58")
    return hints

# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Auto-detect and decode Base16/32/58/64/85 and variants"
    )
    parser.add_argument("input", nargs="?", help="Encoded string or file path")
    parser.add_argument("-f", "--file", help="Read input from file")
    parser.add_argument("-o", "--output", help="Save best decoded output to file")
    parser.add_argument("--all", action="store_true", help="Show all attempts, not just printable results")
    parser.add_argument("--raw", action="store_true", help="Output raw bytes of best result to stdout")
    args = parser.parse_args()

    if args.file:
        text = Path(args.file).read_text(encoding="utf-8", errors="replace").strip()
    elif args.input:
        p = Path(args.input)
        text = p.read_text(encoding="utf-8", errors="replace").strip() if p.exists() else args.input
    elif not sys.stdin.isatty():
        text = sys.stdin.read().strip()
    else:
        parser.print_help()
        sys.exit(1)

    print(f"[*] Input ({len(text)} chars): {text[:80]}{'...' if len(text)>80 else ''}")
    hints = detect_likely(text)
    if hints:
        print(f"[*] Charset hints: {', '.join(hints)}")
    print()

    # Collect all results
    all_results: list[tuple[str, bytes]] = []

    r = try_base16(text)
    if r: all_results.append(r)

    all_results.extend(try_base32(text))
    all_results.extend(try_base64(text))

    r = try_base58(text)
    if r: all_results.append(r)

    all_results.extend(try_base85(text))

    r = try_base36(text)
    if r: all_results.append(r)

    r = try_base62(text)
    if r: all_results.append(r)

    # Deduplicate by decoded bytes
    seen = {}
    for label, dec in all_results:
        if dec not in seen:
            seen[dec] = label
    unique = [(label, dec) for dec, label in seen.items()]
    unique.sort(key=lambda x: result_score(x[1]), reverse=True)

    if not unique:
        print("[!] No successful decodes.")
        return

    best_label, best_dec = None, None
    printed = 0

    for label, dec in unique:
        printable = is_printable(dec)
        flags = FLAG_RE.findall(decode_to_str(dec))
        if not args.all and not printable:
            continue
        text_repr = decode_to_str(dec)
        flag_str = f"  <<< FLAG: {', '.join(flags)}" if flags else ""
        print(f"  [{label}]  {len(dec)} bytes  {'(printable)' if printable else '(binary)'}")
        print(f"    {text_repr[:120]}{'...' if len(text_repr)>120 else ''}{flag_str}")
        if best_label is None:
            best_label, best_dec = label, dec
        printed += 1

    if printed == 0:
        print("[*] No printable results. Use --all to show binary outputs.")

    if best_dec is not None:
        print(f"\n[*] Best guess: {best_label}")
        if args.output:
            Path(args.output).write_bytes(best_dec)
            print(f"[*] Saved to {args.output}")
        if args.raw:
            sys.stdout.buffer.write(best_dec)

    print(f"\n[*] {len(all_results)} decode attempts, {printed} shown.")

if __name__ == "__main__":
    main()
