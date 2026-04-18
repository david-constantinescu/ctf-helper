#!/usr/bin/env python3
"""
strings_extractor.py — pull printable strings + flag patterns from any binary
"""

import sys
import re
import argparse
from pathlib import Path

# Common CTF flag patterns
FLAG_PATTERNS = [
    r'CTF\{[^}]+\}',
    r'flag\{[^}]+\}',
    r'FLAG\{[^}]+\}',
    r'OSC\{[^}]+\}',
    r'picoCTF\{[^}]+\}',
    r'HTB\{[^}]+\}',
    r'THM\{[^}]+\}',
    r'DUCTF\{[^}]+\}',
    r'[A-Z0-9_]{2,10}\{[A-Za-z0-9_\-=+/!@#$%^&*.,?]+\}',
]

COMPILED_FLAGS = [re.compile(p, re.IGNORECASE) for p in FLAG_PATTERNS]

def extract_strings(data: bytes, min_len: int, encoding: str) -> list[tuple[int, str]]:
    results = []
    if encoding == 'ascii':
        pattern = rb'[ -~]{' + str(min_len).encode() + rb',}'
        for m in re.finditer(pattern, data):
            results.append((m.start(), m.group().decode('ascii', errors='replace')))
    elif encoding == 'utf16le':
        pattern = re.compile(rb'(?:[ -~]\x00){' + str(min_len).encode() + rb',}')
        for m in re.finditer(pattern, data):
            try:
                s = m.group().decode('utf-16-le', errors='replace')
                results.append((m.start(), s))
            except Exception:
                pass
    return results

def highlight_flags(s: str) -> tuple[bool, list[str]]:
    hits = []
    for pat in COMPILED_FLAGS:
        for m in pat.finditer(s):
            hits.append(m.group())
    return bool(hits), hits

def main():
    parser = argparse.ArgumentParser(description="Extract printable strings and flag patterns from a binary")
    parser.add_argument("input", help="Input file")
    parser.add_argument("-n", "--min-len", type=int, default=4, help="Minimum string length (default: 4)")
    parser.add_argument("-e", "--encoding", choices=["ascii", "utf16le", "both"], default="both",
                        help="String encoding to search (default: both)")
    parser.add_argument("-o", "--output", default=None, help="Save all strings to file")
    parser.add_argument("--flags-only", action="store_true", help="Print only flag pattern matches")
    parser.add_argument("--offset", action="store_true", help="Show file offset for each string")
    args = parser.parse_args()

    in_path = Path(args.input)
    if not in_path.exists():
        print(f"[!] File not found: {in_path}")
        sys.exit(1)

    data = in_path.read_bytes()
    print(f"[*] Scanning {in_path}  ({len(data):,} bytes)  min-len={args.min_len}\n")

    encodings = []
    if args.encoding in ("ascii", "both"):
        encodings.append("ascii")
    if args.encoding in ("utf16le", "both"):
        encodings.append("utf16le")

    all_strings: list[tuple[int, str, str]] = []
    for enc in encodings:
        for offset, s in extract_strings(data, args.min_len, enc):
            all_strings.append((offset, s, enc))

    all_strings.sort(key=lambda x: x[0])

    flags_found = []
    out_lines = []

    for offset, s, enc in all_strings:
        has_flag, hits = highlight_flags(s)
        if has_flag:
            for hit in hits:
                flags_found.append(hit)

        if args.flags_only and not has_flag:
            continue

        prefix = f"0x{offset:08x}  [{enc:7s}]  " if args.offset else ""
        line = prefix + s
        out_lines.append(line)
        marker = "  <== FLAG!" if has_flag else ""
        print(line + marker)

    if flags_found:
        print("\n" + "=" * 60)
        print(f"[!!!] FLAG PATTERNS FOUND ({len(flags_found)}):")
        for f in dict.fromkeys(flags_found):  # deduplicate preserving order
            print(f"  >>> {f}")
        print("=" * 60)
    else:
        print("\n[*] No flag patterns matched.")

    print(f"\n[*] Total strings found: {len(all_strings)}")

    if args.output:
        out_path = Path(args.output)
        out_path.write_text("\n".join(out_lines), encoding="utf-8")
        print(f"[*] Strings saved to {out_path}")

if __name__ == "__main__":
    main()
