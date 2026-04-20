#!/usr/bin/env python3
"""
js_deobfuscate.py — Basic JavaScript deobfuscation for CTF challenges.
Finds eval/atob/fromCharCode encoded strings, beautifies, extracts literals.
Usage: python3 js_deobfuscate.py <file.js> [--decode-strings] [--beautify]
"""

import sys
import re
import argparse
import base64
import binascii
from pathlib import Path


FLAG_RE  = re.compile(r'(?:CTF|FLAG|OSC|DUCTF|HTB|picoCTF|flag)\{[^}]{1,200}\}', re.IGNORECASE)
B64_RE   = re.compile(r'["\']([A-Za-z0-9+/]{20,}={0,2})["\']')
HEX_RE   = re.compile(r'(?:\\x[0-9a-fA-F]{2}){4,}')
CCHAR_RE = re.compile(r'String\.fromCharCode\(([0-9,\s]+)\)')
ATOB_RE  = re.compile(r'atob\(["\']([A-Za-z0-9+/=]{10,})["\']\)')
EVAL_RE  = re.compile(r'\beval\s*\(')
OBF_VAR  = re.compile(r'\b(_0x[0-9a-fA-F]{4,})\b')


def try_b64(s):
    try:
        decoded = base64.b64decode(s + '==').decode('utf-8', errors='replace')
        if decoded.isprintable():
            return decoded
    except Exception:
        pass
    return None


def decode_hex_escapes(s):
    def repl(m):
        raw = m.group(0)
        try:
            return bytes.fromhex(raw.replace('\\x', '')).decode('utf-8', errors='replace')
        except Exception:
            return raw
    return HEX_RE.sub(repl, s)


def decode_fromcharcode(m):
    nums = [int(x.strip()) for x in m.group(1).split(',') if x.strip().isdigit()]
    return repr(''.join(chr(n) for n in nums))


def beautify_simple(src):
    """Very basic JS beautifier — adds newlines after ; { }"""
    out = []
    indent = 0
    i = 0
    while i < len(src):
        c = src[i]
        if c == '{':
            out.append(' {\n' + '  ' * (indent + 1))
            indent += 1
        elif c == '}':
            indent = max(0, indent - 1)
            out.append('\n' + '  ' * indent + '}\n' + '  ' * indent)
        elif c == ';':
            out.append(';\n' + '  ' * indent)
        else:
            out.append(c)
        i += 1
    return ''.join(out)


def main():
    ap = argparse.ArgumentParser(description="JS Deobfuscator for CTF")
    ap.add_argument("file", help="JavaScript file to analyse")
    ap.add_argument("--decode-strings", "-d", action="store_true",
                    help="Attempt to decode all base64 / hex string literals")
    ap.add_argument("--beautify", "-b", action="store_true",
                    help="Apply basic beautification")
    args = ap.parse_args()

    src = Path(args.file).read_text(errors='replace')
    print(f"[*] File: {args.file}  ({len(src)} chars)")

    # Check for obfuscation indicators
    print("\n[OBFUSCATION INDICATORS]")
    if EVAL_RE.search(src):
        count = len(EVAL_RE.findall(src))
        print(f"  [!] {count} eval() call(s) found — likely obfuscated")
    obf_vars = set(OBF_VAR.findall(src))
    if obf_vars:
        print(f"  [!] {len(obf_vars)} _0xNNNN variable names — hex-array obfuscation detected")
    if 'jsfuck' in src.lower() or src.count('![]') > 20:
        print("  [!] Possible JSFuck encoding detected")
    if src.count('\\x') > 20:
        print(f"  [!] {src.count('\\x')} \\x hex escapes found")

    # Flag search
    print("\n[FLAG SEARCH]")
    flags = FLAG_RE.findall(src)
    if flags:
        print(f"  [!!!] FLAGS FOUND: {flags}")
    else:
        print("  No direct flag strings found")

    # atob() calls — base64 decode
    print("\n[ATOB / BASE64 LITERALS]")
    atob_hits = ATOB_RE.findall(src)
    for b64 in atob_hits:
        decoded = try_b64(b64)
        if decoded:
            print(f"  atob('{b64[:40]}...') → {decoded[:120]}")
            m = FLAG_RE.search(decoded)
            if m:
                print(f"    [!!!] FLAG: {m.group()}")

    # Standalone base64 strings
    if args.decode_strings:
        print("\n[BASE64 STRING LITERALS]")
        for m in B64_RE.finditer(src):
            b64 = m.group(1)
            decoded = try_b64(b64)
            if decoded and len(decoded) > 4:
                print(f"  '{b64[:40]}' → {decoded[:120]}")

    # String.fromCharCode
    print("\n[STRING.FROMCHARCODE]")
    decoded_src = CCHAR_RE.sub(decode_fromcharcode, src)
    if decoded_src != src:
        print("  [+] fromCharCode patterns decoded — see output below")
        m = FLAG_RE.search(decoded_src)
        if m:
            print(f"  [!!!] FLAG after decode: {m.group()}")
    else:
        print("  None found")

    # Hex escape sequences
    print("\n[HEX ESCAPE SEQUENCES]")
    hex_decoded = decode_hex_escapes(src)
    if hex_decoded != src:
        print("  [+] \\x sequences decoded")
        m = FLAG_RE.search(hex_decoded)
        if m:
            print(f"  [!!!] FLAG after decode: {m.group()}")
    else:
        print("  None found")

    # Extract all string literals > 40 chars (potential encoded payloads)
    print("\n[LONG STRING LITERALS (>40 chars)]")
    long_strings = re.findall(r'["\']([A-Za-z0-9+/=\\%]{40,})["\']', src)
    for s in long_strings[:20]:
        print(f"  {s[:100]}")

    # Beautify output
    if args.beautify:
        print("\n[BEAUTIFIED SOURCE]")
        print(beautify_simple(src)[:5000])


if __name__ == "__main__":
    main()
