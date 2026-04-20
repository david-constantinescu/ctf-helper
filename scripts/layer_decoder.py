#!/usr/bin/env python3
"""
layer_decoder.py — Recursive multi-layer encoding detector and decoder for CTF.
Keeps decoding until no further encoding is detected or max depth reached.
Handles: base64, base32, base58, hex, URL, gzip, zlib, ROT13/47, reverse,
         HTML entities, unicode escapes, binary, morse, and more.
Usage: python3 layer_decoder.py <input_string_or_file>
       echo 'SGVsbG8=' | python3 layer_decoder.py -
"""

import sys
import re
import base64
import gzip
import zlib
import urllib.parse
import html
import binascii
import argparse
from pathlib import Path


FLAG_RE = re.compile(r'(?:CTF|FLAG|OSC|DUCTF|HTB|picoCTF|flag)\{[^}]{1,200}\}', re.IGNORECASE)
MAX_DEPTH = 20
MIN_PRINTABLE_RATIO = 0.80


def is_printable(s):
    if not s:
        return False
    printable = sum(1 for c in s if 32 <= ord(c) < 127 or c in '\n\r\t')
    return printable / len(s) >= MIN_PRINTABLE_RATIO


def try_base64(s):
    s = s.strip().replace('\n', '').replace(' ', '')
    if len(s) < 4:
        return None
    for pad in ('', '=', '=='):
        try:
            raw = base64.b64decode(s + pad, validate=False)
            decoded = raw.decode('utf-8', errors='replace')
            if is_printable(decoded) and decoded != s:
                return ('base64', decoded)
        except Exception:
            pass
    return None


def try_base32(s):
    s = s.strip().upper().replace(' ', '')
    if not re.fullmatch(r'[A-Z2-7=]+', s) or len(s) < 8:
        return None
    try:
        raw = base64.b32decode(s + '=' * (-len(s) % 8))
        decoded = raw.decode('utf-8', errors='replace')
        if is_printable(decoded) and decoded != s:
            return ('base32', decoded)
    except Exception:
        pass
    return None


def try_base58(s):
    ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    s = s.strip()
    if not all(c in ALPHABET for c in s) or len(s) < 5:
        return None
    try:
        n = 0
        for c in s:
            n = n * 58 + ALPHABET.index(c)
        length = (n.bit_length() + 7) // 8
        raw = n.to_bytes(length, 'big')
        decoded = raw.decode('utf-8', errors='replace')
        if is_printable(decoded):
            return ('base58', decoded)
    except Exception:
        pass
    return None


def try_hex(s):
    s = s.strip().replace(' ', '').replace('0x', '').replace('\\x', '')
    if not re.fullmatch(r'[0-9a-fA-F]+', s) or len(s) < 8 or len(s) % 2 != 0:
        return None
    try:
        raw = bytes.fromhex(s)
        decoded = raw.decode('utf-8', errors='replace')
        if is_printable(decoded) and decoded != s:
            return ('hex', decoded)
    except Exception:
        pass
    return None


def try_url(s):
    if '%' not in s and '+' not in s:
        return None
    try:
        decoded = urllib.parse.unquote_plus(s)
        if decoded != s and is_printable(decoded):
            return ('url', decoded)
    except Exception:
        pass
    return None


def try_html_entities(s):
    if '&' not in s and '&#' not in s:
        return None
    try:
        decoded = html.unescape(s)
        if decoded != s:
            return ('html_entities', decoded)
    except Exception:
        pass
    return None


def try_rot13(s):
    if not re.search(r'[a-zA-Z]', s):
        return None
    result = []
    for c in s:
        if 'a' <= c <= 'z':
            result.append(chr((ord(c) - ord('a') + 13) % 26 + ord('a')))
        elif 'A' <= c <= 'Z':
            result.append(chr((ord(c) - ord('A') + 13) % 26 + ord('A')))
        else:
            result.append(c)
    decoded = ''.join(result)
    if FLAG_RE.search(decoded):
        return ('rot13', decoded)
    return None


def try_rot47(s):
    result = []
    for c in s:
        if '!' <= c <= '~':
            result.append(chr(33 + (ord(c) - 33 + 47) % 94))
        else:
            result.append(c)
    decoded = ''.join(result)
    if FLAG_RE.search(decoded) and decoded != s:
        return ('rot47', decoded)
    return None


def try_reverse(s):
    decoded = s[::-1]
    if FLAG_RE.search(decoded) or try_base64(decoded) or try_hex(decoded):
        return ('reversed', decoded)
    return None


def try_gzip(s):
    # Accept both raw bytes (if s is somehow bytes) and base64-encoded gzip
    try:
        raw = base64.b64decode(s.strip() + '==')
        text = gzip.decompress(raw).decode('utf-8', errors='replace')
        if is_printable(text):
            return ('gzip+base64', text)
    except Exception:
        pass
    # Raw deflate
    try:
        raw = base64.b64decode(s.strip() + '==')
        text = zlib.decompress(raw, -15).decode('utf-8', errors='replace')
        if is_printable(text):
            return ('deflate+base64', text)
    except Exception:
        pass
    return None


def try_unicode_escapes(s):
    if '\\u' not in s and '\\U' not in s:
        return None
    try:
        decoded = s.encode('raw_unicode_escape').decode('unicode_escape')
        if decoded != s and is_printable(decoded):
            return ('unicode_escape', decoded)
    except Exception:
        pass
    try:
        decoded = re.sub(r'\\u([0-9a-fA-F]{4})',
                         lambda m: chr(int(m.group(1), 16)), s)
        if decoded != s:
            return ('unicode_escape', decoded)
    except Exception:
        pass
    return None


def try_binary(s):
    s = s.strip().replace(' ', '')
    if not re.fullmatch(r'[01]+', s) or len(s) < 8 or len(s) % 8 != 0:
        return None
    try:
        raw = int(s, 2).to_bytes(len(s) // 8, 'big')
        decoded = raw.decode('utf-8', errors='replace')
        if is_printable(decoded):
            return ('binary', decoded)
    except Exception:
        pass
    return None


DECODERS = [
    try_url,
    try_html_entities,
    try_unicode_escapes,
    try_binary,
    try_hex,
    try_base32,
    try_base64,
    try_base58,
    try_gzip,
    try_rot13,
    try_rot47,
    try_reverse,
]


def decode_layers(s, verbose=True):
    history = []
    current = s.strip()

    for depth in range(MAX_DEPTH):
        flag = FLAG_RE.search(current)
        if flag:
            if verbose:
                print(f"\n[!!!] FLAG FOUND at layer {depth}: {flag.group()}")
            break

        found = False
        for decoder in DECODERS:
            result = decoder(current)
            if result:
                name, decoded = result
                if decoded == current:
                    continue
                if verbose:
                    preview = decoded[:120].replace('\n', '\\n')
                    print(f"[Layer {depth+1}] {name}: {preview}")
                history.append((name, decoded))
                current = decoded
                found = True
                break

        if not found:
            if verbose:
                print(f"[*] No further encoding detected at layer {depth+1}")
            break

    return current, history


def main():
    ap = argparse.ArgumentParser(description="Recursive Multi-Layer Decoder for CTF")
    ap.add_argument("input", help="Encoded string, file path, or '-' for stdin")
    ap.add_argument("-q", "--quiet", action="store_true", help="Only show final output")
    args = ap.parse_args()

    if args.input == '-':
        raw = sys.stdin.read().strip()
    elif Path(args.input).exists():
        raw = Path(args.input).read_text(errors='replace').strip()
    else:
        raw = args.input

    print(f"[*] Input ({len(raw)} chars): {raw[:100]}")
    print("=" * 60)

    final, history = decode_layers(raw, verbose=not args.quiet)

    print("\n[FINAL]")
    print(final[:2000])

    if history:
        print(f"\n[PATH] {' → '.join(h[0] for h in history)}")

    flags = FLAG_RE.findall(final)
    if flags:
        print(f"\n[!!!] FLAGS: {flags}")


if __name__ == "__main__":
    main()
