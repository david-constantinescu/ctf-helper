#!/usr/bin/env python3
"""
php_deobfuscate.py — PHP deobfuscation for CTF challenges.
Handles: base64_decode, str_rot13, gzinflate/gzuncompress, eval chains,
         hex/octal string literals, chr() arrays, variable function calls.
Usage: python3 php_deobfuscate.py <file.php>
       echo '<?php eval(base64_decode("...")); ?>' | python3 php_deobfuscate.py -
"""

import sys
import re
import base64
import gzip
import zlib
import argparse
from pathlib import Path


FLAG_RE = re.compile(r'(?:CTF|FLAG|OSC|DUCTF|HTB|picoCTF|flag)\{[^}]{1,200}\}', re.IGNORECASE)


def rot13(s):
    result = []
    for c in s:
        if 'a' <= c <= 'z':
            result.append(chr((ord(c) - ord('a') + 13) % 26 + ord('a')))
        elif 'A' <= c <= 'Z':
            result.append(chr((ord(c) - ord('A') + 13) % 26 + ord('A')))
        else:
            result.append(c)
    return ''.join(result)


def try_b64(s):
    try:
        return base64.b64decode(s + '==').decode('utf-8', errors='replace')
    except Exception:
        return None


def try_decompress(data):
    for fn in (
        lambda d: zlib.decompress(d, -15),  # gzinflate (raw deflate)
        gzip.decompress,                     # gzuncompress / gzdecode
        zlib.decompress,                     # zlib
    ):
        try:
            return fn(data).decode('utf-8', errors='replace')
        except Exception:
            pass
    return None


def decode_hex_strings(src):
    """Replace PHP hex string literals: "\x41\x42" → "AB" """
    def repl(m):
        try:
            return bytes.fromhex(m.group(1).replace('\\x', '')).decode('utf-8', errors='replace')
        except Exception:
            return m.group(0)
    return re.sub(r'((?:\\x[0-9a-fA-F]{2}){2,})', repl, src)


def decode_octal_strings(src):
    """Replace PHP octal literals: "\101\102" → "AB" """
    def repl(m):
        try:
            return bytes([int(o, 8) for o in re.findall(r'\\([0-7]{1,3})', m.group(0))]).decode('utf-8', errors='replace')
        except Exception:
            return m.group(0)
    return re.sub(r'(?:\\[0-7]{1,3}){2,}', repl, src)


def decode_chr_array(src):
    """chr(65).chr(66).chr(67) → "ABC" """
    def repl(m):
        nums = re.findall(r'chr\s*\(\s*(\d+)\s*\)', m.group(0), re.IGNORECASE)
        try:
            return '"' + ''.join(chr(int(n)) for n in nums) + '"'
        except Exception:
            return m.group(0)
    pattern = r'(?:chr\s*\(\s*\d+\s*\)\s*\.?\s*){2,}'
    return re.sub(pattern, repl, src, flags=re.IGNORECASE)


def apply_php_functions(src, depth=0):
    """Iteratively apply PHP string functions visible in source."""
    if depth > 8:
        return src
    changed = True
    while changed and depth < 8:
        changed = False
        depth += 1

        # base64_decode("...")
        for m in re.finditer(r'base64_decode\s*\(\s*[\'"]([A-Za-z0-9+/=\s]{10,})[\'"]\s*\)', src, re.IGNORECASE):
            decoded = try_b64(m.group(1).replace(' ', '').replace('\n', ''))
            if decoded:
                print(f"  [+] base64_decode → {decoded[:200]}")
                src = src[:m.start()] + repr(decoded) + src[m.end():]
                changed = True
                break

        # str_rot13("...")
        for m in re.finditer(r'str_rot13\s*\(\s*[\'"]([^\'"]+)[\'"]\s*\)', src, re.IGNORECASE):
            decoded = rot13(m.group(1))
            print(f"  [+] str_rot13 → {decoded[:200]}")
            src = src[:m.start()] + repr(decoded) + src[m.end():]
            changed = True
            break

        # gzinflate(base64_decode("..."))
        for m in re.finditer(
            r'gzinflate\s*\(\s*base64_decode\s*\(\s*[\'"]([A-Za-z0-9+/=\s]{10,})[\'"]\s*\)\s*\)',
            src, re.IGNORECASE
        ):
            raw = None
            try:
                raw = base64.b64decode(m.group(1).replace(' ', '').replace('\n', '') + '==')
            except Exception:
                pass
            if raw:
                text = try_decompress(raw)
                if text:
                    print(f"  [+] gzinflate(base64_decode) → {text[:200]}")
                    src = src[:m.start()] + repr(text) + src[m.end():]
                    changed = True
                    break

        # str_replace('X','Y', ...) literal
        for m in re.finditer(
            r"str_replace\s*\(\s*['\"]([^'\"]*)['\"],\s*['\"]([^'\"]*)['\"],\s*['\"]([^'\"]*)['\"]",
            src, re.IGNORECASE
        ):
            result = m.group(3).replace(m.group(1), m.group(2))
            src = src[:m.start()] + repr(result) + src[m.end():]
            changed = True
            break

    return src


def analyse(src, depth=0):
    if depth > 6:
        return src
    print(f"\n[LAYER {depth}] {len(src)} chars")

    flags = FLAG_RE.findall(src)
    if flags:
        print(f"[!!!] FLAGS: {flags}")

    # Indicators
    indicators = []
    if re.search(r'eval\s*\(', src, re.IGNORECASE): indicators.append('eval')
    if re.search(r'base64_decode', src, re.IGNORECASE): indicators.append('base64_decode')
    if re.search(r'str_rot13', src, re.IGNORECASE): indicators.append('str_rot13')
    if re.search(r'gzinflate|gzuncompress|gzdecode', src, re.IGNORECASE): indicators.append('gzip')
    if re.search(r'chr\s*\(\s*\d', src, re.IGNORECASE): indicators.append('chr() concat')
    if re.search(r'\\x[0-9a-fA-F]{2}', src): indicators.append('hex escapes')
    if re.search(r'\\[0-7]{2,3}', src): indicators.append('octal escapes')
    if re.search(r'\$[a-z_]+\s*=\s*[\'"][^\'"]{50,}[\'"]', src, re.IGNORECASE): indicators.append('long string var')
    if re.search(r'assert\s*\(', src, re.IGNORECASE): indicators.append('assert() (eval-like)')
    if re.search(r'preg_replace.*\/e\b', src, re.IGNORECASE): indicators.append('preg_replace /e flag')

    if indicators:
        print(f"[*] Detected: {', '.join(indicators)}")
    else:
        print("[*] No obvious PHP obfuscation at this layer")
        return src

    decoded = src
    decoded = decode_hex_strings(decoded)
    decoded = decode_octal_strings(decoded)
    decoded = decode_chr_array(decoded)
    decoded = apply_php_functions(decoded, depth=depth)

    # If there's still eval(...) wrapping the result, recurse
    eval_inner = re.search(r'eval\s*\(\s*(\'[^\']+\'|"[^"]+"|[^;]+)\s*\)\s*;', decoded, re.IGNORECASE | re.DOTALL)
    if eval_inner:
        inner = eval_inner.group(1).strip("'\"")
        if inner != src and len(inner) > 5:
            return analyse(inner, depth + 1)

    return decoded


def main():
    ap = argparse.ArgumentParser(description="PHP Deobfuscator for CTF")
    ap.add_argument("file", help="PHP file or '-' for stdin")
    args = ap.parse_args()

    if args.file == '-':
        src = sys.stdin.read()
    else:
        src = Path(args.file).read_text(errors='replace')

    print(f"[*] Input: {len(src)} chars")
    print("=" * 60)

    result = analyse(src, depth=0)

    print("\n" + "=" * 60)
    print("[FINAL OUTPUT]")
    print(result[:5000])

    flags = FLAG_RE.findall(result)
    if flags:
        print(f"\n[!!!] FLAGS IN FINAL OUTPUT: {flags}")


if __name__ == "__main__":
    main()
