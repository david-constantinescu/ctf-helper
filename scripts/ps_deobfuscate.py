#!/usr/bin/env python3
"""
ps_deobfuscate.py — PowerShell deobfuscation for CTF challenges.
Handles: -EncodedCommand, [char] arrays, -join, Invoke-Expression,
         XOR loops, compressed payloads, string reversal, and more.
Usage: python3 ps_deobfuscate.py <file.ps1>
       echo '<ps1 code>' | python3 ps_deobfuscate.py -
"""

import sys
import re
import base64
import gzip
import zlib
import argparse
from pathlib import Path


FLAG_RE = re.compile(r'(?:CTF|FLAG|OSC|DUCTF|HTB|picoCTF|flag)\{[^}]{1,200}\}', re.IGNORECASE)


def try_b64(s):
    for pad in ('', '=', '=='):
        try:
            raw = base64.b64decode(s + pad)
            # PowerShell uses UTF-16LE for -EncodedCommand
            try:
                return raw.decode('utf-16-le')
            except Exception:
                pass
            try:
                return raw.decode('utf-8')
            except Exception:
                pass
        except Exception:
            pass
    return None


def decode_char_array(match):
    """[char]65,[char]66 or [char[]]@(65,66,67) → string"""
    nums = re.findall(r'\d+', match.group(0))
    try:
        return ''.join(chr(int(n)) for n in nums if 0 < int(n) < 0x110000)
    except Exception:
        return match.group(0)


def decode_join(src):
    """('a','b','c') -join '' → 'abc'"""
    def repl(m):
        items = re.findall(r"['\"]([^'\"]*)['\"]", m.group(1))
        sep_m = re.search(r'-join\s*['\"]([^'\"]*)['\"]', m.group(0))
        sep = sep_m.group(1) if sep_m else ''
        return repr(sep.join(items))
    return re.sub(r'\(([^)]+)\)\s*-join\s*[\'"][^\'"]*[\'"]', repl, src, flags=re.IGNORECASE)


def decode_replace(src):
    """-replace 'X','Y' string operations"""
    def repl(m):
        orig, find, rep = m.group(1), m.group(2), m.group(3)
        return repr(orig.replace(find, rep))
    return re.sub(
        r"['\"]([^'\"]*)['\"]\.replace\(['\"]([^'\"]*)['\"],\s*['\"]([^'\"]*)['\"]",
        repl, src, flags=re.IGNORECASE
    )


def try_decompress(data):
    """Try gzip and deflate decompression."""
    for fn in (gzip.decompress, zlib.decompress, lambda d: zlib.decompress(d, -15)):
        try:
            return fn(data).decode('utf-8', errors='replace')
        except Exception:
            pass
    return None


def analyse(src, depth=0):
    if depth > 10:
        return src
    indent = '  ' * depth

    print(f"\n{indent}[LAYER {depth}] {len(src)} chars")

    # Flag search at this layer
    flags = FLAG_RE.findall(src)
    if flags:
        print(f"{indent}[!!!] FLAGS: {flags}")

    # Detect indicators
    indicators = []
    if re.search(r'-EncodedCommand\b', src, re.IGNORECASE):
        indicators.append('EncodedCommand')
    if re.search(r'Invoke-Expression|IEX\b|\bIEX\s*\(', src, re.IGNORECASE):
        indicators.append('IEX/Invoke-Expression')
    if re.search(r'\[char\]', src, re.IGNORECASE):
        indicators.append('[char] array')
    if re.search(r'-join\b', src, re.IGNORECASE):
        indicators.append('-join')
    if re.search(r'FromBase64String\b', src, re.IGNORECASE):
        indicators.append('FromBase64String')
    if re.search(r'IO\.Compression', src, re.IGNORECASE):
        indicators.append('IO.Compression (gzip)')
    if re.search(r'\bXOR\b|\bBXOR\b|\s-bxor\s', src, re.IGNORECASE):
        indicators.append('XOR loop')
    if re.search(r'::Reverse\b|\[Array\]::Reverse', src, re.IGNORECASE):
        indicators.append('string reversal')
    if re.search(r'str_rot13|rot13', src, re.IGNORECASE):
        indicators.append('ROT13')

    if indicators:
        print(f"{indent}[*] Detected: {', '.join(indicators)}")
    else:
        print(f"{indent}[*] No obvious obfuscation at this layer")
        return src

    decoded = src

    # 1. -EncodedCommand <base64>
    enc_matches = re.findall(
        r'-(?:EncodedCommand|Enc|En|E)\s+([A-Za-z0-9+/=]{20,})',
        decoded, re.IGNORECASE
    )
    for b64 in enc_matches:
        result = try_b64(b64)
        if result:
            print(f"\n{indent}[+] EncodedCommand decoded:")
            print(f"{indent}    {result[:300]}")
            decoded = result
            break

    # 2. [Convert]::FromBase64String(...)
    b64_calls = re.findall(
        r'FromBase64String\s*\(\s*[\'"]([A-Za-z0-9+/=]{20,})[\'"]\s*\)',
        decoded, re.IGNORECASE
    )
    for b64 in b64_calls:
        raw = None
        try:
            raw = base64.b64decode(b64 + '==')
        except Exception:
            pass
        if raw:
            # Try decompression first
            dc = try_decompress(raw)
            if dc:
                print(f"\n{indent}[+] FromBase64String + decompress:")
                print(f"{indent}    {dc[:300]}")
                decoded = dc
                break
            else:
                try:
                    text = raw.decode('utf-16-le') or raw.decode('utf-8', errors='replace')
                    print(f"\n{indent}[+] FromBase64String decoded:")
                    print(f"{indent}    {text[:300]}")
                    decoded = text
                    break
                except Exception:
                    pass

    # 3. [char] arrays
    if '[char]' in decoded.lower():
        decoded_chars = re.sub(
            r'(?:\[char\]\s*\d+(?:\s*[+,]\s*\[char\]\s*\d+)*)',
            decode_char_array,
            decoded,
            flags=re.IGNORECASE
        )
        if decoded_chars != decoded:
            print(f"\n{indent}[+] [char] arrays decoded")
            decoded = decoded_chars

    # 4. String reversal
    rev_m = re.search(r"['\"]([A-Za-z0-9+/=]{10,})['\"].*?-split.*?-join|"
                      r"\[Array\]::Reverse", decoded, re.IGNORECASE | re.DOTALL)
    if re.search(r'::Reverse\b', decoded, re.IGNORECASE):
        str_lits = re.findall(r"['\"]([A-Za-z0-9+/=.,\- ]{10,})['\"]", decoded)
        for s in str_lits:
            rev = s[::-1]
            print(f"{indent}[+] Reversed string: {rev[:200]}")
            b64_try = try_b64(rev)
            if b64_try:
                print(f"{indent}    → base64 decoded: {b64_try[:200]}")
                decoded = b64_try

    # 5. XOR loop: common pattern -bxor KEY
    xor_m = re.search(r'-bxor\s*(\d+)', decoded, re.IGNORECASE)
    if xor_m:
        key = int(xor_m.group(1))
        # Find byte array
        bytes_m = re.search(r'\(([0-9,\s]+)\)', decoded)
        if bytes_m:
            try:
                arr = [int(x.strip()) for x in bytes_m.group(1).split(',') if x.strip().isdigit()]
                xored = bytes(b ^ key for b in arr)
                text = xored.decode('utf-8', errors='replace')
                print(f"\n{indent}[+] XOR key={key} decoded: {text[:300]}")
                decoded = text
            except Exception:
                pass

    # Recurse if IEX present
    if re.search(r'Invoke-Expression|IEX\b', decoded, re.IGNORECASE) and depth < 5:
        # Strip IEX wrapper and recurse
        stripped = re.sub(r'(?:Invoke-Expression|IEX)\s*\(?\s*', '', decoded, flags=re.IGNORECASE)
        if stripped != decoded:
            return analyse(stripped, depth + 1)

    return decoded


def main():
    ap = argparse.ArgumentParser(description="PowerShell Deobfuscator for CTF")
    ap.add_argument("file", help="PS1 file or '-' for stdin")
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
    print(result[:3000])

    flags = FLAG_RE.findall(result)
    if flags:
        print(f"\n[!!!] FLAGS IN FINAL OUTPUT: {flags}")


if __name__ == "__main__":
    main()
