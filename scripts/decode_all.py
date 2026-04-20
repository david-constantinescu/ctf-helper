#!/usr/bin/env python3
"""
decode_all.py — universal CTF decoder
Tries ROT-N, Base*, XOR, Atbash, hex, reverse, URL, and more.
Detects flag-like structure (PREFIX{content}) and attacks each part.
"""

import sys
import re
import base64
import urllib.parse
import html
import argparse
import binascii
import string
from pathlib import Path

# ── Scoring / flag detection ──────────────────────────────────────────────────

FLAG_RE = re.compile(r'[A-Za-z0-9_]{2,10}\{[^}]{3,}\}')
PRINTABLE_RATIO_THRESHOLD = 0.75

ENGLISH_FREQ = {
    'e':12.7,'t':9.1,'a':8.2,'o':7.5,'i':7.0,'n':6.7,'s':6.3,'h':6.1,
    'r':6.0,'d':4.3,'l':4.0,'c':2.8,'u':2.8,'m':2.4,'w':2.4,'f':2.2,
    'g':2.0,'y':2.0,'p':1.9,'b':1.5,'v':1.0,'k':0.8,'j':0.15,'x':0.15,
    'q':0.10,'z':0.07,
}

KNOWN_PREFIXES = {
    "CTF","FLAG","OSC","HTB","THM","PICO","DUCTF","HACK","SEC","CRYPTO",
    "WEB","PWN","REV","MISC","FORENSICS","STEGO","NET",
}

def is_printable(s: str) -> bool:
    if not s:
        return False
    ratio = sum(1 for c in s if c.isprintable()) / len(s)
    return ratio >= PRINTABLE_RATIO_THRESHOLD

def english_score(s: str) -> float:
    s = s.lower()
    letters = [c for c in s if c.isalpha()]
    if not letters:
        return 0.0
    freq = {c: letters.count(c)/len(letters)*100 for c in set(letters)}
    return sum(min(freq.get(c,0), v) for c, v in ENGLISH_FREQ.items())

def has_flag(s: str) -> list[str]:
    return FLAG_RE.findall(s)

def has_known_prefix(s: str) -> bool:
    m = re.match(r'^([A-Z]{2,10})\{', s.upper())
    return bool(m and m.group(1) in KNOWN_PREFIXES)

def score(s: str) -> tuple[int, float]:
    """Returns (flag_count, english_score)."""
    return (len(has_flag(s)), english_score(s))

# ── ROT ───────────────────────────────────────────────────────────────────────

def rot_n(text: str, n: int) -> str:
    out = []
    for c in text:
        if 'a' <= c <= 'z':
            out.append(chr((ord(c) - ord('a') + n) % 26 + ord('a')))
        elif 'A' <= c <= 'Z':
            out.append(chr((ord(c) - ord('A') + n) % 26 + ord('A')))
        else:
            out.append(c)
    return "".join(out)

def rot47(text: str) -> str:
    return "".join(
        chr((ord(c) - 33 + 47) % 94 + 33) if '!' <= c <= '~' else c
        for c in text
    )

# ── Atbash ────────────────────────────────────────────────────────────────────

def atbash(text: str) -> str:
    out = []
    for c in text:
        if 'a' <= c <= 'z':
            out.append(chr(ord('z') - (ord(c) - ord('a'))))
        elif 'A' <= c <= 'Z':
            out.append(chr(ord('Z') - (ord(c) - ord('A'))))
        else:
            out.append(c)
    return "".join(out)

# ── Base decoders ─────────────────────────────────────────────────────────────

def try_base64(s: str) -> str | None:
    for candidate in [s, s + "=", s + "==", s.replace(" ", "+")]:
        try:
            dec = base64.b64decode(candidate, validate=False)
            result = dec.decode("utf-8", errors="replace")
            if is_printable(result):
                return result
        except Exception:
            pass
    return None

def try_base64_url(s: str) -> str | None:
    try:
        dec = base64.urlsafe_b64decode(s + "==")
        result = dec.decode("utf-8", errors="replace")
        return result if is_printable(result) else None
    except Exception:
        return None

def try_base32(s: str) -> str | None:
    for candidate in [s, s.upper(), s.upper() + "=" * ((8 - len(s) % 8) % 8)]:
        try:
            dec = base64.b32decode(candidate, casefold=True)
            result = dec.decode("utf-8", errors="replace")
            if is_printable(result):
                return result
        except Exception:
            pass
    return None

def try_base16(s: str) -> str | None:
    cleaned = s.replace(" ", "").replace(":", "")
    try:
        dec = base64.b16decode(cleaned.upper())
        result = dec.decode("utf-8", errors="replace")
        return result if is_printable(result) else None
    except Exception:
        return None

def try_hex(s: str) -> str | None:
    cleaned = re.sub(r'[^0-9a-fA-F]', '', s)
    if len(cleaned) % 2 != 0 or len(cleaned) < 2:
        return None
    try:
        dec = bytes.fromhex(cleaned)
        result = dec.decode("utf-8", errors="replace")
        return result if is_printable(result) else None
    except Exception:
        return None

def try_base85(s: str) -> str | None:
    try:
        dec = base64.b85decode(s)
        result = dec.decode("utf-8", errors="replace")
        return result if is_printable(result) else None
    except Exception:
        pass
    try:
        dec = base64.a85decode(s, adobe=False)
        result = dec.decode("utf-8", errors="replace")
        return result if is_printable(result) else None
    except Exception:
        return None

BASE58_CHARS = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
def try_base58(s: str) -> str | None:
    if not all(c in BASE58_CHARS for c in s):
        return None
    try:
        n = 0
        for c in s:
            n = n * 58 + BASE58_CHARS.index(c)
        result = n.to_bytes((n.bit_length() + 7) // 8, 'big').decode("utf-8", errors="replace")
        return result if is_printable(result) else None
    except Exception:
        return None

def try_base36(s: str) -> str | None:
    try:
        n = int(s, 36)
        result = n.to_bytes((n.bit_length() + 7) // 8, 'big').decode("utf-8", errors="replace")
        return result if is_printable(result) else None
    except Exception:
        return None

def try_binary(s: str) -> str | None:
    cleaned = re.sub(r'[^01]', '', s)
    if len(cleaned) % 8 != 0 or len(cleaned) < 8:
        return None
    try:
        result = "".join(chr(int(cleaned[i:i+8], 2)) for i in range(0, len(cleaned), 8))
        return result if is_printable(result) else None
    except Exception:
        return None

def try_octal(s: str) -> str | None:
    parts = s.split()
    if not parts or not all(re.fullmatch(r'[0-7]{3}', p) for p in parts):
        return None
    try:
        result = "".join(chr(int(p, 8)) for p in parts)
        return result if is_printable(result) else None
    except Exception:
        return None

# ── Other transforms ──────────────────────────────────────────────────────────

def try_reverse(s: str) -> str:
    return s[::-1]

def try_url_decode(s: str) -> str | None:
    dec = urllib.parse.unquote(s)
    return dec if dec != s else None

def try_html_decode(s: str) -> str | None:
    dec = html.unescape(s)
    return dec if dec != s else None

def try_double_base64(s: str) -> str | None:
    first = try_base64(s)
    if first:
        return try_base64(first)
    return None

def try_reverse_base64(s: str) -> str | None:
    return try_base64(s[::-1])

def try_xor_single(data: bytes, top_n: int = 5) -> list[tuple[int, str]]:
    results = []
    for key in range(1, 256):
        dec = bytes(b ^ key for b in data)
        try:
            text = dec.decode("utf-8", errors="replace")
        except Exception:
            continue
        if is_printable(text):
            results.append((key, text, english_score(text)))
    results.sort(key=lambda x: x[2], reverse=True)
    return [(k, t) for k, t, _ in results[:top_n]]

def try_morse(s: str) -> str | None:
    MORSE = {
        '.-':'A','-.-.':'C','-..':'D','.':'E','..-.':'F','--.':'G',
        '....':'H','..':'I','.---':'J','-.-':'K','.-..':'L','--':'M',
        '-.':'N','---':'O','.--.':'P','--.-':'Q','.-.':'R','...':'S',
        '-':'T','..-':'U','...-':'V','.--':'W','-..-':'X','-.--':'Y',
        '--..':'Z','-----':'0','.----':'1','..---':'2','...--':'3',
        '....-':'4','.....':'5','-....':'6','--...':'7','---..':'8',
        '----.':'9',
    }
    s = s.strip()
    if not re.fullmatch(r'[.\- /]+', s):
        return None
    words = s.split("  ")
    try:
        result = " ".join(
            "".join(MORSE.get(c, "?") for c in word.split(" "))
            for word in words
        )
        return result
    except Exception:
        return None

# ── Flag-structure aware ──────────────────────────────────────────────────────

def split_flag(s: str) -> tuple[str, str, str] | None:
    """Split PREFIX{content} into (prefix, content, suffix)."""
    m = re.match(r'^([A-Za-z0-9_]+)\{(.+)\}$', s.strip())
    if m:
        return m.group(1), m.group(2), ""
    return None

# ── Result collection ─────────────────────────────────────────────────────────

class Result:
    def __init__(self, method: str, output: str, target: str = "full"):
        self.method = method
        self.output = output
        self.target = target
        self.flags = has_flag(output)
        self.known_prefix = has_known_prefix(output)
        self.eng = english_score(output)
        self.printable = is_printable(output)

    def priority(self) -> tuple:
        return (len(self.flags), int(self.known_prefix), self.eng, int(self.printable))

def collect(results: list[Result], method: str, output, target: str = "full"):
    if output is None:
        return
    if isinstance(output, list):
        for key, text in output:
            if text:
                results.append(Result(f"{method} key=0x{key:02x}", text, target))
    else:
        if output:
            results.append(Result(method, str(output), target))

# ── Main ──────────────────────────────────────────────────────────────────────

def run_all(text: str) -> list[Result]:
    results: list[Result] = []
    raw = text.encode("utf-8", errors="replace")

    # ROT on full text
    for n in range(1, 26):
        collect(results, f"ROT-{n}", rot_n(text, n))
    collect(results, "ROT-47", rot47(text))
    collect(results, "Atbash", atbash(text))

    # Base decoders on full text
    collect(results, "Base64", try_base64(text))
    collect(results, "Base64-URL", try_base64_url(text))
    collect(results, "Base64 (double)", try_double_base64(text))
    collect(results, "Base64 (reversed)", try_reverse_base64(text))
    collect(results, "Base32", try_base32(text))
    collect(results, "Base16", try_base16(text))
    collect(results, "Base85", try_base85(text))
    collect(results, "Base58", try_base58(text))
    collect(results, "Base36", try_base36(text))
    collect(results, "Hex", try_hex(text))
    collect(results, "Binary", try_binary(text))
    collect(results, "Octal", try_octal(text))
    collect(results, "URL-decode", try_url_decode(text))
    collect(results, "HTML-decode", try_html_decode(text))
    collect(results, "Morse", try_morse(text))
    collect(results, "Reverse", try_reverse(text))

    # XOR on raw bytes
    collect(results, "XOR single-byte", try_xor_single(raw, top_n=5))

    # Flag-structure aware
    parts = split_flag(text)
    if parts:
        prefix, content, _ = parts

        # Try ROT on prefix only -> reconstruct with original content
        for n in range(1, 26):
            rp = rot_n(prefix, n)
            collect(results, f"ROT-{n} (prefix only)", f"{rp}{{{content}}}", target="prefix")

        collect(results, "Atbash (prefix only)", f"{atbash(prefix)}{{{content}}}", target="prefix")

        # Try all decoders on content only
        for name, fn in [
            ("Base64",     lambda s: try_base64(s)),
            ("Base64-URL", lambda s: try_base64_url(s)),
            ("Base32",     lambda s: try_base32(s)),
            ("Base16",     lambda s: try_base16(s)),
            ("Base85",     lambda s: try_base85(s)),
            ("Base58",     lambda s: try_base58(s)),
            ("Base36",     lambda s: try_base36(s)),
            ("Hex",        lambda s: try_hex(s)),
            ("Reverse",    lambda s: try_reverse(s)),
            ("ROT-13",     lambda s: rot_n(s, 13)),
        ]:
            out = fn(content)
            if out and out != content:
                collect(results, f"{name} (content only)", f"{prefix}{{{out}}}", target="content")

        # ROT on content only -> reconstruct
        for n in range(1, 26):
            rc = rot_n(content, n)
            if rc != content:
                collect(results, f"ROT-{n} (content only)", f"{prefix}{{{rc}}}", target="content")

        collect(results, "ROT-47 (content only)", f"{prefix}{{{rot47(content)}}}", target="content")
        collect(results, "Atbash (content only)", f"{prefix}{{{atbash(content)}}}", target="content")

        # XOR on content bytes
        content_raw = content.encode("utf-8", errors="replace")
        xor_results = try_xor_single(content_raw, top_n=3)
        for key, dec in xor_results:
            collect(results, f"XOR 0x{key:02x} (content only)", f"{prefix}{{{dec}}}", target="content")

    return results

def main():
    parser = argparse.ArgumentParser(
        description="Universal CTF decoder — tries every common encoding/cipher and ranks results"
    )
    parser.add_argument("input", nargs="?", help="Encoded string or file path")
    parser.add_argument("-f", "--file", help="Read input from file")
    parser.add_argument("--all", action="store_true",
                        help="Show all attempts including unreadable ones")
    parser.add_argument("--top", type=int, default=None,
                        help="Show only top N results by score")
    parser.add_argument("--flags-only", action="store_true",
                        help="Show only results that contain a flag pattern")
    parser.add_argument("--min-score", type=float, default=0.0,
                        help="Hide results with english score below this value")
    parser.add_argument("-s", "--search", action="store_true",
                        help="Search ALL outputs for 'ctf', 'osc', 'rocsc' and show matches with their method")
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

    print(f"[*] Input: {text}")
    parts = split_flag(text)
    if parts:
        print(f"[*] Detected flag structure — prefix={parts[0]!r}  content={parts[1][:40]!r}...")
    print(f"[*] Running decoders...\n")

    results = run_all(text)

    # Deduplicate by output
    seen = {}
    for r in results:
        key = r.output.strip()
        if key not in seen or r.priority() > seen[key].priority():
            seen[key] = r
    unique = sorted(seen.values(), key=lambda r: r.priority(), reverse=True)

    # Filter
    if args.flags_only:
        unique = [r for r in unique if r.flags]
    elif not args.all:
        unique = [r for r in unique if r.printable and r.eng >= args.min_score]

    if args.top:
        unique = unique[:args.top]

    # Print
    FLAG_LINE = "=" * 70
    flag_results = [r for r in unique if r.flags]
    known_results = [r for r in unique if r.known_prefix and not r.flags]
    rest = [r for r in unique if not r.flags and not r.known_prefix]

    def print_result(r: Result, label: str = ""):
        flags_str = f"  <<< {', '.join(r.flags)}" if r.flags else ""
        prefix_str = " [known prefix]" if r.known_prefix else ""
        target_str = f" [{r.target}]" if r.target != "full" else ""
        score_str = f"  score={r.eng:.1f}"
        print(f"  {r.method}{target_str}{prefix_str}{score_str}")
        print(f"    {r.output[:120]}{'...' if len(r.output)>120 else ''}{flags_str}")

    if flag_results:
        print(FLAG_LINE)
        print(f"  !!! FLAG PATTERNS FOUND ({len(flag_results)}) !!!")
        print(FLAG_LINE)
        for r in flag_results:
            print_result(r)
        print(FLAG_LINE + "\n")

    if known_results:
        print(f"--- Known CTF prefix results ({len(known_results)}) ---")
        for r in known_results:
            print_result(r)
        print()

    if rest:
        print(f"--- Other readable results ({len(rest)}) ---")
        for r in rest:
            print_result(r)

    # --search: scan every result (before filtering) for ctf/osc/rocsc
    if args.search:
        SEARCH_RE = re.compile(r'(ctf|osc|rocsc)', re.IGNORECASE)
        search_hits: list[tuple[str, str, list[str]]] = []
        all_results_deduped = list({r.output.strip(): r for r in results}.values())
        for r in all_results_deduped:
            matches = SEARCH_RE.findall(r.output)
            if matches:
                # Collect the surrounding context for each match
                snippets = []
                for m in re.finditer(r'.{0,30}(?:ctf|osc|rocsc).{0,30}', r.output, re.IGNORECASE):
                    snippets.append(m.group())
                search_hits.append((r.method, r.output, snippets))

        SEP = "=" * 70
        print(f"\n{SEP}")
        print(f"  SEARCH RESULTS — 'ctf' / 'osc' / 'rocsc'  ({len(search_hits)} method(s) matched)")
        print(SEP)
        if search_hits:
            for method, output, snippets in search_hits:
                print(f"\n  Method : {method}")
                print(f"  Output : {output[:200]}{'...' if len(output)>200 else ''}")
                if snippets:
                    print(f"  Matches:")
                    for s in snippets:
                        print(f"    >>> ...{s}...")
        else:
            print("  No outputs contained 'ctf', 'osc', or 'rocsc'.")
        print(SEP)

    total = len(results)
    shown = len(unique)
    print(f"\n[*] {total} attempts made, {shown} shown. Use --all to see everything.")

if __name__ == "__main__":
    main()
