#!/usr/bin/env python3
"""
rust_demangler.py — Rust binary analysis and symbol demangling for CTF.
Extracts Rust-mangled symbols from ELF/PE binaries, demangles them,
finds panic messages, and identifies interesting functions.
Usage: python3 rust_demangler.py <binary>
"""

import sys
import re
import subprocess
import argparse
from pathlib import Path


FLAG_RE   = re.compile(r'(?:CTF|FLAG|OSC|DUCTF|HTB|picoCTF|flag)\{[^}]{1,200}\}', re.IGNORECASE)
RUST_MAN  = re.compile(r'_ZN[0-9a-zA-Z$._]+E(?:v|[0-9])?')  # legacy Rust mangling
RUST_V0   = re.compile(r'_R[0-9A-Za-z_]+')                   # Rust v0 mangling


def run(cmd, timeout=30):
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return r.stdout, r.stderr
    except subprocess.TimeoutExpired:
        return '', '[timeout]'
    except Exception as e:
        return '', str(e)


def demangle(sym):
    """Use rustfilt or c++filt to demangle a symbol."""
    for tool in ('rustfilt', 'c++filt'):
        out, _ = run(f'{tool} {sym!r} 2>/dev/null')
        if out.strip() and out.strip() != sym:
            return out.strip()
    # Manual v0 demangle attempt (partial)
    if sym.startswith('_ZN'):
        # Extract readable parts
        parts = re.findall(r'[0-9]+([a-zA-Z_][a-zA-Z0-9_]*)', sym)
        if parts:
            return '::'.join(parts)
    return sym


def detect_rust(path):
    """Check if binary is a Rust binary."""
    out, _ = run(f'strings -n 4 {path!r} | grep -c "rust_panic\\|core::panicking\\|std::rt::lang_start\\|_rust_alloc"')
    try:
        count = int(out.strip())
        return count > 0
    except Exception:
        pass
    # Check for .rustc section
    out2, _ = run(f'readelf -S {path!r} 2>/dev/null | grep -c rustc')
    try:
        return int(out2.strip()) > 0
    except Exception:
        return False


def extract_symbols(path):
    """Extract all symbols using nm or readelf."""
    out, _ = run(f'nm --demangle {path!r} 2>/dev/null || nm {path!r} 2>/dev/null')
    if not out:
        out, _ = run(f'readelf -s {path!r} 2>/dev/null')
    return out


def extract_strings(path):
    """Pull all printable strings."""
    out, _ = run(f'strings -n 6 {path!r}')
    return out


def find_panic_messages(strings_out):
    """Rust panics embed source file paths and messages."""
    panics = []
    for line in strings_out.splitlines():
        if any(kw in line for kw in ('panicked at', 'called `unwrap`', 'called `expect`',
                                      'index out of bounds', 'attempt to')):
            panics.append(line)
    return panics


def find_interesting_symbols(syms_out):
    """Find interesting function names for CTF."""
    interesting = []
    keywords = ['flag', 'secret', 'key', 'cipher', 'encrypt', 'decrypt', 'check',
                'verify', 'solve', 'xor', 'aes', 'rsa', 'hash', 'password',
                'auth', 'admin', 'token', 'license', 'crack', 'validate']
    for line in syms_out.splitlines():
        lower = line.lower()
        if any(kw in lower for kw in keywords):
            interesting.append(line.strip())
    return interesting


def find_rust_strings(strings_out):
    """Find Rust-specific patterns in strings."""
    results = {
        'panics':    [],
        'src_paths': [],
        'flags':     [],
        'versions':  [],
        'urls':      [],
        'b64_like':  [],
    }
    for line in strings_out.splitlines():
        line = line.strip()
        if not line:
            continue
        # Flag patterns
        f = FLAG_RE.search(line)
        if f:
            results['flags'].append(f.group())
        # Source file paths (Rust embeds them in panic messages)
        if re.search(r'\.rs:\d+', line):
            results['src_paths'].append(line)
        # Cargo version strings
        if re.search(r'cargo|rustc|edition', line, re.IGNORECASE):
            results['versions'].append(line)
        # URLs
        if re.search(r'https?://', line):
            results['urls'].append(line)
        # Likely base64
        if re.fullmatch(r'[A-Za-z0-9+/=]{40,}', line):
            results['b64_like'].append(line)
        # Panic messages
        if 'panicked' in line or 'unwrap' in line.lower():
            results['panics'].append(line)
    return results


def main():
    ap = argparse.ArgumentParser(description="Rust Binary Analyser for CTF")
    ap.add_argument("binary", help="ELF or PE binary to analyse")
    ap.add_argument("--symbols", "-s", action="store_true", help="Show all demangled symbols")
    args = ap.parse_args()

    path = args.binary
    print(f"[*] Analysing: {path}")

    # Basic file info
    out, _ = run(f'file {path!r}')
    print(f"[*] file: {out.strip()}")

    # Rust detection
    is_rust = detect_rust(path)
    print(f"[*] Rust binary: {'YES' if is_rust else 'probably not (check anyway)'}")

    # Strings analysis
    print("\n[STRINGS ANALYSIS]")
    strings_out = extract_strings(path)
    rust_data = find_rust_strings(strings_out)

    if rust_data['flags']:
        print(f"\n[!!!] FLAGS FOUND: {rust_data['flags']}")

    if rust_data['panics']:
        print(f"\n[PANIC MESSAGES ({len(rust_data['panics'])})]")
        for p in rust_data['panics'][:10]:
            print(f"  {p}")

    if rust_data['src_paths']:
        print(f"\n[SOURCE PATHS ({len(rust_data['src_paths'])})]")
        for p in rust_data['src_paths'][:10]:
            print(f"  {p}")
        print("  → These reveal internal structure: crate name, module layout, dev machine path")

    if rust_data['versions']:
        print(f"\n[VERSION/TOOLCHAIN]")
        for v in rust_data['versions'][:5]:
            print(f"  {v}")

    if rust_data['b64_like']:
        print(f"\n[POSSIBLE BASE64 STRINGS]")
        for b in rust_data['b64_like'][:5]:
            print(f"  {b}")
            import base64
            try:
                dec = base64.b64decode(b + '==').decode('utf-8', errors='replace')
                print(f"    → decoded: {dec[:100]}")
            except Exception:
                pass

    if rust_data['urls']:
        print(f"\n[URLS]")
        for u in rust_data['urls'][:5]:
            print(f"  {u}")

    # Symbol analysis
    print("\n[SYMBOL ANALYSIS]")
    syms_out = extract_symbols(path)
    interesting = find_interesting_symbols(syms_out)
    if interesting:
        print(f"[*] Interesting symbols ({len(interesting)}):")
        for sym in interesting[:30]:
            print(f"  {sym}")
    else:
        print("[*] No obviously interesting symbols (binary may be stripped)")

    if args.symbols:
        print("\n[ALL SYMBOLS]")
        print(syms_out[:5000])

    # Check for UPX packing
    out2, _ = run(f'strings {path!r} | grep -i upx')
    if out2:
        print(f"\n[!] UPX packing detected — unpack with: upx -d {path!r} -o unpacked")

    # Suggest next steps
    print("\n[SUGGESTIONS]")
    print("  - Rust source paths reveal crate/module structure — look for check/verify functions")
    print("  - Panic messages reveal invariants the program expects")
    print("  - Use ghidra/cutter with rust_strings plugin for decompilation")
    print("  - angr/pwntools for symbolic execution of verify() functions")
    print(f"  - ltrace/strace: ltrace -f -s 200 ./{Path(path).name}")
    print("  - Install rustfilt: cargo install rustfilt  (for better demangling)")


if __name__ == "__main__":
    main()
