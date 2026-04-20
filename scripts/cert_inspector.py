#!/usr/bin/env python3
"""
cert_inspector.py — Parse PEM/DER certificates and private keys for CTF.
Extracts RSA/EC parameters, checks validity, looks for weak keys.
Usage: python3 cert_inspector.py <file.pem> [file2.pem ...]
"""

import sys
import subprocess
import os
import re
from pathlib import Path


def run(cmd):
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=15)
        return r.stdout + r.stderr
    except Exception as e:
        return f"[error] {e}"


def inspect_pem(path):
    print(f"\n{'='*60}")
    print(f"FILE: {path}")
    print('='*60)

    raw = Path(path).read_text(errors='replace')

    # Detect what's inside
    if 'CERTIFICATE' in raw:
        print("\n[+] Certificate detected")
        out = run(f'openssl x509 -in "{path}" -noout -text 2>/dev/null || openssl x509 -in "{path}" -inform DER -noout -text')
        print(out)

        # Extract RSA modulus for weak-key check
        mod_out = run(f'openssl x509 -in "{path}" -noout -modulus 2>/dev/null')
        if 'Modulus=' in mod_out:
            modulus_hex = mod_out.split('Modulus=')[1].strip()
            n = int(modulus_hex, 16)
            bits = n.bit_length()
            print(f"[*] RSA modulus: {bits} bits")
            if bits <= 512:
                print("[!] WEAK KEY — ≤512 bits, factorisable!")
            elif bits <= 1024:
                print("[!] WEAK KEY — ≤1024 bits, likely factorisable with GNFS")
            print(f"[*] n (decimal) = {n}")

    elif 'PRIVATE KEY' in raw or 'RSA PRIVATE KEY' in raw:
        print("\n[+] Private key detected")
        if 'RSA' in raw or 'PRIVATE KEY' in raw:
            out = run(f'openssl rsa -in "{path}" -noout -text 2>/dev/null')
            print(out)
            # Extract and print n, e, d for CTF solving
            mod_out = run(f'openssl rsa -in "{path}" -noout -modulus 2>/dev/null')
            if 'Modulus=' in mod_out:
                n = int(mod_out.split('Modulus=')[1].strip(), 16)
                print(f"[*] n = {n}")
        elif 'EC' in raw:
            out = run(f'openssl ec -in "{path}" -noout -text 2>/dev/null')
            print(out)

    elif 'PUBLIC KEY' in raw:
        print("\n[+] Public key detected")
        out = run(f'openssl rsa -pubin -in "{path}" -noout -text 2>/dev/null || openssl pkey -pubin -in "{path}" -noout -text')
        print(out)
        mod_out = run(f'openssl rsa -pubin -in "{path}" -noout -modulus 2>/dev/null')
        if 'Modulus=' in mod_out:
            n = int(mod_out.split('Modulus=')[1].strip(), 16)
            bits = n.bit_length()
            print(f"[*] RSA modulus: {bits} bits, n = {n}")

    else:
        # Try DER
        print("[*] Trying DER format...")
        out = run(f'openssl x509 -in "{path}" -inform DER -noout -text 2>/dev/null')
        if out.strip():
            print(out)
        else:
            out = run(f'openssl rsa -in "{path}" -inform DER -noout -text 2>/dev/null')
            print(out or "[?] Unknown format")

    # Search for flag patterns in raw
    flags = re.findall(r'(?:CTF|FLAG|OSC|DUCTF|HTB|picoCTF)\{[^}]{1,100}\}', raw, re.IGNORECASE)
    if flags:
        print(f"\n[!!!] FLAG PATTERN FOUND: {flags}")

    # Check Subject Alternative Names / CN for encoded data
    cn_match = re.findall(r'CN\s*=\s*([^\n,/]+)', raw)
    if cn_match:
        print(f"\n[*] CN values: {cn_match}")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 cert_inspector.py <file.pem> [file2 ...]")
        sys.exit(1)
    for f in sys.argv[1:]:
        inspect_pem(f)
