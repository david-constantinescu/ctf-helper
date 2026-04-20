#!/usr/bin/env python3
"""
rsa_attack.py — Common RSA attacks for CTF challenges.
Tries: small-e direct root, common factor (GCD), Wiener's theorem, Fermat's factorisation.
Usage: python3 rsa_attack.py --n <N> --e <e> --c <c>
       python3 rsa_attack.py --pubkey cert.pem --c <c>
"""

import sys
import argparse
import math
import struct
from pathlib import Path


def isqrt(n):
    if n < 0:
        raise ValueError("Square root not defined for negative numbers")
    if n == 0:
        return 0
    x = n
    y = (x + 1) // 2
    while y < x:
        x = y
        y = (x + n // x) // 2
    return x


def iroot(k, n):
    """Integer k-th root of n."""
    if n < 0:
        return None
    if n == 0:
        return 0
    u, s = n, n + 1
    while u < s:
        s = u
        t = (k - 1) * s + n // pow(s, k - 1)
        u = t // k
    return s


def fermat_factor(n, max_iter=1_000_000):
    """Fermat factorisation — works when p and q are close together."""
    a = isqrt(n) + 1
    for _ in range(max_iter):
        b2 = a * a - n
        b = isqrt(b2)
        if b * b == b2:
            p, q = a - b, a + b
            if p * q == n:
                return p, q
        a += 1
    return None


def wiener_attack(e, n):
    """Wiener's small-d attack using continued fractions."""
    def convergents(num, den):
        while den:
            q = num // den
            yield q
            num, den = den, num - q * den

    def cf_convergents(e, n):
        convs = []
        h0, h1, k0, k1 = 0, 1, 1, 0
        for q in convergents(e, n):
            h2 = q * h1 + h0
            k2 = q * k1 + k0
            convs.append((h2, k2))
            h0, h1 = h1, h2
            k0, k1 = k1, k2
        return convs

    for k, d in cf_convergents(e, n):
        if k == 0:
            continue
        phi, rem = divmod(e * d - 1, k)
        if rem != 0:
            continue
        # Solve x^2 - (n - phi + 1)x + n = 0
        b = n - phi + 1
        disc = b * b - 4 * n
        if disc < 0:
            continue
        sq = isqrt(disc)
        if sq * sq == disc:
            p = (b + sq) // 2
            q = (b - sq) // 2
            if p * q == n:
                return d, p, q
    return None


def small_e_attack(c, e, n):
    """For small e (2 or 3), try direct integer root."""
    root = iroot(e, c)
    if root is not None and pow(root, e) == c:
        return root
    return None


def common_factor(n_list):
    """Find shared factors between multiple moduli."""
    results = []
    for i in range(len(n_list)):
        for j in range(i + 1, len(n_list)):
            g = math.gcd(n_list[i], n_list[j])
            if g > 1 and g != n_list[i] and g != n_list[j]:
                results.append((i, j, g, n_list[i] // g, n_list[j] // g))
    return results


def read_pubkey_pem(path):
    """Extract n and e from a PEM public key using openssl."""
    import subprocess
    out = subprocess.run(
        f'openssl rsa -pubin -in "{path}" -noout -text 2>/dev/null || '
        f'openssl x509 -in "{path}" -noout -text 2>/dev/null',
        shell=True, capture_output=True, text=True
    )
    text = out.stdout
    # Extract modulus hex
    n = None
    e = None
    in_mod = False
    mod_hex = []
    for line in text.splitlines():
        if 'Modulus:' in line or 'Modulus (' in line:
            in_mod = True
            continue
        if in_mod:
            stripped = line.strip().replace(':', '')
            if all(c in '0123456789abcdefABCDEF' for c in stripped) and stripped:
                mod_hex.append(stripped)
            else:
                in_mod = False
        if 'Exponent:' in line:
            m = __import__('re').search(r'(\d+)', line)
            if m:
                e = int(m.group(1))

    if mod_hex:
        n = int(''.join(mod_hex), 16)
    return n, e


def decrypt_rsa(c, d, n):
    return pow(c, d, n)


def long_to_bytes(n):
    length = (n.bit_length() + 7) // 8
    return n.to_bytes(length, 'big')


def main():
    ap = argparse.ArgumentParser(description="RSA Attack Tool for CTF")
    ap.add_argument("--n", type=lambda x: int(x, 0), help="RSA modulus (decimal or 0x hex)")
    ap.add_argument("--e", type=lambda x: int(x, 0), default=65537, help="Public exponent (default 65537)")
    ap.add_argument("--c", type=lambda x: int(x, 0), help="Ciphertext (decimal or 0x hex)")
    ap.add_argument("--pubkey", help="PEM public key or certificate file")
    ap.add_argument("--p", type=lambda x: int(x, 0), help="Known prime p (to compute d directly)")
    ap.add_argument("--q", type=lambda x: int(x, 0), help="Known prime q (to compute d directly)")
    ap.add_argument("--common-n", nargs='+', type=lambda x: int(x, 0),
                    help="List of N values to check for common factors")
    args = ap.parse_args()

    n, e, c = args.n, args.e, args.c

    if args.pubkey:
        n2, e2 = read_pubkey_pem(args.pubkey)
        if n2:
            n = n or n2
            e = e2 or e
            print(f"[+] Loaded from PEM: n={n}, e={e}")

    if args.common_n:
        print("\n[COMMON FACTOR ATTACK]")
        results = common_factor(args.common_n)
        if results:
            for i, j, g, p, q in results:
                print(f"  [!] n[{i}] and n[{j}] share factor: p={g}")
                print(f"      n[{i}]: p={g}, q={p}")
                print(f"      n[{j}]: p={g}, q={q}")
        else:
            print("  No common factors found")
        return

    if not n:
        ap.error("Provide --n or --pubkey")

    print(f"\n[RSA PARAMETERS]")
    print(f"  n = {n}")
    print(f"  e = {e}")
    if c:
        print(f"  c = {c}")
    print(f"  n bits = {n.bit_length()}")

    # Direct factor if p and q known
    if args.p and args.q:
        print("\n[DIRECT DECRYPTION (p,q known)]")
        p, q = args.p, args.q
        phi = (p - 1) * (q - 1)
        d = pow(e, -1, phi)
        print(f"  d = {d}")
        if c:
            m = decrypt_rsa(c, d, n)
            try:
                print(f"  plaintext = {long_to_bytes(m)}")
            except Exception:
                print(f"  m (int) = {m}")
        return

    # Small e attack
    if c and e <= 3:
        print(f"\n[SMALL e={e} ATTACK]")
        m = small_e_attack(c, e, n)
        if m is not None:
            print(f"  [!!!] Direct root found!")
            try:
                print(f"  plaintext = {long_to_bytes(m)}")
            except Exception:
                print(f"  m (int) = {m}")

    # Wiener's attack (small d)
    print("\n[WIENER'S ATTACK (small d)]")
    result = wiener_attack(e, n)
    if result:
        d, p, q = result
        print(f"  [!!!] d found: {d}")
        print(f"  p = {p}, q = {q}")
        if c:
            m = decrypt_rsa(c, d, n)
            try:
                print(f"  plaintext = {long_to_bytes(m)}")
            except Exception:
                print(f"  m (int) = {m}")
    else:
        print("  Wiener's attack failed (d is not small)")

    # Fermat factorisation
    print("\n[FERMAT FACTORISATION (p ≈ q)]")
    result = fermat_factor(n, max_iter=500_000)
    if result:
        p, q = result
        print(f"  [!!!] Factored! p={p}, q={q}")
        phi = (p - 1) * (q - 1)
        d = pow(e, -1, phi)
        print(f"  d = {d}")
        if c:
            m = decrypt_rsa(c, d, n)
            try:
                print(f"  plaintext = {long_to_bytes(m)}")
            except Exception:
                print(f"  m (int) = {m}")
    else:
        print("  Fermat failed (p and q are not close)")

    print("\n[SUGGESTIONS IF ALL FAILED]")
    print("  - Try factordb.com with the modulus")
    print("  - Check if e=65537 but n is small enough for GNFS")
    print("  - Look for multiple ciphertexts with same n,e (Hastad broadcast)")
    print("  - Use SageMath: factor(n) or rsa_attacks lib")
    print("  - Check for LSB oracle / padding oracle vulnerabilities")


if __name__ == "__main__":
    main()
