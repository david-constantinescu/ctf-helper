#!/usr/bin/env python3
"""
hash_identifier.py — identify hash type by length, charset, and prefix patterns
Covers MD5, SHA family, bcrypt, NTLM, LM, MySQL, Cisco, Drupal, Django, WordPress,
Unix crypt, PBKDF2, Argon2, scrypt, and many more.
"""

import sys
import re
import argparse
from pathlib import Path

# ── Hash signatures ───────────────────────────────────────────────────────────
# Each entry: (name, regex_pattern, notes)

HASH_SIGNATURES = [
    # ── Prefix-identified ─────────────────────────────────────────────────────
    ("Argon2i",          r'^\$argon2i\$',                       "Memory-hard KDF"),
    ("Argon2d",          r'^\$argon2d\$',                       "Memory-hard KDF"),
    ("Argon2id",         r'^\$argon2id\$',                      "Memory-hard KDF"),
    ("bcrypt",           r'^\$2[aby]?\$\d{2}\$',                "Cost factor encoded in hash"),
    ("scrypt",           r'^\$s0\$',                            "scrypt KDF"),
    ("sha512crypt",      r'^\$6\$',                             "Linux shadow (SHA-512)"),
    ("sha256crypt",      r'^\$5\$',                             "Linux shadow (SHA-256)"),
    ("md5crypt",         r'^\$1\$',                             "Linux/BSD md5crypt"),
    ("apr1-md5",         r'^\$apr1\$',                          "Apache MD5"),
    ("sha1crypt",        r'^\$4\$',                             ""),
    ("md5crypt-sun",     r'^\$md5,rounds',                      "Solaris MD5"),
    ("PBKDF2-SHA256",    r'^\$pbkdf2-sha256\$',                 "Django default"),
    ("PBKDF2-SHA512",    r'^\$pbkdf2-sha512\$',                 ""),
    ("PBKDF2-SHA1",      r'^\$pbkdf2-sha1\$',                   ""),
    ("Django bcrypt",    r'^bcrypt\$\$2[aby]?\$',               "Django bcrypt wrapper"),
    ("Django SHA1",      r'^sha1\$[a-zA-Z0-9]+\$',             "Old Django"),
    ("Django MD5",       r'^md5\$[a-zA-Z0-9]+\$',              "Old Django"),
    ("WordPress",        r'^\$P\$',                             "Portable PHP hash (phpass)"),
    ("phpBB3",           r'^\$H\$',                             "phpass"),
    ("Drupal 7",         r'^\$S\$',                             ""),
    ("Cisco IOS MD5",    r'^\$1\$[a-zA-Z0-9./]{4}\$',          "Cisco enable secret type 5"),
    ("Cisco type 7",     r'^[0-9]{2}[0-9A-F]+$',               "Weakly obfuscated, not hashed"),
    ("Cisco type 8",     r'^\$8\$',                             "PBKDF2-SHA256"),
    ("Cisco type 9",     r'^\$9\$',                             "scrypt"),
    ("Joomla",           r'^[a-f0-9]{32}:[a-zA-Z0-9]{32}$',    "MD5:salt"),
    ("SAP CODVN B",      r'^\{x-issha, ',                       ""),
    ("SSHA",             r'^\{SSHA\}',                          "Salted SHA1 (LDAP)"),
    ("SHA1 (LDAP)",      r'^\{SHA\}',                           "Unsalted SHA1 (LDAP)"),
    ("MD5 (LDAP)",       r'^\{MD5\}',                           "Unsalted MD5 (LDAP)"),
    ("Kerberos AFS DES", r'^[a-zA-Z0-9./]{8}$',                "DES-based AFS"),
    ("MySQL 3.x",        r'^[a-f0-9]{16}$',                    "Old MySQL password()"),
    ("DES Unix crypt",   r'^[a-zA-Z0-9./]{13}$',               "Traditional DES crypt"),
    ("MSSQL 2012",       r'^0x0200[A-F0-9]{136}$',             "MSSQL 2012/2014 SHA-512"),
    ("MSSQL 2000",       r'^0x0100[A-F0-9]{88}$',              "MSSQL 2000 SHA-1"),

    # ── Length+charset identified ─────────────────────────────────────────────
    # Handled separately below
]

# (name, length_or_lengths, charset_regex, notes)
LENGTH_BASED = [
    ("LM",                32,  r'^[A-F0-9]+$',        "Windows LM hash (uppercase hex)"),
    ("NTLM",              32,  r'^[a-f0-9]+$',        "Windows NTLM (lowercase hex)"),
    ("MD5",               32,  r'^[a-f0-9]+$',        ""),
    ("MD5 (uppercase)",   32,  r'^[A-F0-9]+$',        ""),
    ("MD4",               32,  r'^[a-f0-9]+$',        ""),
    ("MySQL 4.x",         40,  r'^[a-f0-9]+$',        "SHA1 of SHA1"),
    ("SHA-1",             40,  r'^[a-f0-9]+$',        ""),
    ("SHA-1 (uppercase)", 40,  r'^[A-F0-9]+$',        ""),
    ("Tiger-128",         32,  r'^[a-f0-9]+$',        ""),
    ("Tiger-160",         40,  r'^[a-f0-9]+$',        ""),
    ("Tiger-192",         48,  r'^[a-f0-9]+$',        ""),
    ("SHA-224",           56,  r'^[a-f0-9]+$',        ""),
    ("Keccak-224",        56,  r'^[a-f0-9]+$',        ""),
    ("SHA-256",           64,  r'^[a-f0-9]+$',        ""),
    ("Keccak-256",        64,  r'^[a-f0-9]+$',        "SHA3 variant"),
    ("Blake2s",           64,  r'^[a-f0-9]+$',        ""),
    ("RIPEMD-256",        64,  r'^[a-f0-9]+$',        ""),
    ("SHA3-256",          64,  r'^[a-f0-9]+$',        ""),
    ("Haval-256",         64,  r'^[a-f0-9]+$',        ""),
    ("GOST R 34.11-94",   64,  r'^[a-f0-9]+$',        ""),
    ("SHA-384",           96,  r'^[a-f0-9]+$',        ""),
    ("SHA3-384",          96,  r'^[a-f0-9]+$',        ""),
    ("Keccak-384",        96,  r'^[a-f0-9]+$',        ""),
    ("SHA-512",           128, r'^[a-f0-9]+$',        ""),
    ("SHA3-512",          128, r'^[a-f0-9]+$',        ""),
    ("Keccak-512",        128, r'^[a-f0-9]+$',        ""),
    ("Whirlpool",         128, r'^[a-f0-9]+$',        ""),
    ("Blake2b",           128, r'^[a-f0-9]+$',        ""),
    ("RIPEMD-128",        32,  r'^[a-f0-9]+$',        ""),
    ("RIPEMD-160",        40,  r'^[a-f0-9]+$',        ""),
    ("RIPEMD-320",        80,  r'^[a-f0-9]+$',        ""),
    ("MD2",               32,  r'^[a-f0-9]+$',        ""),
    ("Haval-128",         32,  r'^[a-f0-9]+$',        ""),
    ("Haval-160",         40,  r'^[a-f0-9]+$',        ""),
    ("Haval-192",         48,  r'^[a-f0-9]+$',        ""),
    ("Haval-224",         56,  r'^[a-f0-9]+$',        ""),
    ("Adler-32",          8,   r'^[a-f0-9]+$',        "Checksum, not a hash"),
    ("CRC-32",            8,   r'^[a-f0-9]+$',        "Checksum"),
    ("CRC-64",            16,  r'^[a-f0-9]+$',        "Checksum"),
    ("FNV-32",            8,   r'^[a-f0-9]+$',        "Non-crypto"),
    ("MurmurHash3",       8,   r'^[a-f0-9]+$',        "Non-crypto"),
    # Base64 lengths
    ("MD5 (Base64)",      24,  r'^[A-Za-z0-9+/=]+$',  ""),
    ("SHA-1 (Base64)",    28,  r'^[A-Za-z0-9+/=]+$',  ""),
    ("SHA-256 (Base64)",  44,  r'^[A-Za-z0-9+/=]+$',  ""),
    ("SHA-512 (Base64)",  88,  r'^[A-Za-z0-9+/=]+$',  ""),
]

# ── Analysis ──────────────────────────────────────────────────────────────────

def identify(hash_str: str) -> list[tuple[str, str, str]]:
    """Returns list of (name, confidence, notes)."""
    h = hash_str.strip()
    results = []

    # Prefix-based (high confidence)
    for name, pattern, notes in HASH_SIGNATURES:
        if re.search(pattern, h, re.IGNORECASE):
            results.append((name, "HIGH", notes))

    # Length + charset based
    hlen = len(h)
    for name, length, charset, notes in LENGTH_BASED:
        if hlen == length and re.fullmatch(charset, h):
            # Boost confidence for common ones
            confidence = "MEDIUM"
            if name in ("MD5", "SHA-1", "SHA-256", "SHA-512", "NTLM", "LM"):
                confidence = "HIGH" if not results else "MEDIUM"
            results.append((name, confidence, notes))

    # NTLM vs MD5 disambiguation
    if h.islower() and len(h) == 32 and re.fullmatch(r'^[a-f0-9]+$', h):
        results = [(n, c, nt) for n, c, nt in results if n != "LM"]

    if not results:
        # Unknown — provide stats
        printable_hex = bool(re.fullmatch(r'[0-9a-fA-F]+', h))
        printable_b64 = bool(re.fullmatch(r'[A-Za-z0-9+/=]+', h))
        results.append(("Unknown", "LOW",
                         f"len={hlen}, hex={printable_hex}, b64={printable_b64}"))

    return results

def hashcat_mode(name: str) -> str | None:
    modes = {
        "MD5": "0", "MD4": "900", "SHA-1": "100", "SHA-224": "1300",
        "SHA-256": "1400", "SHA-384": "10800", "SHA-512": "1700",
        "SHA3-256": "17300", "SHA3-512": "17600", "Keccak-256": "18000",
        "NTLM": "1000", "LM": "3000", "MySQL 3.x": "200", "MySQL 4.x": "300",
        "bcrypt": "3200", "md5crypt": "500", "sha512crypt": "1800",
        "sha256crypt": "7400", "PBKDF2-SHA256": "10900", "PBKDF2-SHA512": "12100",
        "Whirlpool": "6100", "RIPEMD-160": "6000", "Blake2b": "600",
        "WordPress": "400", "Drupal 7": "7900", "Django SHA1": "124",
        "SSHA": "111", "apr1-md5": "1600", "Cisco IOS MD5": "500",
        "Cisco type 8": "9200", "Cisco type 9": "9300",
        "Argon2i": "Argon2", "Argon2d": "Argon2", "Argon2id": "Argon2",
    }
    for key, mode in modes.items():
        if key.lower() in name.lower():
            return mode
    return None

def john_format(name: str) -> str | None:
    formats = {
        "MD5": "raw-md5", "SHA-1": "raw-sha1", "SHA-256": "raw-sha256",
        "SHA-512": "raw-sha512", "NTLM": "nt", "LM": "lm",
        "bcrypt": "bcrypt", "md5crypt": "md5crypt", "sha512crypt": "sha512crypt",
        "sha256crypt": "sha256crypt", "MySQL 3.x": "mysql-old",
        "MySQL 4.x": "mysql-sha1", "SSHA": "SSHA", "Whirlpool": "whirlpool",
        "RIPEMD-160": "ripemd-160", "WordPress": "phpass", "Drupal 7": "drupal7",
    }
    for key, fmt in formats.items():
        if key.lower() in name.lower():
            return fmt
    return None

# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Identify hash type by length, charset, and prefix"
    )
    parser.add_argument("hashes", nargs="*", help="Hash string(s) to identify")
    parser.add_argument("-f", "--file", help="File with one hash per line")
    parser.add_argument("--hashcat", action="store_true",
                        help="Show hashcat -m mode numbers")
    parser.add_argument("--john", action="store_true",
                        help="Show john --format values")
    parser.add_argument("--all", action="store_true",
                        help="Show all candidates including low-confidence")
    args = parser.parse_args()

    hashes = []
    if args.file:
        hashes += [l.strip() for l in Path(args.file).read_text().splitlines() if l.strip()]
    if args.hashes:
        hashes += args.hashes
    if not hashes and not sys.stdin.isatty():
        hashes += [l.strip() for l in sys.stdin if l.strip()]

    if not hashes:
        parser.print_help()
        sys.exit(1)

    SEP = "-" * 70
    for h in hashes:
        print(f"\n[*] Hash: {h[:80]}{'...' if len(h)>80 else ''}")
        print(f"    Length: {len(h)}")
        results = identify(h)
        print(SEP)

        for name, conf, notes in results:
            if not args.all and conf == "LOW" and len(results) > 1:
                continue
            hc = f"  hashcat -m {hashcat_mode(name)}" if args.hashcat and hashcat_mode(name) else ""
            jn = f"  john --format={john_format(name)}" if args.john and john_format(name) else ""
            note_str = f"  ({notes})" if notes else ""
            conf_color = {"HIGH": "[HIGH]", "MEDIUM": "[MED] ", "LOW": "[LOW] "}[conf]
            print(f"  {conf_color} {name}{note_str}{hc}{jn}")

        print(SEP)

if __name__ == "__main__":
    main()
