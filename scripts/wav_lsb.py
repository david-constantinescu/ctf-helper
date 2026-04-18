#!/usr/bin/env python3
"""
wav_lsb.py — extract LSB-encoded steganographic data from WAV audio samples
Supports: 8/16/32-bit PCM, mono/stereo, bit planes 0-7, channel selection,
          MSB/LSB packing, null-terminated payload detection.
"""

import sys
import struct
import re
import argparse
from pathlib import Path

FLAG_RE = re.compile(r'[A-Za-z0-9_]{2,10}\{[^}]+\}')

# ── WAV parser ────────────────────────────────────────────────────────────────

def parse_wav(data: bytes) -> tuple[int, int, int, list[int]]:
    """
    Returns (num_channels, sample_rate, bits_per_sample, flat_samples).
    Samples are returned as unsigned integers (8-bit) or sign-extended (16/32-bit).
    """
    if data[:4] != b"RIFF" or data[8:12] != b"WAVE":
        raise ValueError("Not a WAV file")

    # Walk chunks
    off = 12
    fmt_done = False
    num_channels = 1
    sample_rate = 0
    bits_per_sample = 8

    while off < len(data) - 8:
        chunk_id = data[off:off+4]
        chunk_size = struct.unpack_from("<I", data, off+4)[0]

        if chunk_id == b"fmt ":
            audio_format   = struct.unpack_from("<H", data, off+8)[0]
            num_channels   = struct.unpack_from("<H", data, off+10)[0]
            sample_rate    = struct.unpack_from("<I", data, off+12)[0]
            bits_per_sample= struct.unpack_from("<H", data, off+22)[0]
            if audio_format not in (1, 3):  # 1=PCM, 3=float
                raise ValueError(f"Unsupported audio format: {audio_format} (only PCM supported)")
            fmt_done = True

        elif chunk_id == b"data" and fmt_done:
            raw = data[off+8:off+8+chunk_size]
            bytes_per_sample = bits_per_sample // 8
            samples = []
            fmt_char = {1: "B", 2: "<h", 4: "<i"}.get(bytes_per_sample, "B")
            step = bytes_per_sample

            for i in range(0, len(raw) - step + 1, step):
                if bytes_per_sample == 1:
                    samples.append(raw[i])               # unsigned 8-bit
                elif bytes_per_sample == 2:
                    samples.append(struct.unpack_from("<h", raw, i)[0])  # signed 16
                elif bytes_per_sample == 4:
                    samples.append(struct.unpack_from("<i", raw, i)[0])  # signed 32
            return num_channels, sample_rate, bits_per_sample, samples

        off += 8 + chunk_size + (chunk_size % 2)  # chunks are word-aligned

    raise ValueError("WAV data chunk not found")

# ── LSB extraction ────────────────────────────────────────────────────────────

def extract_lsb(
    samples: list[int],
    num_channels: int,
    use_channels: list[int],
    bit_plane: int = 0,
    msb_first: bool = False,
) -> bytes:
    """Extract a specific bit plane from chosen channels."""
    bits = []
    total_frames = len(samples) // num_channels

    for frame in range(total_frames):
        for ch in use_channels:
            idx = frame * num_channels + ch
            if idx < len(samples):
                bit = (samples[idx] >> bit_plane) & 1
                bits.append(bit)

    result = bytearray()
    for i in range(0, len(bits) - 7, 8):
        byte = 0
        for j in range(8):
            if msb_first:
                byte = (byte << 1) | bits[i + j]
            else:
                byte |= bits[i + j] << j
        result.append(byte)

    return bytes(result)

# ── Helpers ───────────────────────────────────────────────────────────────────

def find_null_end(data: bytes, min_len: int = 8) -> bytes:
    idx = data.find(b"\x00\x00\x00")
    if idx != -1 and idx >= min_len:
        return data[:idx]
    return data

def is_interesting(data: bytes, threshold: float = 0.60) -> bool:
    if len(data) < 4:
        return False
    printable = sum(1 for b in data if 0x20 <= b <= 0x7e or b in (9, 10, 13))
    return printable / len(data) >= threshold

def decode_str(b: bytes) -> str:
    for enc in ("utf-8", "latin-1"):
        try:
            return b.decode(enc)
        except Exception:
            pass
    return b.decode("latin-1", errors="replace")

def guess_ext(data: bytes) -> str:
    sigs = [
        (b"\x89PNG\r\n\x1a\n", ".png"), (b"\xff\xd8\xff", ".jpg"),
        (b"PK\x03\x04", ".zip"),         (b"\x1f\x8b", ".gz"),
        (b"BZh", ".bz2"),               (b"\xfd7zXZ", ".xz"),
        (b"7z\xbc\xaf'\x1c", ".7z"),    (b"%PDF-", ".pdf"),
        (b"GIF8", ".gif"),              (b"BM", ".bmp"),
        (b"RIFF", ".wav"),              (b"\x7fELF", ".elf"),
    ]
    for magic, ext in sigs:
        if data[:len(magic)] == magic:
            return ext
    return ".txt" if is_interesting(data) else ".bin"

# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Extract LSB steganographic data from WAV audio samples"
    )
    parser.add_argument("input", help="WAV file")
    parser.add_argument("-o", "--output", default=None,
                        help="Save extracted data to file (auto-extension if not specified)")
    parser.add_argument("--channels", default=None,
                        help="Channels to read: 0,1 for stereo (default: all)")
    parser.add_argument("--bit", type=int, default=None,
                        help="Specific bit plane (0=LSB). Default: try 0-3")
    parser.add_argument("--msb", action="store_true",
                        help="Pack bits MSB-first (default: LSB-first)")
    parser.add_argument("--all", action="store_true",
                        help="Brute-force all channel combos + bit planes 0-7 + packing")
    parser.add_argument("--max-bytes", type=int, default=4096,
                        help="Max bytes to show per result (default: 4096)")
    parser.add_argument("--no-trim", action="store_true",
                        help="Don't trim at null bytes")
    args = parser.parse_args()

    in_path = Path(args.input)
    if not in_path.exists():
        print(f"[!] File not found: {in_path}")
        sys.exit(1)

    data = in_path.read_bytes()
    print(f"[*] File: {in_path}  ({len(data):,} bytes)")

    try:
        num_channels, sample_rate, bits_per_sample, samples = parse_wav(data)
    except Exception as e:
        print(f"[!] WAV parse error: {e}")
        sys.exit(1)

    total_frames = len(samples) // num_channels
    print(f"[*] Channels: {num_channels}  Sample rate: {sample_rate} Hz  "
          f"Bit depth: {bits_per_sample}  Frames: {total_frames:,}")
    print(f"[*] Max LSB payload: ~{total_frames * num_channels // 8:,} bytes\n")

    found = []

    def attempt(label, use_ch, bit, msb):
        raw = extract_lsb(samples, num_channels, use_ch, bit, msb)
        trimmed = raw if args.no_trim else find_null_end(raw)
        if not trimmed:
            return
        preview = trimmed[:args.max_bytes]
        flags = FLAG_RE.findall(decode_str(preview))
        interesting = is_interesting(preview[:256]) or bool(flags)
        if not interesting:
            return
        text = decode_str(preview)
        found.append((label, trimmed, flags))
        flag_str = f"  <<< FLAG: {', '.join(flags)}" if flags else ""
        pack_str = "MSB" if msb else "LSB"
        ch_str = f"ch={use_ch}"
        print(f"  [{label}]  bit={bit}  {ch_str}  {pack_str}-first  {len(trimmed):,} bytes{flag_str}")
        print(f"    {text[:120]}{'...' if len(text)>120 else ''}\n")

    if args.all:
        import itertools
        ch_combos = []
        for r in range(1, num_channels + 1):
            for combo in itertools.combinations(range(num_channels), r):
                ch_combos.append(list(combo))
        for use_ch in ch_combos:
            for bit in range(min(8, bits_per_sample)):
                for msb in [False, True]:
                    label = f"ch{''.join(str(c) for c in use_ch)}_bit{bit}_{'MSB' if msb else 'LSB'}"
                    attempt(label, use_ch, bit, msb)
    else:
        if args.channels:
            use_channels = [int(c.strip()) for c in args.channels.split(",") if c.strip().isdigit()]
            use_channels = [c for c in use_channels if c < num_channels]
        else:
            use_channels = list(range(num_channels))

        bits_to_try = [args.bit] if args.bit is not None else range(min(4, bits_per_sample))
        for bit in bits_to_try:
            for msb in ([args.msb] if args.bit is not None else [False, True]):
                label = f"ch{''.join(str(c) for c in use_channels)}_bit{bit}_{'MSB' if msb else 'LSB'}"
                attempt(label, use_channels, bit, msb)

    if not found:
        print("[*] No interesting data found.")
        print("[*] Try --all to brute-force all combinations.")
        print("[*] Try --bit 0 --msb / --no-trim if payload uses MSB packing or has no null terminator.")
    else:
        print(f"[*] {len(found)} interesting extraction(s).")
        best = sorted(found, key=lambda x: (len(x[2]), len(x[1])), reverse=True)[0]
        label, raw, flags = best

        if args.output:
            out = Path(args.output)
        else:
            ext = guess_ext(raw)
            out = in_path.with_name(in_path.stem + f"_lsb{ext}")

        if args.output or len(found) > 0:
            out.write_bytes(raw)
            print(f"[*] Best result ({label}) saved to {out}")

if __name__ == "__main__":
    main()
