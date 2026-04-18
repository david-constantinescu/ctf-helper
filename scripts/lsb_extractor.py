#!/usr/bin/env python3
"""
lsb_extractor.py — extract LSB-encoded data from PNG/BMP pixel values
Supports: RGB/RGBA channels, bit planes 0-7, row/column order,
          MSB/LSB bit packing, and alpha channel steg.
"""

import sys
import struct
import zlib
import argparse
from pathlib import Path

FLAG_RE = __import__('re').compile(r'[A-Za-z0-9_]{2,10}\{[^}]+\}')

# ── PNG reader ────────────────────────────────────────────────────────────────

def read_png(data: bytes) -> tuple[int, int, int, list[int]]:
    """Returns (width, height, channels, flat_pixel_list)."""
    if data[:8] != b"\x89PNG\r\n\x1a\n":
        raise ValueError("Not a PNG file")

    w = struct.unpack_from(">I", data, 16)[0]
    h = struct.unpack_from(">I", data, 20)[0]
    bit_depth = data[24]
    color_type = data[25]
    channels = {0: 1, 2: 3, 3: 1, 4: 2, 6: 4}.get(color_type, 3)

    # Collect IDAT
    idat = b""
    off = 8
    while off < len(data) - 12:
        length = struct.unpack_from(">I", data, off)[0]
        chunk_type = data[off+4:off+8]
        if chunk_type == b"IDAT":
            idat += data[off+8:off+8+length]
        elif chunk_type == b"IEND":
            break
        off += 12 + length

    raw = zlib.decompress(idat)
    stride = 1 + w * channels * (bit_depth // 8)

    pixels = []
    for row in range(h):
        row_start = row * stride + 1  # skip filter byte
        for col in range(w * channels):
            pixels.append(raw[row_start + col])

    return w, h, channels, pixels

# ── BMP reader ────────────────────────────────────────────────────────────────

def read_bmp(data: bytes) -> tuple[int, int, int, list[int]]:
    """Returns (width, height, channels, flat_pixel_list)."""
    if data[:2] != b"BM":
        raise ValueError("Not a BMP file")
    pixel_offset = struct.unpack_from("<I", data, 10)[0]
    w = struct.unpack_from("<i", data, 18)[0]
    h = struct.unpack_from("<i", data, 22)[0]
    bits_per_pixel = struct.unpack_from("<H", data, 28)[0]

    # Handle negative height (top-down)
    flipped = h < 0
    h = abs(h)
    channels = bits_per_pixel // 8  # 3=BGR, 4=BGRA

    row_size = ((bits_per_pixel * w + 31) // 32) * 4  # padded to 4 bytes
    pixels = []
    for row in range(h):
        src_row = row if flipped else (h - 1 - row)
        row_start = pixel_offset + src_row * row_size
        for col in range(w):
            px_start = row_start + col * channels
            for ch in range(channels):
                pixels.append(data[px_start + ch])

    # BMP is BGR; reorder to RGB
    reordered = []
    for i in range(0, len(pixels), channels):
        if channels >= 3:
            reordered.extend([pixels[i+2], pixels[i+1], pixels[i]])  # BGR->RGB
        if channels == 4:
            reordered.append(pixels[i+3])  # alpha

    return w, h, channels, reordered

# ── LSB extraction ────────────────────────────────────────────────────────────

def extract_lsb(
    pixels: list[int],
    channels: int,
    use_channels: list[int],   # e.g. [0,1,2] = R,G,B
    bit_plane: int = 0,
    msb_first: bool = False,
    row_major: bool = True,
    width: int = 0,
    height: int = 0,
) -> bytes:
    """Extract bits from the specified bit plane of specified channels."""
    bits = []
    total_pixels = len(pixels) // channels

    if row_major:
        pixel_order = range(total_pixels)
    else:
        # Column-major: iterate columns first
        pixel_order = []
        for col in range(width):
            for row in range(height):
                pixel_order.append(row * width + col)

    for pi in pixel_order:
        base = pi * channels
        for ch in use_channels:
            if base + ch < len(pixels):
                bit = (pixels[base + ch] >> bit_plane) & 1
                bits.append(bit)

    # Pack bits into bytes
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

def is_interesting(data: bytes) -> bool:
    if not data:
        return False
    printable = sum(1 for b in data if 0x20 <= b <= 0x7e or b in (9, 10, 13))
    return printable / len(data) > 0.6

def find_null_end(data: bytes) -> bytes:
    """Trim trailing null bytes (LSB payloads often end with \x00)."""
    idx = data.find(b"\x00\x00\x00")
    return data[:idx] if idx != -1 else data

def try_decode(data: bytes) -> str:
    for enc in ("utf-8", "latin-1"):
        try:
            return data.decode(enc)
        except Exception:
            pass
    return data.decode("latin-1", errors="replace")

# ── Main ──────────────────────────────────────────────────────────────────────

CHANNEL_NAMES = {0: "R", 1: "G", 2: "B", 3: "A"}

def main():
    parser = argparse.ArgumentParser(
        description="Extract LSB-encoded steganographic data from PNG or BMP"
    )
    parser.add_argument("input", help="PNG or BMP file")
    parser.add_argument("-o", "--output", default=None,
                        help="Save extracted bytes to file")
    parser.add_argument("--channels", default="RGB",
                        help="Channels to use: any combo of R,G,B,A (default: RGB)")
    parser.add_argument("--bit", type=int, default=None,
                        help="Specific bit plane to extract (0-7). Default: try all")
    parser.add_argument("--msb", action="store_true",
                        help="Pack bits MSB-first (default: LSB-first)")
    parser.add_argument("--column-major", action="store_true",
                        help="Read pixels column-by-column instead of row-by-row")
    parser.add_argument("--all", action="store_true",
                        help="Try all combinations of channels + bit planes + order")
    parser.add_argument("--max-bytes", type=int, default=4096,
                        help="Max bytes to display per result (default: 4096)")
    args = parser.parse_args()

    in_path = Path(args.input)
    data = in_path.read_bytes()

    print(f"[*] File: {in_path}  ({len(data):,} bytes)")

    # Load image
    try:
        if data[:8] == b"\x89PNG\r\n\x1a\n":
            w, h, channels, pixels = read_png(data)
            fmt = "PNG"
        elif data[:2] == b"BM":
            w, h, channels, pixels = read_bmp(data)
            fmt = "BMP"
        else:
            print("[!] Unsupported format. Only PNG and BMP are supported.")
            sys.exit(1)
    except Exception as e:
        print(f"[!] Failed to parse image: {e}")
        sys.exit(1)

    ch_map = {"R": 0, "G": 1, "B": 2, "A": 3}
    print(f"[*] Format: {fmt}  Size: {w}x{h}  Channels: {channels}")
    print(f"[*] Total pixels: {w*h:,}\n")

    found = []

    def attempt(label, use_ch, bit, msb, col_major):
        try:
            raw = extract_lsb(pixels, channels, use_ch, bit, msb, not col_major, w, h)
            trimmed = find_null_end(raw)
            if not trimmed:
                return
            flags = FLAG_RE.findall(try_decode(trimmed[:args.max_bytes]))
            interesting = is_interesting(trimmed[:256]) or bool(flags)
            if not interesting:
                return
            text = try_decode(trimmed[:args.max_bytes])
            found.append((label, trimmed, flags))
            flag_str = f"  <<< FLAG: {', '.join(flags)}" if flags else ""
            order_str = "col-major" if col_major else "row-major"
            pack_str = "MSB" if msb else "LSB"
            print(f"  [{label}] bit={bit} ch={[CHANNEL_NAMES.get(c,'?') for c in use_ch]} {pack_str} {order_str}{flag_str}")
            print(f"    {text[:120]}{'...' if len(text)>120 else ''}\n")
        except Exception:
            pass

    if args.all:
        # Try all combinations
        import itertools
        ch_combos = []
        for r in range(1, channels + 1):
            for combo in itertools.combinations(range(channels), r):
                ch_combos.append(list(combo))
        for use_ch in ch_combos:
            for bit in range(8):
                for msb in [False, True]:
                    for col_major in [False, True]:
                        label = f"{''.join(CHANNEL_NAMES.get(c,'?') for c in use_ch)}_bit{bit}_{'MSB' if msb else 'LSB'}_{'col' if col_major else 'row'}"
                        attempt(label, use_ch, bit, msb, col_major)
    else:
        # Targeted extraction
        requested_ch = [ch_map[c.upper()] for c in args.channels.upper() if c.upper() in ch_map and ch_map[c.upper()] < channels]
        if not requested_ch:
            print(f"[!] No valid channels in '{args.channels}' for this {channels}-channel image.")
            sys.exit(1)

        bits_to_try = [args.bit] if args.bit is not None else range(8)
        for bit in bits_to_try:
            for msb in ([args.msb] if args.bit is not None else [False, True]):
                for col_major in ([args.column_major] if args.bit is not None else [False, True]):
                    label = f"{''.join(CHANNEL_NAMES.get(c,'?') for c in requested_ch)}_bit{bit}"
                    attempt(label, requested_ch, bit, msb, col_major)

    if not found:
        print("[*] No interesting data found in LSB planes.")
        print("[*] Try --all to brute-force all channel/bit/order combinations.")
    else:
        print(f"[*] {len(found)} interesting extraction(s) found.")
        # Save best (with flags > most bytes)
        best = sorted(found, key=lambda x: (len(x[2]), len(x[1])), reverse=True)[0]
        if args.output:
            Path(args.output).write_bytes(best[1])
            print(f"[*] Best result saved to {args.output}")

if __name__ == "__main__":
    main()
