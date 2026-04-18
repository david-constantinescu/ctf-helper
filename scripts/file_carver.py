#!/usr/bin/env python3
"""
file_carver.py — extract embedded files from binary blobs
Detects and carves: ZIP, PNG, JPEG, ELF, PDF, GIF, BMP, WAV, MP3, 7z, RAR
"""

import sys
import os
import argparse
import struct
from pathlib import Path

SIGNATURES = [
    # (name, magic_bytes, extension, end_signature or None, fixed_size or None)
    ("ZIP",   b"\x50\x4b\x03\x04", ".zip",  b"\x50\x4b\x05\x06", None),
    ("PNG",   b"\x89PNG\r\n\x1a\n", ".png", b"\x00\x00\x00\x00IEND\xaeB`\x82", None),
    ("JPEG",  b"\xff\xd8\xff",       ".jpg", b"\xff\xd9",           None),
    ("ELF",   b"\x7fELF",           ".elf", None,                  None),
    ("PDF",   b"%PDF-",             ".pdf", b"%%EOF",              None),
    ("GIF87", b"GIF87a",            ".gif", b"\x00;",              None),
    ("GIF89", b"GIF89a",            ".gif", b"\x00;",              None),
    ("BMP",   b"BM",                ".bmp", None,                  None),
    ("WAV",   b"RIFF",              ".wav", None,                  None),
    ("MP3",   b"\xff\xfb",          ".mp3", None,                  None),
    ("7ZIP",  b"7z\xbc\xaf'\x1c",  ".7z",  None,                  None),
    ("RAR",   b"Rar!\x1a\x07",     ".rar", None,                  None),
]

def elf_size(data, offset):
    """Read ELF e_shoff + section headers to estimate total size."""
    try:
        ei_class = data[offset + 4]  # 1=32bit, 2=64bit
        ei_data  = data[offset + 5]  # 1=LE, 2=BE
        bo = "<" if ei_data == 1 else ">"
        if ei_class == 1:
            e_shoff, e_shentsize, e_shnum = struct.unpack_from(bo + "IHH", data, offset + 32)
        else:
            e_shoff, e_shentsize, e_shnum = struct.unpack_from(bo + "QHH", data, offset + 40)
        end = e_shoff + e_shentsize * e_shnum
        if end > 0 and end <= len(data) - offset:
            return end
    except Exception:
        pass
    return None

def bmp_size(data, offset):
    try:
        return struct.unpack_from("<I", data, offset + 2)[0]
    except Exception:
        return None

def wav_size(data, offset):
    try:
        chunk_size = struct.unpack_from("<I", data, offset + 4)[0]
        return chunk_size + 8
    except Exception:
        return None

def find_end(data, start, end_sig):
    idx = data.find(end_sig, start)
    if idx == -1:
        return None
    return idx + len(end_sig)

def carve(data, out_dir):
    found = []
    i = 0
    while i < len(data):
        matched = False
        for name, magic, ext, end_sig, _ in SIGNATURES:
            if data[i:i+len(magic)] == magic:
                end = None

                if name == "ELF":
                    end = elf_size(data, i)
                elif name == "BMP":
                    end = bmp_size(data, i)
                    if end:
                        end = i + end
                elif name == "WAV":
                    end = wav_size(data, i)
                    if end:
                        end = i + end

                if end is None and end_sig:
                    end = find_end(data, i + len(magic), end_sig)

                if end is None:
                    end = len(data)

                end = min(end, len(data))
                chunk = data[i:end]
                idx = len(found)
                out_path = out_dir / f"carved_{idx:03d}_{name}{ext}"
                out_path.write_bytes(chunk)
                size = len(chunk)
                print(f"  [+] {name:6s} @ offset 0x{i:08x}  size={size:,}  -> {out_path.name}")
                found.append((name, i, size, str(out_path)))
                i = end
                matched = True
                break

        if not matched:
            i += 1

    return found

def main():
    parser = argparse.ArgumentParser(description="Carve embedded files from a binary blob")
    parser.add_argument("input", help="Input file to scan")
    parser.add_argument("-o", "--output", default=None, help="Output directory (default: <input>_carved)")
    parser.add_argument("--min-size", type=int, default=16, help="Skip carved files smaller than N bytes (default: 16)")
    args = parser.parse_args()

    in_path = Path(args.input)
    if not in_path.exists():
        print(f"[!] File not found: {in_path}")
        sys.exit(1)

    out_dir = Path(args.output) if args.output else in_path.parent / (in_path.name + "_carved")
    out_dir.mkdir(parents=True, exist_ok=True)

    data = in_path.read_bytes()
    print(f"[*] Scanning {in_path}  ({len(data):,} bytes)")
    print(f"[*] Output dir: {out_dir}\n")

    found = carve(data, out_dir)

    # Remove files below min-size
    kept = []
    for name, offset, size, path in found:
        if size < args.min_size:
            os.remove(path)
            print(f"  [-] Removed tiny {name} @ 0x{offset:08x} ({size} bytes)")
        else:
            kept.append((name, offset, size, path))

    print(f"\n[*] Done. {len(kept)} file(s) carved to {out_dir}/")

    if not kept:
        print("[*] No embedded files found.")
    else:
        print("\nSummary:")
        for name, offset, size, path in kept:
            print(f"  {name:6s}  offset=0x{offset:08x}  size={size:,}  {Path(path).name}")

if __name__ == "__main__":
    main()
