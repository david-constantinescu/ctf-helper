#!/usr/bin/env python3
"""
metadata_dumper.py — extract EXIF, PDF metadata, ZIP comments, PNG chunks
"""

import sys
import struct
import argparse
import zipfile
from pathlib import Path

# ── PNG ───────────────────────────────────────────────────────────────────────

def parse_png(data: bytes):
    print("[PNG] Chunks:")
    if data[:8] != b"\x89PNG\r\n\x1a\n":
        print("  [!] Not a valid PNG")
        return
    offset = 8
    while offset < len(data) - 12:
        length = struct.unpack_from(">I", data, offset)[0]
        chunk_type = data[offset+4:offset+8].decode("ascii", errors="replace")
        chunk_data = data[offset+8:offset+8+length]
        crc = struct.unpack_from(">I", data, offset+8+length)[0]
        print(f"  [{chunk_type}]  length={length}  crc=0x{crc:08x}")
        if chunk_type == "tEXt":
            parts = chunk_data.split(b"\x00", 1)
            key = parts[0].decode("latin-1")
            val = parts[1].decode("latin-1") if len(parts) > 1 else ""
            print(f"    {key}: {val}")
        elif chunk_type == "iTXt":
            parts = chunk_data.split(b"\x00", 1)
            key = parts[0].decode("latin-1")
            print(f"    {key}: {parts[1][:200]!r}")
        elif chunk_type == "zTXt":
            parts = chunk_data.split(b"\x00", 2)
            key = parts[0].decode("latin-1")
            print(f"    {key}: (compressed text, {length} bytes)")
        elif chunk_type == "IHDR":
            w, h, bd, ct = struct.unpack_from(">IIBB", chunk_data)
            color = {0:"Grayscale",2:"RGB",3:"Indexed",4:"Grayscale+A",6:"RGBA"}.get(ct, str(ct))
            print(f"    Width={w}  Height={h}  BitDepth={bd}  Color={color}")
        offset += 12 + length

# ── JPEG / EXIF ───────────────────────────────────────────────────────────────

EXIF_TAGS = {
    0x010e: "ImageDescription", 0x010f: "Make",       0x0110: "Model",
    0x0112: "Orientation",      0x011a: "XResolution", 0x011b: "YResolution",
    0x0128: "ResolutionUnit",   0x0131: "Software",    0x0132: "DateTime",
    0x013b: "Artist",           0x013e: "WhitePoint",  0x013f: "PrimaryChromaticities",
    0x0211: "YCbCrCoefficients",0x0213: "YCbCrPositioning",
    0x0214: "ReferenceBlackWhite", 0x8298: "Copyright",
    0x8769: "ExifIFDPointer",   0x8825: "GPSInfoIFDPointer",
    0x9003: "DateTimeOriginal", 0x9004: "DateTimeDigitized",
    0x9286: "UserComment",      0xa420: "ImageUniqueID",
    0x0100: "ImageWidth",       0x0101: "ImageLength",
    0x0102: "BitsPerSample",    0x0103: "Compression",
}

def read_tiff_value(data, offset, type_, count, endian):
    fmt_map = {1:"B",2:"s",3:"H",4:"I",5:"II",7:"B",9:"i",10:"ii"}
    sizes   = {1:1,  2:1, 3:2, 4:4, 5:8, 7:1, 9:4, 10:8}
    if type_ not in fmt_map:
        return None
    sz = sizes[type_] * count
    if sz <= 4:
        raw = data[offset:offset+4]
    else:
        ptr = struct.unpack_from(endian+"I", data, offset)[0]
        raw = data[ptr:ptr+sz]
    if type_ == 2:
        return raw.rstrip(b"\x00").decode("latin-1", errors="replace")
    if type_ in (5, 10):
        vals = []
        for i in range(count):
            a, b = struct.unpack_from(endian+"II", raw, i*8)
            vals.append(f"{a}/{b}")
        return ", ".join(vals)
    fmt = endian + fmt_map[type_] * count
    try:
        vals = struct.unpack_from(fmt, raw)
        return vals[0] if count == 1 else vals
    except Exception:
        return None

def parse_exif_ifd(data, ifd_offset, endian, depth=0):
    pad = "    " * depth
    try:
        count = struct.unpack_from(endian+"H", data, ifd_offset)[0]
    except Exception:
        return
    for i in range(count):
        entry = ifd_offset + 2 + i * 12
        tag, type_, cnt = struct.unpack_from(endian+"HHI", data, entry)
        val = read_tiff_value(data, entry + 8, type_, cnt, endian)
        name = EXIF_TAGS.get(tag, f"0x{tag:04x}")
        print(f"{pad}  {name}: {val}")
        if tag in (0x8769, 0x8825) and isinstance(val, int):
            parse_exif_ifd(data, val, endian, depth+1)

def parse_jpeg(data: bytes):
    print("[JPEG] Scanning APP segments:")
    offset = 2
    while offset < len(data) - 4:
        if data[offset] != 0xff:
            break
        marker = data[offset+1]
        length = struct.unpack_from(">H", data, offset+2)[0]
        seg = data[offset+4:offset+2+length]

        if marker == 0xe0:
            print(f"  [APP0/JFIF]  length={length}")
        elif marker == 0xe1:
            if seg[:6] == b"Exif\x00\x00":
                print(f"  [APP1/EXIF]  length={length}")
                tiff = seg[6:]
                endian = "<" if tiff[:2] == b"II" else ">"
                ifd0 = struct.unpack_from(endian+"I", tiff, 4)[0]
                parse_exif_ifd(tiff, ifd0, endian)
            elif seg[:5] == b"http:":
                print(f"  [APP1/XMP]  {seg[:100]!r}")
        elif marker == 0xfe:
            print(f"  [COM]  {seg.decode('latin-1', errors='replace')}")
        elif marker == 0xda:
            break
        offset += 2 + length

# ── ZIP ───────────────────────────────────────────────────────────────────────

def parse_zip(path: Path):
    print("[ZIP] Contents:")
    try:
        with zipfile.ZipFile(path) as zf:
            comment = zf.comment
            if comment:
                print(f"  Archive comment: {comment.decode('utf-8', errors='replace')}")
            for info in zf.infolist():
                print(f"  {info.filename}")
                print(f"    compress={info.compress_type}  size={info.file_size}  "
                      f"crc=0x{info.CRC:08x}  date={info.date_time}")
                if info.comment:
                    print(f"    file comment: {info.comment.decode('utf-8', errors='replace')}")
    except zipfile.BadZipFile as e:
        print(f"  [!] {e}")

# ── PDF ───────────────────────────────────────────────────────────────────────

def parse_pdf(data: bytes):
    print("[PDF] Metadata:")
    text = data.decode("latin-1", errors="replace")
    import re
    # Info dictionary
    info = re.search(r'/Info\s*<<(.*?)>>', text, re.DOTALL)
    if info:
        block = info.group(1)
        for key, val in re.findall(r'/(\w+)\s*\(([^)]*)\)', block):
            print(f"  {key}: {val}")
    # XMP metadata
    xmp = re.search(r'<x:xmpmeta.*?</x:xmpmeta>', text, re.DOTALL)
    if xmp:
        print("\n  [XMP block present]:")
        for tag, val in re.findall(r'<[^/][^>]*>([^<]{1,200})</[^>]+>', xmp.group()):
            val = val.strip()
            if val:
                print(f"    {val}")
    # Version and stream count
    version = re.search(r'%PDF-(\d+\.\d+)', text)
    if version:
        print(f"\n  PDF Version: {version.group(1)}")
    streams = len(re.findall(r'\bstream\b', text))
    print(f"  Stream objects: {streams}")

# ── Dispatcher ────────────────────────────────────────────────────────────────

MAGIC_MAP = {
    b"\x89PNG\r\n\x1a\n": parse_png,
    b"\xff\xd8\xff":       parse_jpeg,
    b"%PDF-":              lambda d: parse_pdf(d),
}

def main():
    parser = argparse.ArgumentParser(description="Dump metadata from images, PDFs, ZIPs")
    parser.add_argument("input", help="Input file")
    args = parser.parse_args()

    in_path = Path(args.input)
    if not in_path.exists():
        print(f"[!] File not found: {in_path}")
        sys.exit(1)

    data = in_path.read_bytes()
    print(f"[*] File: {in_path}  ({len(data):,} bytes)\n")

    # Check magic
    for magic, fn in MAGIC_MAP.items():
        if data[:len(magic)] == magic:
            fn(data)
            return

    # ZIP check (magic can be at offset 0 but also central dir at end)
    if data[:2] == b"PK":
        parse_zip(in_path)
        return

    print("[!] Unknown file type — no metadata extractor available for this format.")

if __name__ == "__main__":
    main()
