#!/usr/bin/env python3
"""
extract_all.py — deep file extractor for CTF challenges
Tries every known method to find and extract files hidden inside a file:
magic carving, zlib/gzip/bzip2/lzma streams, ZIP/TAR/RAR/7z, PDF streams,
PNG chunks, JPEG segments, ELF sections, base64 blobs, hex blobs,
steghide, binwalk, foremost, and more.
"""

import sys
import os
import re
import struct
import base64
import zlib
import gzip
import bz2
import lzma
import zipfile
import tarfile
import shutil
import argparse
import subprocess
import tempfile
from pathlib import Path

# ── Helpers ───────────────────────────────────────────────────────────────────

found_count = 0

def save(out_dir: Path, name: str, data: bytes, source: str) -> Path | None:
    global found_count
    if not data or len(data) < 4:
        return None
    out_path = out_dir / name
    # avoid overwriting
    if out_path.exists():
        stem, suffix = out_path.stem, out_path.suffix
        out_path = out_dir / f"{stem}_{found_count}{suffix}"
    out_path.write_bytes(data)
    found_count += 1
    print(f"  [+] {source:<30s}  {len(data):>8,} bytes  ->  {out_path.name}")
    return out_path

def run_tool(cmd: list[str], cwd=None) -> tuple[bool, str]:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=30, cwd=cwd)
        return r.returncode == 0, r.stdout + r.stderr
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False, ""

def tool_exists(name: str) -> bool:
    return shutil.which(name) is not None

def guess_ext(data: bytes) -> str:
    sigs = [
        (b"\x89PNG\r\n\x1a\n", ".png"), (b"\xff\xd8\xff", ".jpg"),
        (b"GIF8", ".gif"),               (b"BM", ".bmp"),
        (b"PK\x03\x04", ".zip"),         (b"\x1f\x8b", ".gz"),
        (b"BZh", ".bz2"),                (b"\xfd7zXZ", ".xz"),
        (b"7z\xbc\xaf'\x1c", ".7z"),     (b"Rar!\x1a\x07", ".rar"),
        (b"\x7fELF", ".elf"),            (b"%PDF-", ".pdf"),
        (b"RIFF", ".wav"),               (b"\xff\xfb", ".mp3"),
        (b"OggS", ".ogg"),               (b"\x00\x00\x00\x18ftyp", ".mp4"),
        (b"<!DOCTYPE", ".html"),         (b"<html", ".html"),
        (b"<?xml", ".xml"),              (b"MZ", ".exe"),
    ]
    for magic, ext in sigs:
        if data[:len(magic)] == magic:
            return ext
    if all(0x20 <= b <= 0x7e or b in (9, 10, 13) for b in data[:64]):
        return ".txt"
    return ".bin"

# ── 1. Magic signature carving ────────────────────────────────────────────────

SIGNATURES = [
    ("ZIP",    b"PK\x03\x04",         ".zip",  b"PK\x05\x06", None),
    ("PNG",    b"\x89PNG\r\n\x1a\n",  ".png",  b"IEND\xaeB`\x82", None),
    ("JPEG",   b"\xff\xd8\xff",        ".jpg",  b"\xff\xd9", None),
    ("GIF87",  b"GIF87a",             ".gif",  b"\x00;", None),
    ("GIF89",  b"GIF89a",             ".gif",  b"\x00;", None),
    ("ELF",    b"\x7fELF",            ".elf",  None, None),
    ("PDF",    b"%PDF-",              ".pdf",  b"%%EOF", None),
    ("BMP",    b"BM",                 ".bmp",  None, None),
    ("WAV",    b"RIFF",               ".wav",  None, None),
    ("GZIP",   b"\x1f\x8b",           ".gz",   None, None),
    ("BZIP2",  b"BZh",                ".bz2",  b"\x17rE8P\x90", None),
    ("XZ",     b"\xfd7zXZ\x00",       ".xz",   b"YZ", None),
    ("7ZIP",   b"7z\xbc\xaf'\x1c",    ".7z",   None, None),
    ("RAR",    b"Rar!\x1a\x07",       ".rar",  None, None),
    ("EXE",    b"MZ",                 ".exe",  None, None),
    ("CLASS",  b"\xca\xfe\xba\xbe",   ".class",None, None),
    ("OGG",    b"OggS",               ".ogg",  None, None),
    ("MP3",    b"\xff\xfb",           ".mp3",  None, None),
    ("SQLITE", b"SQLite format 3\x00",".db",   None, None),
]

def elf_end(data, off):
    try:
        ei_class = data[off + 4]
        bo = "<" if data[off + 5] == 1 else ">"
        if ei_class == 1:
            e_shoff = struct.unpack_from(bo + "I", data, off + 32)[0]
            e_shentsize, e_shnum = struct.unpack_from(bo + "HH", data, off + 46)
        else:
            e_shoff = struct.unpack_from(bo + "Q", data, off + 40)[0]
            e_shentsize, e_shnum = struct.unpack_from(bo + "HH", data, off + 58)
        end = e_shoff + e_shentsize * e_shnum
        if 0 < end <= len(data) - off:
            return off + end
    except Exception:
        pass
    return None

def bmp_end(data, off):
    try:
        sz = struct.unpack_from("<I", data, off + 2)[0]
        if 0 < sz <= len(data) - off:
            return off + sz
    except Exception:
        pass
    return None

def riff_end(data, off):
    try:
        sz = struct.unpack_from("<I", data, off + 4)[0]
        if 0 < sz <= len(data) - off:
            return off + sz + 8
    except Exception:
        pass
    return None

def carve_signatures(data: bytes, out_dir: Path):
    print("\n[*] Magic signature carving...")
    i = 0
    count = 0
    while i < len(data):
        matched = False
        for name, magic, ext, end_sig, _ in SIGNATURES:
            mlen = len(magic)
            if data[i:i+mlen] != magic:
                continue
            end = None
            if name == "ELF":
                end = elf_end(data, i)
            elif name == "BMP":
                end = bmp_end(data, i)
            elif name == "WAV":
                end = riff_end(data, i)
            if end is None and end_sig:
                idx = data.find(end_sig, i + mlen)
                if idx != -1:
                    end = idx + len(end_sig)
            if end is None:
                end = len(data)
            end = min(end, len(data))
            chunk = data[i:end]
            if len(chunk) >= 8:
                save(out_dir, f"carved_{count:03d}_{name}{ext}", chunk, f"magic-carve:{name}@0x{i:x}")
                count += 1
            i = end
            matched = True
            break
        if not matched:
            i += 1

# ── 2. Compressed stream extraction ──────────────────────────────────────────

def try_decompress(data: bytes, off: int, method: str, fn) -> bytes | None:
    try:
        return fn(data[off:])
    except Exception:
        try:
            return fn(data[off:off+len(data)])
        except Exception:
            return None

def extract_compressed_streams(data: bytes, out_dir: Path):
    print("\n[*] Scanning for compressed streams...")
    count = 0

    # zlib: look for common zlib headers (0x78 0x9c, 0x78 0xda, 0x78 0x01, 0x78 0x5e)
    zlib_headers = [b"\x78\x9c", b"\x78\xda", b"\x78\x01", b"\x78\x5e"]
    for hdr in zlib_headers:
        off = 0
        while True:
            off = data.find(hdr, off)
            if off == -1:
                break
            for length in [len(data)-off, 65536, 32768, 16384, 8192]:
                try:
                    dec = zlib.decompress(data[off:off+length])
                    if len(dec) >= 8:
                        ext = guess_ext(dec)
                        save(out_dir, f"zlib_{count:03d}{ext}", dec, f"zlib@0x{off:x}")
                        count += 1
                        break
                except Exception:
                    pass
            off += 2

    # gzip streams
    off = 0
    while True:
        off = data.find(b"\x1f\x8b", off)
        if off == -1:
            break
        try:
            dec = gzip.decompress(data[off:])
            if len(dec) >= 8:
                ext = guess_ext(dec)
                save(out_dir, f"gzip_{count:03d}{ext}", dec, f"gzip@0x{off:x}")
                count += 1
        except Exception:
            pass
        off += 2

    # bzip2 streams
    off = 0
    while True:
        off = data.find(b"BZh", off)
        if off == -1:
            break
        try:
            dec = bz2.decompress(data[off:])
            if len(dec) >= 8:
                ext = guess_ext(dec)
                save(out_dir, f"bzip2_{count:03d}{ext}", dec, f"bzip2@0x{off:x}")
                count += 1
        except Exception:
            pass
        off += 3

    # xz/lzma streams
    off = 0
    while True:
        off = data.find(b"\xfd7zXZ\x00", off)
        if off == -1:
            break
        try:
            dec = lzma.decompress(data[off:])
            if len(dec) >= 8:
                ext = guess_ext(dec)
                save(out_dir, f"xz_{count:03d}{ext}", dec, f"xz@0x{off:x}")
                count += 1
        except Exception:
            pass
        off += 6

# ── 3. Archive extraction ─────────────────────────────────────────────────────

def extract_archives(in_path: Path, out_dir: Path):
    print("\n[*] Trying archive extraction...")
    data = in_path.read_bytes()

    # ZIP (may be at offset > 0 — find all PK headers)
    offsets = []
    off = 0
    while True:
        off = data.find(b"PK\x03\x04", off)
        if off == -1:
            break
        offsets.append(off)
        off += 4

    for off in offsets:
        try:
            import io
            zf = zipfile.ZipFile(io.BytesIO(data[off:]))
            sub = out_dir / f"zip_at_0x{off:x}"
            sub.mkdir(exist_ok=True)
            zf.extractall(sub)
            comment = zf.comment
            if comment:
                save(out_dir, f"zip_comment_0x{off:x}.txt", comment, f"zip-comment@0x{off:x}")
            for name in zf.namelist():
                print(f"  [+] zip@0x{off:x} extracted: {name}")
        except Exception:
            pass

    # TAR (gzip, bzip2, xz, plain)
    for mode in ["r:gz", "r:bz2", "r:xz", "r:"]:
        try:
            import io
            tf = tarfile.open(fileobj=io.BytesIO(data), mode=mode)
            sub = out_dir / f"tar_{mode.replace(':', '_').replace('*', 'x')}"
            sub.mkdir(exist_ok=True)
            tf.extractall(sub)
            for m in tf.getmembers():
                print(f"  [+] tar[{mode}] extracted: {m.name}")
        except Exception:
            pass

    # 7z via p7zip if available
    if tool_exists("7z"):
        sub = out_dir / "7z_extracted"
        sub.mkdir(exist_ok=True)
        ok, out = run_tool(["7z", "x", "-y", f"-o{sub}", str(in_path)])
        if ok:
            for f in sub.rglob("*"):
                if f.is_file():
                    print(f"  [+] 7z extracted: {f.relative_to(sub)}")

    # RAR via unrar if available
    if tool_exists("unrar"):
        sub = out_dir / "rar_extracted"
        sub.mkdir(exist_ok=True)
        ok, _ = run_tool(["unrar", "x", "-y", str(in_path), str(sub)])
        if ok:
            for f in sub.rglob("*"):
                if f.is_file():
                    print(f"  [+] unrar extracted: {f.relative_to(sub)}")

# ── 4. Base64 blob extraction ─────────────────────────────────────────────────

B64_RE = re.compile(rb'[A-Za-z0-9+/]{40,}={0,2}')
B64URL_RE = re.compile(rb'[A-Za-z0-9_\-]{40,}={0,2}')

def extract_base64_blobs(data: bytes, out_dir: Path):
    print("\n[*] Scanning for Base64 blobs...")
    count = 0
    seen = set()
    for pattern in [B64_RE, B64URL_RE]:
        for m in pattern.finditer(data):
            blob = m.group()
            if blob in seen:
                continue
            seen.add(blob)
            for candidate in [blob, blob + b"=", blob + b"=="]:
                try:
                    dec = base64.b64decode(candidate, validate=False)
                    if len(dec) < 8:
                        continue
                    printable = sum(1 for b in dec if 0x20 <= b <= 0x7e or b in (9, 10, 13))
                    if printable / len(dec) > 0.8 or len(dec) > 16:
                        ext = guess_ext(dec)
                        save(out_dir, f"b64_blob_{count:03d}{ext}", dec,
                             f"base64@0x{m.start():x}")
                        count += 1
                        break
                except Exception:
                    pass

# ── 5. Hex blob extraction ────────────────────────────────────────────────────

HEX_RE = re.compile(rb'(?:[0-9a-fA-F]{2}){16,}')

def extract_hex_blobs(data: bytes, out_dir: Path):
    print("\n[*] Scanning for hex-encoded blobs...")
    count = 0
    seen = set()
    for m in HEX_RE.finditer(data):
        blob = m.group()
        if len(blob) % 2 != 0 or blob in seen:
            continue
        seen.add(blob)
        try:
            dec = bytes.fromhex(blob.decode("ascii"))
            if len(dec) >= 8:
                ext = guess_ext(dec)
                save(out_dir, f"hex_blob_{count:03d}{ext}", dec, f"hex@0x{m.start():x}")
                count += 1
        except Exception:
            pass

# ── 6. PDF stream extraction ──────────────────────────────────────────────────

def extract_pdf_streams(data: bytes, out_dir: Path):
    if b"%PDF-" not in data[:1024]:
        return
    print("\n[*] PDF detected — extracting streams...")
    count = 0
    text = data.decode("latin-1", errors="replace")
    for m in re.finditer(r'stream\r?\n(.*?)\r?\nendstream', text, re.DOTALL):
        raw = m.group(1).encode("latin-1", errors="replace")
        # Try zlib decompress (FlateDecode)
        for hdr in [b"\x78\x9c", b"\x78\xda", b"\x78\x01"]:
            if hdr in raw:
                idx = raw.index(hdr)
                try:
                    dec = zlib.decompress(raw[idx:])
                    ext = guess_ext(dec)
                    save(out_dir, f"pdf_stream_{count:03d}{ext}", dec,
                         f"pdf-stream@{m.start()}")
                    count += 1
                except Exception:
                    pass
        # Save raw stream too if it looks like a known format
        ext = guess_ext(raw)
        if ext != ".bin" or len(raw) > 64:
            save(out_dir, f"pdf_stream_raw_{count:03d}{ext}", raw,
                 f"pdf-stream-raw@{m.start()}")
            count += 1

# ── 7. PNG chunk extraction ───────────────────────────────────────────────────

def extract_png_chunks(data: bytes, out_dir: Path):
    if data[:8] != b"\x89PNG\r\n\x1a\n":
        return
    print("\n[*] PNG detected — extracting non-standard chunks...")
    off = 8
    count = 0
    while off < len(data) - 12:
        length = struct.unpack_from(">I", data, off)[0]
        chunk_type = data[off+4:off+8].decode("ascii", errors="replace")
        chunk_data = data[off+8:off+8+length]
        if chunk_type not in ("IHDR","IDAT","IEND","PLTE","tRNS","gAMA","cHRM","sRGB","bKGD","hIST","pHYs","sPLT","tIME"):
            save(out_dir, f"png_chunk_{count:03d}_{chunk_type}.bin", chunk_data,
                 f"png-chunk:{chunk_type}@0x{off:x}")
            count += 1
        # IDAT: concatenate and try raw decompress
        off += 12 + length

    # Also try to decompress all IDAT chunks combined
    idat = b""
    off = 8
    while off < len(data) - 12:
        length = struct.unpack_from(">I", data, off)[0]
        chunk_type = data[off+4:off+8].decode("ascii", errors="replace")
        if chunk_type == "IDAT":
            idat += data[off+8:off+8+length]
        off += 12 + length
    if idat:
        try:
            raw_pixels = zlib.decompress(idat)
            save(out_dir, "png_raw_pixels.bin", raw_pixels, "png-IDAT-decompressed")
        except Exception:
            pass

# ── 8. JPEG segment extraction ────────────────────────────────────────────────

def extract_jpeg_segments(data: bytes, out_dir: Path):
    if data[:3] != b"\xff\xd8\xff":
        return
    print("\n[*] JPEG detected — extracting APP/COM segments...")
    off = 2
    count = 0
    while off < len(data) - 4:
        if data[off] != 0xff:
            break
        marker = data[off+1]
        if marker == 0xd9:
            # Check for appended data after EOI
            rest = data[off+2:]
            if len(rest) > 8:
                ext = guess_ext(rest)
                save(out_dir, f"jpeg_appended{ext}", rest, "jpeg-appended-after-EOI")
            break
        if marker == 0xda:
            break
        try:
            length = struct.unpack_from(">H", data, off+2)[0]
        except Exception:
            break
        seg_data = data[off+4:off+2+length]
        marker_name = f"APP{marker-0xe0}" if 0xe0 <= marker <= 0xef else f"0x{marker:02x}"
        if marker == 0xfe:
            marker_name = "COM"
        # Save non-standard or large segments
        if marker not in (0xe0, 0xe1) and len(seg_data) > 4:
            ext = guess_ext(seg_data)
            save(out_dir, f"jpeg_seg_{count:03d}_{marker_name}{ext}", seg_data,
                 f"jpeg-segment:{marker_name}@0x{off:x}")
            count += 1
        elif marker == 0xe1 and seg_data[:6] != b"Exif\x00\x00":
            save(out_dir, f"jpeg_app1_noexif_{count:03d}.bin", seg_data,
                 f"jpeg-APP1-non-exif@0x{off:x}")
            count += 1
        off += 2 + length

# ── 9. ELF section extraction ─────────────────────────────────────────────────

def extract_elf_sections(data: bytes, out_dir: Path):
    if data[:4] != b"\x7fELF":
        return
    print("\n[*] ELF detected — extracting sections...")
    try:
        ei_class = data[4]
        bo = "<" if data[5] == 1 else ">"
        if ei_class == 1:
            e_shoff = struct.unpack_from(bo+"I", data, 32)[0]
            e_shentsize, e_shnum, e_shstrndx = struct.unpack_from(bo+"HHH", data, 46)
        else:
            e_shoff = struct.unpack_from(bo+"Q", data, 40)[0]
            e_shentsize, e_shnum, e_shstrndx = struct.unpack_from(bo+"HHH", data, 58)

        # Read section name string table
        shstr_entry = e_shoff + e_shstrndx * e_shentsize
        if ei_class == 1:
            shstr_off, shstr_sz = struct.unpack_from(bo+"II", data, shstr_entry+16)
        else:
            shstr_off, shstr_sz = struct.unpack_from(bo+"QQ", data, shstr_entry+24)
        shstrtab = data[shstr_off:shstr_off+shstr_sz]

        for i in range(e_shnum):
            entry = e_shoff + i * e_shentsize
            if ei_class == 1:
                sh_name_off, sh_type = struct.unpack_from(bo+"II", data, entry)
                sh_offset, sh_size = struct.unpack_from(bo+"II", data, entry+16)
            else:
                sh_name_off, sh_type = struct.unpack_from(bo+"II", data, entry)
                sh_offset, sh_size = struct.unpack_from(bo+"QQ", data, entry+24)
            if sh_size == 0 or sh_type == 8:  # SHT_NOBITS
                continue
            try:
                name_end = shstrtab.index(b"\x00", sh_name_off)
                sec_name = shstrtab[sh_name_off:name_end].decode("ascii", errors="replace")
            except Exception:
                sec_name = f"section_{i}"
            sec_data = data[sh_offset:sh_offset+sh_size]
            if sec_data and len(sec_data) > 0:
                safe_name = sec_name.lstrip(".").replace("/", "_") or f"section_{i}"
                ext = guess_ext(sec_data)
                save(out_dir, f"elf_{safe_name}{ext}", sec_data, f"elf-section:{sec_name}")
    except Exception as e:
        print(f"  [!] ELF parsing error: {e}")

# ── 10. Steganography tools ───────────────────────────────────────────────────

def try_steg_tools(in_path: Path, out_dir: Path):
    print("\n[*] Trying steganography tools...")

    # steghide (JPEG/BMP/WAV without password first, then common passwords)
    if tool_exists("steghide"):
        for pwd in ["", "password", "secret", "ctf", "flag", "hidden", "steg"]:
            out_file = out_dir / f"steghide_out_{pwd or 'nopwd'}.bin"
            ok, _ = run_tool([
                "steghide", "extract", "-sf", str(in_path),
                "-p", pwd, "-f", "-q", "-xf", str(out_file)
            ])
            if ok and out_file.exists() and out_file.stat().st_size > 0:
                print(f"  [+] steghide extracted with password={pwd!r} -> {out_file.name}")

    # zsteg (PNG/BMP)
    if tool_exists("zsteg"):
        ok, output = run_tool(["zsteg", "-a", str(in_path)])
        if ok and output.strip():
            (out_dir / "zsteg_output.txt").write_text(output)
            print(f"  [+] zsteg output saved -> zsteg_output.txt")
            # Extract any files zsteg found
            ok2, _ = run_tool(["zsteg", "-a", "--extract-all", str(out_dir), str(in_path)])

    # stegsolve / outguess if available
    if tool_exists("outguess"):
        out_file = out_dir / "outguess_out.bin"
        run_tool(["outguess", "-r", str(in_path), str(out_file)])
        if out_file.exists() and out_file.stat().st_size > 0:
            print(f"  [+] outguess extracted -> {out_file.name}")

    # exiftool for metadata / embedded thumbnails
    if tool_exists("exiftool"):
        ok, output = run_tool(["exiftool", "-b", "-ThumbnailImage", "-w", str(out_dir / "thumb_%f.jpg"), str(in_path)])
        ok2, output2 = run_tool(["exiftool", str(in_path)])
        if ok2 and output2.strip():
            (out_dir / "exiftool_meta.txt").write_text(output2)
            print(f"  [+] exiftool metadata -> exiftool_meta.txt")

    # strings (human-readable strings from binary)
    if tool_exists("strings"):
        ok, output = run_tool(["strings", "-n", "8", str(in_path)])
        if ok and output.strip():
            (out_dir / "strings_output.txt").write_text(output)
            print(f"  [+] strings output -> strings_output.txt")

# ── 11. External extraction tools ─────────────────────────────────────────────

def try_external_tools(in_path: Path, out_dir: Path):
    print("\n[*] Trying external extraction tools...")

    # binwalk
    if tool_exists("binwalk"):
        sub = out_dir / "binwalk_extracted"
        sub.mkdir(exist_ok=True)
        ok, output = run_tool(["binwalk", "--extract", "--directory", str(sub), str(in_path)])
        if output.strip():
            (out_dir / "binwalk_scan.txt").write_text(output)
            print(f"  [+] binwalk scan -> binwalk_scan.txt")
            for f in sub.rglob("*"):
                if f.is_file():
                    print(f"  [+] binwalk extracted: {f.relative_to(sub)}")

    # foremost
    if tool_exists("foremost"):
        sub = out_dir / "foremost_extracted"
        sub.mkdir(exist_ok=True)
        ok, output = run_tool(["foremost", "-o", str(sub), "-i", str(in_path)])
        if ok:
            for f in sub.rglob("*"):
                if f.is_file() and f.name != "audit.txt":
                    print(f"  [+] foremost extracted: {f.relative_to(sub)}")

    # photorec / testdisk (non-interactive skip)

# ── 12. LSB steganography (PNG/BMP) ──────────────────────────────────────────

def extract_lsb(data: bytes, out_dir: Path):
    if data[:8] != b"\x89PNG\r\n\x1a\n":
        return
    print("\n[*] Attempting LSB extraction from PNG...")
    try:
        import struct, zlib
        # Parse IHDR
        w = struct.unpack_from(">I", data, 16)[0]
        h = struct.unpack_from(">I", data, 20)[0]
        bit_depth = data[24]
        color_type = data[25]
        channels = {0:1, 2:3, 3:1, 4:2, 6:4}.get(color_type, 3)

        # Collect IDAT
        idat = b""
        off = 8
        while off < len(data) - 12:
            length = struct.unpack_from(">I", data, off)[0]
            chunk_type = data[off+4:off+8]
            if chunk_type == b"IDAT":
                idat += data[off+8:off+8+length]
            off += 12 + length

        raw = zlib.decompress(idat)
        stride = 1 + w * channels  # +1 for filter byte

        bits = []
        for row in range(h):
            row_start = row * stride + 1  # skip filter byte
            for col in range(w * channels):
                if row_start + col < len(raw):
                    bits.append(raw[row_start + col] & 1)

        # Reconstruct bytes
        lsb_bytes = bytearray()
        for i in range(0, len(bits) - 7, 8):
            byte = 0
            for j in range(8):
                byte = (byte << 1) | bits[i + j]
            lsb_bytes.append(byte)
            if lsb_bytes[-1] == 0 and len(lsb_bytes) > 8:
                break

        if lsb_bytes:
            ext = guess_ext(bytes(lsb_bytes))
            save(out_dir, f"lsb_extracted{ext}", bytes(lsb_bytes), "PNG-LSB-bit0")
    except Exception as e:
        pass

# ── 13. Appended data detection ───────────────────────────────────────────────

def extract_appended(data: bytes, in_path: Path, out_dir: Path):
    print("\n[*] Checking for appended data...")
    suffix = in_path.suffix.lower()
    end_markers = {
        ".png": b"IEND\xaeB`\x82",
        ".jpg": b"\xff\xd9",
        ".gif": b"\x00;",
        ".zip": None,  # ZIP has central directory at end, hard to detect simply
    }
    marker = end_markers.get(suffix)
    if marker:
        idx = data.rfind(marker)
        if idx != -1:
            after = data[idx+len(marker):]
            if len(after) > 8:
                ext = guess_ext(after)
                save(out_dir, f"appended_data{ext}", after, f"appended-after-EOF-marker")

# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Deep file extractor — tries every method to find hidden files"
    )
    parser.add_argument("input", help="Input file to analyse")
    parser.add_argument("-o", "--output", default=None,
                        help="Output directory (default: <input>_extracted)")
    parser.add_argument("--no-carve", action="store_true", help="Skip magic signature carving")
    parser.add_argument("--no-steg", action="store_true", help="Skip steganography tools")
    parser.add_argument("--no-external", action="store_true", help="Skip binwalk/foremost")
    args = parser.parse_args()

    in_path = Path(args.input)
    if not in_path.exists():
        print(f"[!] File not found: {in_path}")
        sys.exit(1)

    out_dir = Path(args.output) if args.output else in_path.parent / (in_path.name + "_extracted")
    out_dir.mkdir(parents=True, exist_ok=True)

    data = in_path.read_bytes()
    print(f"[*] Input:  {in_path}  ({len(data):,} bytes)")
    print(f"[*] Output: {out_dir}")
    print(f"[*] Type:   {guess_ext(data).lstrip('.')}")

    # Run all extraction methods
    if not args.no_carve:
        carve_signatures(data, out_dir)
    extract_compressed_streams(data, out_dir)
    extract_archives(in_path, out_dir)
    extract_base64_blobs(data, out_dir)
    extract_hex_blobs(data, out_dir)
    extract_pdf_streams(data, out_dir)
    extract_png_chunks(data, out_dir)
    extract_jpeg_segments(data, out_dir)
    extract_elf_sections(data, out_dir)
    extract_lsb(data, out_dir)
    extract_appended(data, in_path, out_dir)
    if not args.no_steg:
        try_steg_tools(in_path, out_dir)
    if not args.no_external:
        try_external_tools(in_path, out_dir)

    print(f"\n{'='*60}")
    print(f"[*] Done. {found_count} item(s) extracted to: {out_dir}/")
    if found_count == 0:
        print("[*] Nothing extracted — file may be clean or use an unsupported format.")

if __name__ == "__main__":
    main()
