#!/usr/bin/env python3
"""
pcap_extractor.py — reconstruct TCP/UDP streams and extract files from .pcap/.pcapng
Pure Python pcap parser (no scapy required). Uses scapy if available for richer analysis.
Extracts: HTTP files, FTP data, raw TCP streams, DNS, SMTP attachments.
"""

import sys
import re
import struct
import argparse
import os
from pathlib import Path
from collections import defaultdict

# Only match flags where the prefix looks like a real CTF prefix (printable alphanum)
# and the content inside braces is mostly printable ASCII
_KNOWN_PREFIXES = re.compile(
    rb'(?:flag|ctf|osc|rocsc|htb|thm|pico|ductf|hack|sec|crypto|web|pwn|rev|misc|forensics|stego|net)',
    re.IGNORECASE,
)

# Broad regex to find candidates, then filter them
_FLAG_CANDIDATE_RE = re.compile(rb'[A-Za-z0-9_]{2,12}\{[^}]{3,120}\}')

def _is_printable_bytes(b: bytes, threshold: float = 0.85) -> bool:
    if not b:
        return False
    printable = sum(1 for x in b if 0x20 <= x <= 0x7e)
    return printable / len(b) >= threshold

def is_real_flag(match_bytes: bytes) -> bool:
    """Return True if the match looks like a genuine CTF flag, not binary garbage."""
    brace = match_bytes.index(b'{')
    prefix = match_bytes[:brace]
    content = match_bytes[brace+1:-1]
    # Accept if it's a known prefix OR the content is fully printable
    if _KNOWN_PREFIXES.fullmatch(prefix):
        return True
    return _is_printable_bytes(prefix) and _is_printable_bytes(content)

# ── PCAP / PCAPNG parser ──────────────────────────────────────────────────────

PCAP_MAGIC_LE   = 0xd4c3b2a1
PCAP_MAGIC_BE   = 0xa1b2c3d4
PCAP_MAGIC_NS_LE= 0x4d3cb2a1
PCAP_MAGIC_NS_BE= 0xa1b23c4d
PCAPNG_MAGIC    = 0x0a0d0d0a

def parse_pcap(data: bytes) -> list[bytes]:
    """Parse classic pcap, return list of raw packet payloads."""
    magic = struct.unpack_from("<I", data, 0)[0]
    if magic in (PCAP_MAGIC_LE, PCAP_MAGIC_NS_LE):
        bo = "<"
    elif magic in (PCAP_MAGIC_BE, PCAP_MAGIC_NS_BE):
        bo = ">"
    else:
        raise ValueError("Not a pcap file")

    link_type = struct.unpack_from(bo + "I", data, 20)[0]
    packets = []
    off = 24
    while off + 16 <= len(data):
        ts_sec, ts_usec, incl_len, orig_len = struct.unpack_from(bo + "IIII", data, off)
        payload = data[off+16:off+16+incl_len]
        packets.append((link_type, payload))
        off += 16 + incl_len
    return packets

def parse_pcapng(data: bytes) -> list[bytes]:
    """Parse pcapng, return list of (link_type, raw_packet) tuples."""
    packets = []
    off = 0
    link_type = 1  # default ethernet

    while off + 12 <= len(data):
        block_type = struct.unpack_from("<I", data, off)[0]
        block_len  = struct.unpack_from("<I", data, off+4)[0]
        if block_len < 12 or off + block_len > len(data):
            break

        if block_type == 0x00000001:   # Interface Description Block
            link_type = struct.unpack_from("<H", data, off+8)[0]
        elif block_type == 0x00000006: # Enhanced Packet Block
            iface_id = struct.unpack_from("<I", data, off+8)[0]
            cap_len  = struct.unpack_from("<I", data, off+20)[0]
            pkt_data = data[off+28:off+28+cap_len]
            packets.append((link_type, pkt_data))
        elif block_type == 0x00000003: # Simple Packet Block
            orig_len = struct.unpack_from("<I", data, off+8)[0]
            pkt_data = data[off+12:off+block_len-4]
            packets.append((link_type, pkt_data))

        off += block_len
    return packets

# ── Ethernet / IP / TCP / UDP dissection ─────────────────────────────────────

def parse_ethernet(raw: bytes) -> tuple[int, bytes]:
    """Returns (ethertype, payload)."""
    if len(raw) < 14:
        return 0, b""
    ethertype = struct.unpack_from(">H", raw, 12)[0]
    if ethertype == 0x8100:  # VLAN
        ethertype = struct.unpack_from(">H", raw, 16)[0]
        return ethertype, raw[18:]
    return ethertype, raw[14:]

def parse_ip(payload: bytes) -> tuple[int, str, str, bytes]:
    """Returns (protocol, src_ip, dst_ip, transport_payload)."""
    if len(payload) < 20:
        return 0, "", "", b""
    version = payload[0] >> 4
    if version == 4:
        ihl = (payload[0] & 0xf) * 4
        proto = payload[9]
        src = ".".join(str(b) for b in payload[12:16])
        dst = ".".join(str(b) for b in payload[16:20])
        return proto, src, dst, payload[ihl:]
    elif version == 6:
        proto = payload[6]
        src = ":".join(f"{struct.unpack_from('>H', payload, 8+i*2)[0]:04x}" for i in range(8))
        dst = ":".join(f"{struct.unpack_from('>H', payload, 24+i*2)[0]:04x}" for i in range(8))
        return proto, src, dst, payload[40:]
    return 0, "", "", b""

def parse_tcp(payload: bytes) -> tuple[int, int, int, bytes]:
    """Returns (src_port, dst_port, flags, tcp_data)."""
    if len(payload) < 20:
        return 0, 0, 0, b""
    src_port = struct.unpack_from(">H", payload, 0)[0]
    dst_port = struct.unpack_from(">H", payload, 2)[0]
    data_off = (payload[12] >> 4) * 4
    flags    = payload[13]
    return src_port, dst_port, flags, payload[data_off:]

def parse_udp(payload: bytes) -> tuple[int, int, bytes]:
    """Returns (src_port, dst_port, udp_data)."""
    if len(payload) < 8:
        return 0, 0, b""
    return struct.unpack_from(">HH", payload)[0], struct.unpack_from(">HH", payload)[1], payload[8:]

# ── Stream reassembly ─────────────────────────────────────────────────────────

class TCPStream:
    def __init__(self):
        self.chunks: list[bytes] = []

    def add(self, data: bytes):
        if data:
            self.chunks.append(data)

    def data(self) -> bytes:
        return b"".join(self.chunks)

def reassemble_streams(packets: list[tuple[int, bytes]]) -> dict[tuple, TCPStream]:
    streams: dict[tuple, TCPStream] = defaultdict(TCPStream)
    udp_flows: dict[tuple, list[bytes]] = defaultdict(list)

    for link_type, raw in packets:
        if link_type == 1:   # Ethernet
            ethertype, ip_payload = parse_ethernet(raw)
        elif link_type == 101:  # Raw IP
            ethertype, ip_payload = 0x0800, raw
        else:
            continue

        if ethertype not in (0x0800, 0x86DD):
            continue

        proto, src_ip, dst_ip, transport = parse_ip(ip_payload)

        if proto == 6:  # TCP
            src_port, dst_port, flags, tcp_data = parse_tcp(transport)
            key = (min((src_ip,src_port),(dst_ip,dst_port)),
                   max((src_ip,src_port),(dst_ip,dst_port)))
            streams[key].add(tcp_data)

        elif proto == 17:  # UDP
            src_port, dst_port, udp_data = parse_udp(transport)
            key = (src_ip, src_port, dst_ip, dst_port)
            udp_flows[key].append(udp_data)

    return streams, udp_flows

# ── HTTP extraction ───────────────────────────────────────────────────────────

HTTP_RESPONSE_RE = re.compile(rb'HTTP/[\d.]+ \d+.*?\r\n\r\n', re.DOTALL)
CONTENT_TYPE_RE  = re.compile(rb'Content-Type:\s*([^\r\n;]+)', re.IGNORECASE)
CONTENT_LEN_RE   = re.compile(rb'Content-Length:\s*(\d+)', re.IGNORECASE)
TRANSFER_ENC_RE  = re.compile(rb'Transfer-Encoding:\s*chunked', re.IGNORECASE)
URL_RE           = re.compile(rb'(?:GET|POST|PUT|DELETE|HEAD)\s+([^\s]+)', re.IGNORECASE)

EXT_MAP = {
    b"image/png": ".png", b"image/jpeg": ".jpg", b"image/gif": ".gif",
    b"application/zip": ".zip", b"application/pdf": ".pdf",
    b"application/octet-stream": ".bin", b"text/html": ".html",
    b"text/plain": ".txt", b"application/json": ".json",
    b"application/javascript": ".js", b"text/javascript": ".js",
}

def unchunk(data: bytes) -> bytes:
    out = bytearray()
    off = 0
    while off < len(data):
        end = data.find(b"\r\n", off)
        if end == -1:
            break
        try:
            size = int(data[off:end], 16)
        except Exception:
            break
        if size == 0:
            break
        out += data[end+2:end+2+size]
        off = end+2+size+2
    return bytes(out)

def extract_http(stream_data: bytes, out_dir: Path, stream_id: str, count: list):
    # Extract URLs
    for m in URL_RE.finditer(stream_data):
        print(f"  [HTTP] {m.group(0).decode('latin-1', errors='replace')[:80]}")

    # Split on HTTP responses
    splits = list(HTTP_RESPONSE_RE.finditer(stream_data))
    for i, m in enumerate(splits):
        header = m.group(0)
        body_start = m.end()
        body_end = splits[i+1].start() if i+1 < len(splits) else len(stream_data)
        body = stream_data[body_start:body_end]

        ct_m = CONTENT_TYPE_RE.search(header)
        ct = ct_m.group(1).strip() if ct_m else b"application/octet-stream"
        ext = EXT_MAP.get(ct, ".bin")

        if TRANSFER_ENC_RE.search(header):
            body = unchunk(body)
        elif m2 := CONTENT_LEN_RE.search(header):
            body = body[:int(m2.group(1))]

        if body:
            fname = f"http_{stream_id}_{count[0]:03d}{ext}"
            (out_dir / fname).write_bytes(body)
            print(f"  [+] HTTP body  {len(body):,} bytes  content-type={ct.decode('latin-1','replace')}  -> {fname}")
            count[0] += 1

# ── HTTP Cookie / Request Smuggling analysis ──────────────────────────────────

COOKIE_RE       = re.compile(rb'Cookie:\s*([^\r\n]+)', re.IGNORECASE)
SET_COOKIE_RE   = re.compile(rb'Set-Cookie:\s*([^\r\n]+)', re.IGNORECASE)
HOST_RE         = re.compile(rb'Host:\s*([^\r\n]+)', re.IGNORECASE)
HTTP_REQ_RE     = re.compile(rb'(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)\s+(\S+)\s+HTTP/[\d.]+', re.IGNORECASE)

def _decode_cookie_value(val: str) -> list[tuple[str, str]]:
    """Try URL-decode, base64-decode, and hex-decode on a cookie value."""
    import base64, urllib.parse, binascii
    results = []
    # URL decode
    try:
        dec = urllib.parse.unquote(val)
        if dec != val and _is_printable_bytes(dec.encode("utf-8", "replace")):
            results.append(("URL-decoded", dec))
    except Exception:
        pass
    # Base64
    for candidate in [val, val + "=", val + "=="]:
        try:
            dec = base64.b64decode(candidate, validate=False).decode("utf-8", errors="replace")
            if _is_printable_bytes(dec.encode("utf-8", "replace")) and dec != val:
                results.append(("Base64", dec))
                break
        except Exception:
            pass
    # Hex
    cleaned = re.sub(r'[^0-9a-fA-F]', '', val)
    if len(cleaned) >= 8 and len(cleaned) % 2 == 0:
        try:
            dec = bytes.fromhex(cleaned).decode("utf-8", errors="replace")
            if _is_printable_bytes(dec.encode("utf-8", "replace")):
                results.append(("Hex", dec))
        except Exception:
            pass
    return results

def analyze_http_smuggling(streams: dict) -> list[str]:
    """
    Scan TCP streams for HTTP request smuggling and interesting cookie data.
    Returns list of finding strings.
    """
    findings = []

    for (key1, key2), stream in streams.items():
        sdata = stream.data()
        if not sdata or b"HTTP/" not in sdata:
            continue

        stream_label = f"{key1} <-> {key2}"

        # ── Smuggling indicators ──────────────────────────────────────────────
        cl_headers = CONTENT_LEN_RE.findall(sdata)
        te_headers = TRANSFER_ENC_RE.findall(sdata)

        if len(cl_headers) >= 2:
            vals = [v.decode("latin-1", "replace") for v in cl_headers]
            findings.append(
                f"[SMUGGLE?] Duplicate Content-Length headers {vals}  stream: {stream_label}"
            )

        if cl_headers and te_headers:
            findings.append(
                f"[SMUGGLE?] Both Content-Length and Transfer-Encoding: chunked present  stream: {stream_label}"
            )

        # Multiple HTTP requests in one stream (pipeline / smuggled requests)
        requests = HTTP_REQ_RE.findall(sdata)
        if len(requests) > 1:
            reqs_str = ", ".join(
                f"{m.decode('latin-1','replace')} {p.decode('latin-1','replace')}"
                for m, p in requests
            )
            findings.append(
                f"[SMUGGLE?] {len(requests)} HTTP requests in one TCP stream  [{reqs_str[:120]}]  stream: {stream_label}"
            )

        # ── Cookie analysis ───────────────────────────────────────────────────
        for m in COOKIE_RE.finditer(sdata):
            raw_cookie = m.group(1).decode("latin-1", "replace")
            for pair in raw_cookie.split(";"):
                pair = pair.strip()
                if "=" not in pair:
                    continue
                name, _, value = pair.partition("=")
                name, value = name.strip(), value.strip()
                decoded = _decode_cookie_value(value)
                for method, dec_val in decoded:
                    finding = (
                        f"[COOKIE] name={name!r}  raw={value[:60]}  "
                        f"({method})={dec_val[:120]}  stream: {stream_label}"
                    )
                    findings.append(finding)
                    # Flag check inside decoded cookie
                    for flag_m in _FLAG_CANDIDATE_RE.finditer(dec_val.encode("utf-8", "replace")):
                        if is_real_flag(flag_m.group()):
                            findings.append(
                                f"[COOKIE FLAG] {flag_m.group().decode('latin-1','replace')}  "
                                f"(via {method} of cookie {name!r})  stream: {stream_label}"
                            )

        # Set-Cookie from server
        for m in SET_COOKIE_RE.finditer(sdata):
            raw_cookie = m.group(1).decode("latin-1", "replace")
            name_val = raw_cookie.split(";")[0].strip()
            if "=" in name_val:
                name, _, value = name_val.partition("=")
                name, value = name.strip(), value.strip()
                decoded = _decode_cookie_value(value)
                for method, dec_val in decoded:
                    findings.append(
                        f"[SET-COOKIE] name={name!r}  raw={value[:60]}  "
                        f"({method})={dec_val[:120]}  stream: {stream_label}"
                    )

    return findings

# ── DNS extraction ────────────────────────────────────────────────────────────

def parse_dns_query(data: bytes) -> str | None:
    try:
        off = 12  # skip header
        labels = []
        while off < len(data):
            length = data[off]
            if length == 0:
                break
            labels.append(data[off+1:off+1+length].decode("ascii", errors="replace"))
            off += 1 + length
        return ".".join(labels)
    except Exception:
        return None

# ── decode_all integration ────────────────────────────────────────────────────

_DECODE_ALL_MOD = None

def _load_decode_all() -> object | None:
    global _DECODE_ALL_MOD
    if _DECODE_ALL_MOD is not None:
        return _DECODE_ALL_MOD
    script_dir = Path(__file__).parent
    decode_path = script_dir / "decode_all.py"
    if not decode_path.exists():
        return None
    import importlib.util
    spec = importlib.util.spec_from_file_location("decode_all", decode_path)
    mod = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(mod)
        _DECODE_ALL_MOD = mod
    except Exception:
        pass
    return _DECODE_ALL_MOD

_FLAG_PREFIXES_RE = re.compile(r'(?:flag|ctf|osc|rocsc)\{', re.IGNORECASE)

def try_decode_flag(raw_text: str) -> list[tuple[str, str]]:
    """
    Run decode_all.run_all on raw_text.
    Return [(method, decoded_text)] for any result that contains flag{/ctf{/osc{/rocsc{.
    """
    mod = _load_decode_all()
    if mod is None:
        return []
    try:
        results = mod.run_all(raw_text)
    except Exception:
        return []
    hits = []
    seen = set()
    for r in results:
        if _FLAG_PREFIXES_RE.search(r.output):
            key = r.output.strip()
            if key not in seen:
                seen.add(key)
                hits.append((r.method, r.output))
    return hits

# ── Main ──────────────────────────────────────────────────────────────────────

def guess_ext(data: bytes) -> str:
    sigs = [
        (b"\x89PNG\r\n\x1a\n", ".png"), (b"\xff\xd8\xff", ".jpg"),
        (b"GIF8", ".gif"), (b"PK\x03\x04", ".zip"), (b"%PDF-", ".pdf"),
        (b"\x1f\x8b", ".gz"), (b"BZh", ".bz2"), (b"\x7fELF", ".elf"),
        (b"BM", ".bmp"), (b"RIFF", ".wav"), (b"OggS", ".ogg"),
    ]
    for magic, ext in sigs:
        if data[:len(magic)] == magic:
            return ext
    printable = sum(1 for b in data[:64] if 0x20 <= b <= 0x7e or b in (9,10,13))
    return ".txt" if data and printable / min(64, len(data)) > 0.8 else ".bin"

def main():
    parser = argparse.ArgumentParser(
        description="Extract TCP streams and files from pcap/pcapng"
    )
    parser.add_argument("input", help="pcap or pcapng file")
    parser.add_argument("-o", "--output", default=None,
                        help="Output directory (default: <input>_streams)")
    parser.add_argument("--min-size", type=int, default=32,
                        help="Minimum stream size to save (default: 32 bytes)")
    parser.add_argument("--http", action="store_true",
                        help="Parse HTTP and extract response bodies")
    parser.add_argument("--dns", action="store_true",
                        help="Dump all DNS queries found in UDP flows")
    parser.add_argument("--search-flags", action="store_true",
                        help="Search all stream data for CTF flag patterns")
    parser.add_argument("--cookies", action="store_true",
                        help="Analyze HTTP cookies and check for request smuggling")
    args = parser.parse_args()

    in_path = Path(args.input)
    if not in_path.exists():
        print(f"[!] File not found: {in_path}")
        sys.exit(1)

    out_dir = Path(args.output) if args.output else in_path.parent / (in_path.name + "_streams")
    out_dir.mkdir(parents=True, exist_ok=True)

    data = in_path.read_bytes()
    print(f"[*] File: {in_path}  ({len(data):,} bytes)")

    # Detect format
    try:
        magic = struct.unpack_from("<I", data, 0)[0]
        if magic == PCAPNG_MAGIC:
            packets = parse_pcapng(data)
            print(f"[*] Format: pcapng  Packets: {len(packets)}")
        else:
            packets = parse_pcap(data)
            print(f"[*] Format: pcap  Packets: {len(packets)}")
    except Exception as e:
        print(f"[!] Parse error: {e}")
        sys.exit(1)

    streams, udp_flows = reassemble_streams(packets)
    print(f"[*] TCP streams: {len(streams)}  UDP flows: {len(udp_flows)}\n")

    http_count = [0]
    stream_count = 0
    flag_hits = []  # list of (source_label, raw_text, [(method, decoded)])

    # Save TCP streams
    print("[*] TCP streams:")
    for (key1, key2), stream in sorted(streams.items(), key=lambda x: -len(x[1].data())):
        sdata = stream.data()
        if len(sdata) < args.min_size:
            continue

        sid = f"{stream_count:04d}"
        ext = guess_ext(sdata)

        if args.search_flags:
            for m in _FLAG_CANDIDATE_RE.finditer(sdata):
                if is_real_flag(m.group()):
                    raw_text = m.group().decode("latin-1", "replace")
                    decoded_hits = try_decode_flag(raw_text)
                    flag_hits.append((f"TCP stream {sid}", raw_text, decoded_hits))

        if args.http and (b"HTTP/" in sdata[:8] or b"HTTP/" in sdata):
            extract_http(sdata, out_dir, sid, http_count)
        else:
            fname = f"stream_{sid}{ext}"
            (out_dir / fname).write_bytes(sdata)
            print(f"  [+] stream_{sid}  {len(sdata):,} bytes  {key1} <-> {key2}  -> {fname}")

        stream_count += 1

    # DNS queries from UDP (always collected, always fully shown)
    dns_queries = []
    for (src_ip, src_port, dst_ip, dst_port), payloads in udp_flows.items():
        if dst_port == 53 or src_port == 53:
            for payload in payloads:
                q = parse_dns_query(payload)
                if q:
                    dns_queries.append(q)
                    if args.search_flags:
                        encoded = q.encode("utf-8", "replace")
                        for m in _FLAG_CANDIDATE_RE.finditer(encoded):
                            if is_real_flag(m.group()):
                                raw_text = m.group().decode("latin-1", "replace")
                                decoded_hits = try_decode_flag(raw_text)
                                flag_hits.append(("DNS query", raw_text, decoded_hits))

    if dns_queries:
        dns_out = out_dir / "dns_queries.txt"
        dns_out.write_text("\n".join(dns_queries))
        print(f"\n[*] DNS queries ({len(dns_queries)}): -> dns_queries.txt")
        for q in dns_queries:
            print(f"  {q}")

    # Cookie / smuggling analysis
    if args.cookies:
        smug_findings = analyze_http_smuggling(streams)
        if smug_findings:
            print(f"\n{'='*60}")
            print(f"[*] HTTP COOKIE / SMUGGLING ANALYSIS ({len(smug_findings)} findings):")
            for f in smug_findings:
                print(f"  {f}")
            print('='*60)
        else:
            print("\n[*] HTTP COOKIE / SMUGGLING ANALYSIS: no notable findings.")

    # Flag search results
    if flag_hits:
        print(f"\n{'='*60}")
        print(f"[!!!] FLAG PATTERNS FOUND ({len(flag_hits)}):")
        for source, raw_flag, decoded_hits in flag_hits:
            print(f"  [{source}] {raw_flag}")
            for method, decoded in decoded_hits:
                print(f"    -> DECODED ({method}): {decoded}")
        print('='*60)

    print(f"\n[*] Done. {stream_count} stream(s) saved to {out_dir}/")

if __name__ == "__main__":
    main()
