#!/usr/bin/env python3
"""
dns_exfil_reader.py — reassemble data exfiltrated via DNS query subdomains
Reads from: pcap/pcapng, plain text file (one query per line), or stdin.
Handles common DNS exfil encodings: hex, base32, base64url, decimal, raw labels.
Auto-detects chunk ordering by sequence prefix (e.g. 01.data.evil.com).
"""

import sys
import re
import struct
import base64
import argparse
from pathlib import Path
from collections import defaultdict

FLAG_RE = re.compile(r'[A-Za-z0-9_]{2,10}\{[^}]+\}', re.IGNORECASE)

# ── DNS query extraction from pcap ───────────────────────────────────────────

PCAP_MAGIC_LE = 0xd4c3b2a1
PCAP_MAGIC_BE = 0xa1b2c3d4
PCAPNG_MAGIC  = 0x0a0d0d0a

def _pcap_packets(data: bytes) -> list[bytes]:
    magic = struct.unpack_from("<I", data, 0)[0]
    bo = "<" if magic in (PCAP_MAGIC_LE, 0x4d3cb2a1) else ">"
    off = 24
    packets = []
    while off + 16 <= len(data):
        incl_len = struct.unpack_from(bo + "I", data, off+8)[0]
        packets.append(data[off+16:off+16+incl_len])
        off += 16 + incl_len
    return packets

def _pcapng_packets(data: bytes) -> list[bytes]:
    packets = []
    off = 0
    while off + 12 <= len(data):
        block_type = struct.unpack_from("<I", data, off)[0]
        block_len  = struct.unpack_from("<I", data, off+4)[0]
        if block_len < 12 or off + block_len > len(data):
            break
        if block_type == 6:  # Enhanced Packet Block
            cap_len = struct.unpack_from("<I", data, off+20)[0]
            packets.append(data[off+28:off+28+cap_len])
        elif block_type == 3:  # Simple Packet Block
            packets.append(data[off+12:off+block_len-4])
        off += block_len
    return packets

def _parse_ethernet_to_udp(raw: bytes) -> bytes | None:
    """Strip Ethernet + IP + UDP headers, return UDP payload."""
    if len(raw) < 42:
        return None
    ethertype = struct.unpack_from(">H", raw, 12)[0]
    if ethertype == 0x8100:
        ethertype = struct.unpack_from(">H", raw, 16)[0]
        raw = raw[4:]
    if ethertype != 0x0800:
        return None
    ihl = (raw[14] & 0xf) * 4
    proto = raw[23]
    if proto != 17:  # UDP
        return None
    udp_start = 14 + ihl
    dst_port = struct.unpack_from(">H", raw, udp_start+2)[0]
    if dst_port != 53:
        return None
    return raw[udp_start+8:]  # UDP payload = DNS message

def parse_dns_name(data: bytes, off: int) -> tuple[str, int]:
    """Parse a DNS name at offset, return (name, new_offset)."""
    labels = []
    visited = set()
    while off < len(data):
        length = data[off]
        if length == 0:
            off += 1
            break
        if length & 0xc0 == 0xc0:  # compression pointer
            ptr = ((length & 0x3f) << 8) | data[off+1]
            off += 2
            if ptr not in visited:
                visited.add(ptr)
                name, _ = parse_dns_name(data, ptr)
                labels.append(name)
            break
        labels.append(data[off+1:off+1+length].decode("ascii", errors="replace"))
        off += 1 + length
    return ".".join(labels), off

def extract_dns_queries_from_pcap(data: bytes) -> list[str]:
    queries = []
    magic = struct.unpack_from("<I", data, 0)[0]
    if magic == PCAPNG_MAGIC:
        packets = _pcapng_packets(data)
    else:
        packets = _pcap_packets(data)

    for raw in packets:
        dns = _parse_ethernet_to_udp(raw)
        if dns is None or len(dns) < 12:
            continue
        flags = struct.unpack_from(">H", dns, 2)[0]
        qr = (flags >> 15) & 1
        if qr != 0:  # only queries
            continue
        qdcount = struct.unpack_from(">H", dns, 4)[0]
        off = 12
        for _ in range(qdcount):
            try:
                name, off = parse_dns_name(dns, off)
                off += 4  # qtype + qclass
                if name:
                    queries.append(name)
            except Exception:
                pass
    return queries

def extract_dns_from_text(text: str) -> list[str]:
    """Extract domain names from free-form text (log file, Wireshark export, etc.)."""
    queries = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        # Try to find domain-like patterns
        m = re.search(r'([a-zA-Z0-9._-]+\.[a-zA-Z]{2,})', line)
        if m:
            queries.append(m.group(1))
        elif re.match(r'^[a-zA-Z0-9._-]+$', line):
            queries.append(line)
    return queries

# ── Chunk decoders ────────────────────────────────────────────────────────────

def try_hex(s: str) -> bytes | None:
    c = re.sub(r'[^0-9a-fA-F]', '', s)
    if len(c) % 2 == 0 and len(c) >= 2:
        try:
            return bytes.fromhex(c)
        except Exception:
            pass
    return None

def try_base32(s: str) -> bytes | None:
    c = re.sub(r'[^A-Z2-7=]', '', s.upper())
    pad = (8 - len(c) % 8) % 8
    try:
        return base64.b32decode(c + "=" * pad, casefold=True)
    except Exception:
        return None

def try_base64url(s: str) -> bytes | None:
    c = re.sub(r'[^A-Za-z0-9_\-=]', '', s)
    try:
        return base64.urlsafe_b64decode(c + "==")
    except Exception:
        return None

def try_decimal(s: str) -> bytes | None:
    parts = re.findall(r'\d{1,3}', s)
    if not parts:
        return None
    try:
        result = bytes(int(p) for p in parts if int(p) <= 255)
        return result if result else None
    except Exception:
        return None

def decode_chunk(s: str) -> bytes | None:
    """Try all decoders, return first non-None result."""
    for fn in [try_hex, try_base32, try_base64url, try_decimal]:
        result = fn(s)
        if result:
            return result
    return s.encode("utf-8", errors="replace")

# ── Sequence number extraction ────────────────────────────────────────────────

SEQ_PREFIX_RE = re.compile(r'^(\d+)[.\-_](.+)$')

def extract_seq_and_data(label: str) -> tuple[int | None, str]:
    """Extract optional leading sequence number from a label."""
    m = SEQ_PREFIX_RE.match(label)
    if m:
        return int(m.group(1)), m.group(2)
    return None, label

# ── Domain analysis ───────────────────────────────────────────────────────────

def analyse_queries(queries: list[str], base_domain: str | None, verbose: bool) -> dict:
    """
    Group queries by base domain, extract data labels, detect encoding.
    Returns dict of {base_domain: [data_labels_in_order]}
    """
    # Count domain suffixes
    suffix_count = defaultdict(int)
    for q in queries:
        parts = q.rstrip(".").split(".")
        if len(parts) >= 2:
            suffix = ".".join(parts[-2:])
            suffix_count[suffix] += 1

    if base_domain:
        bases = [base_domain]
    else:
        # Auto-detect: most common suffix that isn't a public TLD
        common_tlds = {"com","net","org","io","gov","edu","co","uk","de","fr","ru","cn"}
        candidates = {s: c for s, c in suffix_count.items()
                      if s.split(".")[-1] not in common_tlds or c > 5}
        if not candidates:
            candidates = suffix_count
        bases = sorted(candidates, key=candidates.get, reverse=True)[:3]
        print(f"[*] Auto-detected base domains: {bases}")

    result = {}
    for base in bases:
        chunks = []
        for q in queries:
            q_clean = q.rstrip(".")
            if q_clean.endswith("." + base) or q_clean == base:
                label = q_clean[:-(len(base)+1)] if q_clean.endswith("." + base) else ""
                if label:
                    chunks.append(label)
        if chunks:
            result[base] = chunks
            if verbose:
                print(f"\n[*] Base={base}  chunks={len(chunks)}")
                for c in chunks[:5]:
                    print(f"    {c}")
                if len(chunks) > 5:
                    print(f"    ... +{len(chunks)-5} more")

    return result

# ── Reassembly ────────────────────────────────────────────────────────────────

def reassemble(chunks: list[str], encoding: str) -> bytes:
    """Sort by sequence prefix if present, then decode and concatenate."""
    sequenced = []
    unsequenced = []

    for chunk in chunks:
        # A chunk may be multi-label: "aabbcc.01.evil.com" -> we already stripped base
        # Take only the first label (leftmost subdomain component) as data
        parts = chunk.split(".")
        seq, data_part = extract_seq_and_data(parts[0])
        # Remaining labels might be more data
        data_labels = [data_part] + parts[1:]
        data_str = "".join(data_labels)

        if seq is not None:
            sequenced.append((seq, data_str))
        else:
            unsequenced.append(data_str)

    # Sort sequenced chunks
    sequenced.sort(key=lambda x: x[0])
    ordered = [d for _, d in sequenced] + unsequenced

    result = bytearray()
    for d in ordered:
        if encoding == "hex":
            dec = try_hex(d)
        elif encoding == "base32":
            dec = try_base32(d)
        elif encoding == "base64url":
            dec = try_base64url(d)
        elif encoding == "raw":
            dec = d.encode("utf-8", errors="replace")
        else:  # auto
            dec = decode_chunk(d)
        if dec:
            result.extend(dec)

    return bytes(result)

# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Reassemble data exfiltrated via DNS query subdomains"
    )
    parser.add_argument("input", help="pcap/pcapng file, text query log, or '-' for stdin")
    parser.add_argument("-b", "--base-domain", default=None,
                        help="Known base/C2 domain (e.g. 'evil.com'). Auto-detected if omitted.")
    parser.add_argument("-e", "--encoding", default="auto",
                        choices=["auto", "hex", "base32", "base64url", "raw"],
                        help="Chunk encoding (default: auto-detect)")
    parser.add_argument("-o", "--output", default=None,
                        help="Save reassembled data to file")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Show all extracted chunks")
    parser.add_argument("--list-queries", action="store_true",
                        help="Just list all DNS queries found, don't reassemble")
    args = parser.parse_args()

    # Load input
    if args.input == "-":
        text = sys.stdin.read()
        queries = extract_dns_from_text(text)
    else:
        in_path = Path(args.input)
        if not in_path.exists():
            print(f"[!] File not found: {in_path}")
            sys.exit(1)
        data = in_path.read_bytes()
        magic = struct.unpack_from("<I", data, 0)[0] if len(data) >= 4 else 0
        if magic in (PCAP_MAGIC_LE, PCAP_MAGIC_BE, 0x4d3cb2a1, 0xa1b23c4d) or magic == PCAPNG_MAGIC:
            queries = extract_dns_queries_from_pcap(data)
            print(f"[*] Parsed pcap: {len(queries)} DNS queries")
        else:
            text = data.decode("utf-8", errors="replace")
            queries = extract_dns_from_text(text)
            print(f"[*] Parsed text log: {len(queries)} queries")

    if not queries:
        print("[!] No DNS queries found.")
        sys.exit(1)

    if args.list_queries:
        for q in queries:
            print(q)
        return

    print(f"[*] Total queries: {len(queries)}")
    if args.verbose:
        for q in queries[:20]:
            print(f"  {q}")
        if len(queries) > 20:
            print(f"  ... +{len(queries)-20} more")

    # Analyse and group
    groups = analyse_queries(queries, args.base_domain, args.verbose)

    if not groups:
        print("[!] Could not group queries by base domain. Try --base-domain.")
        sys.exit(1)

    SEP = "=" * 60
    for base, chunks in groups.items():
        print(f"\n{SEP}")
        print(f"[*] Reassembling: {base}  ({len(chunks)} chunks)  encoding={args.encoding}")
        result = reassemble(chunks, args.encoding)
        print(f"[*] Reassembled: {len(result):,} bytes")

        # Try to display
        try:
            text_out = result.decode("utf-8")
            printable = True
        except Exception:
            text_out = result.decode("latin-1", errors="replace")
            printable = sum(1 for b in result if 0x20 <= b <= 0x7e) / max(len(result),1) > 0.7

        if printable:
            print(f"\n[Output]\n{text_out[:500]}{'...' if len(text_out)>500 else ''}")
        else:
            print(f"[Output] (binary data — use -o to save)")
            print(f"  hex preview: {result[:32].hex()}")

        # Flag search
        flags = FLAG_RE.findall(text_out)
        if flags:
            print(f"\n[!!!] FLAGS FOUND:")
            for f in flags:
                print(f"  >>> {f}")

        if args.output:
            out_path = Path(args.output)
            out_path.write_bytes(result)
            print(f"\n[*] Saved to {out_path}")

if __name__ == "__main__":
    main()
