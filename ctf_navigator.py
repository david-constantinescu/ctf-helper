#!/usr/bin/env python3
"""
CTF Navigator — OSC 2026 Investigation Assistant
Rule-based expert system. No AI/ML. Competition-legal.
"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import json
import os
import sys
import subprocess
import platform
from pathlib import Path
from datetime import datetime
from copy import deepcopy

try:
    from tkinterdnd2 import TkinterDnD, DND_FILES
    HAS_DND = True
except ImportError:
    HAS_DND = False

_TkBase = (TkinterDnD.Tk if HAS_DND else tk.Tk)

# ─── Theme ────────────────────────────────────────────────────────────────────
BG_ROOT   = "#f4f6fb"
BG_PANEL  = "#ffffff"
BG_HEADER = "#16213e"
FG_HEADER = "#e0e6ff"
FG_MAIN   = "#16213e"
FG_SEC    = "#5a607a"
FG_CODE   = "#1a1a2e"
BG_CODE   = "#eef0f8"
ACCENT    = "#3a5bd9"
SUCCESS   = "#1b8a3e"
FAIL_C    = "#b71c1c"
BORDER    = "#dde1ee"
BG_HIT    = "#e8f5e9"
BG_MISS   = "#fafafa"
BG_PEND   = "#ffffff"

CAT = {
    "network":   ("#dbeafe", "#1d4ed8", "Network"),
    "forensics": ("#e0f2fe", "#0369a1", "Forensics"),
    "stego":     ("#fef9c3", "#a16207", "Stego"),
    "crypto":    ("#f3e8ff", "#7e22ce", "Crypto"),
    "re":        ("#ffedd5", "#c2410c", "Rev / Pwn"),
    "web":       ("#fce7f3", "#9d174d", "Web"),
    "misc":      ("#d1fae5", "#065f46", "Misc"),
}

CONFIG_FILE  = Path.home() / ".ctf_navigator.json"
SCRIPTS_PATH = str(Path.home() / "Documents" / "useful python scripts")

def load_cfg():
    if CONFIG_FILE.exists():
        try: return json.loads(CONFIG_FILE.read_text())
        except: pass
    return {"scripts": SCRIPTS_PATH}

def save_cfg(c):
    CONFIG_FILE.write_text(json.dumps(c, indent=2))

# ─── Artifact type definitions ────────────────────────────────────────────────
ARTIFACT_TYPES = {
    "pcap":    "Network Capture (.pcap / .pcapng)",
    "image":   "Image File (.png / .jpg / .bmp / .gif)",
    "audio":   "Audio File (.wav / .mp3 / .ogg)",
    "zip":     "ZIP / Archive (.zip / .tar / .7z / .rar)",
    "elf":     "Linux Executable (ELF binary)",
    "exe":     "Windows Executable (.exe / .dll)",
    "pdf":     "PDF Document",
    "text":    "Text / Encoded String",
    "web":     "Web Application / URL",
    "docker":  "Docker Image / Container",
    "memory":  "Memory Dump (.dmp / .raw / .vmem)",
    "unknown": "Unknown / Other Binary",
}

ARTIFACT_SUBTYPES = {
    "pcap":   ["pcapng", "pcap", "cap"],
    "image":  ["PNG", "JPEG/JPG", "BMP", "GIF", "TIFF", "other"],
    "audio":  ["WAV", "MP3", "OGG", "FLAC", "other"],
    "zip":    ["ZIP", "TAR/GZ", "7z", "RAR", "multiple files in folder"],
    "elf":    ["stripped", "not stripped", "statically linked", "packed/obfuscated"],
    "exe":    ["x86", "x64", ".NET", "packed/obfuscated"],
    "pdf":    ["normal", "password-protected", "with JavaScript"],
    "text":   ["looks like base64", "looks like hex", "looks like cipher", "random garbage"],
    "web":    ["static site", "dynamic/PHP/Python", "login page", "API/REST", "admin panel"],
    "docker": ["image file (.tar)", "running container", "docker-compose"],
    "memory": ["Windows dump", "Linux dump", "unknown OS"],
    "unknown":["binary", "mixed text+binary", "all printable"],
}

# ─── Suggestion node tree ─────────────────────────────────────────────────────
# Each node: id, title, category, description, tool, command, tips, on_hit, on_miss, artifacts
NODES = {

    # ══════════ PCAP / NETWORK ════════════════════════════════════════════════

    "pcap_extract": {
        "title": "Extract & Reconstruct TCP/UDP Streams",
        "category": "network",
        "description":
            "Parse the capture file, reassemble TCP streams, and auto-extract HTTP response bodies "
            "and DNS query names. Searches all stream data for flag patterns.",
        "tool": "pcap_extractor.py",
        "command": 'python3 "{S}/pcap_extractor.py" <file.pcap> {ARGS}',
        "args": [
            {"flag": "--http",         "label": "HTTP bodies",    "default": True},
            {"flag": "--dns",          "label": "DNS queries",    "default": True},
            {"flag": "--search-flags", "label": "Search flags",   "default": True},
        ],
        "tips": [
            "Output folder: <file.pcap>_streams/",
            "HTTP bodies saved as http_*.{html,zip,png,...}",
            "DNS queries saved to dns_queries.txt",
            "Use Wireshark → Follow TCP/UDP Stream for visual inspection",
        ],
        "on_hit": ["pcap_http", "pcap_dns", "pcap_streams_analyze"],
        "on_miss": ["pcap_strings", "pcap_wireshark_filters"],
        "artifacts": ["pcap"],
    },

    "pcap_http": {
        "title": "Inspect HTTP Traffic",
        "category": "network",
        "description":
            "HTTP streams detected. Examine requests for credentials, cookies, auth tokens, and "
            "flag strings. Check response bodies for embedded files or encoded data.",
        "tool": "strings_extractor.py",
        "command": 'python3 "{S}/strings_extractor.py" <stream_file> --flags-only --offset',
        "tips": [
            "Look for 'Authorization: Bearer <jwt>' headers → try jwt_none.py",
            "Check POST body parameters for credentials",
            "Look at Set-Cookie responses",
            "Search for flag{} or ctf{ patterns in .html files",
            "In Wireshark: File → Export Objects → HTTP",
        ],
        "on_hit": ["web_jwt", "pcap_creds_found"],
        "on_miss": ["pcap_dns"],
        "artifacts": ["pcap"],
    },

    "pcap_dns": {
        "title": "Check DNS for Data Exfiltration",
        "category": "network",
        "description":
            "Unusual DNS queries may carry exfiltrated data encoded in subdomain labels "
            "(hex/base32/base64url). Reassemble chunks in sequence order.",
        "tool": "dns_exfil_reader.py",
        "command": 'python3 "{S}/dns_exfil_reader.py" <file.pcap> {ARGS}',
        "args": [
            {"flag": "-v",           "label": "Verbose",       "default": True},
            {"flag": "-e hex",       "label": "Hex encoded",   "default": False},
            {"flag": "-e base32",    "label": "Base32",        "default": False},
            {"flag": "-e base64url", "label": "Base64url",     "default": False},
        ],
        "tips": [
            "Look for many queries to the same base domain",
            "Chunks often prefixed with sequence numbers: 01.aabbcc.evil.com",
            "Try --encoding hex / base32 / base64url if auto fails",
            "In Wireshark: filter 'dns.qry.name' and sort by name",
        ],
        "on_hit": ["txt_decode"],
        "on_miss": ["pcap_strings"],
        "artifacts": ["pcap"],
    },

    "pcap_streams_analyze": {
        "title": "Analyse Raw Stream Content",
        "category": "network",
        "description":
            "Open individual stream files and check for non-HTTP protocols: FTP, SMTP, IRC, "
            "Telnet (credentials in plaintext), or custom binary protocols.",
        "tool": "strings_extractor.py + entropy_scanner.py",
        "command": 'python3 "{S}/strings_extractor.py" <stream_XXXX.bin> --flags-only\npython3 "{S}/entropy_scanner.py" <stream_XXXX.bin>',
        "tips": [
            "FTP: look for USER/PASS commands and RETR file transfers",
            "SMTP: look for base64-encoded email attachments",
            "High entropy stream → possibly encrypted → try xor_brute",
            "IRC: flag might be in channel topic or private message",
        ],
        "on_hit": ["xor_brute_file", "file_carve"],
        "on_miss": ["pcap_strings"],
        "artifacts": ["pcap"],
    },

    "pcap_strings": {
        "title": "Run Strings Search on Raw pcap",
        "category": "forensics",
        "description":
            "Sometimes the flag is embedded directly in the packet data as plaintext. "
            "Pull all printable strings and specifically search for CTF flag patterns.",
        "tool": "strings_extractor.py",
        "command": 'python3 "{S}/strings_extractor.py" <file.pcap> --flags-only --offset',
        "tips": [
            "Try -n 6 for longer minimum string length to reduce noise",
            "Also try grep -a 'CTF{\\|FLAG{\\|OSC{' <file.pcap>",
            "Check for email addresses, URLs, usernames that hint at the flag",
        ],
        "on_hit": ["txt_decode"],
        "on_miss": [],
        "artifacts": ["pcap"],
    },

    "pcap_wireshark_filters": {
        "title": "Wireshark Display Filters",
        "category": "network",
        "description":
            "Use targeted Wireshark filters to isolate relevant traffic when automated tools "
            "miss something.",
        "tool": "Wireshark (external)",
        "command": "wireshark <file.pcapng>",
        "tips": [
            "tcp contains 'flag'   — search all TCP payloads",
            "http.request.method == 'POST'   — only POST requests",
            "dns.qry.name contains 'evil'   — suspicious DNS",
            "frame contains 'CTF'   — raw frame search",
            "icmp && data.len > 0   — ICMP data exfil",
            "Ctrl+F → String search across all packets",
        ],
        "on_hit": ["pcap_streams_analyze"],
        "on_miss": [],
        "artifacts": ["pcap"],
    },

    "pcap_creds_found": {
        "title": "Credentials Found — Try Them",
        "category": "network",
        "description":
            "You found credentials in the traffic. Try them on the challenge service, "
            "or use them to decrypt other data in the capture (e.g., TLS pre-master secret).",
        "tool": "—",
        "command": "# Try credentials on the challenge endpoint",
        "tips": [
            "Username/password → try SSH, FTP, HTTP login",
            "If TLS: Wireshark → Edit → Preferences → TLS → add pre-master log",
            "If the password looks hashed → hash_identifier.py → hashcat/john",
        ],
        "on_hit": [],
        "on_miss": ["hash_id"],
        "artifacts": ["pcap"],
    },

    "pcap_stats": {
        "title": "Traffic Overview & Statistics",
        "category": "network",
        "description":
            "Get a high-level overview: protocol distribution, top talkers, conversation "
            "list. Run first to decide where to focus.",
        "tool": "tshark / capinfos (external)",
        "command": "capinfos <file.pcap>\ntshark -r <file.pcap> -q -z io,phs\ntshark -r <file.pcap> -q -z conv,tcp\ntshark -r <file.pcap> -q -z endpoints,ip",
        "tips": [
            "io,phs → protocol hierarchy: see every protocol present",
            "conv,tcp → list all TCP conversations: find heavy hitters",
            "endpoints,ip → top IP talkers: identify attacker vs victim",
            "capinfos → file-level: capture duration, packet count, link type",
            "Wireshark → Statistics → Protocol Hierarchy (GUI equivalent)",
        ],
        "on_hit": ["pcap_extract", "pcap_tls", "pcap_dns"],
        "on_miss": ["pcap_strings"],
        "artifacts": ["pcap"],
    },

    "pcap_tls": {
        "title": "TLS/SSL Traffic Analysis",
        "category": "network",
        "description":
            "Detect TLS sessions and identify cipher suites. Attempt decryption if a "
            "private key or SSLKEYLOGFILE pre-master secret log is available.",
        "tool": "tshark / Wireshark (external)",
        "command": 'tshark -r <file.pcap> -Y "tls" -T fields -e ip.src -e ip.dst -e tls.handshake.type -e tls.record.version\n# Decrypt with SSLKEYLOGFILE:\nwireshark -r <file.pcap>  # Edit → Preferences → TLS → pre-master secret log\n# Export TLS application data:\ntshark -r <file.pcap> --export-objects tls,./tls_out/',
        "args": [
            {"flag": '-Y "tls"',        "label": "TLS only",       "default": True},
            {"flag": '-Y "ssl"',        "label": "SSL only",       "default": False},
            {"flag": '-Y "tls.alert"',  "label": "Alerts",         "default": False},
            {"flag": "--export-objects tls,./tls_out/", "label": "Export data", "default": False},
        ],
        "tips": [
            "SSLKEYLOGFILE: set env var before starting browser/curl → captures session keys",
            "RSA private key → Wireshark → Edit → Preferences → TLS → RSA Keys",
            "TLS 1.3 requires key log — RSA private key alone won't decrypt DHE sessions",
            "Check certificate: tshark -r <pcap> -Y 'tls.handshake.certificate' -V",
            "Self-signed cert → export and analyze with: openssl x509 -text -noout -in cert.pem",
        ],
        "on_hit": ["pcap_http", "pcap_creds_found"],
        "on_miss": ["pcap_dns"],
        "artifacts": ["pcap"],
    },

    "pcap_icmp": {
        "title": "ICMP Covert Channel / Data Exfil",
        "category": "network",
        "description":
            "Inspect ICMP echo request/reply payloads. Tools like icmpsh and ptunnel "
            "hide full TCP sessions or data inside ICMP packets.",
        "tool": "tshark (external)",
        "command": 'tshark -r <file.pcap> -Y "icmp" -T fields -e ip.src -e ip.dst -e icmp.type -e frame.len -e data\n# Dump payloads only:\ntshark -r <file.pcap> -Y "icmp.type==8" -T fields -e data | xxd -r -p > icmp_payload.bin',
        "tips": [
            "Normal ping: 32–56 bytes payload; unusually large → suspicious",
            "Wireshark filter: icmp && data.len > 64",
            "Payload may be: plain text, base64, hex-encoded, XOR'd with a key",
            "icmpsh C2: requests = shell commands, replies = command output",
            "ptunnel: reassemble all ICMP payloads in order for full TCP session",
        ],
        "on_hit": ["txt_decode"],
        "on_miss": ["pcap_udp"],
        "artifacts": ["pcap"],
    },

    "pcap_udp": {
        "title": "UDP Stream Analysis",
        "category": "network",
        "description":
            "List UDP conversations and inspect payloads. DNS, SNMP, TFTP, NTP, and "
            "custom C2 channels all use UDP. Non-standard ports warrant closer inspection.",
        "tool": "tshark / Wireshark (external)",
        "command": 'tshark -r <file.pcap> -Y "udp" -T fields -e udp.srcport -e udp.dstport -e udp.length | sort | uniq -c | sort -rn | head -30\n# Follow a UDP stream:\ntshark -r <file.pcap> -Y "udp.stream eq 0" -T fields -e data',
        "args": [
            {"flag": "-Y \"udp.port==53\"",   "label": "DNS (53)",   "default": False},
            {"flag": "-Y \"udp.port==161\"",  "label": "SNMP (161)", "default": False},
            {"flag": "-Y \"udp.port==69\"",   "label": "TFTP (69)",  "default": False},
            {"flag": "-Y \"udp.port==123\"",  "label": "NTP (123)",  "default": False},
        ],
        "tips": [
            "TFTP (port 69) commonly used for file transfers in lab/competition scenarios",
            "SNMP communities may reveal credentials or configuration data",
            "Wireshark → Analyze → Follow UDP Stream",
            "Unknown high port UDP → dump raw payload → run strings + decode_all",
        ],
        "on_hit": ["pcap_dns", "txt_decode"],
        "on_miss": ["pcap_tcp_flags"],
        "artifacts": ["pcap"],
    },

    "pcap_ftp": {
        "title": "FTP Session Reconstruction",
        "category": "network",
        "description":
            "FTP sends credentials and file contents in cleartext. Reconstruct the "
            "control channel commands and reassemble transferred files from data channels.",
        "tool": "Wireshark / tshark (external)",
        "command": 'tshark -r <file.pcap> -Y "ftp" -T fields -e ftp.request.command -e ftp.request.arg -e ftp.response.code -e ftp.response.arg\n# Export transferred files:\nwireshark -r <file.pcap>  # File → Export Objects → FTP-DATA',
        "tips": [
            "USER / PASS in control channel = credentials in plaintext",
            "RETR <name> = downloaded file; STOR = uploaded file",
            "Active FTP: data on port 20; Passive FTP: ephemeral high port",
            "Follow the data channel TCP stream to get raw file bytes",
            "Wireshark → File → Export Objects → FTP-DATA saves all transfers at once",
        ],
        "on_hit": ["file_carve", "zip_inspect"],
        "on_miss": ["pcap_smtp"],
        "artifacts": ["pcap"],
    },

    "pcap_smtp": {
        "title": "SMTP / Email Content Extraction",
        "category": "network",
        "description":
            "Reconstruct SMTP email sessions. Flags may appear in subject/body or as "
            "base64-encoded MIME attachments.",
        "tool": "Wireshark / tshark (external)",
        "command": 'tshark -r <file.pcap> -Y "smtp" -T fields -e smtp.req.command -e smtp.req.parameter\n# Export full email messages:\nwireshark -r <file.pcap>  # File → Export Objects → IMF',
        "tips": [
            "Follow: EHLO → MAIL FROM → RCPT TO → DATA → QUIT",
            "MIME base64 attachment: starts after 'Content-Transfer-Encoding: base64'",
            "Copy the base64 block and run: base_decoder.py '<block>'",
            "Wireshark → File → Export Objects → IMF saves all messages",
            "POP3/IMAP also transmit emails — filter: pop || imap",
        ],
        "on_hit": ["txt_decode", "file_carve"],
        "on_miss": ["pcap_icmp"],
        "artifacts": ["pcap"],
    },

    "pcap_arp": {
        "title": "ARP Spoofing / MITM Detection",
        "category": "network",
        "description":
            "Detect ARP cache poisoning where an attacker maps their MAC to another host's IP, "
            "intercepting traffic. The MITM host may hold decrypted data.",
        "tool": "tshark (external)",
        "command": 'tshark -r <file.pcap> -Y "arp" -T fields -e arp.src.proto_ipv4 -e arp.src.hw_mac\n# Find IPs that claimed by more than one MAC:\ntshark -r <file.pcap> -Y "arp" -T fields -e arp.src.proto_ipv4 -e arp.src.hw_mac | sort | uniq',
        "tips": [
            "Same IP, two different MACs → ARP poisoning confirmed",
            "Wireshark alert: 'Duplicate IP address detected'",
            "After poisoning: the attacker's machine receives all victim traffic",
            "Wireshark filter: arp.duplicate-address-detected",
            "Gratuitous ARP (unsolicited who-has = is-at): can be malicious",
        ],
        "on_hit": ["pcap_http", "pcap_tls"],
        "on_miss": ["pcap_tcp_flags"],
        "artifacts": ["pcap"],
    },

    "pcap_tcp_flags": {
        "title": "TCP Flag & Sequence Anomalies",
        "category": "network",
        "description":
            "Detect port scans, data encoded in sequence numbers/urgent pointers, "
            "and covert channels using unused TCP flag bits.",
        "tool": "tshark (external)",
        "command": '# URG flag (data at urgent pointer offset):\ntshark -r <file.pcap> -Y "tcp.flags.urg==1" -T fields -e ip.src -e tcp.urgent_pointer -e data\n# SYN scan detection:\ntshark -r <file.pcap> -Y "tcp.flags.syn==1 && tcp.flags.ack==0" -T fields -e ip.dst -e tcp.dstport | sort | uniq -c | sort -rn',
        "args": [
            {"flag": '-Y "tcp.flags.urg==1"',    "label": "URG flag",   "default": True},
            {"flag": '-Y "tcp.flags.syn==1 && tcp.flags.ack==0"', "label": "SYN scan", "default": False},
            {"flag": '-Y "tcp.flags.rst==1"',    "label": "RST flood",  "default": False},
            {"flag": '-Y "tcp.flags.fin==1"',    "label": "FIN scan",   "default": False},
        ],
        "tips": [
            "URG + urgent_pointer > 0: data at that offset is 'urgent' — inspect it",
            "SYN only (no ACK) to many ports: nmap -sS style stealth scan",
            "RST storm from target: port is closed, nmap mapping the network",
            "Sequence numbers can encode data — export and check for patterns",
            "Tools: covert_tcp, ncovert hide data in IP ID or TCP seq fields",
        ],
        "on_hit": ["pcap_covert", "txt_decode"],
        "on_miss": [],
        "artifacts": ["pcap"],
    },

    "pcap_covert": {
        "title": "Covert Channel Detection",
        "category": "network",
        "description":
            "Look for data hidden in IP/TCP header fields (IP ID, TTL, seq numbers), "
            "DNS TXT records, HTTP headers, or timing-based encoding.",
        "tool": "tshark (external)",
        "command": '# IP ID as covert channel:\ntshark -r <file.pcap> -T fields -e ip.id | python3 -c "import sys; d=bytes(int(x,16)&0xff for x in sys.stdin if x.strip()); print(d[:200])"\n# DNS TXT records:\ntshark -r <file.pcap> -Y "dns.txt" -T fields -e dns.txt\n# HTTP custom headers:\ntshark -r <file.pcap> -Y "http" -T fields -e http.request.line | grep -v "standard"',
        "tips": [
            "IP ID field (16-bit) can carry 2 bytes per packet",
            "Abnormal TTL values (not 64/128/255) or non-monotonic decreases",
            "DNS TXT records are designed for arbitrary text data",
            "HTTP X-* custom headers can carry arbitrary payloads",
            "Timing: measure inter-packet gaps — unusual rhythms may encode bits",
            "Use: scapy, dpkt, or tshark -T ek (JSON) for programmatic analysis",
        ],
        "on_hit": ["txt_decode"],
        "on_miss": [],
        "artifacts": ["pcap"],
    },

    # ══════════ IMAGE / STEGO ═════════════════════════════════════════════════

    "img_meta": {
        "title": "Extract Image Metadata",
        "category": "stego",
        "description":
            "Dump EXIF data, PNG text chunks, and file comments. The flag or a hint is "
            "often hidden in metadata fields like Artist, Comment, Software, or GPS.",
        "tool": "metadata_dumper.py",
        "command": 'python3 "{S}/metadata_dumper.py" <image>',
        "tips": [
            "Also try: exiftool <image> | grep -i flag",
            "PNG tEXt chunks can hold arbitrary key-value pairs",
            "Check GPS coordinates — they might spell out a location/hint",
            "Software field may reveal the steg tool used",
        ],
        "on_hit": [],
        "on_miss": ["img_strings", "img_lsb"],
        "artifacts": ["image"],
    },

    "img_strings": {
        "title": "Extract Strings from Image Binary",
        "category": "stego",
        "description":
            "Pull all printable ASCII and UTF-16 strings from the raw image file. "
            "Flags or hints are sometimes stored as plaintext inside the binary.",
        "tool": "strings_extractor.py",
        "command": 'python3 "{S}/strings_extractor.py" <image> --flags-only --offset',
        "tips": [
            "Also try: strings -n 8 <image>",
            "Look for URLs, file paths, or commands embedded in the image",
            "Check both ASCII and UTF-16LE (-e both)",
        ],
        "on_hit": [],
        "on_miss": ["img_entropy"],
        "artifacts": ["image"],
    },

    "img_entropy": {
        "title": "Entropy Scan for Hidden Data",
        "category": "stego",
        "description":
            "Measure Shannon entropy block by block. Regions with suspiciously high entropy "
            "(>7.5 bits/byte) indicate encrypted or compressed hidden content.",
        "tool": "entropy_scanner.py",
        "command": 'python3 "{S}/entropy_scanner.py" <image> -b 256',
        "tips": [
            "Normal image data typically has entropy 6.0–7.0",
            "A single high-entropy block at the end → appended encrypted data",
            "Note the offset of suspicious regions for targeted carving",
        ],
        "on_hit": ["xor_brute_file", "img_carve"],
        "on_miss": ["img_lsb"],
        "artifacts": ["image"],
    },

    "img_lsb": {
        "title": "LSB Steganography Extraction (PNG/BMP)",
        "category": "stego",
        "description":
            "Check all bit planes (0–7) across R, G, B, A channels in row and column order "
            "for hidden LSB-encoded data. Works on PNG and BMP.",
        "tool": "lsb_extractor.py",
        "command": 'python3 "{S}/lsb_extractor.py" <image.png> {ARGS} -o lsb_out.bin',
        "args": [
            {"flag": "--all",         "label": "All combos",  "default": True},
            {"flag": "--channels R",  "label": "Red only",    "default": False},
            {"flag": "--channels G",  "label": "Green only",  "default": False},
            {"flag": "--channels B",  "label": "Blue only",   "default": False},
            {"flag": "--bit 0",       "label": "Bit 0 (LSB)", "default": False},
            {"flag": "--bit 1",       "label": "Bit 1",       "default": False},
        ],
        "tips": [
            "Most common: bit plane 0 (LSB), RGB channels, row-major order",
            "Try --channels R, then G, then B separately if --all is slow",
            "If result is binary: run file_carver.py on lsb_out.bin",
            "If result looks encoded: run decode_all.py on it",
        ],
        "on_hit": ["txt_decode", "file_carve"],
        "on_miss": ["img_steg_tools"],
        "artifacts": ["image"],
    },

    "img_carve": {
        "title": "Carve Embedded Files",
        "category": "forensics",
        "description":
            "Scan the image binary for magic signatures of other file types (ZIP, ELF, PDF, "
            "PNG-within-PNG, etc.) and extract them.",
        "tool": "file_carver.py",
        "command": 'python3 "{S}/file_carver.py" <image>',
        "tips": [
            "Common trick: ZIP appended after JPEG EOF (FF D9)",
            "A PNG inside a PNG is common in CTF stego",
            "Check carved_000_ZIP.zip if one is found — unzip it",
        ],
        "on_hit": ["zip_inspect", "txt_decode"],
        "on_miss": ["img_appended"],
        "artifacts": ["image"],
    },

    "img_appended": {
        "title": "Check for Data Appended After EOF",
        "category": "stego",
        "description":
            "Many CTF images have data appended after the official EOF marker "
            "(FF D9 for JPEG, IEND for PNG). Check what follows the end.",
        "tool": "extract_all.py",
        "command": 'python3 "{S}/extract_all.py" <image>\n# or manually:\npython3 -c "d=open(\'<image>\',\'rb\').read(); print(d[d.rfind(b\'IEND\'.....)+8:][:64].hex())"',
        "tips": [
            "JPEG: data after last FF D9 byte",
            "PNG: data after IEND chunk (4+4+4 = 12 bytes from IEND start)",
            "Even a few bytes can be a ROT/XOR key for other data",
        ],
        "on_hit": ["txt_decode", "xor_brute_file"],
        "on_miss": ["img_steg_tools"],
        "artifacts": ["image"],
    },

    "img_steg_tools": {
        "title": "Run External Steg Tools",
        "category": "stego",
        "description":
            "Try steghide (JPEG/BMP/WAV), zsteg (PNG/BMP), and outguess. "
            "Each uses different algorithms — try common passwords too.",
        "tool": "steghide / zsteg / outguess (external)",
        "command": 'steghide extract -sf <image> -p ""\nsteghide extract -sf <image> -p "password"\nzsteg -a <image.png>\noutguess -r <image> out.txt',
        "tips": [
            "Common steghide passwords: password, secret, ctf, flag, hidden, ''",
            "zsteg -a tries all bit-plane/channel combos automatically",
            "If Software=GIMP in EXIF, likely not steghide",
            "stegcracker <image> /usr/share/wordlists/rockyou.txt for brute force",
        ],
        "on_hit": ["txt_decode"],
        "on_miss": [],
        "artifacts": ["image"],
    },

    # ══════════ AUDIO ═════════════════════════════════════════════════════════

    "aud_meta": {
        "title": "Extract Audio Metadata",
        "category": "stego",
        "description":
            "Dump ID3 tags (MP3), RIFF comments (WAV), and other embedded metadata. "
            "Flags are sometimes in the Title, Comment, or Artist fields.",
        "tool": "metadata_dumper.py",
        "command": 'python3 "{S}/metadata_dumper.py" <audio>\nexiftool <audio>',
        "tips": [
            "Check all ID3 tag fields — not just title/artist",
            "WAV RIFF INFO chunks: INAM, ICMT, ISFT, IART",
            "Cover art embedded in MP3 → extract and analyze as image",
        ],
        "on_hit": [],
        "on_miss": ["aud_lsb"],
        "artifacts": ["audio"],
    },

    "aud_lsb": {
        "title": "WAV LSB Steganography Extraction",
        "category": "stego",
        "description":
            "Extract hidden data encoded in the least-significant bits of WAV PCM samples. "
            "Tries all channel/bit-plane/packing combinations.",
        "tool": "wav_lsb.py",
        "command": 'python3 "{S}/wav_lsb.py" <audio.wav> {ARGS} -o extracted.bin',
        "args": [
            {"flag": "--all",        "label": "All combos",    "default": True},
            {"flag": "--bit 0",      "label": "Bit 0 (LSB)",   "default": False},
            {"flag": "--bit 1",      "label": "Bit 1",         "default": False},
            {"flag": "--channels 0", "label": "Left channel",  "default": False},
            {"flag": "--channels 1", "label": "Right channel", "default": False},
        ],
        "tips": [
            "Most common encoding: bit 0, all channels, MSB-first packing",
            "A 44100 Hz stereo WAV can hide ~11 KB per second at 1 bps",
            "If extracted looks encoded, run decode_all.py on it",
        ],
        "on_hit": ["txt_decode", "file_carve"],
        "on_miss": ["aud_spectrum"],
        "artifacts": ["audio"],
    },

    "aud_spectrum": {
        "title": "Visual Spectrogram Analysis",
        "category": "stego",
        "description":
            "Open the audio in Audacity or Sonic Visualiser and look at the spectrogram view. "
            "Text, QR codes, or images are sometimes drawn in the frequency domain.",
        "tool": "Audacity (external)",
        "command": "audacity <audio>",
        "tips": [
            "Audacity: View → Spectrogram (right-click track label)",
            "Set window size to 512 or 1024, linear scale",
            "Look at both channels independently",
            "Use SonicVisualiser for higher resolution spectrograms",
            "Also try: sox <audio.wav> -n stat  — check for unusual sample values",
        ],
        "on_hit": [],
        "on_miss": ["aud_strings"],
        "artifacts": ["audio"],
    },

    "aud_strings": {
        "title": "Strings from Audio Binary",
        "category": "stego",
        "description":
            "Pull printable strings from the raw audio file — sometimes a flag or encoded "
            "payload is simply concatenated to the file.",
        "tool": "strings_extractor.py",
        "command": 'python3 "{S}/strings_extractor.py" <audio> --flags-only',
        "tips": [
            "Also check for appended data after audio EOF",
            "MP3 may have multiple ID3v2 tags — check each one",
        ],
        "on_hit": [],
        "on_miss": [],
        "artifacts": ["audio"],
    },

    # ══════════ ZIP / ARCHIVE ═════════════════════════════════════════════════

    "zip_inspect": {
        "title": "Inspect Archive Contents",
        "category": "forensics",
        "description":
            "List all files, check for ZIP comment, check encryption, and look for unusual "
            "file names (null bytes, path traversal, hidden files).",
        "tool": "metadata_dumper.py",
        "command": 'python3 "{S}/metadata_dumper.py" <archive.zip>\nunzip -l <archive.zip>\nunzip -v <archive.zip>',
        "tips": [
            "ZIP comment (-z flag in zipinfo) often contains hints",
            "Look for files named . or .. or with null bytes",
            "If all files are 0 bytes but archive is large → data is in the comment or extra fields",
            "7z l -slt <archive.zip>  — shows all extra fields and comments",
        ],
        "on_hit": ["zip_crack", "zip_contained"],
        "on_miss": ["zip_crack", "zip_contained"],
        "artifacts": ["zip"],
    },

    "zip_crack": {
        "title": "Crack ZIP Password",
        "category": "crypto",
        "description":
            "If the archive is password-protected, try common CTF passwords then wordlist attack. "
            "ZipCrypto (old) is vulnerable to known-plaintext attacks.",
        "tool": "john / hashcat / zip2john (external)",
        "command": 'zip2john <archive.zip> > hash.txt\njohn hash.txt --wordlist=/usr/share/wordlists/rockyou.txt\n# or: hashcat -m 13600 hash.txt rockyou.txt',
        "tips": [
            "Try: password, 1234, ctf, flag, secret, admin, 12345678",
            "If you have one plaintext file → pkcrack or bkcrack for known-plaintext",
            "bkcrack -C <enc.zip> -c <known_file> -p <plaintext_version>",
            "Check challenge description — password is often hinted there",
        ],
        "on_hit": ["zip_contained"],
        "on_miss": ["zip_carve"],
        "artifacts": ["zip"],
    },

    "zip_contained": {
        "title": "Analyse Extracted Files",
        "category": "forensics",
        "description":
            "Extract and analyse each file inside the archive. Identify their types and "
            "apply the appropriate analysis path to each one.",
        "tool": "file_carver.py / extract_all.py",
        "command": 'unzip <archive.zip> -d ./extracted/\nfor f in ./extracted/*; do file "$f"; done\npython3 "{S}/extract_all.py" <suspicious_file>',
        "tips": [
            "Run `file` on every extracted file — extensions can be misleading",
            "A .txt file might actually be base64-encoded binary",
            "Nested ZIPs within ZIPs are common",
            "Check each file with strings_extractor.py for flag patterns",
        ],
        "on_hit": ["txt_decode", "img_meta", "elf_strings"],
        "on_miss": [],
        "artifacts": ["zip"],
    },

    "zip_carve": {
        "title": "Carve the Archive Binary",
        "category": "forensics",
        "description":
            "Run magic-signature carving on the archive binary itself to find files "
            "concatenated before or after it, or embedded inside.",
        "tool": "file_carver.py",
        "command": 'python3 "{S}/file_carver.py" <archive.zip>',
        "tips": [
            "A second ZIP at the end of a ZIP is a common trick",
            "Polyglot files (ZIP that is also a valid JPEG) are common",
            "Check with: hexdump -C <archive.zip> | tail -20",
        ],
        "on_hit": ["zip_inspect"],
        "on_miss": [],
        "artifacts": ["zip"],
    },

    # ══════════ ELF / LINUX BINARY ════════════════════════════════════════════

    "elf_strings": {
        "title": "Extract Strings from Binary",
        "category": "re",
        "description":
            "Pull all printable strings. Often reveals hardcoded flags, passwords, "
            "format strings, system calls, and internal logic clues.",
        "tool": "strings_extractor.py",
        "command": 'python3 "{S}/strings_extractor.py" <binary> --flags-only --offset\n# also:\nstrings -n 8 <binary> | grep -iE "flag|ctf|osc|key|pass|secret"',
        "tips": [
            "strings -el <binary>  — also check UTF-16LE (Windows paths etc.)",
            "Interesting: format strings (%s, %d), file paths, URLs, error messages",
            "Look for base64-looking strings → run base_decoder.py on them",
            "If nothing found: binary might be packed — check entropy next",
        ],
        "on_hit": ["txt_decode"],
        "on_miss": ["elf_entropy"],
        "artifacts": ["elf"],
    },

    "elf_entropy": {
        "title": "Entropy Scan for Packing/Obfuscation",
        "category": "re",
        "description":
            "High average entropy (>7 bits/byte) across .text section indicates packing "
            "(UPX, custom). Unpack first before deeper analysis.",
        "tool": "entropy_scanner.py",
        "command": 'python3 "{S}/entropy_scanner.py" <binary> -b 512',
        "tips": [
            "UPX packed: upx -d <binary> -o unpacked",
            "Check: file <binary>  — may say 'packed with UPX'",
            "If custom packer: trace with ltrace/strace to find unpack routine",
            "High entropy .data section → encrypted strings, XOR'd constants",
        ],
        "on_hit": ["elf_unpack"],
        "on_miss": ["elf_sections"],
        "artifacts": ["elf"],
    },

    "elf_unpack": {
        "title": "Unpack / Deobfuscate Binary",
        "category": "re",
        "description":
            "The binary appears packed. Attempt automatic unpacking with UPX, then "
            "re-analyse the unpacked version.",
        "tool": "UPX (external)",
        "command": "upx -d <binary> -o <binary>_unpacked\nfile <binary>_unpacked",
        "tips": [
            "If upx -d fails: try upx-unpack, unipacker, or VMProtect unpacker",
            "Run the binary under strace -e trace=all to see what it does",
            "GDB: set a breakpoint after OEP (original entry point) — memory will be decrypted",
        ],
        "on_hit": ["elf_strings", "elf_sections"],
        "on_miss": ["elf_debug"],
        "artifacts": ["elf"],
    },

    "elf_sections": {
        "title": "Examine ELF Sections",
        "category": "re",
        "description":
            "Extract each ELF section and look for unusual ones. Non-standard section names, "
            "a .secret, .flag, or data-only sections often hide the answer.",
        "tool": "file_carver.py + readelf",
        "command": 'python3 "{S}/file_carver.py" <binary>\nreadelf -S <binary>\nobjdump -s -j .rodata <binary>',
        "tips": [
            "readelf -p .rodata <binary>  — dump read-only data as strings",
            "objdump -d <binary>  — disassemble .text",
            "Look for sections named .secret, .data1, .hidden, .flag",
            "nm <binary>  — list symbols (if not stripped)",
        ],
        "on_hit": ["txt_decode"],
        "on_miss": ["elf_debug"],
        "artifacts": ["elf"],
    },

    "elf_debug": {
        "title": "Dynamic Analysis / Debugging",
        "category": "re",
        "description":
            "Run the binary under ltrace/strace to see system calls and library calls. "
            "Use GDB+GEF or pwndbg for interactive debugging.",
        "tool": "GDB / ltrace / strace (external)",
        "command": 'ltrace ./<binary>\nstrace ./<binary>\ngdb ./<binary>  # then: run, bt, info regs',
        "tips": [
            "ltrace shows strcmp() calls → you see what password is expected",
            "strace shows open()/read()/write() → see what files it accesses",
            "GDB: b *main → r → ni/si to step, x/s $rdi to dump strings",
            "Set LD_PRELOAD to hook functions without recompiling",
            "Angr/Z3 for constraint solving if input validation is complex",
        ],
        "on_hit": [],
        "on_miss": ["elf_ghidra"],
        "artifacts": ["elf"],
    },

    "elf_ghidra": {
        "title": "Static Reverse Engineering",
        "category": "re",
        "description":
            "Load the binary in Ghidra or IDA Free for full decompilation. Look for the "
            "flag validation routine, hardcoded keys, or XOR decryption loops.",
        "tool": "Ghidra / IDA Free (external)",
        "command": "ghidra  # then: File → New Project → Import File",
        "tips": [
            "Search for string references: right-click → References → Show References",
            "Look for functions called 'check', 'validate', 'verify', 'strcmp'",
            "XOR decryption loop: look for xor instructions with a constant key",
            "Ghidra Script: SearchText for 'flag' in .rodata",
            "radare2: aaa → afl → pdf @ main",
        ],
        "on_hit": [],
        "on_miss": [],
        "artifacts": ["elf"],
    },

    # ══════════ WINDOWS EXECUTABLE ════════════════════════════════════════════

    "exe_strings": {
        "title": "Extract Strings from PE Binary",
        "category": "re",
        "description":
            "Pull printable strings from the .exe/.dll. Check for .NET assemblies "
            "(use dnSpy/ILSpy), or native PE (use x64dbg/Ghidra).",
        "tool": "strings_extractor.py",
        "command": 'python3 "{S}/strings_extractor.py" <binary.exe> --flags-only --offset',
        "tips": [
            "file <binary.exe>  — check if it's a .NET assembly",
            ".NET → use dnSpy or ILSpy for full decompilation (C# source)",
            "Packed PE → check with die (Detect It Easy) tool",
            "Resources may contain encrypted strings → use Resource Hacker",
        ],
        "on_hit": ["txt_decode"],
        "on_miss": ["exe_entropy"],
        "artifacts": ["exe"],
    },

    "exe_entropy": {
        "title": "Check PE for Packing",
        "category": "re",
        "description":
            "Scan PE sections for high entropy. Packed executables hide their real "
            "code in a compressed/encrypted blob.",
        "tool": "entropy_scanner.py",
        "command": 'python3 "{S}/entropy_scanner.py" <binary.exe>\ndie <binary.exe>  # Detect It Easy',
        "tips": [
            "die (Detect It Easy): identifies UPX, ASPack, Themida, etc.",
            "UPX: upx -d <binary.exe> -o unpacked.exe",
            "Run in a VM with Process Monitor/Hacker to catch runtime unpacking",
        ],
        "on_hit": ["elf_ghidra"],
        "on_miss": ["exe_debug"],
        "artifacts": ["exe"],
    },

    "exe_debug": {
        "title": "Debug PE with x64dbg / OllyDbg",
        "category": "re",
        "description":
            "Run the PE under a Windows debugger (or Wine) to trace execution, "
            "inspect memory, and intercept function calls at runtime.",
        "tool": "x64dbg / Wine (external)",
        "command": "wine <binary.exe>\n# or in Windows: x64dbg → File → Open",
        "tips": [
            "Set breakpoints on strcmp, MessageBox, GetWindowText to catch comparisons",
            "x64dbg: right-click → Search → All Modules → String References",
            "If .NET: use dnSpy debugger directly",
        ],
        "on_hit": [],
        "on_miss": [],
        "artifacts": ["exe"],
    },

    # ══════════ PDF ═══════════════════════════════════════════════════════════

    "pdf_meta": {
        "title": "Extract PDF Metadata & Structure",
        "category": "forensics",
        "description":
            "Dump PDF metadata (author, creator, creation date) and inspect the document "
            "structure for hidden layers, white-on-white text, or comments.",
        "tool": "metadata_dumper.py",
        "command": 'python3 "{S}/metadata_dumper.py" <doc.pdf>\nexiftool <doc.pdf>\npdfinfo <doc.pdf>',
        "tips": [
            "Select-all in PDF viewer — white text on white background becomes visible",
            "Check all layers: Adobe → View → Navigation Panels → Layers",
            "PDF stream count indicates complexity — more streams = more hiding spots",
            "Metadata fields can contain base64-encoded flags",
        ],
        "on_hit": [],
        "on_miss": ["pdf_strings"],
        "artifacts": ["pdf"],
    },

    "pdf_strings": {
        "title": "Extract Strings from PDF Binary",
        "category": "forensics",
        "description":
            "Pull all printable strings from the PDF binary, including embedded JavaScript, "
            "form fields, annotations, and encoded stream data.",
        "tool": "strings_extractor.py",
        "command": 'python3 "{S}/strings_extractor.py" <doc.pdf> --flags-only',
        "tips": [
            "Search for /JS or /JavaScript — embedded scripts may hold the flag",
            "Form field values: /V (Value) entries in AcroForm",
            "Annotation /Contents fields — invisible comments",
        ],
        "on_hit": ["txt_decode"],
        "on_miss": ["pdf_streams"],
        "artifacts": ["pdf"],
    },

    "pdf_streams": {
        "title": "Extract & Decompress PDF Streams",
        "category": "forensics",
        "description":
            "PDF streams (images, fonts, embedded files) are often FlateDecode compressed. "
            "Extract and inspect each one for hidden content.",
        "tool": "extract_all.py",
        "command": 'python3 "{S}/extract_all.py" <doc.pdf>\n# or: pdfextract / pdf-parser.py',
        "tips": [
            "pdf-parser.py --stats <doc.pdf>  — overview of all objects",
            "pdf-parser.py --object <N> --filter <doc.pdf>  — dump one stream",
            "Embedded file streams: /EmbeddedFile type → extract with pdfdetach",
            "peepdf is excellent for interactive PDF analysis",
        ],
        "on_hit": ["file_carve", "txt_decode"],
        "on_miss": [],
        "artifacts": ["pdf"],
    },

    # ══════════ TEXT / ENCODED STRING ═════════════════════════════════════════

    "txt_decode": {
        "title": "Auto-Decode: Try All Methods",
        "category": "crypto",
        "description":
            "Run the universal decoder on the string/data. Tries ROT-N, Base16/32/58/64/85, "
            "XOR, Atbash, Morse, hex, binary, URL decode — all at once, ranked by readability.",
        "tool": "decode_all.py",
        "command": 'python3 "{S}/decode_all.py" "<encoded_string>" {ARGS}',
        "args": [
            {"flag": "--search",     "label": "Search CTF/OSC", "default": True},
            {"flag": "--all",        "label": "Show all",       "default": False},
            {"flag": "--top 5",      "label": "Top 5 only",     "default": False},
            {"flag": "--flags-only", "label": "Flags only",     "default": False},
        ],
        "tips": [
            "Use --top 5 to see only the best-scoring results",
            "If flag structure PREFIX{...} detected, prefix and content are attacked separately",
            "--search flag highlights any output containing ctf/osc/rocsc",
            "For files: python3 decode_all.py -f <file>",
        ],
        "on_hit": [],
        "on_miss": ["txt_base", "txt_xor"],
        "artifacts": ["text", "pcap", "image", "zip", "pdf", "unknown"],
    },

    "txt_base": {
        "title": "Base Encoding Detection & Decode",
        "category": "crypto",
        "description":
            "Specifically detect and decode Base16/32/58/62/64/85 encodings. "
            "Auto-detects charset and tries all variants (URL-safe, padded, double).",
        "tool": "base_decoder.py",
        "command": 'python3 "{S}/base_decoder.py" "<encoded_string>"',
        "tips": [
            "Pure hex (0-9a-f, even length) → likely Base16",
            "Uppercase + 2-7 only → Base32",
            "Mixed case alphanumeric + +/ or _- → Base64",
            "No 0/O/I/l characters → likely Base58",
            "Use --raw to pipe raw bytes to another tool",
        ],
        "on_hit": ["txt_decode"],
        "on_miss": ["txt_rot"],
        "artifacts": ["text"],
    },

    "txt_rot": {
        "title": "ROT-N Brute Force",
        "category": "crypto",
        "description":
            "Try all 25 ROT shifts plus ROT-47 (printable ASCII). Scores each "
            "by English letter frequency and highlights flag patterns.",
        "tool": "brute_rot.py",
        "command": 'python3 "{S}/brute_rot.py" "<ciphertext>"',
        "tips": [
            "ROT-13 is by far the most common in CTF",
            "If it looks like a flag but with shifted prefix: MZX{...} = ROT-N of CTF{...}",
            "ROT-47 works on all printable ASCII — try if ROT-13 fails",
        ],
        "on_hit": [],
        "on_miss": ["txt_xor"],
        "artifacts": ["text"],
    },

    "txt_xor": {
        "title": "XOR Brute Force",
        "category": "crypto",
        "description":
            "Brute-force single-byte XOR key (0x00–0xFF). For multi-byte: auto-detect "
            "key length via Index of Coincidence, then crack each position independently.",
        "tool": "xor_brute.py",
        "command": 'python3 "{S}/xor_brute.py" <file_or_binary> {ARGS}',
        "args": [
            {"flag": "--single",       "label": "Single-byte",   "default": True},
            {"flag": "--max-keylen 8", "label": "Multi-byte ≤8", "default": False},
            {"flag": "--max-keylen 16","label": "Multi-byte ≤16","default": False},
            {"flag": "--top 10",       "label": "Top 10 results","default": False},
        ],
        "tips": [
            "Single-byte XOR is extremely common in CTF",
            "If the key is printable ASCII (e.g. 'key') → multi-byte mode",
            "XOR with itself = 0, so null bytes in plaintext reveal key bytes",
            "Known-plaintext: if you know part of the flag (e.g. 'CTF{'), XOR with ciphertext",
        ],
        "on_hit": [],
        "on_miss": ["txt_freq"],
        "artifacts": ["text"],
    },

    "txt_freq": {
        "title": "Letter Frequency Analysis",
        "category": "crypto",
        "description":
            "Analyse letter frequencies and compare to English. High IoC → monoalphabetic "
            "substitution. Low IoC → polyalphabetic (Vigenere). Suggests mapping automatically.",
        "tool": "freq_analysis.py",
        "command": 'python3 "{S}/freq_analysis.py" "<ciphertext>" --digraphs --ioc\n# Then apply suggested key:\npython3 "{S}/freq_analysis.py" "<ciphertext>" --key "A=E,B=T,..."',
        "tips": [
            "IoC ≈ 0.065 → likely substitution cipher",
            "IoC ≈ 0.038 → likely Vigenere/polyalphabetic",
            "Most frequent cipher letter → usually maps to 'E' in English",
            "Common digraphs: TH, HE, IN, ER, AN, RE, ON",
        ],
        "on_hit": [],
        "on_miss": ["txt_vigenere"],
        "artifacts": ["text"],
    },

    "txt_vigenere": {
        "title": "Crack Vigenere Cipher",
        "category": "crypto",
        "description":
            "Automatically determine the key length using Kasiski examination and Index of "
            "Coincidence, then recover the key via per-column frequency analysis.",
        "tool": "vigenere_crack.py",
        "command": 'python3 "{S}/vigenere_crack.py" "<ciphertext>" --max-keylen 20 --try-all',
        "tips": [
            "Works best with ciphertext > 100 characters",
            "If you know part of the plaintext → use --key if you already found it",
            "Very short keys (1–3): simple Caesar — try brute_rot.py first",
        ],
        "on_hit": [],
        "on_miss": [],
        "artifacts": ["text"],
    },

    # ══════════ WEB APPLICATION ═══════════════════════════════════════════════

    "web_recon": {
        "title": "Directory & Endpoint Discovery",
        "category": "web",
        "description":
            "Enumerate hidden directories, files, and endpoints. Check robots.txt, sitemap.xml, "
            ".git exposure, backup files, and admin panels.",
        "tool": "gobuster / dirb / ffuf (external)",
        "command": 'gobuster dir -u <url> -w /usr/share/wordlists/dirb/common.txt\nffuf -u <url>/FUZZ -w /usr/share/wordlists/dirb/big.txt\ncurl <url>/robots.txt\ncurl <url>/.git/HEAD',
        "tips": [
            "Always check robots.txt and sitemap.xml first",
            "Look for .bak, .old, .txt, .php~, .swp backup files",
            "/.git/ exposed → git-dumper to clone the source code",
            "Admin panels: /admin, /panel, /dashboard, /phpmyadmin",
            "Nikto for quick vuln scan: nikto -h <url>",
        ],
        "on_hit": ["web_source", "web_sqli", "web_lfi"],
        "on_miss": ["web_source"],
        "artifacts": ["web"],
    },

    "web_source": {
        "title": "Inspect Page Source & JS",
        "category": "web",
        "description":
            "View page source for HTML comments, hidden form fields, and inline JavaScript. "
            "Flags, credentials, and API endpoints are often left in comments.",
        "tool": "browser (Ctrl+U) / curl",
        "command": 'curl -s <url> | grep -i "flag\\|ctf\\|todo\\|fixme\\|password\\|secret"\ncurl -s <url> | python3 -c "import sys,html; print(html.unescape(sys.stdin.read()))"',
        "tips": [
            "Ctrl+U in browser → page source. Ctrl+Shift+I → DevTools",
            "Check JS files linked in <script src=...>",
            "Look for <!-- comments --> throughout the HTML",
            "JS sourcemaps (.js.map) may expose original source code",
            "Check localStorage / sessionStorage in browser console",
        ],
        "on_hit": ["web_jwt", "web_cookies"],
        "on_miss": ["web_sqli"],
        "artifacts": ["web"],
    },

    "web_cookies": {
        "title": "Analyse Cookies & Session Tokens",
        "category": "web",
        "description":
            "Inspect cookies for JWT tokens, base64-encoded data, or serialized objects. "
            "Tamper with session values to escalate privileges.",
        "tool": "jwt_none.py + decode_all.py",
        "command": 'python3 "{S}/jwt_none.py" "<cookie_value>"\npython3 "{S}/decode_all.py" "<cookie_value>"',
        "tips": [
            "JWT (three base64 parts separated by dots) → try jwt_none.py first",
            "base64-decoded cookie may be a Python pickle → deserialisation RCE",
            "PHP serialized: O:4:\"User\":... → look for object injection",
            "Flask session cookies: flask-unsign to decode/brute/forge",
        ],
        "on_hit": ["web_jwt"],
        "on_miss": ["web_sqli"],
        "artifacts": ["web"],
    },

    "web_jwt": {
        "title": "JWT Vulnerability Testing",
        "category": "web",
        "description":
            "Test JWTs for alg:none bypass, RS256→HS256 confusion, and weak HMAC secrets. "
            "Forge tokens with modified claims (role=admin, admin=true).",
        "tool": "jwt_none.py",
        "command": 'python3 "{S}/jwt_none.py" "<jwt>" --alg-none --set "role=admin"\npython3 "{S}/jwt_none.py" "<jwt>" --brute --wordlist /usr/share/wordlists/rockyou.txt',
        "tips": [
            "Most common CTF attack: alg:none with modified payload",
            "Try --set 'admin=true', --set 'role=admin', --set 'isAdmin=1'",
            "Check JWT contents first: payload shows what claims to modify",
            "Weak secrets: secret, password, ctf, jwt, key, 1234567890",
        ],
        "on_hit": [],
        "on_miss": ["web_sqli"],
        "artifacts": ["web"],
    },

    "web_sqli": {
        "title": "SQL Injection Testing",
        "category": "web",
        "description":
            "Test all input parameters for SQL injection. Try manual payloads first, "
            "then automated testing with sqlmap.",
        "tool": "sqlmap (external)",
        "command": "sqlmap -u '<url>?id=1' --dbs --batch\nsqlmap -u '<url>' --data 'user=admin&pass=1' --dbs\n# manual: ' OR '1'='1\n# error-based: ' AND 1=CONVERT(int,@@version)--",
        "tips": [
            "Start with: ' OR 1=1-- and ' OR '1'='1",
            "If you get different responses → vulnerable, use sqlmap",
            "sqlmap -u <url> --forms --dbs --batch  — auto-detect forms",
            "Check for blind SQLi: time-based ' OR SLEEP(5)--",
            "SQLite: SELECT name FROM sqlite_master WHERE type='table'",
        ],
        "on_hit": [],
        "on_miss": ["web_lfi"],
        "artifacts": ["web"],
    },

    "web_lfi": {
        "title": "LFI / Path Traversal",
        "category": "web",
        "description":
            "Test for Local File Inclusion and path traversal vulnerabilities. "
            "Read /etc/passwd, flag.txt, or source files via the exploit.",
        "tool": "curl / Burp Suite",
        "command": "curl '<url>?page=../../etc/passwd'\ncurl '<url>?file=....//....//etc/passwd'\ncurl '<url>?page=php://filter/convert.base64-encode/resource=index.php'",
        "tips": [
            "Try: ../../../../etc/passwd with varying depths (1-8 ../ segments)",
            "URL-encoded: %2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            "php://filter/read=convert.base64-encode/resource=<file> → get PHP source",
            "Look for flag in /flag, /flag.txt, /var/www/html/flag, /home/*/flag",
            "Log poisoning if you can read Apache/Nginx logs",
        ],
        "on_hit": [],
        "on_miss": ["web_padding"],
        "artifacts": ["web"],
    },

    "web_padding": {
        "title": "CBC Padding Oracle Attack",
        "category": "crypto",
        "description":
            "If the app decrypts user-supplied ciphertext and returns different errors for "
            "bad padding vs. bad data, a padding oracle attack can decrypt the ciphertext "
            "and forge arbitrary plaintexts.",
        "tool": "padding_oracle.py",
        "command": 'python3 "{S}/padding_oracle.py" \\\n  --url "http://target/decrypt?ct=CIPHERTEXT" \\\n  --ciphertext <hex_or_b64> \\\n  --error-string "Invalid padding"\n# Forge:\npython3 "{S}/padding_oracle.py" ... --forge "admin=true;role=admin"',
        "tips": [
            "Need: endpoint that decrypts controlled data + distinguishable padding error",
            "Two different HTTP status codes = sufficient oracle",
            "Slower = more padding per request check",
            "padbuster tool is also popular for this attack",
        ],
        "on_hit": [],
        "on_miss": [],
        "artifacts": ["web"],
    },

    # ══════════ DOCKER / CONTAINER ════════════════════════════════════════════

    "docker_inspect": {
        "title": "Inspect Docker Image",
        "category": "misc",
        "description":
            "Inspect image configuration, entrypoint, exposed ports, volumes, and all "
            "layer metadata. Build history often reveals secrets added then 'deleted'.",
        "tool": "docker (external)",
        "command": "docker inspect <image>\ndocker history --no-trunc <image>\ndive <image>  # interactive layer explorer",
        "tips": [
            "'docker history' shows every RUN command — secrets added and removed still exist in layers",
            "Environment variables: docker inspect <c> | grep -i env",
            "Exposed ports hint at what services are running",
            "dive tool: interactive layer-by-layer filesystem diff",
        ],
        "on_hit": ["docker_extract"],
        "on_miss": ["docker_env"],
        "artifacts": ["docker"],
    },

    "docker_env": {
        "title": "Check Environment Variables",
        "category": "misc",
        "description":
            "Environment variables in Docker often contain API keys, passwords, flags, "
            "or database connection strings.",
        "tool": "docker (external)",
        "command": 'docker run --rm <image> env\ndocker inspect <container> | python3 -c "import json,sys; c=json.load(sys.stdin); print(c[0][\'Config\'][\'Env\'])"',
        "tips": [
            "Also check /etc/environment and /etc/profile inside the container",
            "Check .env files: docker run <image> cat /app/.env",
            "AWS credentials: ~/.aws/credentials, AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY",
        ],
        "on_hit": [],
        "on_miss": ["docker_extract"],
        "artifacts": ["docker"],
    },

    "docker_extract": {
        "title": "Extract & Search Container Filesystem",
        "category": "misc",
        "description":
            "Export the full container filesystem as a tar and search for flags, "
            "credentials, config files, and secrets across all layers.",
        "tool": "docker save / tar",
        "command": 'docker save <image> -o image.tar\nmkdir -p layers && tar xf image.tar -C layers\n# Search all layers:\nfind layers/ -name "*.tar" -exec tar tf {} \\;\ngrep -r "flag\\|CTF\\|secret\\|password" layers/ 2>/dev/null',
        "tips": [
            "Each layer is a tar inside the image tar — extract all of them",
            "Deleted files still exist in earlier layers",
            "Look in: /root/, /home/*, /var/www/, /opt/, /srv/, /tmp/",
            "Check git repos inside the image: git log --all --oneline",
        ],
        "on_hit": ["elf_strings", "txt_decode"],
        "on_miss": [],
        "artifacts": ["docker"],
    },

    # ══════════ MEMORY DUMP ═══════════════════════════════════════════════════

    "mem_strings": {
        "title": "Extract Strings from Memory Dump",
        "category": "forensics",
        "description":
            "Pull all printable strings from the dump. Memory often contains plaintext "
            "passwords, encryption keys, decrypted data, and processes' command lines.",
        "tool": "strings_extractor.py",
        "command": 'python3 "{S}/strings_extractor.py" <dump.raw> --flags-only --offset\nstrings -n 8 <dump.raw> | grep -iE "flag|ctf|osc|password|key"',
        "tips": [
            "Also: strings -el <dump.raw>  — UTF-16LE (Windows process memory)",
            "Look for process names, command-line arguments, file paths",
            "Browser process memory may contain session cookies in plaintext",
        ],
        "on_hit": [],
        "on_miss": ["mem_volatility"],
        "artifacts": ["memory"],
    },

    "mem_volatility": {
        "title": "Analyse with Volatility",
        "category": "forensics",
        "description":
            "Use Volatility to list processes, network connections, loaded DLLs, "
            "command history, clipboard, and registry hives from the memory dump.",
        "tool": "Volatility 3 (external)",
        "command": "python3 vol.py -f <dump.raw> windows.pslist\npython3 vol.py -f <dump.raw> windows.cmdline\npython3 vol.py -f <dump.raw> windows.hashdump\npython3 vol.py -f <dump.raw> linux.bash",
        "tips": [
            "First: determine profile — vol.py -f dump imageinfo  (vol2)",
            "windows.filescan → find files; windows.dumpfiles to extract",
            "windows.clipboard → clipboard content at time of dump",
            "linux.bash → bash history; linux.psaux → process command lines",
            "windows.truecrypt → TrueCrypt volumes; mimikatz for credentials",
        ],
        "on_hit": ["txt_decode", "hash_id"],
        "on_miss": ["mem_carve"],
        "artifacts": ["memory"],
    },

    "mem_carve": {
        "title": "Carve Files from Memory Dump",
        "category": "forensics",
        "description":
            "Scan the memory dump for file magic signatures and carve out complete files "
            "(JPEGs, ZIPs, PDFs, ELFs) that were in memory at capture time.",
        "tool": "file_carver.py",
        "command": 'python3 "{S}/file_carver.py" <dump.raw> --min-size 128',
        "tips": [
            "Carve with larger block size for speed on large dumps",
            "Files in memory may be fragmented — look at partial carves too",
            "foremost and bulk_extractor also good for memory carving",
        ],
        "on_hit": ["img_meta", "zip_inspect", "pdf_meta"],
        "on_miss": [],
        "artifacts": ["memory"],
    },

    # ══════════ UNKNOWN BINARY ════════════════════════════════════════════════

    "unk_file_type": {
        "title": "Identify File Type",
        "category": "forensics",
        "description":
            "Use `file` and magic-byte inspection to determine the true type of an "
            "unknown binary, regardless of its extension.",
        "tool": "file / extract_all.py",
        "command": 'file <binary>\npython3 "{S}/file_carver.py" <binary>\npython3 "{S}/entropy_scanner.py" <binary>',
        "tips": [
            "`file` reads magic bytes — extension means nothing",
            "xxd <binary> | head -4  → look at first 16 bytes manually",
            "High uniform entropy → encrypted or compressed",
            "Low entropy with printable chars → text/encoded data",
        ],
        "on_hit": ["txt_decode", "zip_inspect", "elf_strings"],
        "on_miss": ["unk_strings"],
        "artifacts": ["unknown"],
    },

    "unk_strings": {
        "title": "Extract Strings from Unknown Binary",
        "category": "forensics",
        "description":
            "Pull printable strings — even from unknown binary formats this often "
            "reveals the format, purpose, embedded data, or the flag itself.",
        "tool": "strings_extractor.py",
        "command": 'python3 "{S}/strings_extractor.py" <binary> --flags-only --offset',
        "tips": [
            "Look for file format hints in strings: 'JFIF', 'PNG', '%PDF'",
            "Version strings or copyright notices identify the format",
            "Base64 blobs in strings → decode with base_decoder.py",
        ],
        "on_hit": ["txt_decode"],
        "on_miss": ["unk_xor_all"],
        "artifacts": ["unknown"],
    },

    "unk_xor_all": {
        "title": "Try XOR Decryption on Unknown Data",
        "category": "crypto",
        "description":
            "If the file type is unrecognised and entropy is high, it may be XOR-encrypted. "
            "Try all single-byte keys and look for recognisable output.",
        "tool": "xor_brute.py",
        "command": 'python3 "{S}/xor_brute.py" <binary> --single --top 10\npython3 "{S}/xor_brute.py" <binary> --max-keylen 8',
        "tips": [
            "XOR 0x00 = identity — if key byte 0x00 scores high, data is already plaintext",
            "Known-plaintext: if you expect a PNG → XOR first 8 bytes with PNG magic",
            "Result looks like a different format → run file_carver.py on it",
        ],
        "on_hit": ["unk_file_type"],
        "on_miss": [],
        "artifacts": ["unknown"],
    },

    # ══════════ SHARED / CROSS-ARTIFACT ═══════════════════════════════════════

    "file_carve": {
        "title": "Carve Embedded Files (Generic)",
        "category": "forensics",
        "description":
            "Scan any file for embedded file magic signatures — ZIPs, PNGs, ELFs, PDFs "
            "and many more formats hidden inside another file.",
        "tool": "file_carver.py",
        "command": 'python3 "{S}/file_carver.py" <file>',
        "tips": [
            "Output folder: <file>_carved/",
            "ZIP at end of JPEG is extremely common — check carved_*_ZIP.zip",
            "Use --min-size 64 to skip tiny false positives",
        ],
        "on_hit": ["zip_inspect", "img_meta", "txt_decode"],
        "on_miss": [],
        "artifacts": [],
    },

    "hash_id": {
        "title": "Identify & Crack Hash",
        "category": "crypto",
        "description":
            "Identify the hash type by its length and charset, then crack it with "
            "hashcat or john.",
        "tool": "hash_identifier.py",
        "command": 'python3 "{S}/hash_identifier.py" "<hash>" --hashcat --john\nhashcat -m <mode> <hash> /usr/share/wordlists/rockyou.txt\njohn --format=<format> --wordlist=/usr/share/wordlists/rockyou.txt hash.txt',
        "tips": [
            "MD5 (32 hex chars) → hashcat -m 0",
            "SHA-1 (40 hex chars) → hashcat -m 100",
            "SHA-256 (64 hex chars) → hashcat -m 1400",
            "bcrypt ($2b$...) → hashcat -m 3200 (slow)",
            "NTLM (32 hex) → hashcat -m 1000",
            "Online: crackstation.net, hashes.com",
        ],
        "on_hit": [],
        "on_miss": [],
        "artifacts": [],
    },

    "xor_brute_file": {
        "title": "XOR Brute-Force on Extracted Data",
        "category": "crypto",
        "description":
            "The extracted/carved data may be XOR-encrypted. Try all single-byte keys "
            "and multi-byte keys up to length 16.",
        "tool": "xor_brute.py",
        "command": 'python3 "{S}/xor_brute.py" <extracted_file> --single --top 5\npython3 "{S}/xor_brute.py" <extracted_file> --max-keylen 12 -o decrypted.bin',
        "tips": [
            "Save the best decryption with -o and then run file on it",
            "If output looks like a known format → carve it with file_carver.py",
        ],
        "on_hit": ["file_carve", "txt_decode"],
        "on_miss": [],
        "artifacts": [],
    },
}

# ─── Which nodes start for each artifact type ─────────────────────────────────
INITIAL_NODES = {
    "pcap":    ["pcap_stats", "pcap_extract", "pcap_strings", "pcap_wireshark_filters"],
    "image":   ["img_meta", "img_strings", "img_entropy", "img_lsb", "img_carve"],
    "audio":   ["aud_meta", "aud_lsb", "aud_spectrum"],
    "zip":     ["zip_inspect"],
    "elf":     ["elf_strings", "elf_entropy"],
    "exe":     ["exe_strings", "exe_entropy"],
    "pdf":     ["pdf_meta", "pdf_strings"],
    "text":    ["txt_decode", "txt_base", "txt_rot"],
    "web":     ["web_recon", "web_source", "web_cookies"],
    "docker":  ["docker_inspect", "docker_env"],
    "memory":  ["mem_strings", "mem_volatility"],
    "unknown": ["unk_file_type", "unk_strings"],
}

# ─── Investigation Engine ─────────────────────────────────────────────────────
class Engine:
    def __init__(self):
        self.artifacts  = []      # list of {type, subtype, name, notes}
        self.active     = []      # node IDs currently shown
        self.status     = {}      # node_id → "hit" | "miss" | "pending"
        self.path       = []      # list of (node_id, result, timestamp)
        self.notes      = {}      # node_id → str (user notes per card)
        self.scripts    = load_cfg()["scripts"]

    def save_note(self, node_id, text):
        self.notes[node_id] = text

    def add_artifact(self, atype, subtype, name, notes):
        self.artifacts.append({"type": atype, "subtype": subtype, "name": name, "notes": notes})
        initial = INITIAL_NODES.get(atype, [])
        for nid in initial:
            if nid not in self.active and nid not in self.status:
                self.active.append(nid)
                self.status[nid] = "pending"

    def remove_artifact(self, index):
        self.artifacts.pop(index)

    def mark(self, node_id, result):
        """Mark a node as hit or miss, reveal follow-up nodes."""
        self.status[node_id] = result
        ts = datetime.now().strftime("%H:%M:%S")
        self.path.append((node_id, result, ts))
        follow_key = "on_hit" if result == "hit" else "on_miss"
        node = NODES.get(node_id, {})
        for nid in node.get(follow_key, []):
            if nid not in self.status:
                self.active.append(nid)
                self.status[nid] = "pending"

    def reset(self):
        self.artifacts.clear()
        self.active.clear()
        self.status.clear()
        self.path.clear()

    def get_command(self, node_id, selected_args=None):
        node = NODES.get(node_id, {})
        cmd = node.get("command", "")
        cmd = cmd.replace("{S}", self.scripts)
        if "{ARGS}" in cmd:
            if selected_args is None:
                selected_args = [a["flag"] for a in node.get("args", [])
                                 if a.get("default", True)]
            cmd = cmd.replace("{ARGS}", " ".join(selected_args)).strip()
        return cmd

    def export(self):
        lines = [f"CTF Navigator Export — {datetime.now():%Y-%m-%d %H:%M}\n"]
        lines.append("ARTIFACTS:")
        for a in self.artifacts:
            lines.append(f"  [{a['type']}] {a['name']} ({a['subtype']}) — {a['notes']}")
        lines.append("\nINVESTIGATION PATH:")
        for nid, res, ts in self.path:
            node = NODES.get(nid, {})
            icon = "✓" if res == "hit" else "✗"
            lines.append(f"  {ts} {icon} {node.get('title','?')}")
        lines.append("\nACTIVE SUGGESTIONS:")
        for nid in self.active:
            if self.status.get(nid) == "pending":
                node = NODES.get(nid, {})
                lines.append(f"  • {node.get('title','?')}")
        return "\n".join(lines)


# ─── GUI ──────────────────────────────────────────────────────────────────────

FONT_MAIN  = ("Segoe UI", 10) if platform.system() == "Windows" else ("DejaVu Sans", 10)
FONT_BOLD  = ("Segoe UI", 10, "bold") if platform.system() == "Windows" else ("DejaVu Sans", 10, "bold")
FONT_SMALL = ("Segoe UI", 9)  if platform.system() == "Windows" else ("DejaVu Sans", 9)
FONT_MONO  = ("Courier New", 9) if platform.system() == "Windows" else ("DejaVu Sans Mono", 9)
FONT_H1    = ("Segoe UI", 12, "bold") if platform.system() == "Windows" else ("DejaVu Sans", 12, "bold")
FONT_TITLE = ("Segoe UI", 14, "bold") if platform.system() == "Windows" else ("DejaVu Sans", 14, "bold")


class ScrollableFrame(tk.Frame):
    def __init__(self, parent, bg=BG_ROOT, **kw):
        super().__init__(parent, bg=bg, **kw)
        self.canvas = tk.Canvas(self, bg=bg, highlightthickness=0, bd=0)
        self.vsb    = ttk.Scrollbar(self, orient="vertical", command=self.canvas.yview)
        self.inner  = tk.Frame(self.canvas, bg=bg)
        self.inner.bind("<Configure>", lambda e: self.canvas.configure(
            scrollregion=self.canvas.bbox("all")))
        self._win = self.canvas.create_window((0, 0), window=self.inner, anchor="nw")
        self.canvas.configure(yscrollcommand=self.vsb.set)
        self.canvas.bind("<Configure>", self._on_canvas_resize)
        self.vsb.pack(side="right", fill="y")
        self.canvas.pack(side="left", fill="both", expand=True)
        self._bind_scroll(self.canvas)
        self._bind_scroll(self.inner)

    def _on_canvas_resize(self, e):
        self.canvas.itemconfig(self._win, width=e.width)

    def _bind_scroll(self, widget):
        widget.bind("<MouseWheel>", self._scroll)
        widget.bind("<Button-4>",   self._scroll)
        widget.bind("<Button-5>",   self._scroll)

    def _scroll(self, e):
        if e.num == 4 or e.delta > 0:
            self.canvas.yview_scroll(-1, "units")
        elif e.num == 5 or e.delta < 0:
            self.canvas.yview_scroll(1, "units")

    def scroll_to_bottom(self):
        self.update_idletasks()
        self.canvas.yview_moveto(1.0)


class SuggestionCard(tk.Frame):
    def __init__(self, parent, node_id, engine, on_change, **kw):
        super().__init__(parent, bg=BG_PANEL, relief="flat",
                         highlightbackground=BORDER, highlightthickness=1, **kw)
        self.node_id   = node_id
        self.engine    = engine
        self.on_change = on_change
        self.collapsed = False
        self._build()

    def _build(self):
        node   = NODES.get(self.node_id, {})
        status = self.engine.status.get(self.node_id, "pending")
        cat    = node.get("category", "misc")
        cat_bg, cat_fg, cat_label = CAT.get(cat, ("#e0e0e0","#333","Misc"))

        bg_card = {"hit": BG_HIT, "miss": BG_MISS, "pending": BG_PEND}[status]
        self.configure(bg=bg_card)

        # ── Header row ──
        header = tk.Frame(self, bg=bg_card, cursor="hand2")
        header.pack(fill="x", padx=10, pady=(10, 4))
        header.bind("<Button-1>", self._toggle)

        cat_pill = tk.Label(header, text=f" {cat_label} ", bg=cat_bg, fg=cat_fg,
                            font=FONT_SMALL, relief="flat", padx=4, pady=1)
        cat_pill.pack(side="left")
        cat_pill.bind("<Button-1>", self._toggle)

        if status == "hit":
            status_icon = tk.Label(header, text=" ✓ Found ", bg=SUCCESS, fg="white",
                                   font=FONT_SMALL, padx=4)
            status_icon.pack(side="right", padx=(4, 0))
        elif status == "miss":
            status_icon = tk.Label(header, text=" ✗ No result ", bg="#9e9e9e", fg="white",
                                   font=FONT_SMALL, padx=4)
            status_icon.pack(side="right", padx=(4, 0))

        title = tk.Label(header, text=node.get("title", self.node_id),
                         font=FONT_BOLD, bg=bg_card, fg=FG_MAIN, anchor="w")
        title.pack(side="left", padx=(8, 0))
        title.bind("<Button-1>", self._toggle)

        # ── Body (collapsible) ──
        self.body = tk.Frame(self, bg=bg_card)
        self.body.pack(fill="x", padx=10, pady=(0, 10))

        desc = tk.Label(self.body, text=node.get("description", ""),
                        font=FONT_MAIN, bg=bg_card, fg=FG_SEC,
                        wraplength=550, justify="left", anchor="w")
        desc.pack(fill="x", pady=(0, 6))

        # Tool row
        tool_text = f"Tool: {node.get('tool','—')}"
        tk.Label(self.body, text=tool_text, font=FONT_SMALL, bg=bg_card,
                 fg=FG_SEC).pack(anchor="w")

        # Arg toggles (if node defines selectable arguments)
        node_args = node.get("args", [])
        self._arg_vars = []
        if node_args:
            args_row = tk.Frame(self.body, bg=bg_card)
            args_row.pack(fill="x", pady=(2, 0))
            tk.Label(args_row, text="Options:", font=FONT_BOLD,
                     bg=bg_card, fg=FG_MAIN).pack(side="left", padx=(0, 6))
            for arg in node_args:
                var = tk.BooleanVar(value=arg.get("default", True))
                self._arg_vars.append(var)
                cb = tk.Checkbutton(args_row, text=arg["label"], variable=var,
                                    font=FONT_SMALL, bg=bg_card, fg=FG_MAIN,
                                    activebackground=bg_card,
                                    command=self._update_cmd_display)
                cb.pack(side="left", padx=4)

        # Command box
        cmd = self.engine.get_command(self.node_id)
        self._cmd_text = None
        if cmd:
            cmd_frame = tk.Frame(self.body, bg=BG_CODE,
                                 highlightbackground="#c0c4d8", highlightthickness=1)
            cmd_frame.pack(fill="x", pady=(4, 4))
            self._cmd_text = tk.Text(cmd_frame, font=FONT_MONO, bg=BG_CODE, fg=FG_CODE,
                                     height=cmd.count("\n") + 1, relief="flat",
                                     wrap="none", cursor="xterm")
            self._cmd_text.insert("1.0", cmd)
            self._cmd_text.configure(state="disabled")
            self._cmd_text.pack(fill="x", padx=6, pady=4)

            copy_btn = tk.Button(cmd_frame, text="Copy", font=FONT_SMALL,
                                 bg=ACCENT, fg="white", relief="flat",
                                 padx=6, pady=1, cursor="hand2",
                                 command=self._copy_cmd)
            copy_btn.place(relx=1.0, rely=0, anchor="ne", x=-4, y=4)

        # Tips
        tips = node.get("tips", [])
        if tips:
            tips_frame = tk.Frame(self.body, bg=bg_card)
            tips_frame.pack(fill="x", pady=(2, 6))
            tk.Label(tips_frame, text="Tips:", font=FONT_BOLD, bg=bg_card,
                     fg=FG_MAIN).pack(anchor="w")
            for tip in tips:
                tk.Label(tips_frame, text=f"  • {tip}", font=FONT_SMALL,
                         bg=bg_card, fg=FG_SEC, wraplength=540,
                         justify="left", anchor="w").pack(fill="x")

        # Buttons + Run (only if pending)
        if status == "pending":
            btn_row = tk.Frame(self.body, bg=bg_card)
            btn_row.pack(fill="x", pady=(4, 4))
            tk.Button(btn_row, text="✓  Found something!", font=FONT_BOLD,
                      bg=SUCCESS, fg="white", relief="flat",
                      padx=12, pady=5, cursor="hand2",
                      command=lambda: self._result("hit")).pack(side="left", padx=(0, 8))
            tk.Button(btn_row, text="✗  Nothing here", font=FONT_MAIN,
                      bg="#9e9e9e", fg="white", relief="flat",
                      padx=12, pady=5, cursor="hand2",
                      command=lambda: self._result("miss")).pack(side="left")
            tk.Button(btn_row, text="▶ Run", font=FONT_SMALL,
                      bg="#2a2a4a", fg="white", relief="flat",
                      padx=8, pady=5, cursor="hand2",
                      command=self._run_first_line).pack(side="right")

        # Notes area (always visible)
        notes_outer = tk.Frame(self.body, bg=bg_card)
        notes_outer.pack(fill="x", pady=(4, 0))
        tk.Label(notes_outer, text="Notes:", font=FONT_BOLD,
                 bg=bg_card, fg=FG_MAIN).pack(anchor="w")
        self.notes_txt = tk.Text(notes_outer, height=2, font=FONT_SMALL,
                                  bg="#f0f4ff", fg=FG_CODE,
                                  relief="solid", bd=1, wrap="word")
        existing = self.engine.notes.get(self.node_id, "")
        if existing:
            self.notes_txt.insert("1.0", existing)
        self.notes_txt.pack(fill="x", pady=(2, 0))
        self.notes_txt.bind("<FocusOut>", self._save_note)

        if status != "pending":
            self.collapsed = True
            self.body.pack_forget()

    def _get_selected_args(self):
        node = NODES.get(self.node_id, {})
        args = node.get("args", [])
        return [a["flag"] for a, var in zip(args, self._arg_vars) if var.get()]

    def _update_cmd_display(self):
        if not self._cmd_text:
            return
        cmd = self.engine.get_command(self.node_id, self._get_selected_args())
        self._cmd_text.configure(state="normal")
        self._cmd_text.delete("1.0", "end")
        self._cmd_text.insert("1.0", cmd)
        lines = cmd.count("\n") + 1
        self._cmd_text.configure(state="disabled", height=lines)

    def _copy_cmd(self):
        cmd = self.engine.get_command(self.node_id, self._get_selected_args())
        self.clipboard_clear()
        self.clipboard_append(cmd)

    def _toggle(self, e=None):
        if self.collapsed:
            self.body.pack(fill="x", padx=10, pady=(0, 10))
            self.collapsed = False
        else:
            self.body.pack_forget()
            self.collapsed = True

    def _save_note(self, event=None):
        text = self.notes_txt.get("1.0", "end").strip()
        self.engine.save_note(self.node_id, text)

    def _run_first_line(self):
        cmd = self.engine.get_command(self.node_id, self._get_selected_args())
        first = next((l for l in cmd.splitlines() if l.strip() and not l.strip().startswith("#")), "")
        if first:
            self._run(first)

    def _run(self, cmd):
        term = None
        for t in ("x-terminal-emulator", "gnome-terminal", "xterm", "konsole"):
            if subprocess.call(["which", t], stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL) == 0:
                term = t
                break
        if term == "gnome-terminal":
            subprocess.Popen([term, "--", "bash", "-c", f"{cmd}; exec bash"])
        elif term:
            subprocess.Popen([term, "-e", f"bash -c '{cmd}; exec bash'"])
        else:
            messagebox.showinfo("Run", f"No terminal found.\nCommand:\n{cmd}")

    def _result(self, res):
        self._save_note()
        self.engine.mark(self.node_id, res)
        self.on_change()


class AddArtifactDialog(tk.Toplevel):
    # Extension → artifact type mapping used for drag-drop auto-detection
    _EXT_MAP = {
        ".pcap": "pcap", ".pcapng": "pcap", ".cap": "pcap",
        ".png": "image", ".jpg": "image", ".jpeg": "image",
        ".bmp": "image", ".gif": "image", ".tiff": "image", ".tif": "image",
        ".wav": "audio", ".mp3": "audio", ".ogg": "audio", ".flac": "audio",
        ".zip": "zip",   ".tar": "zip",   ".gz": "zip",
        ".bz2": "zip",   ".xz": "zip",   ".7z": "zip",    ".rar": "zip",
        ".pdf": "pdf",
        ".txt": "text",  ".log": "text",  ".md": "text",
        ".exe": "exe",   ".dll": "exe",
        ".dmp": "memory",".raw": "memory",".vmem": "memory",".mem": "memory",
    }

    def __init__(self, parent, prefill=None):
        super().__init__(parent)
        self.title("Add Artifact")
        self.resizable(True, False)
        self.configure(bg=BG_ROOT)
        self.result = None
        self._prefill = prefill or {}
        self._build()
        # Register as DnD drop target (works because parent is TkinterDnD.Tk)
        if HAS_DND:
            self.drop_target_register(DND_FILES)
            self.dnd_bind("<<Drop>>", self._on_drop)
        self.transient(parent)
        self.grab_set()
        self.lift()
        self.focus_force()
        self.wait_window()

    def _build(self):
        pad = {"padx": 16, "pady": 4}
        tk.Label(self, text="Add Challenge Artifact", font=FONT_H1,
                 bg=BG_ROOT, fg=FG_MAIN).pack(padx=16, pady=(14, 4))

        # Drag-drop hint strip
        dnd_color = "#e8f0fe" if HAS_DND else "#f5f5f5"
        dnd_txt   = "⬇  Drop a file here to auto-fill" if HAS_DND else "Browse or type a filename below"
        self._drop_lbl = tk.Label(self, text=dnd_txt, font=FONT_SMALL,
                                   bg=dnd_color, fg="#3a5bd9",
                                   relief="flat", pady=6, cursor="hand2" if HAS_DND else "")
        self._drop_lbl.pack(fill="x", padx=16, pady=(0, 6))

        # ── Type ──────────────────────────────────────────────────────────────
        tk.Label(self, text="Artifact type:", font=FONT_BOLD,
                 bg=BG_ROOT, fg=FG_MAIN, anchor="w").pack(fill="x", **pad)
        type_row = tk.Frame(self, bg=BG_ROOT)
        type_row.pack(fill="x", padx=16, pady=(0, 4))

        self.type_var = tk.StringVar(value=self._prefill.get("type", list(ARTIFACT_TYPES.keys())[0]))
        self.type_cb = ttk.Combobox(type_row, textvariable=self.type_var,
                                    values=list(ARTIFACT_TYPES.keys()),
                                    state="readonly", width=14)
        self.type_cb.pack(side="left")
        self.type_lbl = tk.Label(type_row, text="", font=FONT_SMALL,
                                 bg=BG_ROOT, fg=FG_SEC, wraplength=240, justify="left")
        self.type_lbl.pack(side="left", padx=8)

        # ── Subtype ────────────────────────────────────────────────────────────
        tk.Label(self, text="Details / subtype:", font=FONT_BOLD,
                 bg=BG_ROOT, fg=FG_MAIN, anchor="w").pack(fill="x", **pad)
        self.sub_var = tk.StringVar()
        self.sub_cb  = ttk.Combobox(self, textvariable=self.sub_var,
                                    state="readonly", width=36)
        self.sub_cb.pack(fill="x", padx=16, pady=(0, 4))

        # NOW it's safe to fire type-change (sub_cb exists)
        self.type_var.trace_add("write", self._on_type_change)
        self._on_type_change()

        # ── Name / path ────────────────────────────────────────────────────────
        tk.Label(self, text="Name / filename:", font=FONT_BOLD,
                 bg=BG_ROOT, fg=FG_MAIN, anchor="w").pack(fill="x", **pad)
        name_row = tk.Frame(self, bg=BG_ROOT)
        name_row.pack(fill="x", padx=16, pady=(0, 4))
        self.name_var = tk.StringVar(value=self._prefill.get("name", ""))
        tk.Entry(name_row, textvariable=self.name_var, width=30).pack(side="left", expand=True, fill="x")
        tk.Button(name_row, text="Browse…", font=FONT_SMALL,
                  bg=ACCENT, fg="white", relief="flat",
                  padx=8, pady=2, cursor="hand2",
                  command=self._browse).pack(side="left", padx=(6, 0))

        # ── Notes ──────────────────────────────────────────────────────────────
        tk.Label(self, text="Notes (what you know so far):", font=FONT_BOLD,
                 bg=BG_ROOT, fg=FG_MAIN, anchor="w").pack(fill="x", **pad)
        self.notes_txt = tk.Text(self, height=3, width=44, font=FONT_MAIN,
                                 relief="solid", bd=1, wrap="word")
        self.notes_txt.pack(fill="x", padx=16, pady=(0, 6))
        if self._prefill.get("notes"):
            self.notes_txt.insert("1.0", self._prefill["notes"])

        # ── Buttons ────────────────────────────────────────────────────────────
        btn_row = tk.Frame(self, bg=BG_ROOT)
        btn_row.pack(fill="x", padx=16, pady=(0, 14))
        tk.Button(btn_row, text="Add Artifact", font=FONT_BOLD,
                  bg=ACCENT, fg="white", relief="flat",
                  padx=14, pady=6, cursor="hand2",
                  command=self._confirm).pack(side="right")
        tk.Button(btn_row, text="Cancel", font=FONT_MAIN,
                  bg="#9e9e9e", fg="white", relief="flat",
                  padx=14, pady=6, cursor="hand2",
                  command=self.destroy).pack(side="right", padx=8)

    def _on_type_change(self, *_):
        t = self.type_var.get()
        self.type_lbl.configure(text=ARTIFACT_TYPES.get(t, ""))
        subs = ARTIFACT_SUBTYPES.get(t, ["—"])
        self.sub_cb.configure(values=subs)
        cur = self._prefill.get("subtype")
        self.sub_cb.set(cur if cur in subs else subs[0])

    def _browse(self):
        path = filedialog.askopenfilename(title="Select artifact file")
        if path:
            self._apply_path(path)

    def _on_drop(self, event):
        raw = event.data.strip()
        # tkinterdnd2 wraps paths with spaces in braces
        paths = self.tk.splitlist(raw)
        if paths:
            self._apply_path(paths[0])
        self._drop_lbl.configure(text="✓ File loaded — adjust type if needed", fg="#1b8a3e")

    def _apply_path(self, path):
        p = Path(path)
        self.name_var.set(p.name)
        ext = p.suffix.lower()
        atype = self._EXT_MAP.get(ext)
        # Check ELF magic if extension didn't match
        if not atype:
            try:
                with open(path, "rb") as f:
                    magic = f.read(4)
                if magic == b"\x7fELF":
                    atype = "elf"
            except OSError:
                pass
        if not atype:
            atype = "unknown"
        self.type_var.set(atype)   # triggers _on_type_change

    def _confirm(self):
        self.result = {
            "type":    self.type_var.get(),
            "subtype": self.sub_var.get(),
            "name":    self.name_var.get().strip() or "(unnamed)",
            "notes":   self.notes_txt.get("1.0", "end").strip(),
        }
        self.destroy()


class SettingsDialog(tk.Toplevel):
    def __init__(self, parent, engine):
        super().__init__(parent)
        self.title("Settings")
        self.resizable(False, False)
        self.configure(bg=BG_ROOT)
        self.engine = engine
        self._build()
        self.transient(parent)
        self.grab_set()
        self.wait_window()

    def _build(self):
        tk.Label(self, text="Settings", font=FONT_H1,
                 bg=BG_ROOT, fg=FG_MAIN).pack(padx=16, pady=(16, 6))
        tk.Label(self, text="Scripts folder path:", font=FONT_BOLD,
                 bg=BG_ROOT, fg=FG_MAIN, anchor="w").pack(fill="x", padx=16, pady=(8, 2))
        tk.Label(self, text="(folder containing the CTF Python scripts)",
                 font=FONT_SMALL, bg=BG_ROOT, fg=FG_SEC).pack(anchor="w", padx=16)
        row = tk.Frame(self, bg=BG_ROOT)
        row.pack(fill="x", padx=16, pady=4)
        self.path_var = tk.StringVar(value=self.engine.scripts)
        tk.Entry(row, textvariable=self.path_var, width=38).pack(side="left")
        tk.Button(row, text="Browse", font=FONT_SMALL, bg=ACCENT, fg="white",
                  relief="flat", padx=6, command=self._browse).pack(side="left", padx=6)

        btn_row = tk.Frame(self, bg=BG_ROOT)
        btn_row.pack(fill="x", padx=16, pady=16)
        tk.Button(btn_row, text="Save", font=FONT_BOLD, bg=ACCENT, fg="white",
                  relief="flat", padx=14, pady=5, command=self._save).pack(side="right")
        tk.Button(btn_row, text="Cancel", font=FONT_MAIN, bg="#9e9e9e", fg="white",
                  relief="flat", padx=14, pady=5, command=self.destroy).pack(side="right", padx=8)

    def _browse(self):
        d = filedialog.askdirectory(title="Select scripts folder")
        if d:
            self.path_var.set(d)

    def _save(self):
        self.engine.scripts = self.path_var.get()
        cfg = load_cfg()
        cfg["scripts"] = self.engine.scripts
        save_cfg(cfg)
        self.destroy()


class CTFNavigator(_TkBase):
    def __init__(self):
        super().__init__()
        self.title("CTF Navigator — OSC 2026")
        self.geometry("1100x720")
        self.minsize(800, 500)
        self.configure(bg=BG_ROOT)
        self.engine    = Engine()
        self._cards    = {}    # node_id → SuggestionCard
        self._cat_filter = set()  # empty = show all categories
        self._filter_btns = {}
        self._build()
        self._refresh()

    # ── Layout ────────────────────────────────────────────────────────────────

    def _build(self):
        self._build_header()
        content = tk.Frame(self, bg=BG_ROOT)
        content.pack(fill="both", expand=True, padx=10, pady=(4, 10))
        content.columnconfigure(1, weight=1)
        content.rowconfigure(0, weight=1)
        self._build_left(content)
        self._build_right(content)

    def _build_header(self):
        hdr = tk.Frame(self, bg=BG_HEADER)
        hdr.pack(fill="x")
        tk.Label(hdr, text="🔍  CTF Navigator", font=FONT_TITLE,
                 bg=BG_HEADER, fg=FG_HEADER).pack(side="left", padx=16, pady=10)
        tk.Label(hdr, text="OSC 2026  ·  Rule-based  ·  No AI/ML",
                 font=FONT_SMALL, bg=BG_HEADER, fg="#8892b0").pack(side="left", padx=4)
        tk.Button(hdr, text="⚙ Settings", font=FONT_SMALL,
                  bg="#2a2a4a", fg=FG_HEADER, relief="flat",
                  padx=10, pady=4, cursor="hand2",
                  command=self._open_settings).pack(side="right", padx=8, pady=8)
        tk.Button(hdr, text="↓ Export", font=FONT_SMALL,
                  bg="#2a2a4a", fg=FG_HEADER, relief="flat",
                  padx=10, pady=4, cursor="hand2",
                  command=self._export).pack(side="right", pady=8)
        tk.Button(hdr, text="⟳ Reset", font=FONT_SMALL,
                  bg="#2a2a4a", fg="#f48fb1", relief="flat",
                  padx=10, pady=4, cursor="hand2",
                  command=self._reset_confirm).pack(side="right", pady=8)

    def _build_left(self, parent):
        left = tk.Frame(parent, bg=BG_ROOT, width=270)
        left.grid(row=0, column=0, sticky="nsew", padx=(0, 8))
        left.pack_propagate(False)

        # ── Artifacts ──
        art_hdr = tk.Frame(left, bg=BG_ROOT)
        art_hdr.pack(fill="x", pady=(8, 4))
        tk.Label(art_hdr, text="ARTIFACTS", font=FONT_BOLD,
                 bg=BG_ROOT, fg=FG_SEC).pack(side="left")
        tk.Button(art_hdr, text="+ Add", font=FONT_SMALL,
                  bg=ACCENT, fg="white", relief="flat",
                  padx=8, pady=2, cursor="hand2",
                  command=self._add_artifact).pack(side="right")

        self.art_frame = tk.Frame(left, bg=BG_ROOT)
        self.art_frame.pack(fill="x")

        # Drop zone
        dz_bg  = "#e8f0fe" if HAS_DND else BG_PANEL
        dz_txt = "⬇  Drop file here" if HAS_DND else "Click + Add or drag files here"
        self._drop_zone = tk.Label(left, text=dz_txt, font=FONT_SMALL,
                                    bg=dz_bg, fg=ACCENT,
                                    relief="flat", pady=5, cursor="hand2")
        self._drop_zone.pack(fill="x", pady=(4, 0))
        self._drop_zone.bind("<Button-1>", lambda e: self._add_artifact())
        if HAS_DND:
            self._drop_zone.drop_target_register(DND_FILES)
            self._drop_zone.dnd_bind("<<Drop>>", self._on_drop)

        ttk.Separator(left, orient="horizontal").pack(fill="x", pady=8)

        # ── Investigation Path ──
        tk.Label(left, text="INVESTIGATION PATH", font=FONT_BOLD,
                 bg=BG_ROOT, fg=FG_SEC).pack(anchor="w")
        path_sf = ScrollableFrame(left, bg=BG_ROOT)
        path_sf.pack(fill="both", expand=True)
        self.path_frame = path_sf.inner

    def _build_right(self, parent):
        right = tk.Frame(parent, bg=BG_ROOT)
        right.grid(row=0, column=1, sticky="nsew")

        hdr = tk.Frame(right, bg=BG_ROOT)
        hdr.pack(fill="x", pady=(8, 2))
        tk.Label(hdr, text="SUGGESTIONS", font=FONT_BOLD,
                 bg=BG_ROOT, fg=FG_SEC).pack(side="left")
        self.count_lbl = tk.Label(hdr, text="", font=FONT_SMALL,
                                   bg=BG_ROOT, fg=FG_SEC)
        self.count_lbl.pack(side="left", padx=8)

        # Category filter buttons
        filter_row = tk.Frame(right, bg=BG_ROOT)
        filter_row.pack(fill="x", pady=(0, 4))
        tk.Label(filter_row, text="Filter:", font=FONT_SMALL,
                 bg=BG_ROOT, fg=FG_SEC).pack(side="left", padx=(0, 4))
        for cat_id, (cat_bg, cat_fg, cat_label) in CAT.items():
            btn = tk.Button(filter_row, text=cat_label, font=FONT_SMALL,
                            bg=cat_bg, fg=cat_fg, relief="flat",
                            padx=6, pady=2, cursor="hand2",
                            command=lambda c=cat_id: self._toggle_filter(c))
            btn.pack(side="left", padx=2)
            self._filter_btns[cat_id] = btn
        tk.Button(filter_row, text="All", font=FONT_SMALL,
                  bg=BORDER, fg=FG_MAIN, relief="flat",
                  padx=6, pady=2, cursor="hand2",
                  command=self._clear_filter).pack(side="left", padx=(6, 0))

        self.sug_sf = ScrollableFrame(right, bg=BG_ROOT)
        self.sug_sf.pack(fill="both", expand=True)
        self.sug_inner = self.sug_sf.inner
        self.sug_inner.pack_propagate(True)

        # Empty state
        self.empty_lbl = tk.Label(self.sug_inner,
            text="← Add an artifact to start your investigation",
            font=FONT_MAIN, bg=BG_ROOT, fg=FG_SEC)
        self.empty_lbl.pack(pady=60)

        # Status bar
        self.status_bar = tk.Label(self, text="Ready", font=FONT_SMALL,
                                    bg=BG_HEADER, fg="#8892b0",
                                    anchor="w", padx=10, pady=3)
        self.status_bar.pack(side="bottom", fill="x")

    # ── Actions ───────────────────────────────────────────────────────────────

    def _add_artifact(self):
        dlg = AddArtifactDialog(self)
        if dlg.result:
            r = dlg.result
            self.engine.add_artifact(r["type"], r["subtype"], r["name"], r["notes"])
            self._refresh()

    def _open_settings(self):
        SettingsDialog(self, self.engine)

    def _reset_confirm(self):
        if messagebox.askyesno("Reset", "Clear all artifacts and start over?"):
            self.engine.reset()
            self._cards.clear()
            self._refresh()

    def _export(self):
        if not self.engine.artifacts:
            messagebox.showinfo("Export", "Nothing to export yet.")
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".txt", filetypes=[("Text","*.txt"),("All","*")],
            initialfile="ctf_notes.txt")
        if path:
            Path(path).write_text(self.engine.export())
            messagebox.showinfo("Exported", f"Saved to {path}")

    def on_change(self):
        self._refresh()
        # New follow-up cards appear at top — scroll there
        self.update_idletasks()
        self.sug_sf.canvas.yview_moveto(0.0)

    # ── Refresh ───────────────────────────────────────────────────────────────

    def _refresh(self):
        self._refresh_artifacts()
        self._refresh_suggestions()
        self._refresh_path()

    def _refresh_artifacts(self):
        for w in self.art_frame.winfo_children():
            w.destroy()
        for i, a in enumerate(self.engine.artifacts):
            row = tk.Frame(self.art_frame, bg=BG_PANEL,
                           highlightbackground=BORDER, highlightthickness=1)
            row.pack(fill="x", pady=2)
            icon = {"pcap":"📡","image":"🖼","audio":"🎵","zip":"📦",
                    "elf":"⚙","exe":"💻","pdf":"📄","text":"🔤",
                    "web":"🌐","docker":"🐳","memory":"🧠","unknown":"❓"}.get(a["type"],"📁")
            tk.Label(row, text=f"{icon} {a['name']}", font=FONT_BOLD,
                     bg=BG_PANEL, fg=FG_MAIN).pack(side="left", padx=8, pady=4)
            tk.Label(row, text=a["subtype"], font=FONT_SMALL,
                     bg=BG_PANEL, fg=FG_SEC).pack(side="left")
            tk.Button(row, text="✕", font=FONT_SMALL, bg=BG_PANEL, fg=FAIL_C,
                      relief="flat", cursor="hand2",
                      command=lambda idx=i: self._remove_artifact(idx)).pack(side="right", padx=4)
        if not self.engine.artifacts:
            tk.Label(self.art_frame, text="No artifacts added.",
                     font=FONT_SMALL, bg=BG_ROOT, fg=FG_SEC).pack(pady=4)

    def _remove_artifact(self, idx):
        self.engine.remove_artifact(idx)
        self._refresh()

    def _on_drop(self, event):
        paths = self.tk.splitlist(event.data.strip())
        for raw in paths:
            self._auto_add_file(raw.strip("{}"))
        self._drop_zone.configure(text="⬇  Drop file here", fg=ACCENT)

    def _auto_add_file(self, path):
        p = Path(path)
        ext = p.suffix.lower()
        atype = AddArtifactDialog._EXT_MAP.get(ext)
        if not atype:
            try:
                with open(path, "rb") as f:
                    if f.read(4) == b"\x7fELF":
                        atype = "elf"
            except OSError:
                pass
        if not atype:
            atype = "unknown"
        subtype = ARTIFACT_SUBTYPES.get(atype, ["—"])[0]
        self.engine.add_artifact(atype, subtype, p.name, f"Dropped: {path}")
        self._refresh()
        self._drop_zone.configure(
            text=f"✓ Added {p.name} — drop another or click + Add",
            fg=SUCCESS)

    def _toggle_filter(self, cat_id):
        if cat_id in self._cat_filter:
            self._cat_filter.discard(cat_id)
        else:
            self._cat_filter.add(cat_id)
        self._update_filter_btn_styles()
        self._refresh_suggestions()

    def _clear_filter(self):
        self._cat_filter.clear()
        self._update_filter_btn_styles()
        self._refresh_suggestions()

    def _update_filter_btn_styles(self):
        for cat_id, btn in self._filter_btns.items():
            cat_bg, cat_fg, _ = CAT[cat_id]
            if self._cat_filter and cat_id not in self._cat_filter:
                btn.configure(bg="#d4d4d4", fg="#9e9e9e")
            else:
                btn.configure(bg=cat_bg, fg=cat_fg)

    def _refresh_suggestions(self):
        # Destroy and rebuild all cards — simple, correct ordering guaranteed
        for card in list(self._cards.values()):
            card.destroy()
        self._cards.clear()

        has_active = bool(self.engine.active)
        if self.empty_lbl.winfo_exists():
            if has_active:
                self.empty_lbl.pack_forget()
            else:
                self.empty_lbl.pack(pady=60)

        if not has_active:
            self.count_lbl.configure(text="")
            self._update_status_bar()
            return

        pending = [n for n in self.engine.active if self.engine.status.get(n) == "pending"]
        done    = [n for n in self.engine.active if self.engine.status.get(n) != "pending"]

        for nid in pending + done:
            if nid not in NODES:
                continue
            if self._cat_filter:
                cat = NODES[nid].get("category", "misc")
                if cat not in self._cat_filter:
                    continue
            card = SuggestionCard(self.sug_inner, nid, self.engine,
                                  on_change=self.on_change)
            card.pack(fill="x", padx=4, pady=4)
            self._cards[nid] = card

        pending_count = len(pending)
        total = len(self.engine.active)
        self.count_lbl.configure(
            text=f"{pending_count} pending  ·  {total - pending_count} done")
        self._update_status_bar()

    def _update_status_bar(self):
        n_art = len(self.engine.artifacts)
        n_pend = sum(1 for s in self.engine.status.values() if s == "pending")
        n_done = sum(1 for s in self.engine.status.values() if s != "pending")
        n_hits = sum(1 for s in self.engine.status.values() if s == "hit")
        if n_art:
            self.status_bar.configure(
                text=f"  {n_art} artifact{'s' if n_art != 1 else ''}  ·  "
                     f"{n_pend} pending  ·  {n_done} completed  ·  {n_hits} hits")
        else:
            self.status_bar.configure(text="  Ready — add an artifact to begin")

    def _refresh_path(self):
        for w in self.path_frame.winfo_children():
            w.destroy()
        if not self.engine.path:
            tk.Label(self.path_frame, text="No steps taken yet.",
                     font=FONT_SMALL, bg=BG_ROOT, fg=FG_SEC).pack(anchor="w", pady=4)
            return
        for nid, res, ts in self.engine.path:
            node = NODES.get(nid, {})
            icon = "✓" if res == "hit" else "✗"
            color = SUCCESS if res == "hit" else "#9e9e9e"
            row = tk.Frame(self.path_frame, bg=BG_ROOT)
            row.pack(fill="x", pady=1)
            tk.Label(row, text=icon, font=FONT_BOLD, bg=BG_ROOT, fg=color,
                     width=2).pack(side="left")
            title = node.get("title", nid)
            display = title if len(title) <= 28 else title[:25] + "..."
            tk.Label(row, text=display, font=FONT_SMALL, bg=BG_ROOT,
                     fg=FG_MAIN).pack(side="left")
            tk.Label(row, text=ts, font=FONT_SMALL, bg=BG_ROOT,
                     fg=FG_SEC).pack(side="right")


def main():
    app = CTFNavigator()
    app.mainloop()


if __name__ == "__main__":
    main()
