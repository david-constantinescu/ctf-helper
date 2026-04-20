#!/usr/bin/env python3
"""
tshark_extract.py — Quick tshark wrappers for CTF pcap analysis.
Runs common extraction tasks without needing Wireshark GUI open.
Usage: python3 tshark_extract.py <file.pcap> [--mode MODE]
Modes: streams, http-files, credentials, dns, conversations, follow, decode-as, voip
"""

import sys
import re
import argparse
import subprocess
import tempfile
import os
from pathlib import Path


FLAG_RE = re.compile(r'(?:CTF|FLAG|OSC|DUCTF|HTB|picoCTF|flag)\{[^}]{1,200}\}', re.IGNORECASE)


def run(cmd, capture=True, timeout=60):
    try:
        if capture:
            r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
            return r.stdout, r.stderr
        else:
            subprocess.run(cmd, shell=True, timeout=timeout)
            return '', ''
    except subprocess.TimeoutExpired:
        return '', '[timeout]'
    except Exception as e:
        return '', str(e)


def check_tshark():
    out, _ = run('tshark --version 2>/dev/null | head -1')
    if not out:
        print('[!] tshark not found. Install: sudo apt install tshark')
        sys.exit(1)
    print(f'[+] {out.strip()}')


def mode_streams(pcap):
    """List all TCP/UDP streams with byte counts."""
    print('\n[TCP STREAMS]')
    out, _ = run(f'tshark -r "{pcap}" -q -z conv,tcp 2>/dev/null')
    print(out[:3000] or '[none]')

    print('\n[UDP STREAMS]')
    out, _ = run(f'tshark -r "{pcap}" -q -z conv,udp 2>/dev/null')
    print(out[:3000] or '[none]')


def mode_conversations(pcap):
    """IP-level conversation summary."""
    print('\n[IP CONVERSATIONS]')
    out, _ = run(f'tshark -r "{pcap}" -q -z conv,ip 2>/dev/null')
    print(out[:4000] or '[none]')

    print('\n[PROTOCOL HIERARCHY]')
    out, _ = run(f'tshark -r "{pcap}" -q -z io,phs 2>/dev/null')
    print(out[:2000] or '[none]')


def mode_http_files(pcap, outdir):
    """Extract HTTP transferred objects (files, images, etc.)."""
    outdir = Path(outdir)
    outdir.mkdir(exist_ok=True)
    print(f'\n[HTTP FILE EXPORT] → {outdir}')
    out, err = run(f'tshark -r "{pcap}" --export-objects "http,{outdir}" 2>/dev/null')
    files = list(outdir.iterdir())
    print(f'  Exported {len(files)} objects')
    for f in sorted(files)[:20]:
        print(f'  {f.name}  ({f.stat().st_size} bytes)')
        # Flag search in text-like files
        if f.stat().st_size < 1_000_000:
            try:
                content = f.read_text(errors='replace')
                m = FLAG_RE.search(content)
                if m:
                    print(f'    [!!!] FLAG: {m.group()}')
            except Exception:
                pass

    # Also try SMB exports
    smb_dir = outdir / 'smb'
    smb_dir.mkdir(exist_ok=True)
    run(f'tshark -r "{pcap}" --export-objects "smb,{smb_dir}" 2>/dev/null')
    smb_files = list(smb_dir.iterdir())
    if smb_files:
        print(f'\n[SMB FILE EXPORT] {len(smb_files)} objects')
        for f in sorted(smb_files)[:10]:
            print(f'  {f.name}')


def mode_credentials(pcap):
    """Extract cleartext credentials from common protocols."""
    print('\n[CREDENTIALS & AUTH]')

    protocols = [
        ('HTTP Basic Auth',  'http.authorization contains "Basic"', 'http.authorization'),
        ('FTP credentials',  'ftp.request.command == "USER" or ftp.request.command == "PASS"', 'ftp.request.arg'),
        ('POP3',             'pop.request.command == "USER" or pop.request.command == "PASS"', 'pop.request.parameter'),
        ('SMTP AUTH',        'smtp.auth.username or smtp.auth.password', 'smtp.auth.username,smtp.auth.password'),
        ('Telnet data',      'telnet', 'telnet.data'),
        ('HTTP POST body',   'http.request.method == "POST"', 'http.request.uri,http.file_data'),
    ]

    for name, filt, fields in protocols:
        out, _ = run(f'tshark -r "{pcap}" -Y "{filt}" -T fields -e {fields} 2>/dev/null')
        if out.strip():
            print(f'\n  [{name}]')
            for line in out.strip().splitlines()[:20]:
                print(f'    {line}')
                if FLAG_RE.search(line):
                    print(f'    [!!!] FLAG PATTERN')

    # Kerberos / NTLM
    print('\n  [Kerberos/NTLM hashes]')
    out, _ = run(f'tshark -r "{pcap}" -Y "kerberos or ntlmssp" -T fields '
                 f'-e kerberos.cipher -e ntlmssp.auth.username 2>/dev/null')
    if out.strip():
        for line in out.strip().splitlines()[:10]:
            print(f'    {line}')
    else:
        print('    [none found]')


def mode_dns(pcap):
    """Detailed DNS query/response analysis for exfiltration detection."""
    print('\n[DNS QUERIES]')
    out, _ = run(f'tshark -r "{pcap}" -Y "dns" -T fields '
                 f'-e frame.number -e ip.src -e dns.qry.name -e dns.resp.addr 2>/dev/null')
    queries = out.strip().splitlines()
    print(f'  {len(queries)} DNS packets')

    # Find unusually long subdomains (exfil indicator)
    long_labels = []
    for line in queries:
        domains = re.findall(r'[a-zA-Z0-9._-]{30,}\.[a-z]{2,10}', line)
        for d in domains:
            parts = d.split('.')
            if any(len(p) > 25 for p in parts):
                long_labels.append(d)

    if long_labels:
        print(f'\n  [!] SUSPICIOUS LONG SUBDOMAINS ({len(long_labels)}) — possible DNS exfil:')
        for d in long_labels[:20]:
            print(f'    {d}')
            # Try base64 decode of the first label
            label = d.split('.')[0]
            import base64
            try:
                dec = base64.b64decode(label + '==').decode('utf-8', errors='replace')
                if dec.isprintable():
                    print(f'      → b64: {dec[:80]}')
                    if FLAG_RE.search(dec):
                        print(f'      [!!!] FLAG: {FLAG_RE.search(dec).group()}')
            except Exception:
                pass
    else:
        print('  No suspicious long subdomains found')

    # Most queried domains
    print('\n  [TOP QUERIED DOMAINS]')
    out, _ = run(f'tshark -r "{pcap}" -Y "dns.qry.name" -T fields -e dns.qry.name 2>/dev/null '
                 f'| sort | uniq -c | sort -rn | head -20')
    print(out or '  [none]')


def mode_follow(pcap, stream_num=0, proto='tcp'):
    """Follow and print a TCP/UDP stream as ASCII."""
    print(f'\n[FOLLOW {proto.upper()} STREAM {stream_num}]')
    out, _ = run(f'tshark -r "{pcap}" -q -z "follow,{proto},ascii,{stream_num}" 2>/dev/null')
    print(out[:5000] or '[empty]')
    m = FLAG_RE.search(out)
    if m:
        print(f'\n[!!!] FLAG: {m.group()}')


def mode_decode_as(pcap, port, proto='http'):
    """Force Wireshark to decode a port as a specific protocol."""
    print(f'\n[DECODE port {port} AS {proto.upper()}]')
    out, _ = run(f'tshark -r "{pcap}" -d "tcp.port=={port},{proto}" '
                 f'-Y "{proto}" -T fields -e frame.number -e {proto}.request.uri 2>/dev/null | head -30')
    print(out or '[no matching frames]')


def mode_voip(pcap, outdir):
    """Extract VoIP/RTP audio streams."""
    outdir = Path(outdir)
    outdir.mkdir(exist_ok=True)
    print(f'\n[VOIP/RTP EXTRACTION] → {outdir}')
    out, _ = run(f'tshark -r "{pcap}" -q -z rtp,streams 2>/dev/null')
    print(out[:2000] or '[no RTP streams]')
    # Extract raw RTP payload
    out2, _ = run(f'tshark -r "{pcap}" -Y "rtp" -T fields -e rtp.payload 2>/dev/null | head -5')
    if out2:
        print('[*] RTP payload bytes detected — use Wireshark > Telephony > RTP > Play to hear audio')


def mode_all(pcap, outdir):
    """Run all extraction modes."""
    mode_conversations(pcap)
    mode_streams(pcap)
    mode_credentials(pcap)
    mode_dns(pcap)
    mode_http_files(pcap, outdir)


def main():
    ap = argparse.ArgumentParser(description='tshark CTF Extractor')
    ap.add_argument('pcap', help='PCAP/PCAPNG file')
    ap.add_argument('--mode', '-m', default='all',
                    choices=['all', 'streams', 'http-files', 'credentials', 'dns',
                             'conversations', 'follow', 'decode-as', 'voip'],
                    help='Extraction mode (default: all)')
    ap.add_argument('--stream', '-s', type=int, default=0,
                    help='Stream number for --mode follow')
    ap.add_argument('--proto', '-p', default='tcp',
                    help='Protocol for follow/decode-as (default: tcp)')
    ap.add_argument('--port', type=int, default=8080,
                    help='Port for --mode decode-as')
    ap.add_argument('--outdir', '-o', default=None,
                    help='Output directory for file exports')
    args = ap.parse_args()

    check_tshark()
    pcap = args.pcap
    outdir = args.outdir or (Path(pcap).stem + '_tshark_out')

    print(f'[*] Analysing: {pcap}')

    dispatch = {
        'all':          lambda: mode_all(pcap, outdir),
        'streams':      lambda: mode_streams(pcap),
        'http-files':   lambda: mode_http_files(pcap, outdir),
        'credentials':  lambda: mode_credentials(pcap),
        'dns':          lambda: mode_dns(pcap),
        'conversations':lambda: mode_conversations(pcap),
        'follow':       lambda: mode_follow(pcap, args.stream, args.proto),
        'decode-as':    lambda: mode_decode_as(pcap, args.port, args.proto),
        'voip':         lambda: mode_voip(pcap, outdir),
    }
    dispatch[args.mode]()


if __name__ == '__main__':
    main()
