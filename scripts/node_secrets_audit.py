#!/usr/bin/env python3
"""
node_secrets_audit.py — Scan Node.js / JavaScript projects for secrets and flags.
Finds: hardcoded API keys, passwords, JWTs, flag patterns, suspicious eval/exec,
       typosquatted packages, malicious npm scripts, and prototype pollution.
Usage: python3 node_secrets_audit.py <directory_or_file>
       python3 node_secrets_audit.py . --deep
"""

import sys
import re
import json
import argparse
from pathlib import Path


FLAG_RE = re.compile(r'(?:CTF|FLAG|OSC|DUCTF|HTB|picoCTF|flag)\{[^}]{1,200}\}', re.IGNORECASE)

SECRET_PATTERNS = [
    ('API key (generic)',       re.compile(r'["\']?(?:api[_-]?key|apikey)["\']?\s*[:=]\s*["\']([A-Za-z0-9_\-]{20,})["\']', re.IGNORECASE)),
    ('Password (hardcoded)',    re.compile(r'["\']?(?:password|passwd|pwd|secret)["\']?\s*[:=]\s*["\']([^"\']{4,})["\']', re.IGNORECASE)),
    ('JWT token',               re.compile(r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+')),
    ('AWS key',                 re.compile(r'AKIA[0-9A-Z]{16}')),
    ('Private key header',      re.compile(r'-----BEGIN (?:RSA |EC )?PRIVATE KEY-----')),
    ('GitHub token',            re.compile(r'gh[pousr]_[A-Za-z0-9]{36}')),
    ('Slack token',             re.compile(r'xox[baprs]-[0-9A-Za-z\-]+')),
    ('Hex secret (32+ chars)',  re.compile(r'["\']([0-9a-fA-F]{32,})["\']')),
    ('Base64 secret',           re.compile(r'["\']([A-Za-z0-9+/]{40,}={0,2})["\']')),
    ('Database URL',            re.compile(r'(?:mongodb|mysql|postgres|redis|sqlite)://[^\s\'"]{10,}', re.IGNORECASE)),
    ('Flag pattern',            FLAG_RE),
]

DANGEROUS_JS = [
    ('eval() with variable',    re.compile(r'\beval\s*\([^"\']+\)')),
    ('child_process exec',      re.compile(r'(?:exec|execSync|spawn|spawnSync)\s*\(')),
    ('require from variable',   re.compile(r'\brequire\s*\([^"\']+\)')),
    ('Prototype pollution',     re.compile(r'__proto__|constructor\s*\[|Object\.setPrototypeOf')),
    ('Dynamic import',          re.compile(r'\bimport\s*\([^"\'"]')),
    ('Buffer.from unsafe',      re.compile(r'Buffer\s*\(\s*[^"\'0-9]')),
    ('Command injection risk',  re.compile(r'(?:exec|system)\s*\([^)]*\+[^)]*\)')),
    ('Deserialization',         re.compile(r'unserialize|deserialize|pickle\.loads|yaml\.load\s*\([^)]*Loader', re.IGNORECASE)),
]

# Known CTF-style obfuscated/suspicious package name patterns
TYPOSQUAT_PATTERNS = [
    re.compile(r'^[a-z]+-[a-z]+-[a-z]+$'),  # triple-hyphen names
    re.compile(r'\d{5,}'),                    # lots of digits
]

SUSPICIOUS_PKG_NAMES = [
    'colors', 'faker', 'node-ipc', 'event-stream', 'flatmap-stream',
    'left-pad', 'is-promise',  # historical supply chain incidents
]


def scan_file(path, verbose=True):
    findings = []
    try:
        src = path.read_text(errors='replace')
    except Exception as e:
        return findings

    for name, pattern in SECRET_PATTERNS:
        for m in pattern.finditer(src):
            line_no = src[:m.start()].count('\n') + 1
            findings.append({
                'type': 'secret',
                'name': name,
                'file': str(path),
                'line': line_no,
                'match': m.group()[:200],
            })

    for name, pattern in DANGEROUS_JS:
        for m in pattern.finditer(src):
            line_no = src[:m.start()].count('\n') + 1
            findings.append({
                'type': 'dangerous',
                'name': name,
                'file': str(path),
                'line': line_no,
                'match': m.group()[:200],
            })

    return findings


def scan_package_json(path):
    findings = []
    try:
        data = json.loads(path.read_text())
    except Exception:
        return findings

    # Check scripts for suspicious commands
    scripts = data.get('scripts', {})
    for script_name, cmd in scripts.items():
        if re.search(r'curl|wget|nc |bash|sh -c|python|eval', cmd, re.IGNORECASE):
            findings.append({
                'type': 'suspicious_script',
                'name': f'npm script [{script_name}]',
                'file': str(path),
                'line': 0,
                'match': f'{script_name}: {cmd}',
            })

    # Check dependencies for known bad packages
    all_deps = {}
    for key in ('dependencies', 'devDependencies', 'optionalDependencies'):
        all_deps.update(data.get(key, {}))

    for pkg in all_deps:
        if pkg in SUSPICIOUS_PKG_NAMES:
            findings.append({
                'type': 'suspicious_package',
                'name': f'Known incident package',
                'file': str(path),
                'line': 0,
                'match': pkg,
            })

    # Check for pinned versions with unusual hashes
    lock_path = path.parent / 'package-lock.json'
    if lock_path.exists():
        try:
            lock = json.loads(lock_path.read_text())
            packages = lock.get('packages', lock.get('dependencies', {}))
            for pkg_name, pkg_data in packages.items():
                if isinstance(pkg_data, dict):
                    resolved = pkg_data.get('resolved', '')
                    if resolved and 'registry.npmjs.org' not in resolved and resolved.startswith('http'):
                        findings.append({
                            'type': 'unusual_registry',
                            'name': 'Non-npm registry',
                            'file': str(lock_path),
                            'line': 0,
                            'match': f'{pkg_name}: {resolved[:100]}',
                        })
        except Exception:
            pass

    return findings


def main():
    ap = argparse.ArgumentParser(description="Node.js Secrets & Security Audit for CTF")
    ap.add_argument("target", help="File or directory to scan")
    ap.add_argument("--deep", "-d", action="store_true", help="Also scan node_modules")
    ap.add_argument("--quiet", "-q", action="store_true", help="Only show high-value findings")
    args = ap.parse_args()

    target = Path(args.target)
    all_findings = []

    if target.is_file():
        files = [target]
    else:
        # Collect JS/TS/JSON files
        extensions = ['*.js', '*.ts', '*.jsx', '*.tsx', '*.mjs', '*.cjs', '*.json']
        files = []
        for ext in extensions:
            glob_target = target.rglob if args.deep else target.glob
            # Exclude node_modules unless --deep
            for f in target.rglob(ext) if args.deep else target.glob(f'**/{ext}'):
                if not args.deep and 'node_modules' in f.parts:
                    continue
                files.append(f)

    print(f"[*] Scanning {len(files)} files in {target}")
    print("=" * 60)

    for f in sorted(files):
        if f.name == 'package.json':
            found = scan_package_json(f)
        else:
            found = scan_file(f)

        if found:
            all_findings.extend(found)
            for item in found:
                if args.quiet and item['type'] not in ('secret', 'suspicious_script', 'unusual_registry'):
                    continue
                icon = {'secret': '[!!!]', 'dangerous': '[!]', 'suspicious_script': '[!]',
                        'suspicious_package': '[?]', 'unusual_registry': '[!]'}.get(item['type'], '[*]')
                print(f"{icon} {item['name']}")
                print(f"    File: {item['file']}:{item['line']}")
                print(f"    Match: {item['match'][:150]}")
                print()

    # Summary
    print("=" * 60)
    by_type = {}
    for f in all_findings:
        by_type[f['type']] = by_type.get(f['type'], 0) + 1

    print(f"[SUMMARY] {len(all_findings)} findings:")
    for t, count in sorted(by_type.items()):
        print(f"  {t}: {count}")

    # Collect all flags
    flags = [f['match'] for f in all_findings if FLAG_RE.search(f['match'])]
    if flags:
        print(f"\n[!!!] FLAG MATCHES:")
        for flag in flags:
            m = FLAG_RE.search(flag)
            if m:
                print(f"  {m.group()}")


if __name__ == "__main__":
    main()
