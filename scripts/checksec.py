#!/usr/bin/env python3
"""
checksec.py — Check binary security mitigations for CTF pwn challenges.
Detects: NX/DEP, Stack Canary, PIE/ASLR, RELRO, FORTIFY, RPATH issues.
Usage: python3 checksec.py <binary> [binary2 ...]
"""

import sys
import re
import subprocess
from pathlib import Path


def run(cmd):
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)
        return r.stdout + r.stderr
    except Exception as e:
        return ''


def check_elf(path):
    print(f"\n{'='*60}")
    print(f"  {path}")
    print('='*60)

    out_sec   = run(f'readelf -S "{path}" 2>/dev/null')
    out_sym   = run(f'readelf -s "{path}" 2>/dev/null')
    out_dyn   = run(f'readelf -d "{path}" 2>/dev/null')
    out_hdr   = run(f'readelf -h "{path}" 2>/dev/null')
    out_file  = run(f'file "{path}" 2>/dev/null')

    results = {}

    # Architecture
    arch_m = re.search(r'Machine:\s+(.+)', out_hdr)
    cls_m  = re.search(r'Class:\s+(ELF\w+)', out_hdr)
    results['arch'] = arch_m.group(1).strip() if arch_m else '?'
    results['bits'] = '64-bit' if 'ELF64' in (cls_m.group(1) if cls_m else '') else '32-bit'

    # NX (Non-executable stack)
    nx_out = run(f'readelf -l "{path}" 2>/dev/null')
    if 'GNU_STACK' in nx_out:
        stack_line = [l for l in nx_out.splitlines() if 'GNU_STACK' in l]
        if stack_line:
            nx = 'RWE' not in stack_line[0] and ' E ' not in stack_line[0].split('GNU_STACK')[1][:20]
        else:
            nx = True
    else:
        nx = False
    results['NX'] = nx

    # Stack Canary
    canary = '__stack_chk_fail' in out_sym or 'stack_chk' in out_sym
    results['Canary'] = canary

    # PIE
    pie_m = re.search(r'Type:\s+(DYN|EXEC)', out_hdr)
    pie = pie_m and pie_m.group(1) == 'DYN'
    # Double-check: shared objects can also be DYN but not PIE
    if pie and 'pie' not in out_file.lower():
        # check if it has a base address of 0
        interp = run(f'readelf -l "{path}" 2>/dev/null')
        pie = 'INTERP' in interp  # real executable, not just .so
    results['PIE'] = pie

    # RELRO
    if 'GNU_RELRO' in out_sec or 'GNU_RELRO' in nx_out:
        if 'BIND_NOW' in out_dyn or 'FLAGS_1' in out_dyn and 'NOW' in out_dyn:
            relro = 'Full'
        else:
            relro = 'Partial'
    else:
        relro = 'None'
    results['RELRO'] = relro

    # FORTIFY
    fortify = '_chk@' in out_sym or '__fprintf_chk' in out_sym or '__printf_chk' in out_sym
    results['FORTIFY'] = fortify

    # Stripped
    stripped = 'not stripped' not in out_file
    results['Stripped'] = stripped

    # RPATH / RUNPATH (DLL hijack risk)
    rpath = 'RPATH' in out_dyn or 'RUNPATH' in out_dyn
    results['RPATH'] = rpath

    # Print results
    def status(val, good_if_true=True):
        good = val if good_if_true else not val
        color = '\033[32m' if good else '\033[31m'
        reset = '\033[0m'
        return f"{color}{'✓' if val else '✗'}{reset}"

    print(f"  Arch:     {results['bits']} {results['arch']}")
    print(f"  NX:       {status(results['NX'])}  {'enabled' if results['NX'] else 'DISABLED — stack/heap executable!'}")
    print(f"  Canary:   {status(results['Canary'])}  {'present' if results['Canary'] else 'NONE — stack overflow no canary check'}")
    print(f"  PIE:      {status(results['PIE'])}  {'enabled (ASLR)' if results['PIE'] else 'DISABLED — fixed base address'}")
    print(f"  RELRO:    {status(results['RELRO'] != 'None')}  {results['RELRO']}")
    print(f"  FORTIFY:  {status(results['FORTIFY'])}  {'enabled' if results['FORTIFY'] else 'not used'}")
    print(f"  Stripped: {'yes (harder to debug)' if results['Stripped'] else 'no (symbols present)'}")
    if results['RPATH']:
        print(f"  RPATH:    \033[31m✗  set — potential DLL hijack\033[0m")

    # Attack surface summary
    print(f"\n  [ATTACK SURFACE]")
    if not results['NX']:
        print("  → NX disabled: shellcode injection possible (jmp esp / call eax)")
    if not results['Canary']:
        print("  → No canary: classic stack buffer overflow to overwrite return address")
    if not results['PIE']:
        print("  → No PIE: gadget addresses are fixed — ROP chain without leaking addresses")
    if results['RELRO'] == 'None':
        print("  → No RELRO: GOT entries writable — GOT overwrite / PLT hijack possible")
    elif results['RELRO'] == 'Partial':
        print("  → Partial RELRO: GOT still writable after relocation")
    if not results['NX'] and not results['Canary'] and not results['PIE']:
        print("  → Ideal ret2shellcode target")
    elif not results['Canary'] and not results['PIE']:
        print("  → Good ret2plt / ret2libc target")
    elif results['Canary'] and not results['PIE']:
        print("  → Need canary leak first, then fixed-address ROP")


def main():
    if len(sys.argv) < 2:
        print("Usage: python3 checksec.py <binary> [binary2 ...]")
        sys.exit(1)

    for path in sys.argv[1:]:
        if not Path(path).exists():
            print(f"[!] Not found: {path}")
            continue
        try:
            check_elf(path)
        except Exception as e:
            print(f"[!] Error analysing {path}: {e}")


if __name__ == '__main__':
    main()
