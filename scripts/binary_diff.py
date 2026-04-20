#!/usr/bin/env python3
"""
binary_diff.py — Compare two binaries byte-by-byte for CTF patch analysis.
Shows changed bytes, identifies patched instructions, and highlights NOP sleds.
Usage: python3 binary_diff.py <original> <patched> [--context N] [--asm]
"""

import sys
import argparse
from pathlib import Path


def run(cmd):
    import subprocess
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)
        return r.stdout
    except Exception:
        return ''


def diff_binaries(orig_bytes, patch_bytes, context=4):
    diffs = []
    length = max(len(orig_bytes), len(patch_bytes))
    i = 0
    while i < length:
        ob = orig_bytes[i] if i < len(orig_bytes) else None
        pb = patch_bytes[i] if i < len(patch_bytes) else None
        if ob != pb:
            # Collect run of differing bytes
            start = i
            changed_orig  = []
            changed_patch = []
            while i < length:
                o = orig_bytes[i] if i < len(orig_bytes) else None
                p = patch_bytes[i] if i < len(patch_bytes) else None
                if o == p and i > start + 1:
                    break
                changed_orig.append(o)
                changed_patch.append(p)
                i += 1
            diffs.append((start, changed_orig, changed_patch))
        else:
            i += 1
    return diffs


def is_nop(b):
    return b == 0x90


def classify_patch(orig_bytes, patch_bytes):
    """Try to classify what kind of patch was applied."""
    o = [b for b in orig_bytes if b is not None]
    p = [b for b in patch_bytes if b is not None]

    if all(b == 0x90 for b in p):
        return "NOP sled — instruction was patched out"
    if all(b == 0x00 for b in p):
        return "Zeroed out"
    if len(p) == 1:
        # Jump condition flips
        jump_flips = {
            0x74: (0x75, "je  → jne"),
            0x75: (0x74, "jne → je"),
            0x7c: (0x7d, "jl  → jge"),
            0x7d: (0x7c, "jge → jl"),
            0x7e: (0x7f, "jle → jg"),
            0x7f: (0x7e, "jg  → jle"),
            0x72: (0x73, "jb  → jae"),
            0x73: (0x72, "jae → jb"),
        }
        if o and o[0] in jump_flips and p[0] == jump_flips[o[0]][0]:
            return f"Jump flip: {jump_flips[o[0]][1]}"
        if o and o[0] == 0xeb and p[0] in (0x74, 0x75, 0x7c, 0x7d):
            return "Short jump changed to conditional"
    if len(p) >= 2 and p[0] == 0xeb:
        return "Patched to short jump (jmp)"
    if len(p) >= 5 and p[0] == 0xe9:
        return "Patched to long jump (jmp rel32)"
    if len(o) >= 1 and o[0] == 0xc3 and p[0] != 0xc3:
        return "ret removed"
    if p and p[-1] == 0xc3:
        return "ret inserted / early return added"
    return None


def main():
    ap = argparse.ArgumentParser(description='Binary Diff for CTF Patch Analysis')
    ap.add_argument('original', help='Original binary')
    ap.add_argument('patched',  help='Patched binary')
    ap.add_argument('--context', '-c', type=int, default=8,
                    help='Bytes of context around each diff (default: 8)')
    ap.add_argument('--asm', '-a', action='store_true',
                    help='Disassemble changed regions with objdump')
    ap.add_argument('--max', '-m', type=int, default=50,
                    help='Max diffs to show (default: 50)')
    args = ap.parse_args()

    orig_bytes  = Path(args.original).read_bytes()
    patch_bytes = Path(args.patched).read_bytes()

    print(f"[*] Original: {args.original}  ({len(orig_bytes)} bytes)")
    print(f"[*] Patched:  {args.patched}   ({len(patch_bytes)} bytes)")
    print(f"[*] Size diff: {len(patch_bytes) - len(orig_bytes):+d} bytes")

    diffs = diff_binaries(orig_bytes, patch_bytes, args.context)
    print(f"\n[+] {len(diffs)} difference region(s) found\n")

    for n, (offset, orig_run, patch_run) in enumerate(diffs[:args.max]):
        classification = classify_patch(orig_run, patch_run)

        print(f"--- Diff #{n+1} at offset {hex(offset)} ({offset}) ---")
        if classification:
            print(f"    [!] {classification}")

        # Context before
        ctx_start = max(0, offset - args.context)
        ctx_orig  = orig_bytes[ctx_start:offset]
        ctx_patch = patch_bytes[ctx_start:offset]

        def fmt_bytes(blist, highlight_start=None, highlight_len=None):
            parts = []
            for i, b in enumerate(blist):
                if b is None:
                    parts.append('??')
                elif highlight_start is not None and highlight_start <= i < highlight_start + highlight_len:
                    parts.append(f'\033[31m{b:02x}\033[0m')
                else:
                    parts.append(f'{b:02x}')
            return ' '.join(parts)

        ctx_len = len(ctx_orig)
        orig_display  = list(ctx_orig)  + [b for b in orig_run  if b is not None] + list(orig_bytes[offset+len(orig_run):offset+len(orig_run)+args.context])
        patch_display = list(ctx_patch) + [b for b in patch_run if b is not None] + list(patch_bytes[offset+len(patch_run):offset+len(patch_run)+args.context])

        print(f"    ORIG  {hex(ctx_start)}: {fmt_bytes(orig_display, ctx_len, len(orig_run))}")
        print(f"    PATCH {hex(ctx_start)}: {fmt_bytes(patch_display, ctx_len, len(patch_run))}")

        changed_o = bytes(b for b in orig_run  if b is not None)
        changed_p = bytes(b for b in patch_run if b is not None)
        print(f"    Changed: [{changed_o.hex()}] → [{changed_p.hex()}]")

        if args.asm:
            # Disassemble the region using objdump
            import tempfile, os
            # Write a tiny binary snippet to a temp file
            region_orig  = orig_bytes[max(0, offset-4):offset+len(orig_run)+4]
            region_patch = patch_bytes[max(0, offset-4):offset+len(patch_run)+4]
            for label, data in [('ORIG', region_orig), ('PATCH', region_patch)]:
                with tempfile.NamedTemporaryFile(delete=False, suffix='.bin') as tf:
                    tf.write(data)
                    tf_name = tf.name
                asm_out = run(f'objdump -D -b binary -m i386:x86-64 "{tf_name}" 2>/dev/null | tail -n +8 | head -20')
                os.unlink(tf_name)
                if asm_out.strip():
                    print(f"    [{label} disasm]")
                    for line in asm_out.strip().splitlines()[:8]:
                        print(f"      {line}")
        print()

    if len(diffs) > args.max:
        print(f"[*] Showing {args.max}/{len(diffs)} diffs. Use --max N to see more.")

    # Summary
    if diffs:
        print("[SUMMARY]")
        classifications = [classify_patch(o, p) for _, o, p in diffs if classify_patch(o, p)]
        for c in set(classifications):
            print(f"  {classifications.count(c)}x {c}")
        print(f"\n  Hint: Open both files in Ghidra, use 'Version Tracking' for side-by-side diff")


if __name__ == '__main__':
    main()
