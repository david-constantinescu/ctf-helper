#!/usr/bin/env python3
"""
entropy_scanner.py — find encrypted/compressed regions by measuring byte entropy per block
High entropy (>7.0) usually means encrypted or compressed data.
"""

import sys
import math
import argparse
from pathlib import Path

def shannon_entropy(block: bytes) -> float:
    if not block:
        return 0.0
    counts = [0] * 256
    for b in block:
        counts[b] += 1
    n = len(block)
    entropy = 0.0
    for c in counts:
        if c:
            p = c / n
            entropy -= p * math.log2(p)
    return entropy

def classify(entropy: float) -> str:
    if entropy >= 7.5:
        return "ENCRYPTED/COMPRESSED"
    elif entropy >= 6.5:
        return "likely compressed"
    elif entropy >= 5.0:
        return "mixed/code"
    elif entropy >= 3.0:
        return "text/structured"
    else:
        return "low (nulls/repetitive)"

def bar(entropy: float, width: int = 40) -> str:
    filled = int(entropy / 8.0 * width)
    return "[" + "#" * filled + "." * (width - filled) + f"] {entropy:.3f}"

def merge_regions(regions: list[tuple[int, int, float]], gap: int) -> list[tuple[int, int, float]]:
    if not regions:
        return []
    merged = [list(regions[0])]
    for start, end, ent in regions[1:]:
        if start - merged[-1][1] <= gap:
            merged[-1][1] = end
            merged[-1][2] = max(merged[-1][2], ent)
        else:
            merged.append([start, end, ent])
    return [tuple(r) for r in merged]

def main():
    parser = argparse.ArgumentParser(description="Scan a binary for high-entropy (encrypted/compressed) regions")
    parser.add_argument("input", help="Input file")
    parser.add_argument("-b", "--block-size", type=int, default=256, help="Block size in bytes (default: 256)")
    parser.add_argument("-t", "--threshold", type=float, default=7.0, help="Entropy threshold to flag (default: 7.0)")
    parser.add_argument("--all", action="store_true", help="Print entropy for every block, not just high ones")
    parser.add_argument("--no-bar", action="store_true", help="Suppress ASCII bar chart")
    parser.add_argument("-o", "--output", default=None, help="Save report to file")
    args = parser.parse_args()

    in_path = Path(args.input)
    if not in_path.exists():
        print(f"[!] File not found: {in_path}")
        sys.exit(1)

    data = in_path.read_bytes()
    size = len(data)
    block = args.block_size

    print(f"[*] File: {in_path}  ({size:,} bytes)")
    print(f"[*] Block size: {block}  |  Threshold: {args.threshold}\n")

    high_regions = []
    lines = []
    num_blocks = (size + block - 1) // block

    for i in range(num_blocks):
        start = i * block
        chunk = data[start:start + block]
        ent = shannon_entropy(chunk)
        label = classify(ent)
        flagged = ent >= args.threshold

        if flagged:
            high_regions.append((start, start + len(chunk), ent))

        if args.all or flagged:
            b = "" if args.no_bar else "  " + bar(ent)
            line = f"  0x{start:08x} - 0x{start+len(chunk):08x}  {b}  {label}"
            lines.append(line)
            marker = "  <<< HIGH ENTROPY" if flagged else ""
            print(line + marker)

    # Merge adjacent high-entropy blocks
    merged = merge_regions(high_regions, gap=block * 2)

    print(f"\n{'='*60}")
    print(f"[*] Blocks scanned: {num_blocks}")
    print(f"[*] High-entropy blocks (>= {args.threshold}): {len(high_regions)}")
    if merged:
        print(f"\n[!!!] Suspicious regions ({len(merged)}):")
        for start, end, max_ent in merged:
            print(f"  0x{start:08x} - 0x{end:08x}  ({end-start:,} bytes)  max_entropy={max_ent:.3f}")
    else:
        print("[*] No high-entropy regions found.")

    if args.output:
        out_path = Path(args.output)
        report = [f"Entropy scan: {in_path}", f"Block size: {block}, Threshold: {args.threshold}", ""] + lines
        if merged:
            report += ["", "Suspicious regions:"]
            for start, end, max_ent in merged:
                report.append(f"  0x{start:08x} - 0x{end:08x}  ({end-start} bytes)  max_entropy={max_ent:.3f}")
        out_path.write_text("\n".join(report), encoding="utf-8")
        print(f"\n[*] Report saved to {out_path}")

if __name__ == "__main__":
    main()
