#!/usr/bin/env python3
"""
sql_inspector.py — Inspect SQLite databases for CTF challenges.
Dumps schema, searches for flag patterns, extracts blobs.
Usage: python3 sql_inspector.py <database.db> [--search PATTERN] [--blobs]
"""

import sys
import sqlite3
import re
import argparse
import os
from pathlib import Path


FLAG_RE = re.compile(r'(?:CTF|FLAG|OSC|DUCTF|HTB|picoCTF|flag)\{[^}]{1,200}\}', re.IGNORECASE)
HEX_RE  = re.compile(r'[0-9a-fA-F]{32,}')


def dump_schema(conn):
    cur = conn.execute("SELECT name, type, sql FROM sqlite_master WHERE sql IS NOT NULL ORDER BY type, name")
    print("\n[SCHEMA]")
    for name, kind, sql in cur.fetchall():
        print(f"  [{kind}] {name}")
        if sql:
            print(f"    {sql}")


def search_table(conn, table, search_re=None):
    try:
        cur = conn.execute(f'SELECT * FROM "{table}" LIMIT 5000')
        cols = [d[0] for d in cur.description]
        rows = cur.fetchall()
        print(f"\n[TABLE] {table}  ({len(rows)} rows shown, cols: {', '.join(cols)})")

        hits = []
        for row in rows:
            for i, val in enumerate(row):
                if val is None:
                    continue
                sval = str(val)
                # Flag search
                m = FLAG_RE.search(sval)
                if m:
                    hits.append(f"  [FLAG] col={cols[i]}: {m.group()}")
                # Custom search
                if search_re and search_re.search(sval):
                    hits.append(f"  [MATCH] col={cols[i]}: {sval[:200]}")
                # Hex strings
                h = HEX_RE.search(sval)
                if h and len(h.group()) >= 64:
                    hits.append(f"  [HEX] col={cols[i]}: {h.group()[:80]}...")

        if hits:
            print("\n".join(hits))
        else:
            # Print first 3 rows as preview
            for row in rows[:3]:
                print("  " + " | ".join(str(v)[:60] if v is not None else "NULL" for v in row))

    except Exception as e:
        print(f"  [error reading table {table}]: {e}")


def extract_blobs(conn, table, outdir):
    try:
        cur = conn.execute(f'SELECT * FROM "{table}" LIMIT 1000')
        cols = [d[0] for d in cur.description]
        rows = cur.fetchall()
        for row_i, row in enumerate(rows):
            for col_i, val in enumerate(row):
                if isinstance(val, bytes) and len(val) > 8:
                    fname = outdir / f"{table}_{row_i}_{cols[col_i]}.bin"
                    fname.write_bytes(val)
                    print(f"  [BLOB] Saved {len(val)} bytes → {fname}")
    except Exception as e:
        print(f"  [error extracting blobs from {table}]: {e}")


def main():
    ap = argparse.ArgumentParser(description="CTF SQLite Inspector")
    ap.add_argument("db", help="SQLite database file")
    ap.add_argument("--search", "-s", default=None, help="Extra search pattern (regex)")
    ap.add_argument("--blobs", "-b", action="store_true", help="Extract BLOB columns to files")
    args = ap.parse_args()

    db_path = Path(args.db)
    if not db_path.exists():
        print(f"[!] File not found: {db_path}")
        sys.exit(1)

    # Check magic bytes
    raw = db_path.read_bytes()[:16]
    if not raw.startswith(b'SQLite format 3'):
        print(f"[!] Warning: file does not look like SQLite (magic={raw[:16]})")

    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row

    search_re = re.compile(args.search, re.IGNORECASE) if args.search else None

    dump_schema(conn)

    # Get all tables and views
    tables = [r[0] for r in conn.execute(
        "SELECT name FROM sqlite_master WHERE type IN ('table','view') ORDER BY name"
    ).fetchall()]

    print(f"\n[*] Found {len(tables)} table(s): {tables}")

    blob_dir = db_path.parent / (db_path.stem + "_blobs")
    if args.blobs:
        blob_dir.mkdir(exist_ok=True)

    for table in tables:
        search_table(conn, table, search_re)
        if args.blobs:
            extract_blobs(conn, table, blob_dir)

    # Also search sqlite_master itself for embedded data
    print("\n[*] Checking sqlite_master for unusual entries...")
    for row in conn.execute("SELECT type, name, sql FROM sqlite_master"):
        sval = " ".join(str(v) for v in row if v)
        m = FLAG_RE.search(sval)
        if m:
            print(f"  [FLAG in metadata] {m.group()}")

    conn.close()


if __name__ == "__main__":
    main()
