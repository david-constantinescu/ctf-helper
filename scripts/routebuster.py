#!/usr/bin/env python3
import asyncio
import argparse
import os
import sys
from urllib.parse import urljoin

try:
    import aiohttp
except Exception:
    print("aiohttp not found — attempting to install via pip...")
    import subprocess
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", "aiohttp"])
        import aiohttp
    except Exception:
        print("Automatic install failed. Please install aiohttp manually: pip install aiohttp")
        sys.exit(1)

DEFAULT_DIRB_PATHS = [
    "/usr/share/dirb/wordlists/common.txt",
    "/usr/local/share/dirb/wordlists/common.txt",
]

FALLBACK_WORDS = [
    "admin",
    "login",
    "uploads",
    "images",
    "css",
    "js",
    "api",
    "config",
    "backup",
    "test",
]


def load_wordlist(path: str = None):
    if path:
        if os.path.isfile(path):
            with open(path, "r", errors="ignore") as f:
                return [l.strip() for l in f if l.strip() and not l.startswith("#")]
        else:
            print(f"Wordlist not found at {path}, falling back to system locations.")

    for p in DEFAULT_DIRB_PATHS:
        if os.path.isfile(p):
            with open(p, "r", errors="ignore") as f:
                return [l.strip() for l in f if l.strip() and not l.startswith("#")]

    return FALLBACK_WORDS


async def fetch_one(session, url, sem, timeout):
    async with sem:
        try:
            async with session.get(url, allow_redirects=False, timeout=timeout) as resp:
                status = resp.status
                length = resp.headers.get("Content-Length")
                return url, status, length
        except Exception as e:
            return url, None, None


async def run_scan(base_url, words, concurrency, timeout, extensions):
    # generate targets
    base = base_url.rstrip("/") + "/"
    targets = set()
    for w in words:
        w = w.lstrip("/")
        if not w:
            continue
        targets.add(urljoin(base, w))
        targets.add(urljoin(base, w + "/"))
        for ext in extensions:
            if ext:
                targets.add(urljoin(base, w + ext))

    conn = aiohttp.TCPConnector(limit=0, ssl=False)
    timeout_obj = aiohttp.ClientTimeout(total=None, sock_connect=timeout, sock_read=timeout)
    sem = asyncio.Semaphore(concurrency)
    async with aiohttp.ClientSession(connector=conn, timeout=timeout_obj) as session:
        tasks = [asyncio.create_task(fetch_one(session, t, sem, timeout_obj)) for t in targets]
        results = []
        for fut in asyncio.as_completed(tasks):
            url, status, length = await fut
            # filter out obvious not-found / errors
            if status is None:
                continue
            if status == 404:
                continue
            results.append((status, url, length))
    return sorted(results, key=lambda x: (-x[0], x[1]))


def normalize_url(url: str):
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "http://" + url
    return url


def parse_extensions(ext_str: str):
    if not ext_str:
        return [""]
    parts = [p.strip() for p in ext_str.split(",") if p.strip()]
    normalized = []
    for p in parts:
        if not p.startswith("."):
            p = "." + p
        normalized.append(p)
    normalized.append("")
    return normalized


def main():
    parser = argparse.ArgumentParser(description="Fast async route scanner (uses dirb common wordlist if available)")
    parser.add_argument("-w", "--wordlist", help="Path to wordlist (optional)")
    parser.add_argument("-c", "--concurrency", type=int, default=200, help="Concurrent requests (default 200)")
    parser.add_argument("-t", "--timeout", type=float, default=10.0, help="Socket timeout seconds (default 10)")
    parser.add_argument("-e", "--ext", help="Comma-separated extensions to try (e.g. php,html)")
    args = parser.parse_args()
    # prompt for target URL via input() per user request
    base_input = input("Target URL (e.g. https://example.com): ").strip()
    if not base_input:
        print("No target provided. Exiting.")
        return
    base_url = normalize_url(base_input)
    words = load_wordlist(args.wordlist)
    extensions = parse_extensions(args.ext)

    # use asyncio.run() to avoid event loop deprecation issues
    results = asyncio.run(run_scan(base_url, words, args.concurrency, args.timeout, extensions))

    if not results:
        print("No interesting responses found.")
        return

    for status, url, length in results:
        tag = ""
        if 200 <= status < 300:
            tag = "OK"
        elif 300 <= status < 400:
            tag = "REDIR"
        elif status == 403:
            tag = "FORBIDDEN"
        else:
            tag = "STATUS"
        print(f"{status}\t{tag}\t{url}\t{length or '-'}")


if __name__ == "__main__":
    main()
