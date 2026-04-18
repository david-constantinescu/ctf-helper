#!/usr/bin/env python3
"""
JAR Decompiler CLI
Decompiles a JAR file's .class files into Java source code and writes everything to a single .txt file.

Requires: Java runtime (java) installed and on PATH.
On first run, downloads the CFR decompiler JAR automatically.
"""

import argparse
import os
import sys
import zipfile
import tempfile
import shutil
import subprocess
import urllib.request

CFR_VERSION = "0.152"
CFR_JAR_NAME = f"cfr-{CFR_VERSION}.jar"
CFR_URL = f"https://github.com/leibnitz27/cfr/releases/download/{CFR_VERSION}/{CFR_JAR_NAME}"


def get_cfr_path() -> str:
    """Return the path to the CFR decompiler JAR, downloading it if needed."""
    cfr_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".decompiler_cache")
    cfr_path = os.path.join(cfr_dir, CFR_JAR_NAME)

    if os.path.isfile(cfr_path):
        return cfr_path

    os.makedirs(cfr_dir, exist_ok=True)
    print(f"[*] Downloading CFR decompiler v{CFR_VERSION} ...")
    try:
        urllib.request.urlretrieve(CFR_URL, cfr_path)
        print(f"[+] Saved to {cfr_path}")
    except Exception as e:
        print(f"[!] Failed to download CFR: {e}", file=sys.stderr)
        sys.exit(1)

    return cfr_path


def check_java() -> str:
    """Verify that java is available and return the path."""
    java = shutil.which("java")
    if java is None:
        print("[!] Error: 'java' not found on PATH. Install a JRE/JDK first.", file=sys.stderr)
        sys.exit(1)
    return java


def decompile_jar(jar_path: str, output_txt: str) -> None:
    jar_path = os.path.abspath(jar_path)

    if not os.path.isfile(jar_path):
        print(f"[!] File not found: {jar_path}", file=sys.stderr)
        sys.exit(1)

    # Check file size
    file_size = os.path.getsize(jar_path)
    if file_size == 0:
        print(f"[!] File is empty (0 bytes): {jar_path}", file=sys.stderr)
        print("[!] Please provide a valid JAR file.", file=sys.stderr)
        sys.exit(1)

    if not zipfile.is_zipfile(jar_path):
        print(f"[!] Not a valid JAR/ZIP file: {jar_path}", file=sys.stderr)
        print(f"[!] File size: {file_size} bytes", file=sys.stderr)
        print("[!] JAR files must be valid ZIP archives containing .class files.", file=sys.stderr)
        sys.exit(1)

    java = check_java()
    cfr_path = get_cfr_path()

    # Count .class files for progress info
    with zipfile.ZipFile(jar_path, "r") as zf:
        class_files = [n for n in zf.namelist() if n.endswith(".class")]

    if not class_files:
        print("[!] No .class files found in the JAR.")
        sys.exit(0)

    print(f"[*] Found {len(class_files)} .class file(s) in {os.path.basename(jar_path)}")
    print(f"[*] Decompiling with CFR ...")

    # Use a temp directory for CFR output
    with tempfile.TemporaryDirectory(prefix="decompile_") as tmpdir:
        cmd = [
            java, "-jar", cfr_path,
            jar_path,
            "--outputdir", tmpdir,
            "--silent", "true",
        ]

        result = subprocess.run(cmd, capture_output=True, text=True)

        if result.returncode != 0:
            stderr = result.stderr.strip()
            print(f"[!] CFR returned exit code {result.returncode}", file=sys.stderr)
            if stderr:
                print(stderr, file=sys.stderr)
            # Continue anyway — partial output may still be useful

        # Collect all .java files from the output directory
        java_files: list[tuple[str, str]] = []
        for root, _dirs, files in os.walk(tmpdir):
            for fname in sorted(files):
                if fname.endswith(".java"):
                    full = os.path.join(root, fname)
                    rel = os.path.relpath(full, tmpdir)
                    java_files.append((rel, full))

        java_files.sort(key=lambda x: x[0])

        if not java_files:
            print("[!] CFR produced no output. The JAR may not contain decompilable classes.")
            sys.exit(1)

        # Write everything into one .txt file
        separator = "=" * 80
        with open(output_txt, "w", encoding="utf-8") as out:
            out.write(f"// Decompiled from: {os.path.basename(jar_path)}\n")
            out.write(f"// Classes: {len(java_files)}\n")
            out.write(f"// Decompiler: CFR {CFR_VERSION}\n")
            out.write(f"{separator}\n\n")

            for i, (rel_path, abs_path) in enumerate(java_files, 1):
                out.write(f"{separator}\n")
                out.write(f"// File: {rel_path}\n")
                out.write(f"{separator}\n\n")
                try:
                    with open(abs_path, "r", encoding="utf-8", errors="replace") as f:
                        out.write(f.read())
                except OSError as e:
                    out.write(f"// Error reading file: {e}\n")
                out.write("\n\n")

    print(f"[+] Decompiled {len(java_files)} class(es)")
    print(f"[+] Output written to: {output_txt}")


def main():
    parser = argparse.ArgumentParser(
        description="Decompile a JAR file and write all Java source code to a .txt file."
    )
    parser.add_argument("jar", help="Path to the .jar file to decompile")
    parser.add_argument(
        "-o", "--output",
        help="Output .txt file path (default: <jar_name>_decompiled.txt in same directory)",
        default=None,
    )
    args = parser.parse_args()

    jar_path = os.path.abspath(args.jar)

    if args.output:
        output_txt = os.path.abspath(args.output)
    else:
        jar_dir = os.path.dirname(jar_path)
        jar_base = os.path.splitext(os.path.basename(jar_path))[0]
        output_txt = os.path.join(jar_dir, f"{jar_base}_decompiled.txt")

    decompile_jar(jar_path, output_txt)


if __name__ == "__main__":
    main()
