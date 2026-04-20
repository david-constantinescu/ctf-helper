#!/usr/bin/env bash
# CTF Helper — build standalone executable (Linux / macOS)
set -e

cd "$(dirname "$0")"

if ! command -v pyinstaller &>/dev/null; then
    echo "[*] Installing PyInstaller..."
    pip3 install --quiet pyinstaller
fi

echo "[*] Building CTF Navigator..."
pyinstaller \
    --onefile \
    --name ctf_navigator \
    --windowed \
    ctf_navigator.py

echo ""
echo "[+] Done! Executable: dist/ctf_navigator"
echo "    Launch with: ./dist/ctf_navigator"
echo "    Or double-click it in your file manager."
