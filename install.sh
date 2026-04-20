#!/usr/bin/env bash
# CTF Helper — Linux / macOS installer
set -e

REPO_DIR="$(cd "$(dirname "$0")" && pwd)"
SCRIPTS_DIR="$REPO_DIR/scripts"
CONFIG_FILE="$HOME/.ctf_navigator.json"

echo "================================================"
echo "  CTF Helper Installer"
echo "================================================"
echo ""

# ── Python 3 ──────────────────────────────────────────────────────────────────
if ! command -v python3 &>/dev/null; then
    echo "[!] Python 3 not found."
    if [[ "$OSTYPE" == "darwin"* ]]; then
        echo "    Install with: brew install python3"
    else
        echo "    Install with: sudo apt install python3 python3-pip"
    fi
    exit 1
fi

PY_VER=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
echo "[+] Python $PY_VER found"

# ── pip ───────────────────────────────────────────────────────────────────────
if ! python3 -m pip --version &>/dev/null; then
    echo "[!] pip not found. Install python3-pip first."
    exit 1
fi
echo "[+] pip found"

# ── tkinter ───────────────────────────────────────────────────────────────────
if ! python3 -c "import tkinter" &>/dev/null 2>&1; then
    echo "[!] tkinter not found."
    if command -v apt &>/dev/null; then
        echo "[*] Installing python3-tk..."
        sudo apt install -y python3-tk
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        echo "    On macOS: brew install python-tk"
        echo "    Or install Python from python.org (includes tkinter)"
        exit 1
    else
        echo "    Install the python3-tk package for your distro."
        exit 1
    fi
fi
echo "[+] tkinter found"

# ── Core script dependencies ───────────────────────────────────────────────────
echo ""
echo "[*] Installing core Python dependencies..."
python3 -m pip install --quiet --upgrade \
    pyinstaller \
    Pillow \
    pycryptodome \
    scapy

# ── Optional but useful ────────────────────────────────────────────────────────
echo "[*] Installing optional dependencies (gmpy2 for RSA, pyshark)..."
python3 -m pip install --quiet gmpy2 pyshark 2>/dev/null || true

# ── Write config ──────────────────────────────────────────────────────────────
echo ""
echo "[*] Writing config → $CONFIG_FILE"
python3 - << PYEOF
import json, pathlib
cfg_path = pathlib.Path("$CONFIG_FILE")
cfg = {}
if cfg_path.exists():
    try:
        cfg = json.loads(cfg_path.read_text())
    except Exception:
        pass
cfg["scripts"] = "$SCRIPTS_DIR"
cfg_path.write_text(json.dumps(cfg, indent=2))
print(f"    scripts path: $SCRIPTS_DIR")
PYEOF

# ── Build executable (optional) ───────────────────────────────────────────────
echo ""
read -r -p "[?] Build standalone executable now? [y/N] " BUILD_NOW
if [[ "$BUILD_NOW" =~ ^[Yy]$ ]]; then
    bash "$REPO_DIR/build.sh"
else
    echo "[*] Skipped. Run ./build.sh whenever you want the executable."
fi

echo ""
echo "================================================"
echo "[+] Installation complete!"
echo ""
echo "  Run the navigator:  python3 $REPO_DIR/ctf_navigator.py"
if [[ -f "$REPO_DIR/dist/ctf_navigator" ]]; then
echo "  Or the executable:  $REPO_DIR/dist/ctf_navigator"
fi
echo ""
echo "  Scripts live in:    $SCRIPTS_DIR"
echo "  Config file:        $CONFIG_FILE"
echo "================================================"
