# CTF Helper — Windows installer (PowerShell)
# Run from an elevated or normal PowerShell prompt:
#   Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned
#   .\install.ps1

$ErrorActionPreference = "Stop"

$RepoDir    = Split-Path -Parent $MyInvocation.MyCommand.Path
$ScriptsDir = Join-Path $RepoDir "scripts"
$ConfigFile = Join-Path $env:USERPROFILE ".ctf_navigator.json"

Write-Host "================================================" -ForegroundColor Cyan
Write-Host "  CTF Helper Installer (Windows)"               -ForegroundColor Cyan
Write-Host "================================================" -ForegroundColor Cyan
Write-Host ""

# ── Python 3 ──────────────────────────────────────────────────────────────────
$PyCmd = $null
foreach ($candidate in @("python", "python3", "py")) {
    try {
        $ver = & $candidate --version 2>&1
        if ($ver -match "Python 3\.") {
            $PyCmd = $candidate
            Write-Host "[+] $ver found ($candidate)" -ForegroundColor Green
            break
        }
    } catch {}
}

if (-not $PyCmd) {
    Write-Host "[!] Python 3 not found." -ForegroundColor Red
    Write-Host "    Download from: https://www.python.org/downloads/"
    Write-Host "    Make sure to check 'Add Python to PATH' during install."
    exit 1
}

# ── pip ───────────────────────────────────────────────────────────────────────
try {
    & $PyCmd -m pip --version | Out-Null
    Write-Host "[+] pip found" -ForegroundColor Green
} catch {
    Write-Host "[!] pip not available. Re-install Python with pip included." -ForegroundColor Red
    exit 1
}

# ── tkinter ───────────────────────────────────────────────────────────────────
$TkCheck = & $PyCmd -c "import tkinter; print('ok')" 2>&1
if ($TkCheck -ne "ok") {
    Write-Host "[!] tkinter not found." -ForegroundColor Red
    Write-Host "    Re-install Python from python.org and ensure 'tcl/tk and IDLE' is checked."
    exit 1
}
Write-Host "[+] tkinter found" -ForegroundColor Green

# ── Core dependencies ─────────────────────────────────────────────────────────
Write-Host ""
Write-Host "[*] Installing core Python dependencies..." -ForegroundColor Yellow
& $PyCmd -m pip install --quiet --upgrade pyinstaller Pillow pycryptodome scapy
Write-Host "[+] Core dependencies installed" -ForegroundColor Green

# ── Optional dependencies ─────────────────────────────────────────────────────
Write-Host "[*] Installing optional dependencies (gmpy2 for RSA)..." -ForegroundColor Yellow
try {
    & $PyCmd -m pip install --quiet gmpy2 2>&1 | Out-Null
    Write-Host "[+] gmpy2 installed" -ForegroundColor Green
} catch {
    Write-Host "[~] gmpy2 not available (RSA attacks still work, just slower)" -ForegroundColor DarkYellow
}

# ── Write config ──────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "[*] Writing config -> $ConfigFile" -ForegroundColor Yellow

$ScriptsDirEscaped = $ScriptsDir -replace '\\', '\\\\'
& $PyCmd - << "PYEOF"
import json, pathlib, os
cfg_path = pathlib.Path(os.path.expanduser("~") + "/.ctf_navigator.json")
cfg = {}
if cfg_path.exists():
    try:
        cfg = json.loads(cfg_path.read_text())
    except Exception:
        pass
cfg["scripts"] = r"$ScriptsDir"
cfg_path.write_text(json.dumps(cfg, indent=2))
print("    scripts path: " + cfg["scripts"])
PYEOF

Write-Host "[+] Config written" -ForegroundColor Green

# ── Build executable (optional) ───────────────────────────────────────────────
Write-Host ""
$BuildNow = Read-Host "[?] Build standalone .exe now? [y/N]"
if ($BuildNow -match "^[Yy]$") {
    & "$RepoDir\build.ps1"
} else {
    Write-Host "[*] Skipped. Run .\build.ps1 whenever you want the .exe." -ForegroundColor DarkYellow
}

Write-Host ""
Write-Host "================================================" -ForegroundColor Cyan
Write-Host "[+] Installation complete!" -ForegroundColor Green
Write-Host ""
Write-Host "  Run the navigator:  $PyCmd `"$RepoDir\ctf_navigator.py`""
$ExePath = Join-Path $RepoDir "dist\ctf_navigator.exe"
if (Test-Path $ExePath) {
    Write-Host "  Or the executable:  $ExePath"
}
Write-Host ""
Write-Host "  Scripts live in:    $ScriptsDir"
Write-Host "  Config file:        $ConfigFile"
Write-Host "================================================" -ForegroundColor Cyan
