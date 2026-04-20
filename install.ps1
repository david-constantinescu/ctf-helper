# CTF Helper — Windows installer (PowerShell)
# Run locally:
#   Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned
#   .\install.ps1
#
# Or via IRM (one-liner from any PowerShell):
#   iex (irm https://raw.githubusercontent.com/david-constantinescu/ctf-helper/main/install.ps1)

$ErrorActionPreference = "Stop"

$RepoUrl = "https://github.com/david-constantinescu/ctf-helper.git"

# If running via IRM (no local file), clone the repo first
if (-not (Test-Path "ctf_navigator.py")) {
    Write-Host "[*] Cloning ctf-helper repository..." -ForegroundColor Yellow
    git clone --depth 1 $RepoUrl ctf-helper
    Set-Location ctf-helper
}

$RepoDir    = (Get-Location).Path
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
    Write-Host "    Check 'Add Python to PATH' during install."
    exit 1
}

# ── pip ───────────────────────────────────────────────────────────────────────
try {
    & $PyCmd -m pip --version | Out-Null
    Write-Host "[+] pip found" -ForegroundColor Green
} catch {
    Write-Host "[!] pip not available." -ForegroundColor Red; exit 1
}

# ── tkinter ───────────────────────────────────────────────────────────────────
$TkCheck = & $PyCmd -c "import tkinter; print('ok')" 2>&1
if ($TkCheck -ne "ok") {
    Write-Host "[!] tkinter missing — re-install Python with 'tcl/tk and IDLE' checked." -ForegroundColor Red
    exit 1
}
Write-Host "[+] tkinter found" -ForegroundColor Green

# ── Python dependencies ────────────────────────────────────────────────────────
Write-Host ""
Write-Host "[*] Installing Python dependencies..." -ForegroundColor Yellow
& $PyCmd -m pip install --quiet --upgrade pyinstaller tkinterdnd2 Pillow pycryptodome scapy
Write-Host "[+] Core dependencies installed" -ForegroundColor Green

Write-Host "[*] Installing optional dependencies..." -ForegroundColor Yellow
try { & $PyCmd -m pip install --quiet gmpy2 2>&1 | Out-Null } catch {}
Write-Host "[+] Done" -ForegroundColor Green

# ── Write config ──────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "[*] Writing config -> $ConfigFile" -ForegroundColor Yellow

$ScriptsDirEscaped = $ScriptsDir -replace '\\', '\\\\'
& $PyCmd -c @"
import json, pathlib
cfg_path = pathlib.Path(r'$ConfigFile')
cfg = {}
if cfg_path.exists():
    try: cfg = json.loads(cfg_path.read_text())
    except: pass
cfg['scripts'] = r'$ScriptsDir'
cfg_path.write_text(json.dumps(cfg, indent=2))
print('    scripts path: $ScriptsDir')
"@
Write-Host "[+] Config written" -ForegroundColor Green

# ── Build executable (optional) ───────────────────────────────────────────────
Write-Host ""
$BuildNow = Read-Host "[?] Build standalone .exe now? [y/N]"
if ($BuildNow -match "^[Yy]$") {
    & "$RepoDir\build.ps1"
} else {
    Write-Host "[*] Skipped. Run .\build.ps1 to build later." -ForegroundColor DarkYellow
}

Write-Host ""
Write-Host "================================================" -ForegroundColor Cyan
Write-Host "[+] Installation complete!" -ForegroundColor Green
Write-Host ""
Write-Host "  Run:     $PyCmd `"$RepoDir\ctf_navigator.py`""
$ExePath = Join-Path $RepoDir "dist\ctf_navigator.exe"
if (Test-Path $ExePath) { Write-Host "  Or exe:  $ExePath" }
Write-Host ""
Write-Host "  Scripts: $ScriptsDir"
Write-Host "  Config:  $ConfigFile"
Write-Host ""
Write-Host "  Drag & drop files onto the window to add artifacts."
Write-Host "  Double-click an artifact to add cues (e.g. 'http', 'pwn', 'xor')."
Write-Host "================================================" -ForegroundColor Cyan
