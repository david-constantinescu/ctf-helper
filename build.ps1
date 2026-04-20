# CTF Helper — build standalone .exe (Windows)
# Usage: .\build.ps1

$ErrorActionPreference = "Stop"

$RepoDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $RepoDir

# Find Python
$PyCmd = $null
foreach ($candidate in @("python", "python3", "py")) {
    try {
        $ver = & $candidate --version 2>&1
        if ($ver -match "Python 3\.") { $PyCmd = $candidate; break }
    } catch {}
}
if (-not $PyCmd) {
    Write-Host "[!] Python 3 not found. Install from python.org." -ForegroundColor Red
    exit 1
}

# Ensure PyInstaller is available
try {
    & $PyCmd -m PyInstaller --version | Out-Null
} catch {
    Write-Host "[*] Installing PyInstaller..." -ForegroundColor Yellow
    & $PyCmd -m pip install --quiet pyinstaller
}

Write-Host "[*] Building CTF Navigator..." -ForegroundColor Yellow

& $PyCmd -m PyInstaller `
    --onefile `
    --name ctf_navigator `
    --windowed `
    --icon NONE `
    ctf_navigator.py

Write-Host ""
Write-Host "[+] Done! Executable: dist\ctf_navigator.exe" -ForegroundColor Green
Write-Host "    Double-click dist\ctf_navigator.exe to launch."
Write-Host "    Or run from PowerShell: .\dist\ctf_navigator.exe"
