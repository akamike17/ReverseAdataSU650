# x32dbg + MPTool capture - correct syntax
# Requires PowerShell 5+

$ErrorActionPreference = 'Stop'

# Kill existing debug processes
Get-Process x32dbg,SM2258XTMPToolQ0816A -ErrorAction SilentlyContinue | Stop-Process -Force
Start-Sleep -Seconds 2

$x32dbgPath = "C:\Users\Admin\Downloads\snapshot_2026-05-27_12-11\release\x32\x32dbg.exe"
$mptoolPath = "C:\SM2258XT_MPTool\SM2258XTMPToolQ0816A.exe"

# Verify
if (-not (Test-Path $x32dbgPath)) { Write-Error "Not found: $x32dbgPath"; exit 1 }
if (-not (Test-Path $mptoolPath)) { Write-Error "Not found: $mptoolPath"; exit 1 }

Write-Host "Launching..." -ForegroundColor Cyan

# Start process
$psi = New-Object System.Diagnostics.ProcessStartInfo
$psi.FileName = $x32dbgPath
$psi.Arguments = '"' + $mptoolPath + '"'
$psi.WorkingDirectory = Split-Path $x32dbgPath

try {
    $proc = [System.Diagnostics.Process]::Start($psi)
    Write-Host "PID: $($proc.Id)" -ForegroundColor Green
    Start-Sleep -Seconds 8
} catch {
    Write-Host "Failed: $_" -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "=== PROCESS STATUS ===" -ForegroundColor Yellow

$x32 = Get-Process x32dbg -ErrorAction SilentlyContinue
$mp = Get-Process SM2258XTMPToolQ0816A -ErrorAction SilentlyContinue

if ($x32) {
    Write-Host "x32dbg [OK] PID=$($x32.Id)"
    if ($x32.MainWindowTitle) { Write-Host "  Title: $($x32.MainWindowTitle)" }
}
if ($mp) {
    Write-Host "MPTool [OK] PID=$($mp.Id)"
    Write-Host "  Title: $($mp.MainWindowTitle)"
}

Write-Host ""
Write-Host "=== MANUAL STEPS ===" -ForegroundColor Yellow
Write-Host "1. In x32dbg: Wait for 'System breakpoint'"
Write-Host "2. Command bar: type 'bpdll SWPtest.dll'"
Write-Host "3. Press F9 (Run)"
Write-Host "4. When SWPtest loads, note the ImageBase address"
Write-Host "5. Command bar: type 'bp <address>+0x7AD8' (if base is 0x10000000)"
Write-Host "6. Press F9 again"
Write-Host "7. Click Start in MPTool window"
Write-Host "8. Capture registers and stack when breakpoint hits"
