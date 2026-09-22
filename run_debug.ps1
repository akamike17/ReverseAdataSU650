# Headless x32dbg launcher - runs MPTool under debugger with breakpoint on DownloadMPISP
# Usage: powershell -File run_debug.ps1

$ErrorActionPreference = "Continue"
$x32dbgPath = "C:\Users\Admin\Downloads\snapshot_2026-05-27_12-11\release\x32"
$mptoolPath = "C:\SM2258XT_MPTool\SM2258XTMPToolQ0816A.exe"
$logDir = "C:\SM2258XT_MPTool\log"
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"

# Create log directory
New-Item -ItemType Directory -Path $logDir -Force -ErrorAction SilentlyContinue | Out-Null

Write-Host "=== X32DBG CLI CAPTURE ===" 
Write-Host "Time: $(Get-Date)"
Write-Host ""

# Check if x32dbg exists
if (-not (Test-Path "$x32dbgPath\x32dbg.exe")) {
    Write-Host "ERROR: x32dbg.exe not found at $x32dbgPath"
    exit 1
}

# Create script for x32dbg CLI
$scriptContent = @"
; x32dbg CLI script
; Load and debug MPTool

load "$mptoolPath"

; Wait for entry
entry

; Set breakpoint on DownloadMPISP export
bp _SMIPtestDownloadMPISP

; Enable logging
logopen "$logDir\x32dbg_$timestamp.log"

; Continue execution
run

; Wait for breakpoint (this blocks until BP hit)
; When hit, dump context and continue

; Dump registers
r

; Dump stack (32 values)
stack 32

; Dump memory at ESP (call site)
dump esp, 64

; Get the module base for SWPtest
mod SWPtest.dll

; Continue execution
run

; Close and save
logclose
stop
"@

$scriptPath = "$logDir\x32dbg_cmd_$timestamp.txt"
$scriptContent | Out-File -FilePath $scriptPath -Encoding ASCII

Write-Host "Script created: $scriptPath"
Write-Host ""
Write-Host "MANUAL STEP REQUIRED:"
Write-Host "1. Open CMD as Administrator"
Write-Host "2. cd `"$x32dbgPath`""
Write-Host "3. x32dbg.exe -script `"$scriptPath`""
Write-Host ""
Write-Host "OR use headless mode:"
Write-Host "headless.exe -script `"$scriptPath`""
Write-Host ""

# Try to create a batch file for easy execution
$batContent = @"
@echo off
cd /d "$x32dbgPath"
x32dbg.exe -script "$scriptPath"
pause
"@

$batPath = "$logDir\run_debug.bat"
$batContent | Out-File -FilePath $batPath -Encoding ASCII

Write-Host "Batch file created: $batPath"
Write-Host ""
Write-Host "NEXT STEP:"
Write-Host "Run as Administrator: $batPath"
