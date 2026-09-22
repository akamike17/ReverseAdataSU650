# X32DBG SIMPLE CAPTURE - Using -c for command string
# This runs MPTool, sets breakpoint, waits for hit, then dumps

$mptool = "C:\SM2258XT_MPTool\SM2258XTMPToolQ0816A.exe"
$x32dbgDir = "C:\Users\Admin\Downloads\snapshot_2026-05-27_12-11\release\x32"
$headless = "$x32dbgDir\headless.exe"
$logDir = "C:\SM2258XT_MPTool\log"
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$logFile = "$logDir\x32dbg_simple_$timestamp.log"

Write-Host "=== X32DBG SIMPLE CAPTURE ===" -ForegroundColor Cyan

# Create a simple command file that we pipe to headless
# Format: each line is a command

$commands = @"
logopen "$logFile"
load "$mptool"
entry

; Wait for SWPtest.dll - using bpdll command
bpdll SWPtest.dll
run

; When we hit here, SWPtest is loaded
; Set breakpoint on DownloadMPISP export
; Using module:RVA format
bp SWPtest.dll:7AD8, DownloadMPISP

; Continue and wait for hit
run

; If hit, dump context
echo "DownloadMPISP called"
r
stack 32

; Get param pointers
echo "Stack params:"
dd esp, 8

; Dump context if available
echo "Done"
stop
"@

$cmdFile = "$logDir\cmds_$timestamp.txt"
$commands | Out-File -FilePath $cmdFile -Encoding ASCII

Write-Host "Command file: $cmdFile"
Write-Host ""

# Method 1: Try piping commands
Write-Host "Attempting method 1: pipe commands..."
Get-Content $cmdFile | & $headless $mptool 2>&1

Write-Host ""
Write-Host "If no breakpoint hit, MPTool may need GUI interaction."
Write-Host "Try opening MPTool manually and clicking Scan/Start."
