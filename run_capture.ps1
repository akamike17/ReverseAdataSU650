# X32DBG HEADLESS - Automated capture with proper script
# The key: wait for SWPtest.dll to load, then set breakpoint by address not symbol

$mptool = "C:\SM2258XT_MPTool\SM2258XTMPToolQ0816A.exe"
$x32dbgDir = "C:\Users\Admin\Downloads\snapshot_2026-05-27_12-11\release\x32"
$headless = "$x32dbgDir\headless.exe"
$logDir = "C:\SM2258XT_MPTool\log"
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$logFile = "$logDir\x32dbg_auto_$timestamp.log"

Write-Host "=== X32DBG HEADLESS CAPTURE ===" -ForegroundColor Cyan
Write-Host "Target: $mptool"
Write-Host "Log: $logFile"
Write-Host ""

# Create script that:
# 1. Loads target
# 2. Waits for SWPtest.dll to load (DLL load event)
# 3. Sets breakpoint on DownloadMPISP using RVA
# 4. Continues and waits for hit

$scriptContent = @"
; X32DBG HEADLESS CAPTURE SCRIPT
; Target: MPTool.exe calling DownloadMPISP

; Initialize logging
logopen "$logFile"
log "=== CAPTURE START ==="

; Load target process
load "$mptool"
log "Target loaded"

; Wait for entry point
entry

; At entry, SWPtest.dll is NOT yet loaded
; We need to wait for DLL load event

; Set breakpoint on LdrLoadDll to catch SWPtest loading
; Or use: dllbreak SWPtest.dll
; This will pause when SWPtest.dll loads

; Wait for SWPtest.dll to load
; When it loads, we'll be at its entry point
; Then we set our real breakpoint

; For now, try direct RVA breakpoint (SWPtest base will be random due to ASLR)
; But we can use module name:RVA syntax which x32dbg resolves

; First, let process run until SWPtest loads
; We do: dllbreak SWPtest.dll, then run
dllbreak SWPtest.dll
log "DLL break set for SWPtest.dll"
run

; When we hit here, SWPtest.dll is loaded
; Now set real breakpoint on DownloadMPISP export
; Export RVA is 0x7AD8, we use module:RVA format
bphws SWPtest.dll:7AD8, x
log "Hardware breakpoint set on DownloadMPISP"

; Continue execution
run

; If we hit the breakpoint, dump context
; The dump commands will execute when breakpoint hits
echo "=== DownloadMPISP HIT ==="

; Dump registers
r

; Dump stack (parameters are on stack)
; [ESP+4] = param1 (drive handle)
; [ESP+8] = param2 (data pointer)  
; [ESP+C] = param3 (word)
; [ESP+10] = param4 (context)
stack 32

; Dump context buffer
; Get context from stack: dd esp+10, 1
; Then dump that address
dump [esp+10], 256

; Dump data buffer  
dump [esp+8], 256

; Log success
echo "=== CAPTURE COMPLETE ==="
logclose

; Stop
stop
"@

$scriptPath = "$logDir\x32dbg_auto_$timestamp.txt"
$scriptContent | Out-File -FilePath $scriptPath -Encoding ASCII

Write-Host "Script: $scriptPath"
Write-Host ""

# Create the launch command
$cmd = "`"$headless`" -cf `"$scriptPath`" `"$mptool`""
Write-Host "Executing headless debugger..."
Write-Host "Command: $cmd"
Write-Host ""
Write-Host "The debugger will:"
Write-Host "1. Load MPTool"
Write-Host "2. Wait for SWPtest.dll to load"
Write-Host "3. Set breakpoint on DownloadMPISP"
Write-Host "4. When MPTool calls it, capture all context"
Write-Host ""
Write-Host "You will see output below when capture completes."
Write-Host "If nothing happens for 60s, the breakpoint didn't hit."
Write-Host "You may need to interact with MPTool GUI to trigger Scan/Start."
Write-Host ""

# Execute and capture output
& $headless -cf $scriptPath $mptool 2>&1 | Tee-Object -FilePath "$logDir\output_console.txt"

Write-Host ""
Write-Host "=== CAPTURE ENDED ==="
Write-Host "Log file: $logFile"
