# X32DBG HEADLESS CLI CAPTURE
# Captures DownloadMPISP context without GUI interaction
# Run: powershell -ExecutionPolicy Bypass -File launch_debug.ps1

$mptool = "C:\SM2258XT_MPTool\SM2258XTMPToolQ0816A.exe"
$x32dbgDir = "C:\Users\Admin\Downloads\snapshot_2026-05-27_12-11\release\x32"
$headless = "$x32dbgDir\headless.exe"
$logDir = "C:\SM2258XT_MPTool\log"
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$logFile = "$logDir\x32dbg_headless_$timestamp.log"

# Verify paths
if (-not (Test-Path $headless)) { Write-Host "ERROR: headless.exe not found at $headless"; exit 1 }
if (-not (Test-Path $mptool)) { Write-Host "ERROR: MPTool not found at $mptool"; exit 1 }
New-Item -ItemType Directory -Path $logDir -Force -ErrorAction SilentlyContinue | Out-Null

Write-Host "=== HEADLESS DEBUGGER LAUNCH ===" -ForegroundColor Cyan
Write-Host "Target: $mptool"
Write-Host "Debugger: $headless"
Write-Host ""

# Create x32dbg script
$scriptContent = @"
; x32dbg headless script
; Captures DownloadMPISP call context

; Log everything to file
logopen "$logFile"

; Load target
load "$mptool"

; Wait for entry point
entry

; Set breakpoint on DownloadMPISP (SWPtest.dll export)
bp _SMIPtestDownloadMPISP

; Alternatively, use direct address if symbol fails:
; bp SWPtest.dll:7AD8

; Log initial state
echo "=== BREAKPOINT SET ==="
echo "Target: $mptool"
echo "Waiting for DownloadMPISP call..."

; Continue execution
run

; ==== THIS WILL HIT WHEN MPTool CALLS DownloadMPISP ====
; The following commands execute at breakpoint

echo ""
echo "=== DownloadMPISP CALLED ==="

; Dump registers
r

; Get stack pointer
echo "ESP content:"
dump esp, 64

; Get EBP frame
echo "EBP frame:"
dump ebp, 64

; Read parameters from stack
; [ESP] = return address
; [ESP+4] = param1 (drive handle)
; [ESP+8] = param2 (data pointer)
; [ESP+C] = param3 (word param)
; [ESP+10] = param4 (context)

echo "Parameters from stack:"
dd esp, 8

; Get module base for SWPtest
echo "Module info:"
mod SWPtest.dll

; Get the actual DownloadMPISP function address
echo "DownloadMPISP address:"
lib _SMIPtestDownloadMPISP

; Dump the context buffer (param4)
; First get context pointer from stack
; context = [ESP+10h]
set ctx, [esp+0x10]
echo "Context pointer:"
dd ctx, 16

; Read from context buffer (first 256 bytes)
echo "Context buffer contents:"
dump ctx, 256

; Get data pointer (param2)
set dataptr, [esp+8]
echo "Data pointer (BootISP):"
dd dataptr, 32

; Log completion
echo "=== CAPTURE COMPLETE ==="

; Wait a moment then stop
sleep 1000
logclose
stop
"@

$scriptPath = "$logDir\x32dbg_script_$timestamp.txt"
$scriptContent | Out-File -FilePath $scriptPath -Encoding ASCII

Write-Host "Script created: $scriptPath"
Write-Host ""

# Create the batch file with proper quoting
$batchContent = @"
@echo off
echo Launching x32dbg headless...
echo Target: $mptool
echo Log: $logFile
echo.

cd /d "$x32dbgDir"

rem Launch headless with script
"$headless" -cf "$scriptPath" "$mptool"

if errorlevel 1 (
    echo.
    echo ERROR: Headless launch failed
    echo Check if x32dbg dir is correct
    pause
    exit /b 1
)

echo.
echo Done. Check log: $logFile
pause
"@

$batPath = "$logDir\launch_headless_debug.bat"
$batchContent | Out-File -FilePath $batPath -Encoding ASCII

Write-Host "=== READY TO EXECUTE ===" -ForegroundColor Green
Write-Host ""
Write-Host "To run headless capture:"
Write-Host "  Right-click: $batPath"
Write-Host "  Select: Run as Administrator"
Write-Host ""
Write-Host "This will:"
Write-Host "1. Launch MPTool under debugger"
Write-Host "2. Set breakpoint on _SMIPtestDownloadMPISP"
Write-Host "3. Wait for you to click 'Scan' or 'Start' in MPTool GUI"
Write-Host "4. When breakpoint hits, capture all context to log"
Write-Host "5. Log file: $logFile"
Write-Host ""
Write-Host "NOTE: MPTool GUI will still open. You need to:"
Write-Host "  - Click 'Scan' to trigger the ISP sequence"
Write-Host "  - The breakpoint will fire when DownloadMPISP is called"
Write-Host ""

# ALSO: Create a simpler version using Python ctypes to call SWPtest directly
# and log what happens
$pyContent = @'
#!/usr/bin/env python3
"""
Direct SWPtest.dll API call using Python ctypes.
This bypasses x32dbg and calls the functions directly.
"""
import ctypes
import struct
import sys
import os
from pathlib import Path

# Setup paths
MPTOOL_DIR = Path(r"C:\SM2258XT_MPTool")
DLL_PATH = MPTOOL_DIR / "Dll" / "SWPtest.dll"
BOOTISP_PATH = MPTOOL_DIR / "Firmware" / "2258" / "IMB16" / "BootISP2258.bin"
LOG_DIR = MPTOOL_DIR / "log"
LOG_DIR.mkdir(exist_ok=True)

LOG_FILE = LOG_DIR / f"swptest_direct_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"

def log(msg):
    print(f"[{datetime.now().strftime('%H:%M:%S.%f')[:-3]}] {msg}")
    with open(LOG_FILE, 'a') as f:
        f.write(f"[{datetime.now().strftime('%H:%M:%S.%f')[:-3]}] {msg}\n")

log("=== DIRECT SWPtest.dll CALL ===")
log(f"Loading: {DLL_PATH}")

if not DLL_PATH.exists():
    log(f"ERROR: DLL not found at {DLL_PATH}")
    sys.exit(1)

# Load DLL (32-bit)
try:
    # Use WinDLL for Cdecl by default, but we can specify
    dll = ctypes.WinDLL(str(DLL_PATH), use_last_error=True)
    log("DLL loaded successfully")
except Exception as e:
    log(f"ERROR loading DLL: {e}")
    sys.exit(1)

# Function prototypes
# All take (handle, context) as first two params based on disassembly

# _SMISetPassThroughType(BYTE type)
SetPassThroughType = dll._SMISetPassThroughType
SetPassThroughType.argtypes = [ctypes.c_byte]
SetPassThroughType.restype = ctypes.c_bool

# _SMIScanSMIDrive(DWORD* handleArray, DWORD* count)
ScanSMIDrive = dll._SMIScanSMIDrive
ScanSMIDrive.argtypes = [ctypes.POINTER(ctypes.c_uint32), ctypes.POINTER(ctypes.c_uint32)]
ScanSMIDrive.restype = ctypes.c_bool

# _SMIPtestCheckRunMode(DWORD handle, PVOID context, PVOID modeOut)
CheckRunMode = dll._SMIPtestCheckRunMode
CheckRunMode.argtypes = [ctypes.c_uint32, ctypes.c_void_p, ctypes.c_void_p]
CheckRunMode.restype = ctypes.c_bool

# _SMIPtestDownloadMPISP(DWORD handle, PVOID data, WORD param, PVOID context)
DownloadMPISP = dll._SMIPtestDownloadMPISP
DownloadMPISP.argtypes = [ctypes.c_uint32, ctypes.c_void_p, ctypes.c_uint16, ctypes.c_void_p]
DownloadMPISP.restype = ctypes.c_bool

log("Functions bound")

# Test sequence
try:
    # 1. Set pass through
    log("Calling SetPassThroughType(0)...")
    result = SetPassThroughType(0)
    log(f"  Result: {result}")
    
    # 2. Scan for drives
    log("Calling ScanSMIDrive...")
    handles = (ctypes.c_uint32 * 16)()
    count = ctypes.c_uint32(0)
    result = ScanSMIDrive(handles, ctypes.byref(count))
    log(f"  Result: {result}, Drives found: {count.value}")
    
    if count.value == 0:
        log("  No SMI drives in ROM mode (expected - drive is normal)")
        # Try opening PhysicalDrive1 directly
        log("  Attempting direct PhysicalDrive1 access...")
        
        # CreateFile via ctypes
        kernel32 = ctypes.windll.kernel32
        handle = kernel32.CreateFileW(
            r"\\.\PhysicalDrive1",
            0xC0000000,  # GENERIC_READ | GENERIC_WRITE
            0x3,         # FILE_SHARE_READ | FILE_SHARE_WRITE
            None,
            3,           # OPEN_EXISTING
            0,
            None
        )
        
        if handle == -1 or handle == 0:
            err = ctypes.get_last_error()
            log(f"  ERROR: CreateFile failed: {err}")
        else:
            log(f"  Opened PhysicalDrive1: handle=0x{handle:X}")
            
            # Allocate context buffer
            ctx_buf = ctypes.create_string_buffer(0x8400)
            
            # Call CheckRunMode
            log("Calling CheckRunMode...")
            mode_out = ctypes.c_uint32(0)
            result = CheckRunMode(handle, ctx_buf, ctypes.byref(mode_out))
            log(f"  Result: {result}, Mode: {mode_out.value}")
            
            # Read BootISP
            log(f"Reading BootISP: {BOOTISP_PATH}")
            with open(BOOTISP_PATH, 'rb') as f:
                boot_data = f.read()
            log(f"  Size: {len(boot_data)} bytes")
            log(f"  First 16: {boot_data[:16].hex(' ')}")
            
            # Try DownloadMPISP
            log("Calling DownloadMPISP...")
            data_buf = ctypes.create_string_buffer(boot_data[:0x400], 0x400)
            result = DownloadMPISP(handle, data_buf, 0, ctx_buf)
            log(f"  Result: {result}")
            
            kernel32.CloseHandle(handle)
    
except Exception as e:
    log(f"EXCEPTION: {type(e).__name__}: {e}")
    import traceback
    traceback.print_exc()

log("=== COMPLETE ===")
log(f"Log saved: {LOG_FILE}")
'@

$pyPath = "$logDir\direct_swptest.py"
$pyContent | Out-File -FilePath $pyPath -Encoding ASCII

Write-Host "ALTERNATIVE: Direct Python call"
Write-Host "  Run: python $pyPath"
Write-Host "(Requires: pip install pywin32)"
Write-Host ""
Write-Host "IMPORTANT: This Python script calls SWPtest.dll directly"
Write-Host "It may crash or need admin - run with caution"
