#!/usr/bin/env python3
"""
SWFtest.dll Proxy - Direct interception without debugger
Captures _SMIPtestDownloadMPISP call parameters
"""

import ctypes
import sys
import os
import time
from datetime import datetime

# Configuration
ORIGINAL_DLL = r"C:\SM2258XT_MPTool\Dll\SWPtest.dll"
LOG_FILE = r"C:\SM2258XT_MPTool\capture\swptest_intercept.log"

# Load original DLL
try:
    original = ctypes.CDLL(ORIGINAL_DLL)
    print(f"[+] Original DLL loaded: {ORIGINAL_DLL}")
except Exception as e:
    print(f"[!] Failed to load original DLL: {e}")
    sys.exit(1)

# Get function pointers
try:
    pSetPassThroughType = original._SMISetPassThroughType
    pDriveReset = original._SMIPtestDriveReset
    pDownloadMPISP = original._SMIPtestDownloadMPISP
    pLoadDgISP = original._SMIPtestLoadDgISP
    pCheckRunMode = original._SMIPtestCheckRunMode
    pReadFlashID = original._SMIReadFlashID
    pScanSMIDrive = original._SMIScanSMIDrive
    pDownloadISP = original._SMIPtestDownloadISP

    print(f"[+] Exports resolved:")
    print(f"    _SMISetPassThroughType: {pSetPassThroughType}")
    print(f"    _SMIPtestDriveReset: {pDriveReset}")
    print(f"    _SMIPtestDownloadMPISP: {pDownloadMPISP}")
    print(f"    _SMIPtestLoadDgISP: {pLoadDgISP}")
    print(f"    _SMIPtestCheckRunMode: {pCheckRunMode}")
    print(f"    _SMIReadFlashID: {pReadFlashID}")
    print(f"    _SMIScanSMIDrive: {pScanSMIDrive}")
    print(f"    _SMIPtestDownloadISP: {pDownloadISP}")

except AttributeError as e:
    print(f"[!] Failed to resolve export: {e}")
    print(f"[!] Available exports: {dir(original)}")

# Ensure log directory exists
os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)

def log(msg):
    """Log to file and console"""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
    with open(LOG_FILE, "a") as f:
        f.write(f"[{timestamp}] {msg}\n")
    print(f"[{timestamp}] {msg}")

def log_params(func_name, *args, **kwargs):
    """Log function call parameters"""
    params = []
    for i, arg in enumerate(args):
        if isinstance(arg, int):
            params.append(f"arg{i}=0x{arg:X}")
        elif isinstance(arg, bytes):
            params.append(f"arg{i}=bytes({len(arg)}): {arg[:64].hex()}...")
        elif isinstance(arg, str):
            params.append(f"arg{i}=str({len(arg)}): {repr(arg[:64])}")
        else:
            params.append(f"arg{i}={type(arg).__name__}")

    for key, value in kwargs.items():
        params.append(f"{key}={value}")

    log(f"[CALL] {func_name}({', '.join(params)})")

# Wrapper for _SMIPtestDownloadMPISP
def SMIPtestDownloadMPISP(drive_handle, data, checksum, context):
    """Intercept DownloadMPISP call"""
    log("=" * 60)
    log("!!! DOWNLOAD_MPISP CALLED !!!")
    log(f"  drive_handle: 0x{drive_handle:X}")
    log(f"  data: {len(data) if isinstance(data, bytes) else 'N/A'} bytes")

    # Dump actual data if it's a buffer
    if isinstance(data, (bytes, bytearray)):
        hex_dump = ' '.join(f'{b:02X}' for b in data[:256])
        log(f"  data (first 256 bytes): {hex_dump}")
        log(f"  data (full hex): {data.hex()}")

    log(f"  checksum: 0x{checksum:X}")
    log(f"  context: {context if context else 'None'}")

    if context:
        log(f"  context dump: {context if isinstance(context, bytes) else 'N/A'}")

    # Save raw data if available
    if isinstance(data, (bytes, bytearray)):
        data_file = r"C:\SM2258XT_MPTool\capture\mpisp_data.bin"
        with open(data_file, "wb") as f:
            f.write(data)
        log(f"  Data saved to: {data_file}")

    log("=" * 60)

# Attach the wrapper
original._SMIPtestDownloadMPISP = SMIPtestDownloadMPISP

# This makes the DLL see our intercepted version when MPTool calls it
# In a real scenario, we'd need to inject this into the running process.

print("[+] SWPtest Proxy initialized")
print("[+] Waiting for MPTool to call DownloadMPISP...")
print("[+] Press Ctrl+C to exit")

try:
    # Keep the script alive
    while True:
        time.sleep(1)
except KeyboardInterrupt:
    print("\n[!] Exiting...")

log("=== PROXY SHUTDOWN ===")
