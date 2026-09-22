# SM2258XT Reverse Engineering - COMPLETE FLASHER PROJECT
# Target: ADATA SU650 240GB/256GB
# Goal: Automated flash without JP2 hardware pin shorting
#
# RESEARCH PHASES:
# 1. Static analysis of SWPtest.dll exports
# 2. Dynamic capture of DownloadMPISP context
# 3. Reverse engineer context structure
# 4. Implement automated flasher

$ErrorActionPreference = "Stop"
$ProjectDir = "C:\SM2258XT_MPTool"
$AnalysisDir = "$ProjectDir\analysis"
$LogDir = "$ProjectDir\logs"

# Create directories
New-Item -ItemType Directory -Force -Path $AnalysisDir | Out-Null
New-Item -ItemType Directory -Force -Path $LogDir | Out-Null

# Start transcript
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$LogFile = "$LogDir\re_analysis_$timestamp.log"
Start-Transcript -Path $LogFile -Append

Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "SM2258XT RE - COMPLETE ANALYSIS" -ForegroundColor Cyan
Write-Host "Target: ADATA SU650 240GB/256GB" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host ""

# ============================================================================
# PHASE 1: Static Binary Analysis
# ============================================================================

Write-Host "[PHASE 1] Static Binary Analysis" -ForegroundColor Yellow
Write-Host "==================================" -ForegroundColor Yellow

# 1.1 PE Structure
Write-Host "`n[1.1] PE Structure Analysis"
$peOutput = "$AnalysisDir\pe_structure.txt"

python -c @"
import pefile
import sys

dll = pefile.PE(r'$ProjectDir\Dll\SWPtest.dll')
print('Machine:', hex(dll.FILE_HEADER.Machine))
print('Entry Point:', hex(dll.OPTIONAL_HEADER.AddressOfEntryPoint))
print('Image Base:', hex(dll.OPTIONAL_HEADER.ImageBase))
print()
print('Sections:')
for s in dll.sections:
    name = s.Name.decode().rstrip(chr(0))
    print(f'  {name:10} VA:0x{s.VirtualAddress:08X} Size:0x{s.Misc_VirtualSize:08X}')
print()
print('Exports:')
for exp in dll.DIRECTORY_ENTRY_EXPORT.symbols:
    if exp.name:
        print(f'  0x{exp.address:08X} {exp.name.decode()}')
"@ | Out-File $peOutput

Get-Content $peOutput | Select-Object -First 50

# 1.2 String Analysis
Write-Host "`n[1.2] String Analysis"
$stringsOutput = "$AnalysisDir\strings.txt"

python -c @"
import sys

with open(r'$ProjectDir\Dll\SWPtest.dll', 'rb') as f:
    data = f.read()

strings = []
current = bytearray()

for byte in data:
    if 32 <= byte < 127:
        current.append(byte)
    else:
        if len(current) >= 4:
            strings.append(current.decode('ascii'))
        current = bytearray()

if len(current) >= 4:
    strings.append(current.decode('ascii'))

# Filter for interesting strings
keywords = ['ROM', 'ISP', 'MPISP', 'DGISP', 'FLASH', 'ERASE', 'PROGRAM', 
            'PHYSICALDRIVE', 'SCSI', 'ATA', 'SATA', 'VENDOR', '0xE0', '0xF1']

for s in strings:
    if any(k in s.upper() for k in keywords):
        print(s)
"@ | Out-File $stringsOutput

Write-Host "Found strings (first 50):"
Get-Content $stringsOutput | Select-Object -First 50

# ============================================================================
# PHASE 2: Export Analysis
# ============================================================================

Write-Host "`n[PHASE 2] Export Analysis" -ForegroundColor Yellow
Write-Host "==========================" -ForegroundColor Yellow

# 2.1 Export to call chain mapping
Write-Host "`n[2.1] Export Call Chains"

python "$ProjectDir\full_reverse_engineering.py" | Out-File "$AnalysisDir\call_chains.txt"

Get-Content "$AnalysisDir\call_chains.txt" | Select-Object -First 100

# ============================================================================
# PHASE 3: Context Structure Analysis
# ============================================================================

Write-Host "`n[PHASE 3] Context Structure Analysis" -ForegroundColor Yellow
Write-Host "=====================================" -ForegroundColor Yellow

Write-Host @"
From previous crash analysis:
- DownloadMPISP crashes at 0x406496: mov byte ptr [edx+eax], cl
- This is a memcpy-like operation
- The pointer [edx+eax] is invalid -> context structure missing

Expected context structure (from reverse engineering):
- Offset +0x0000: Drive handle (DWORD*)
- Offset +0x0004: Data buffer pointer
- Offset +0x0008: Word/checksum value
- Offset +0x000C: Pointer to sub-context (0x8400 bytes)
- Offset +0x4200: Internal buffer for flash operations
"@

# ============================================================================
# PHASE 4: NAND/Flash Configuration
# ============================================================================

Write-Host "`n[PHASE 4] NAND Configuration Analysis" -ForegroundColor Yellow
Write-Host "======================================" -ForegroundColor Yellow

# Parse Flash.SET for 240GB/256GB configuration
Write-Host "Parsing Flash.SET for 240GB/256GB Micron B27A..."

python -c @"
import re

with open(r'$ProjectDir\FlashDB\2258\Flash.SET', 'rb') as f:
    data = f.read()

# Look for B27A pattern (240GB/256GB typically)
# Micron B27A IDs: 2C C4 18 32 A2 00 (from docs)
# Let's search for these patterns

patterns = [
    (b'\x2C\xC4\x18\x32\xA2\x00', 'B27A-256GB'),
    (b'\x2C\x84\x64\x32\xA6\x00', 'Hynix-120GB'),
    (b'\x2C\xA4\x08\x32\xA1\x00', 'Micron-B16A'),
    (b'\x2C\xA4\x08\x32\xA2\x00', 'Micron-B27A'),
]

for pattern, name in patterns:
    idx = 0
    while True:
        idx = data.find(pattern, idx)
        if idx == -1:
            break
        print(f'Found {name} at offset 0x{idx:X}')
        # Print surrounding context
        start = max(0, idx - 32)
        end = min(len(data), idx + 64)
        context = data[start:end]
        print(f'  Context: {context.hex()}')
        idx += 1
"@

Write-Host ""
Write-Host "==========================================" -ForegroundColor Green
Write-Host "ANALYSIS COMPLETE - See $AnalysisDir" -ForegroundColor Green
Write-Host "==========================================" -ForegroundColor Green

Stop-Transcript
