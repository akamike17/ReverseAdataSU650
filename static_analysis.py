#!/usr/bin/env python3
"""
SWPtest.dll Static Analysis - Complete Reverse Engineering
"""
import pefile
import struct
import sys
from pathlib import Path

def analyze_pe(filepath):
    pe = pefile.PE(filepath)
    print(f"=== PE Analysis: {filepath} ===")
    print(f"Machine: {hex(pe.FILE_HEADER.Machine)}")
    print(f"Timestamp: {pe.FILE_HEADER.TimeDateStamp}")
    print(f"Entry Point: {hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint)}")
    print(f"Image Base: {hex(pe.OPTIONAL_HEADER.ImageBase)}")
    
    # Sections
    print("\n--- Sections ---")
    for section in pe.sections:
        print(f"{section.Name.decode():8} VA: {hex(section.VirtualAddress):10} Size: {hex(section.Misc_VirtualSize)}")
    
    # Exports
    print("\n--- Exports (93 functions) ---")
    if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
        for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            if exp.name:
                name = exp.name.decode('utf-8', errors='ignore')
                if 'MPISP' in name.upper() or 'ISP' in name.upper() or 'ROM' in name.upper():
                    print(f"  {hex(exp.address):10} {name}")
    
    return pe

def parse_flash_set(filepath):
    print(f"\n=== Flash.SET Analysis: {filepath} ===")
    data = open(filepath, 'rb').read()
    print(f"Size: {len(data)} bytes")
    
    # Flash.SET structure analysis
    # Each entry is typically 32 bytes: FlashID (6 bytes) + Name (24 bytes) + Attributes (2 bytes)
    entry_size = 32  # hypothesis - need to verify
    
    print("\n--- Raw Hex Dump (first 512 bytes) ---")
    for i in range(0, min(512, len(data)), 16):
        hex_bytes = ' '.join(f'{b:02X}' for b in data[i:i+16])
        ascii_str = ''.join(chr(b) if 32 <= b < 127 else '.' for b in data[i:i+16])
        print(f"{i:08X}: {hex_bytes:<48} {ascii_str}")
    
    # Look for B27A pattern (Micron B27A NAND)
    print("\n--- Searching for B27A / Micron patterns ---")
    micron_id = bytes([0x2C, 0xA4, 0x08, 0x32, 0xA1, 0x00])  # Micron B27A 64L TLC
    b27a_id = bytes([0x2C, 0xA4, 0x08, 0x32, 0xA2, 0x00])
    
    for i in range(0, len(data) - 6, 8):
        if data[i:i+6] == micron_id or data[i:i+6] == b27a_id:
            print(f"[FOUND] Micron pattern at offset 0x{i:04X}: {data[i:i+6].hex()}")
            # Print surrounding context
            start = max(0, i-32)
            end = min(len(data), i+64)
            print(f"Context ({start:#x}-{end:#x}):")
            for j in range(start, end, 16):
                hex_bytes = ' '.join(f'{b:02X}' for b in data[j:j+16])
                ascii_str = ''.join(chr(b) if 32 <= b < 127 else '.' for b in data[j:j+16])
                marker = " <--" if j <= i < j+16 else ""
                print(f"  {j:08X}: {hex_bytes:<48} {ascii_str}{marker}")

if __name__ == "__main__":
    # Analyze SWPtest.dll
    dll_path = r"C:\SM2258XT_MPTool\Dll\SWPtest.dll"
    pe = analyze_pe(dll_path)
    
    # Analyze Flash.SET
    flash_set = r"C:\SM2258XT_MPTool\FlashDB\2258\Flash.SET"
    parse_flash_set(flash_set)
    
    print("\n=== Analysis Complete ===")
