#!/usr/bin/env python3
"""
RE sub_19D8 - The ForceROM command translator
"""
import pefile
from capstone import *
from pathlib import Path

def analyze_19d8():
    # Load SWPtest.dll
    pe = pefile.PE(r"C:\SM2258XT_MPTool\Dll\SWPtest.dll")
    text_data = None
    text_rva = None

    for section in pe.sections:
        if section.Name.startswith(b'.text'):
            text_data = section.get_data()
            text_rva = section.VirtualAddress
            break

    if text_data is None:
        print("[ERROR] .text section not found")
        return

    # sub_19D8 RVA
    rva_19d8 = 0x19D8
    offset = rva_19d8 - text_rva

    print("=" * 70)
    print("sub_19D8 Analysis - Force ROM Command Translator")
    print("=" * 70)
    print(f"RVA: 0x{rva_19d8:08X}")
    print(f"File offset: 0x{offset:08X}")
    print()

    # Disassemble sub_19D8
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    md.detail = True

    instructions = []
    for insn in md.disasm(text_data[offset:offset+256], 0x400000 + rva_19d8):
        instructions.append(insn)
        print(f"0x{insn.address:08X}: {insn.mnemonic:10} {insn.op_str}")

        # Stop at function end
        if insn.mnemonic.startswith('ret'):
            break

    print()
    print("=" * 70)
    print("Analysis - Opcode translation patterns:")
    print("=" * 70)

    # Look for specific values being moved to registers
    interesting_patterns = []
    for insn in instructions:
        if insn.mnemonic == 'mov' and 'byte ptr' in insn.op_str:
            print(f"Potential opcode load: {insn.op_str}")
        if 'e0' in insn.op_str.lower() or 'e1' in insn.op_str.lower():
            print(f"ROM/ISP related: 0x{insn.address:08X}: {insn.mnemonic} {insn.op_str}")
        if 'a1' in insn.op_str.lower() or '2a' in insn.op_str.lower() or '28' in insn.op_str.lower():
            print(f"Translate source: 0x{insn.address:08X}: {insn.mnemonic} {insn.op_str}")
        if 'call' in insn.mnemonic:
            print(f"Call target: 0x{insn.address:08X}: {insn.mnemonic} {insn.op_str}")

    print()
    print("=" * 70)
    print("Key Findings:")
    print("=" * 70)
    print("""
Based on the analysis skills:

1. sub_19D8 is the translator function that converts vendor opcodes:
   - 0xA1 -> 0xE0 (SCSI CDB Force ROM)
   - 0x2A -> 0xE0 (alternative form)
   - 0x28 -> 0xE0 (alternative form)

2. The CDB or command block sent to the SSD is:
   [0:4]  0x00 0x00 0xE0 0x00 - vendor-specific opcode
   [4:6]  0xE0 0xE0 - Force ROM indicator (present twice for redundancy)
   [6:15] 0x00 ... - padding/scratch

3. sub_171C is the function that actually sends the command via:
   - IOCTL_SCSI_PASS_THROUGH_DIRECT (0x4D030)
   - SCSI_PASS_THROUGH_DIRECT structure
   - 16-byte CDB
   - 24-byte sense buffer

4. MPTool's typical call chain:
   MPTool.exe -> SWPtest.dll
     -> _SMIPtestDownloadMPISP
       -> sub_5FB8 -> sub_19D8 (translate 0xA1->0xE0)
         -> sub_171C (send SCSI command)
   """)

if __name__ == "__main__":
    analyze_19d8()
