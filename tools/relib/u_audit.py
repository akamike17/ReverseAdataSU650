# u_audit.py — static sweep for byte-value 0x05 producers in SWPtest.dll
# Includes: mov reg/mem, 5; push 5; add/xor/or/and producing 5; and case tables.
import struct, sys
import pefile, capstone

p = pefile.PE(r'C:\SM2258XT_MPTool\SWPtest.dll')
base = p.OPTIONAL_HEADER.ImageBase
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)

def rd(rva, n):
    for s in p.sections:
        if s.VirtualAddress <= rva < s.VirtualAddress + s.Misc_VirtualSize:
            return p.__data__[s.PointerToRawData + rva - s.VirtualAddress:
                              s.PointerToRawData + rva - s.VirtualAddress + n]
    raise ValueError(hex(rva))

# Full disassembly of .text, find all instructions referencing immediate 5
# in any position (mov ?,5 / push 5 / cmp ?,5 / etc.) and byte-writes.
# Restrict ourselves to constants that look like "5" (not 5<<k etc).
print('=== .text sweep for immediate byte 5 producers/writers ===')
seg = rd(0x1000, 0x46000)

import io
out = io.StringIO()
for i in md.disasm(seg, base + 0x1000):
    opi = i.op_str
    # capture forms: ",5", ", 5" at end of operand string; "push 5"; "...,5"
    need = False
    if opi.endswith(", 5") or opi.endswith(",5"): need = True
    if opi == "5" and i.mnemonic == 'push': need = True
    if opi.startswith('byte ptr [') and opi.endswith(', 5'): need = True
    if opi.startswith('dword ptr [') and opi.endswith(', 5'): need = True
    if not need: continue
    line = f"{i.address:#x}: {i.mnemonic:10s} {opi}"
    print(line)
