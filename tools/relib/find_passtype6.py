# find_passtype6.py — disasm the 3 call sites properly with lookahead context
import pefile, capstone, struct
p = pefile.PE('SM2258XTMPToolQ0816A.exe')
base = p.OPTIONAL_HEADER.ImageBase
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)

def rd(rva,n):
    for s in p.sections:
        if s.VirtualAddress <= rva < s.VirtualAddress + s.Misc_VirtualSize:
            return p.__data__[s.PointerToRawData + rva - s.VirtualAddress:
                              s.PointerToRawData + rva - s.VirtualAddress + n]
    return b''

# Show the bytes RAW around 0x3A7E0..0x3A840
print('=== RAW bytes @ RVA 0x3A7D0..0x3A840 ===')
raw = rd(0x3A7D0, 0x70)
for row in range(0, len(raw), 16):
    chunk = raw[row:row+16]
    print(f'  RVA {0x3A7D0+row:#x}: ' + ' '.join(f'{b:02X}' for b in chunk))

# Disasm starting exactly at 0x3A7E0 (no backtracking); stop after the call sites
print()
print('=== Disasm from RVA 0x3A7E0 forward ===')
for i in md.disasm(rd(0x3A7E0, 0x60), base+0x3A7E0):
    print(f'{i.address:#x}: {i.mnemonic:10s} {i.op_str}')
