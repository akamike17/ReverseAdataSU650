# sub171c_full.py — full deterministic disassembly of sub_171C + decode each arg position
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

# Full body — sub_171C starts at RVA 0x171C, ends just before sub_1838 at 0x1838
print('=== sub_171C full disasm (RVA 0x171C..0x1838) ===')
for i in md.disasm(rd(0x171C, 0x11C), base+0x171C):
    print(f'{i.address:#x}: {i.mnemonic:10s} {i.op_str}')
