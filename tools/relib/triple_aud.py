# triple_aud.py — full dispatch analysis for sub_1838 and sub_19D8
import pefile, capstone
p = pefile.PE(r'C:\SM2258XT_MPTool\SWPtest.dll')
base = p.OPTIONAL_HEADER.ImageBase
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
def rd(rva,n):
    for s in p.sections:
        if s.VirtualAddress <= rva < s.VirtualAddress + s.Misc_VirtualSize:
            return p.__data__[s.PointerToRawData + rva - s.VirtualAddress:s.PointerToRawData + rva - s.VirtualAddress + n]

# sub_1838's dispatch region — first look at structure
print('--- sub_1838 head and triple-dispatch ---')
for i in md.disasm(rd(0x1838, 0x220), base+0x1838):
    print(f'{i.address:#x}: {i.mnemonic:8s} {i.op_str}')
