# final_pass.py — Part 2/3/5: every write derivable from arg3 inside sub_CF98 + helper sub_406438/sub_40674C
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

# helpers used by sub_40B178: 0x406438 (takes pushed ctx+4 and string) and 0x40674C (called on arg2)
print('=== sub_406438 (called by sub_40B178) head ===')
for i in md.disasm(rd(0x6438, 0x120), base+0x6438):
    print(f"{i.address:#x}: {i.mnemonic:10s} {i.op_str}")
print()
print('=== sub_40674C (called twice by sub_40B178 on arg2) ===')
for i in md.disasm(rd(0x674C, 0x80), base+0x674C):
    print(f"{i.address:#x}: {i.mnemonic:10s} {i.op_str}")
