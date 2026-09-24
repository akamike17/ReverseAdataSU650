# sub4024e0.py — full disasm of the drive-reset implementation
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

# start at the function beginning and disasm slowly
print('=== sub_4024E0 (the reset helper — called by _SMIPtestDriveReset) ===')
code = rd(0x24E0, 0x600)
for ins in md.disasm(code, base+0x24E0):
    print(f'  {ins.address:#x}: {ins.mnemonic:10s} {ins.op_str}')
