# b27a_audit3.py — precise mode-assignment blocks in sub_5FB8 and sub_165C/sub_171C CDB layouts
import pefile, capstone
p = pefile.PE(r'C:\SM2258XT_MPTool\SWPtest.dll')
base = p.OPTIONAL_HEADER.ImageBase
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)

def rd(rva, n):
    for s in p.sections:
        if s.VirtualAddress <= rva < s.VirtualAddress + s.Misc_VirtualSize:
            off = s.PointerToRawData + (rva - s.VirtualAddress)
            return p.__data__[off:off+n]
    raise ValueError(hex(rva))

def dis(rva, size, tag):
    print(f'--- {tag} ---')
    for i in md.disasm(rd(rva, size), base + rva):
        print(f"{i.address:#x}: {i.mnemonic:10s} {i.op_str}")
    print()

# [A] sub_5FB8 mode-assign blocks: 0x60CF..0x61AF
dis(0x60CF, 0xE0, 'sub_5FB8 mode assignment chain')

# [B] transports exactly
dis(0x165C, 0xC0, 'sub_165C IOCTL_0x4D014 SCSI_PASS_THROUGH')
dis(0x171C, 0xC0, 'sub_171C IOCTL_0x4D030 SCSI_PASS_THROUGH_DIRECT')
