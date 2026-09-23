# b27a_audit.py — Part 1-5: mode gate chain + SCSI CDB reconstruction
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
    print(f'--- {tag} (RVA {rva:#x}) ---')
    for i in md.disasm(rd(rva, size), base+rva):
        print(f"{i.address:#x}: {i.mnemonic:10s} {i.op_str}")
    print()

# sub_406618 — used by sub_5FB8 to send "SM2258"/"ISP"/"MPISP"/"ROMDE" string commands
dis(0x6618, 0x280, 'sub_406618 (called by sub_5FB8 with cmd string)')

# sub_2300 already known; focus on its data-write into arg2+0x210 (the mode byte)
dis(0x2429, 0x60, 'sub_2300 tail around mode-byte store')

# helpers used by sub_5FB8's strings: 0x45EA8 (string builder) and 0x45F68 (cleanup), and 0x406220 (memset?)
dis(0x6220, 0x90, 'helper 0x406220 (called from sub_5FB8 and sub_2300)')
