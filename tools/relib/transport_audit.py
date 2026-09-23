# transport_audit.py — sub_171C and sub_165C complete analysis + callergraph
import pefile, capstone, struct
p = pefile.PE(r'C:\SM2258XT_MPTool\SWPtest.dll')
base = p.OPTIONAL_HEADER.ImageBase
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)

def rd(rva, n):
    for s in p.sections:
        if s.VirtualAddress <= rva < s.VirtualAddress + s.Misc_VirtualSize:
            return p.__data__[s.PointerToRawData + rva - s.VirtualAddress:
                              s.PointerToRawData + rva - s.VirtualAddress + n]
    raise ValueError(hex(rva))

# ----- Full disassembly of both transports -----
print('======= sub_165C full (0x4D014 SCSI_PASS_THROUGH) =======')
for i in md.disasm(rd(0x165C, 0xC0), base+0x165C):
    print(f'{i.address:#x}: {i.mnemonic:10s} {i.op_str}')

print('\n======= sub_171C full (0x4D030 SCSI_PASS_THROUGH_DIRECT) =======')
for i in md.disasm(rd(0x171C, 0x120), base+0x171C):
    print(f'{i.address:#x}: {i.mnemonic:10s} {i.op_str}')

# ----- Callergraph: who calls sub_171C / sub_165C -----
print('\n======= Callers of sub_171C (IOCTL 0x4D030 path) =======')
seg = rd(0x1000, 0x46000)
target = base + 0x171C
hits_171c = []
for i in range(len(seg)-5):
    if seg[i] == 0xE8:
        va_call = base + 0x1000 + i
        rel = struct.unpack_from('<i', seg, i+1)[0]
        if va_call + 5 + rel == target:
            hits_171c.append(va_call)
print(f'{len(hits_171c)} callers:')
for h in hits_171c: print(f'  {h:#x}')

print('\n======= Callers of sub_165C (IOCTL 0x4D014 path) =======')
target2 = base + 0x165C
hits_165c = []
for i in range(len(seg)-5):
    if seg[i] == 0xE8:
        va_call = base + 0x1000 + i
        rel = struct.unpack_from('<i', seg, i+1)[0]
        if va_call + 5 + rel == target2:
            hits_165c.append(va_call)
print(f'{len(hits_165c)} callers:')
for h in hits_165c: print(f'  {h:#x}')
