# passtype3.py — find all actual accesses to [0x45DD4C] given ImageBase=0x400000
import pefile, capstone, struct
p = pefile.PE(r'C:\SM2258XT_MPTool\SWPtest.dll')
base = p.OPTIONAL_HEADER.ImageBase  # 0x400000
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)

def rd(rva, n):
    for s in p.sections:
        if s.VirtualAddress <= rva < s.VirtualAddress + s.Misc_VirtualSize:
            return p.__data__[s.PointerToRawData + rva - s.VirtualAddress:
                              s.PointerToRawData + rva - s.VirtualAddress + n]
    raise ValueError(hex(rva))

seg = rd(0x1000, 0x46000)
needle = struct.pack('<I', base + 0x45DD4C)  # 4C DD 45 40
hits = []
i = 0
while True:
    j = seg.find(needle, i)
    if j < 0: break
    hits.append(0x1000 + j)
    i = j + 1

print(f'{len(hits)} references to VA {base+0x45DD4C:#x}:')
for rv in hits:
    # find enclosing instruction by disassembling backwards up to 16 bytes
    hit_rva = rv
    got = False
    for back in range(1, 17):
        start = hit_rva - back
        try:
            code = rd(start, back + 12)
        except Exception:
            continue
        for ins in md.disasm(code, base + start):
            if ins.address == base + start:
                iabs = start
                # check if operand region covers hit
                if start < hit_rva < start + ins.size and hit_rva - start >= 1:
                    print(f'  @ RVA {start:#x} in {ins.mnemonic} {ins.op_str}')
                    got = True
                    break
        if got: break
    if not got:
        # Often the imm is mid-instruction; just show *the instruction starting at hit_rva - 5*
        start = hit_rva - 5
        code = rd(start, 20)
        for ins in md.disasm(code, base + start):
            if ins.size > 5:
                print(f'  @ RVA {start:#x} in {ins.mnemonic} {ins.op_str}')
                break
