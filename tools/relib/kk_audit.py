# kk_audit.py — Phase C final micro-audit per kk.md: sub_40B178 + sub_40B104
import pefile, capstone, struct
p = pefile.PE(r'C:\SM2258XT_MPTool\SWPtest.dll')
base = p.OPTIONAL_HEADER.ImageBase
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
md.detail = True

def rd(rva, n):
    for s in p.sections:
        if s.VirtualAddress <= rva < s.VirtualAddress + s.Misc_VirtualSize:
            off = s.PointerToRawData + rva - s.VirtualAddress
            return p.__data__[off:off+n]
    raise ValueError(hex(rva))

def disasm_full(rva, size, tag):
    print(f'--- {tag} (RVA {rva:#x}, VA {base+rva:#x}) ---')
    for i in md.disasm(rd(rva, size), base + rva):
        note = ''
        op = i.op_str
        for a, off in [('[ebp+8]','ARG1'),('[ebp+0xc]','ARG2'),('[ebp+0x10]','ARG3'),('[ebp+0x14]','ARG4')]:
            key = a.replace('[','').replace(']','')
            if key in op.replace('ebp + 0x','ebp+0x').replace('ebp + 8','ebp+8'):
                note = f'<- {off}'
        if 'call' in i.mnemonic: note = (note+' CALL').strip()
        if i.mnemonic.startswith('ret'): note = (note+' RET').strip()
        print(f"{i.address:#x}: {i.mnemonic:10s} {op:60s} {note}")
    print()

print('=== sub_40B104 ===')
disasm_full(0xB104, 0x74, 'sub_40B104')
print('=== sub_40B178 (full) ===')
disasm_full(0xB178, 0x600, 'sub_40B178')

# find callers of sub_40B178 (E8 rel32)
print('=== callers of VA 0x40B178 (raw rel32 scan) ===')
text_rva = 0x1000
seg = rd(text_rva, 0x46000)
target = base + 0xB178
hits = []
for i in range(len(seg)-5):
    if seg[i] == 0xE8:
        va_call = base + text_rva + i
        rel = struct.unpack_from('<i', seg, i+1)[0]
        if va_call + 5 + rel == target:
            hits.append(va_call)
print(f'{len(hits)} callers:')
for h in hits: print(f'  {h:#x}')
PYEOF = None
