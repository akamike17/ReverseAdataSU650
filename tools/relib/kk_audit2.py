# kk_audit2.py — caller scan for sub_40B178 and string table for 0x44bea4..44bebe
import struct
import pefile
p = pefile.PE(r'C:\SM2258XT_MPTool\SWPtest.dll')
base = p.OPTIONAL_HEADER.ImageBase

def rd(rva, n):
    for s in p.sections:
        if s.VirtualAddress <= rva < s.VirtualAddress + s.Misc_VirtualSize:
            return p.__data__[s.PointerToRawData + rva - s.VirtualAddress:
                              s.PointerToRawData + rva - s.VirtualAddress + n]
    raise ValueError(hex(rva))

seg = rd(0x1000, 0x46000)
target = base + 0xB178
hits = []
for i in range(len(seg) - 5):
    if seg[i] == 0xE8:
        va_call = base + 0x1000 + i
        rel = struct.unpack_from('<i', seg, i + 1)[0]
        if va_call + 5 + rel == target:
            hits.append(va_call)
print(f'callers of sub_40B178 ({len(hits)}):')
for h in hits: print(f'  {h:#x}')

# strings used in sub_40B178 body
for va in [0x44bea4, 0x44bea6, 0x44bea8, 0x44bebe, 0x44c008, 0x44bf74]:
    rva = va - base
    data = rd(rva, 64).split(b'\x00')[0]
    print(hex(va), data)
