# u_audit2.py — raw byte-pattern sweep for immediate-5 encodings in SWPtest.dll .text
import struct
import pefile

p = pefile.PE(r'C:\SM2258XT_MPTool\SWPtest.dll')
base = p.OPTIONAL_HEADER.ImageBase

def rd(rva, n):
    for s in p.sections:
        if s.VirtualAddress <= rva < s.VirtualAddress + s.Misc_VirtualSize:
            off = s.PointerToRawData + (rva - s.VirtualAddress)
            return p.__data__[off:off+n]
    raise ValueError(hex(rva))

seg = rd(0x1000, 0x46000)
results = {
    'push 5 (6A 05)': [],
    'push dword 5 (68 05000000)': [],
    'mov reg,5 (B8+r 05000000)': [],
    'mov byte ptr [reg+off8],5 (C6 /r ib=05)': [],
    'mov dword ptr [rm],5 (C7 /0 05000000)': [],
    'cmp ...,5 (83 /7 ib=05)': [],
    'add ...,5 (83 /0 ib=05)': [],
    'xor ...,5 (83 /6 ib=05)': [],
}
L = len(seg)
i = 0
while i < L - 8:
    b = seg[i]
    va = base + 0x1000 + i
    if b == 0x6A and seg[i+1] == 5:
        results['push 5 (6A 05)'].append(va); i += 2; continue
    if b == 0x68 and seg[i+1:i+5] == b'\x05\x00\x00\x00':
        results['push dword 5 (68 05000000)'].append(va); i += 5; continue
    if 0xB8 <= b <= 0xBF and seg[i+1:i+5] == b'\x05\x00\x00\x00':
        results['mov reg,5 (B8+r 05000000)'].append(va); i += 5; continue
    if b == 0xC6:
        modrm = seg[i+1]
        # modrm mod bits 01 or 10 with ib following displacement, or mod00 direct
        mod = modrm >> 6
        if mod == 1 and seg[i+3] == 5:
            results['mov byte ptr [reg+off8],5 (C6 /r ib=05)'].append(va); i += 4; continue
        if mod == 0 and (modrm & 7) != 5 and seg[i+2] == 5:
            results['mov byte ptr [reg+off8],5 (C6 /r ib=05)'].append(va); i += 3; continue
    if b == 0xC7 and seg[i+2:i+6] == b'\x05\x00\x00\x00':
        results['mov dword ptr [rm],5 (C7 /0 05000000)'].append(va); i += 6; continue
    if b == 0x83:
        modrm = seg[i+1]
        subop = (modrm >> 3) & 7
        if seg[i+2] == 5:  # ib byte
            if subop == 7: results['cmp ...,5 (83 /7 ib=05)'].append(va)
            elif subop == 0: results['add ...,5 (83 /0 ib=05)'].append(va)
            elif subop == 6: results['xor ...,5 (83 /6 ib=05)'].append(va)
    i += 1

for k, v in results.items():
    print(f"{k}: {len(v)} hits")
    for va in v[:25]:
        print(f"  {va:#x} (RVA {va-base:#x})")
