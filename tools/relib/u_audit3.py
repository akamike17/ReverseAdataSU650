# u_audit3.py — context analysis: is each 0x05-immediate inside a function reachable from _SMIPtestCheckRunMode?
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

# Reachable from sub_CF98 (call graph computed incrementally by hand from prior phases):
# sub_CF98 (0xCF98..0xD266)
#   -> sub_2300 (0x2300..0x24DF)
#   -> sub_40B104 (0xB104..0xB175)  [failure only]
#   -> sub_40B178 (0xB178..0xB330)
#   -> sub_406438 (memcpy append) / sub_40674C (returns length of AnsiString)
#   -> Borland RTL helpers: 0x43CA1C (SEH init), 0x445EA8 (str init), 0x445F68, 0x405F6C,
#      0x43B28C (malloc), 0x43B0C4 (free), 0x444B30, 0x4048AC, 0x434980, 0x44610C, 0x445FC0
# None of the immediate-5 hits fall within 0xCF98..0xD266 nor 0x2300..0x24DF except 0x40D09E
# (the already-known log-level push on failure branch).
# Below we confirm the immediate-5 hits are all outside this graph.

relevant_range = list(range(0xCF98, 0xD267)) + list(range(0x2300, 0x24E0)) + \
                 list(range(0xB104, 0xB175)) + list(range(0xB178, 0xB330))

seg = rd(0x1000, 0x46000)
hits_5 = []
L = len(seg)
i = 0
while i < L - 8:
    b = seg[i]
    va = base + 0x1000 + i
    found = False
    if b == 0x6A and seg[i+1] == 5: found = True; step = 2
    elif b == 0x68 and seg[i+1:i+5] == b'\x05\x00\x00\x00': found = True; step = 5
    elif 0xB8 <= b <= 0xBF and seg[i+1:i+5] == b'\x05\x00\x00\x00': found = True; step = 5
    elif b == 0xC6:
        modrm = seg[i+1]; mod = modrm >> 6
        if mod == 1 and seg[i+3] == 5: found = True; step = 4
        elif mod == 0 and (modrm & 7) != 5 and seg[i+2] == 5: found = True; step = 3
        else: step = 1
    elif b == 0xC7 and seg[i+2:i+6] == b'\x05\x00\x00\x00': found = True; step = 6
    elif b == 0x83:
        modrm = seg[i+1]; subop = (modrm >> 3) & 7
        if seg[i+2] == 5 and subop in (0, 6, 7): found = True; step = 3
        else: step = 1
    else: step = 1
    if found:
        hits_5.append(va - base)
        i += step
    else:
        i += 1

# Check membership in relevant range
print(f'Total immediate-5 ops found: {len(hits_5)}')
in_scope = [r for r in hits_5 if r in set(relevant_range)]
print(f'Inside sub_CF98 / sub_2300 / sub_40B104 / sub_40B178 bodies: {len(in_scope)}')
for r in in_scope: print(f'  RVA {r:#x}')
print()
print('All hits with zone annotations:')
for r in hits_5:
    which = []
    if 0xCF98 <= r < 0xD267: which.append('sub_CF98')
    if 0x2300 <= r < 0x24E0: which.append('sub_2300')
    if 0xB104 <= r < 0xB175: which.append('sub_40B104')
    if 0xB178 <= r < 0xB330: which.append('sub_40B178')
    if 0x6438 <= r < 0x650C: which.append('sub_406438(memcpy)')
    if 0x674C <= r < 0x6850: which.append('sub_40674C(strlen)')
    label = ', '.join(which) if which else 'elsewhere-in-DLL'
    print(f'  RVA {r:#7x}  {label}')
