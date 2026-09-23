# passtype2.py — resolve sub_40136C and locate every reference to 0x45DD4C & sibling globals
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

print('=== sub_40136C (called by _SMISetPassThroughType with arg=type) ===')
for i in md.disasm(rd(0x136C, 0x80), base+0x136C):
    print(f'{i.address:#x}: {i.mnemonic:10s} {i.op_str}')

# Search all references to VA 0x45DD4C pattern in raw bytes (little-endian 4C DD 45 00)
print('\n=== Raw byte search for 0x45DD4C (le = 4C DD 45 00) ===')
seg = rd(0x1000, 0x46000)
needle = struct.pack('<I', base + 0x45DD4C)
i = 0
hits = []
while True:
    j = seg.find(needle, i)
    if j < 0: break
    hits.append(base + 0x1000 + j)
    i = j + 1
print(f'{len(hits)} raw offsets reference VA {base+0x45DD4C:#x}:')
for h in hits: print(f'  {h:#x} ({h-base:#x})')

# Now disasm a few rows around each hit and identify which one writes vs reads (instruction boundaries)
print('\n== Disasm hits as instruction starts (5B window before) ==')
for h in hits:
    try:
        start = h - base - 8
        # find instruction boundary: scan back
        window = rd(start, 0x14)
        # Get the full instruction containing this operand (operand is at pos ~ 4 bytes before end)
        for i in md.disasm(window, base + start):
            if h - base >= i.address - base and h - base < i.address - base + i.size:
                print(f'  {i.address:#x}: {i.mnemonic} {i.op_str}')
                break
    except Exception as e:
        print(f'  {h:#x}: disasm err {e}')
