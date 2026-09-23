# find_passtype3.py — find who refs the string _SMISetPassThroughType (GetProcAddress call sites)
import pefile, capstone, struct
p = pefile.PE('SM2258XTMPToolQ0816A.exe')
base = p.OPTIONAL_HEADER.ImageBase
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)

def rd(rva,n):
    for s in p.sections:
        if s.VirtualAddress <= rva < s.VirtualAddress + s.Misc_VirtualSize:
            return p.__data__[s.PointerToRawData + rva - s.VirtualAddress:
                              s.PointerToRawData + rva - s.VirtualAddress + n]
    return b''

# String VA (with base)
sva = base + 0xF6C2C  # VA of "_SMISetPassThroughType\0" in .data
print(f'Searching for references to string VA {sva:#x} (RVA 0xF6C2C)')
needle = struct.pack('<I', sva)

# Scan all .text for references to this VA
text = rd(0x1000, 0x45400)
hits = []
i = 0
while True:
    j = text.find(needle, i)
    if j < 0: break
    hits.append(0x1000 + j)
    i = j+1
print(f'{len(hits)} actors reference string VA {sva:#x}:')

for rv in hits:
    # disasm around to find instruction
    code = rd(rv-8, 0x30)
    # find containing insn: scan back each start
    found = None
    for back in range(0, 12):
        start = rv - back
        cc = rd(start, 0x14)
        for ins in md.disasm(cc, base+start):
            if ins.address == base+start and start < rv < start + ins.size:
                found = (start, ins.mnemonic, ins.op_str)
                break
        if found: break
    if found:
        print(f'  @ RVA {found[0]:#x} (hit in same insn): {found[1]} {found[2]}')
    else:
        print(f'  @ RVA {rv:#x} (operand contains VA)')

# Also find all references to "SWPtest.dll" string (RVA 0xF7819)
print()
sva2 = base + 0xF7819
print(f'Searching for references to SWPtest.dll string VA {sva2:#x}')
needle2 = struct.pack('<I', sva2)
hits2 = []
i = 0
while True:
    j = text.find(needle2, i)
    if j < 0: break
    hits2.append(0x1000 + j)
    i = j+1
for rv in hits2:
    code = rd(rv-8, 0x30)
    found = None
    for back in range(0, 12):
        start = rv - back
        cc = rd(start, 0x14)
        for ins in md.disasm(cc, base+start):
            if ins.address == base+start and start < rv < start + ins.size:
                found = (start, ins.mnemonic, ins.op_str)
                break
        if found: break
    print(f'  @ RVA {found[0]:#x}: {found[1]} {found[2]}' if found else f'  @ {rv:#x}')

# Now look at the EXE's GetProcAddress stubs — find the IAT slot for GetProcAddress from kernel32
print('\n=== kernel32 GetProcAddress IAT slot ===')
for ent in p.DIRECTORY_ENTRY_IMPORT:
    if ent.dll.decode() == 'KERNEL32.dll':
        for imp in ent.imports:
            nm = imp.name.decode() if imp.name else ''
            if 'GetProcAddress' in nm or 'LoadLibrary' in nm or 'GetModuleHandle' in nm:
                print(f'  {nm} @ IAT RVA {imp.address:#x} VA {base+imp.address:#x}')
