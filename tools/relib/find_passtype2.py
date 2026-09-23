# find_passtype2.py — better strategy: scan EXE for the string '_SMISetPassThroughType'
# to find the import stub, then find all 'call dword [IAT_slot_for_that_import]' in .text
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

# Step 1: locate the literal string '_SMISetPassThroughType' anywhere in any section
target_str = b'_SMISetPassThroughType\x00'
import os
print('File size:', os.path.getsize('SM2258XTMPToolQ0816A.exe'))
whole = open('SM2258XTMPToolQ0816A.exe','rb').read()
i = 0
hits = []
while True:
    j = whole.find(target_str, i)
    if j < 0: break
    hits.append(j)
    i = j+1
print(f'{len(hits)} hits of "_SMISetPassThroughType\\0" in file:')
for h in hits:
    # find which section
    for s in p.sections:
        filelo = s.PointerToRawData
        rva_lo = s.VirtualAddress
        filehi = filelo + s.SizeOfRawData
        if filelo <= h < filehi:
            rv = rva_lo + (h - filelo)
            print(f'  file off {h:#x} -> RVA {rv:#x} VA {base+rv:#x} section {s.Name}')
            # Show next 32 bytes around
            print(f'  bytes: {" ".join(f"{b:02X}" for b in whole[h:h+40])}')

# Step 2: how does the EXE call SWPtest exports? Standard Borland EXE links statically
# or uses GetProcAddress(GetModuleHandleA('SWPtest.dll'), '_SMISetPassThroughType').
# Search for 'SWPtest.dll' string first
print()
print('=== SWPtest.dll string references ===')
target2 = b'SWPtest.dll\x00'
i = 0
while True:
    j = whole.find(target2, i)
    if j < 0: break
    for s in p.sections:
        filelo = s.PointerToRawData
        rva_lo = s.VirtualAddress
        filehi = filelo + s.SizeOfRawData
        if filelo <= j < filehi:
            rv = rva_lo + (j - filelo)
            print(f'  file off {j:#x} -> RVA {rv:#x} section {s.Name}')
            print(f'  bytes: {" ".join(f"{b:02X}" for b in whole[j:j+32])}')
    i = j+1

# Step 3: Try the import directory — does the EXE statically import SWPtest.dll?
print()
print('=== Import directories ===')
if hasattr(p, 'DIRECTORY_ENTRY_IMPORT'):
    for ent in p.DIRECTORY_ENTRY_IMPORT:
        dll = ent.dll.decode()
        if 'SWP' in dll or 'swp' in dll.lower():
            print(f'IMPORTED DLL: {dll}')
            for imp in ent.imports:
                nm = imp.name.decode() if imp.name else f'ord{imp.ordinal}'
                print(f'  {nm} @ IAT RVA {imp.address:#x}')
        else:
            print(f'  (other: {dll})')
