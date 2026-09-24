# romcode_paths.py — find every function in EXE that references RomCode strings
import pefile, capstone, struct
pe = pefile.PE(r'C:\SM2258XT_MPTool\SM2258XTMPToolQ0816A.exe')
base = pe.OPTIONAL_HEADER.ImageBase
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)

def rd(rva,n):
    for s in pe.sections:
        if s.VirtualAddress <= rva < s.VirtualAddress + s.Misc_VirtualSize:
            return pe.__data__[s.PointerToRawData + rva - s.VirtualAddress:s.PointerToRawData + rva - s.VirtualAddress + n]

romcode_strings = [0xECA24, 0xECCE6, 0xFB172, 0x1023F2, 0x10250B, 0x1044A6]
# error: previous line had typo — let me clean it up
print('These are the RomCode string locations:')
string_rvas = [0xECA24, 0xECCE6, 0xFB172, 0x1023F2, 0x10250B, 0x1044A6]
for rva in string_rvas:
    va = base + rva
    # find xrefs to va
    text_seg = None
    for s in pe.sections:
        if s.Name.startswith(b'.text'):
            text_seg = pe.__data__[s.PointerToRawData:s.PointerToRawData + s.SizeOfRawData]
            text_rva = s.VirtualAddress
            text_base_va = base + s.VirtualAddress
            break
    if text_seg is None: continue
    
    ptr = struct.pack('<I', va)
    # find calls JMP/MOV/LEA referencing this string
    pos = 0; found = []
    while True:
        i = text_seg.find(ptr, pos)
        if i < 0: break
        site_rva = text_rva + i
        site_va = base + site_rva
        found.append(site_va)
        pos = i + 1
    if found:
        print(f'String @{va:#x}: {len(found)} refs')
        for v in found[:5]:
            print(f'  ref at VA {v:#x}')
