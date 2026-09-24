# audit2.py — continue: callers of DriveReset in EXE + transport + timing + post-state
import pefile, capstone, struct

pe = pefile.PE(r'C:\SM2258XT_MPTool\SM2258XTMPToolQ0816A.exe')
base = pe.OPTIONAL_HEADER.ImageBase
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)

def rd(rva, n):
    for s in pe.sections:
        if s.VirtualAddress <= rva < s.VirtualAddress + s.Misc_VirtualSize:
            return pe.__data__[s.PointerToRawData + rva - s.VirtualAddress:
                               s.PointerToRawData + rva - s.VirtualAddress + n]
    raise ValueError(hex(rva))

# Find DriveReset import VA via IAT
drva = None
drname = None
for dll in pe.DIRECTORY_ENTRY_IMPORT:
    if b'SWPtest' in dll.dll:
        for imp in dll.imports:
            if imp.name and b'DriveReset' in imp.name:
                drva = imp.address
                drname = imp.name.decode()
                break
print(f'DriveReset IAT VA = {drva:#x} name={drname}')

# Scan for "call dword ptr [drva]" pattern in .text
text_seg = rd(0x400, 0xCE000)
pattern_ff15 = b'\xff\x15' + struct.pack('<I', drva)   # FF 15 XX XX XX XX
i = 0
callers = []
while True:
    j = text_seg.find(pattern_ff15, i)
    if j < 0: break
    callers.append(base + 0x400 + j)
    i = j + 1
print(f'callers of DriveReset (FF15 call): {len(callers)}')
for c in callers:
    print(f'  call site VA = {c:#x}')
