# find_writers.py — read the strings near 0x4F7E44, plus identify [0x4CF348] IAT slot
import pefile, struct
p = pefile.PE('SM2258XTMPToolQ0816A.exe')
base = p.OPTIONAL_HEADER.ImageBase

def rd(rva,n):
    for s in p.sections:
        if s.VirtualAddress <= rva < s.VirtualAddress + s.Misc_VirtualSize:
            return p.__data__[s.PointerToRawData + rva - s.VirtualAddress:
                              s.PointerToRawData + rva - s.VirtualAddress + n]
    return b''

# The IAT slot for the lookup function — find which import this is
print('=== IAT slot VA 0x4CF344 and 0x4CF348 ===')
# From earlier: kernel32 GetProcAddress=[0x4CF358], LoadLibraryA=[0x4CF370], GetModuleHandleA=[0x4CF428]
# Look up KERNEL32 imports table
for ent in p.DIRECTORY_ENTRY_IMPORT:
    if ent.dll.decode() == 'KERNEL32.dll':
        for imp in ent.imports:
            nm = imp.name.decode() if imp.name else f'ord{imp.ordinal}'
            if abs((base + imp.address) - 0x4CF344) < 0x30 or abs((base + imp.address) - 0x4CF348) < 0x30:
                print(f'  {nm} @ IAT_VAbsULT={base+imp.address:#x}')

# Read the strings near 0xF7E44 (RVA). Converting VA 0x4F7E44 -> RVA 0xF7E44 (base 0x400000)
print()
print('=== Strings in .data around the INI keys ===')
for rva in [0xF7E44, 0xF7E48, 0xF7E54, 0xF7E60, 0xF7E68, 0xF7E70,
            0xF7E8C, 0xF7E94, 0xF7EA4, 0xF7EAC, 0xF7EC0, 0xF7EC8, 0xF7ED8]:
    s = rd(rva, 64)
    # extract nul-terminated
    end = s.find(b'\x00')
    if end > 0:
        txt = s[:end].decode('ascii', errors='replace')
        print(f'  VA {hex(base+rva)}: {txt}')
