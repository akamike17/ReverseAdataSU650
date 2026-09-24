# audit3.py — resolve DriveReset ordinal/address and EXE callers properly
import pefile, capstone, struct

# In SWPtest.dll the exports table showed:
#   ordinal=20, RVA=0x7D10, name=_SMIPtestDriveReset
# In the EXE, the same import is referenced via the IAT thunks.

pe = pefile.PE(r'C:\SM2258XT_MPTool\SM2258XTMPToolQ0816A.exe')
base = pe.OPTIONAL_HEADER.ImageBase
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)

def rd(rva, n):
    for s in pe.sections:
        if s.VirtualAddress <= rva < s.VirtualAddress + s.Misc_VirtualSize:
            return pe.__data__[s.PointerToRawData + rva - s.VirtualAddress:
                               s.PointerToRawData + rva - s.VirtualAddress + n]

# Enumerate imports dynamically
print('=== EXE imports from SWPtest.dll ===')
for dll in pe.DIRECTORY_ENTRY_IMPORT:
    if b'SWPtest' not in dll.dll:
        continue
    for imp in dll.imports:
        nm = imp.name.decode() if imp.name else f'@{imp.ordinal}'
        print(f'  IAT VA={imp.address:#x}  hint={imp.hint}  {nm}')

# Note: ordinal imports have no name; find by ordinal=20 (decimal)
# If ordinal-based, the reference will be a 16-bit ordinal in the Import Lookup Table
