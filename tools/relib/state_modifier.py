# state_modifier.py — find every export in SWPtest.dll that can set up the drive before CheckRunMode
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

# Dump every export in SWPtest.dll — looking for state-modifying (non-read-only) exports
print('=== SWPtest.dll exports (full list) ===')
exports = []
for exp in p.DIRECTORY_ENTRY_EXPORT.symbols:
    name = exp.name.decode() if exp.name else f'ord{exp.ordinal}'
    exports.append((exp.ordinal, exp.address, name))

exports.sort(key=lambda x: x[1])
for o, rva, n in exports:
    print(f'  ord={o:4d} RVA={rva:#8x} {n}')
