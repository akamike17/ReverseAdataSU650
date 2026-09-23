# passtype_audit.py — Part 1: _SMISetPassThroughType + global read/write map of [0x45DD4C]
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

# Locating _SMISetPassThroughType export RVA
for exp in p.DIRECTORY_ENTRY_EXPORT.symbols:
    name = exp.name.decode() if exp.name else ''
    if 'PassThrough' in name or 'passThrough' in name:
        rva = exp.address
        print(f'EXPORT {name} @ RVA {rva:#x}')
        for i in md.disasm(rd(rva, 0x100), base + rva):
            print(f'{i.address:#x}: {i.mnemonic:10s} {i.op_str}')
            if i.mnemonic.startswith('ret') and i.address != base + rva:
                break

# Read default value of [0x45DD4C] in .data / .bss
# Find the section that contains RVA 0x45DD4C
for s in p.sections:
    if s.VirtualAddress <= 0x45DD4C < s.VirtualAddress + s.Misc_VirtualSize:
        va_off = 0x45DD4C - s.VirtualAddress
        # If section is .bss (virtual only)
        if s.SizeOfRawData == 0 or va_off >= s.SizeOfRawData:
            print(f'\n[0x45DD4C] lives in UNINITIALIZED section {s.Name} -> default = BORLAND RTL zero-init (CONFIRMED)')
            print(f'  section VA {hex(s.VirtualAddress)}, VSize {hex(s.Misc_VirtualSize)}, RawSize {hex(s.SizeOfRawData)}')
        else:
            off = s.PointerToRawData + va_off
            print(f'\n[0x45DD4C] lives in section {s.Name}, raw byte = {p.__data__[off]:#x}')
        break

# All reads/writes of [0x45DD4C] in .text
print('\n=== Accesses to [0x45DD4C] in .text ===')
seg = rd(0x1000, 0x46000)
target = base + 0x45DD4C
for i in md.disasm(seg, base + 0x1000):
    if i.mnemonic == 'mov' and 'byte ptr [0x45dd4c]' in i.op_str.lower():
        side = 'READ' if i.op_str.startswith('byte ptr') else 'WRITE'
        # distinguish: 'mov X, byte ptr [addr]' = read; 'mov byte ptr [addr], X' = write
        ops = i.op_str.split(',', 1)
        if ops[0].startswith('byte ptr'):
            print(f'WRITE @ {i.address:#x}: {i.mnemonic} {i.op_str}')
        else:
            print(f'READ  @ {i.address:#x}: {i.mnemonic} {i.op_str}')
    elif 'byte ptr [0x45dd4c]' in i.op_str.lower() or '[0x45dd4c]' in i.op_str.lower():
        print(f'OTHER @ {i.address:#x}: {i.mnemonic} {i.op_str}')
