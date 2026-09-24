# forcerom_disassembly.py — disassemble ForceROM.exe main path
import pefile, capstone, struct
p = pefile.PE(r'C:\SM2258XT_MPTool\ForceROM.exe')
base = p.OPTIONAL_HEADER.ImageBase
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)

# disasm entry point
epva = p.OPTIONAL_HEADER.AddressOfEntryPoint
textsec = next(s for s in p.sections if s.VirtualAddress <= epva < s.VirtualAddress + s.Misc_VirtualSize)
ep_off = textsec.PointerToRawData + (epva - textsec.VirtualAddress)
code = p.__data__[ep_off:ep_off + 0x400]

print(f'ForceROM.exe entry point @ RVA {epva:#x}, VA {base+epva:#x}')
print()
print('First 256 bytes disassembled:')
for ins in md.disasm(code, base + epva):
    fl = f'0x{ins.address:x}'
    if int(fl, 16) > base + epva + 0x400: break
    print(f'  {ins.address:#x}: {ins.mnemonic:8s} {ins.op_str}')
