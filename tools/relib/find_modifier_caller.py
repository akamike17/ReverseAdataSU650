# find_modifier_caller.py — find function containing RVA 0x3A01B and its callers
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

# Find function start near RVA 0x3A01B
print('=== Backward scan for function containing 0x3A01B ===')
code = rd(0x3A01B - 0x400, 0x800)
# find all 'push ebp; mov ebp, esp' in that window
for off in range(0, 0x400):
    if code[off:off+3] == b'\x55\x8B\xEC':
        rva = 0x3A01B - 0x400 + off
        # disasm 4 bytes to confirm
        for ins in md.disasm(code[off:off+8], base + rva):
            print(f'  fn-start candidate @ RVA {rva:#x}: {ins.mnemonic} {ins.op_str}')
            break

print()
print('=== Disasm from RVA 0x39FC0 to 0x3A080 (context around the caller) ===')
for ins in md.disasm(rd(0x39FC0, 0xC0), base+0x39FC0):
    print(f'  {ins.address:#x}: {ins.mnemonic:12s} {ins.op_str}')

# That function contains the call at 0x3A01B and persists the flags read for later use
print()
print('=== All calls targeting the function we are tracing into ===')
# We don't know its RVA yet — see disasm above
