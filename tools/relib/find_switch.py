# find_switch.py — decode the SetPassThroughType switcher fn (RVA ~0x3A7B8) and its callers
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

# Function start: from the bytes, prologue of the fn containing 0x3A7FA is before 0x3A7D0.
# The bytes at 0x3A7D0: '00 68 8C 7A 4F' looks like push 0x4F7A8C (string ptr). Go back.
# Scan window 0x3A700..0x3A7E0 for prologue
print('=== Window 0x3A700..0x3A840 decoded from RVA 0x3A700 ===')
code = rd(0x3A700, 0x140)
for ins in md.disasm(code, base+0x3A700):
    print(f'  {ins.address:#x}: {ins.mnemonic:12s} {ins.op_str}')
print()

# The 0x507FD0 and 0x507FC4 flags: search for 'mov dword ptr [0x507FD0], imm' (write)
print('=== Writers of [0x507FD0] (flag for type=2) ===')
# encode: C7 05 D0 7F 50 00 <imm32>
target1 = struct.pack('<I', 0x507FD0)
needle = b'\xC7\x05' + target1
text = rd(0x1000, 0xCE000)
i = 0
while True:
    j = text.find(needle, i)
    if j < 0: break
    imm = struct.unpack_from('<i', text, j+6)[0]
    print(f'  @ RVA {0x1000+j:#x}: mov dword ptr [0x507fd0], {imm}')
    # Show next 6 bytes for context (likely the next cmp/test)
    i = j+1

print()
print('=== Writers of [0x507FC4] (flag for type=1) ===')
target2 = struct.pack('<I', 0x507FC4)
needle = b'\xC7\x05' + target2
i = 0
while True:
    j = text.find(needle, i)
    if j < 0: break
    imm = struct.unpack_from('<i', text, j+6)[0]
    print(f'  @ RVA {0x1000+j:#x}: mov dword ptr [0x507fc4], {imm}')
    i = j+1

# Also nonzero writes via 'mov [global], reg'
# That requires full disasm. Let's just show 'cmp dword [0x507FD0], 0' sites (readers):
print()
print('=== Readers (cmp/test) of [0x507FD0] and [0x507FC4] ===')
needle3 = b'\x83\x3D' + target1
i = 0
while True:
    j = text.find(needle3, i)
    if j < 0: break
    imm8 = text[j+6]
    print(f'  @ RVA {0x1000+j:#x}: cmp dword ptr [0x507fd0], {imm8}')
    i = j+1
needle4 = b'\x83\x3D' + target2
i = 0
while True:
    j = text.find(needle4, i)
    if j < 0: break
    imm8 = text[j+6]
    print(f'  @ RVA {0x1000+j:#x}: cmp dword ptr [0x507fc4], {imm8}')
    i = j+1
