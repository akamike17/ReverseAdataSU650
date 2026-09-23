# find_passtype5.py — find the FUNCTION containing RVA 0x3A7FD/0x3A813/0x3A820,
# then find ALL callers of that function
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

# Show full context: from RVA 0x3A7E0 to 0x3A840
print('=== Around the 3 call sites ===')
for i in md.disasm(rd(0x3A7E0, 0x80), base+0x3A7E0):
    print(f'{i.address:#x}: {i.mnemonic:10s} {i.op_str}')

print()
print('=== Find function start (scan backward from 0x3A7E0 for "push ebp; mov ebp, esp") ===')
# A standard Borland function starts with 55 8B EC (or 55 8B EC 83 EC/81 EC etc.)
target_off = 0x3A7E0 - 0x1000
seg = rd(0x1000, 0x46000)
for back in range(0, 0x200):
    st = target_off - back
    if st < 0: break
    if seg[st:st+3] == b'\x55\x8B\xEC':
        # function start found
        print(f'  Func start candidate @ RVA {0x1000+st:#x}')
        # confirm next is sub esp or push regs
        rest = seg[st+3:st+8]
        print(f'    next bytes: {" ".join(f"{b:02X}" for b in rest)}')
        break
