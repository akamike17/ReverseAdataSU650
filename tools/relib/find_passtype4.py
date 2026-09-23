# find_passtype4.py — find where EXE stores the _SMISetPassThroughType pointer, then its callers
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

# Disasm around RVA 0x327BC to see what's stored where (the GetProcAddress call site)
print('=== Around RVA 0x327BC (pushing string) ===')
for i in md.disasm(rd(0x327B0, 0x60), base+0x327B0):
    print(f'{i.address:#x}: {i.mnemonic:12s} {i.op_str}')

# The string is pushed as GetProcAddress arg. The return value goes to EAX,
# then it's stored to some global slot. Find that slot from the disasm above.
# Then collect every 'call dword [slot]' in .text.
