# read10_recon.py — exact CDB built by sub_1838 type=0 (the path the historical harness took)
import pefile, capstone
p = pefile.PE(r'C:\SM2258XT_MPTool\SWPtest.dll')
base = p.OPTIONAL_HEADER.ImageBase
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)

def rd(rva, n):
    for s in p.sections:
        if s.VirtualAddress <= rva < s.VirtualAddress + s.Misc_VirtualSize:
            return p.__data__[s.PointerToRawData + rva - s.VirtualAddress:
                              s.PointerToRawData + rva - s.VirtualAddress + n]
    raise ValueError(hex(rva))

# The sub_1838 type==0 branch is at RVA 0x401942..0x40196E
print('=== sub_1838 type=0 (default) branch — RVA 0x1942..0x1979 ===')
for i in md.disasm(rd(0x1942, 0x40), base+0x1942):
    print(f'{i.address:#x}: {i.mnemonic:10s} {i.op_str}')

# Note: at 0x401976 the call target is sub_165C (SCSI_PASS_THROUGH, buffer-based)
# struct 165C: caller passes [ebp+0xC] (the just-filled struct area), sub_165C then sends
# DeviceIoControl(handle, 0x4D014, structBase, 0x70, structBase, 0x70, &bytesReturned, 0)
print()
print('=== sub_165C full pass-through call ===')
for i in md.disasm(rd(0x165C, 0xB0), base+0x165C):
    print(f'{i.address:#x}: {i.mnemonic:10s} {i.op_str}')

print()
print('=== sub_2300 — the caller of sub_1838 with sector count ===')
for i in md.disasm(rd(0x2429, 0x60), base+0x2429):
    print(f'{i.address:#x}: {i.mnemonic:10s} {i.op_str}')
