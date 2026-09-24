# audit_8c43536.py — exhaustive forensic trace for the DriveReset → DownloadMPISP chain
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

pe = pefile.PE(r'C:\SM2258XT_MPTool\SM2258XTMPToolQ0816A.exe')
base_exe = pe.OPTIONAL_HEADER.ImageBase

def rd_exe(rva, n):
    for s in pe.sections:
        if s.VirtualAddress <= rva < s.VirtualAddress + s.Misc_VirtualSize:
            return pe.__data__[s.PointerToRawData + rva - s.VirtualAddress:
                               s.PointerToRawData + rva - s.VirtualAddress + n]
    raise ValueError(hex(rva))

# 1) sub_4024E0 full body — where the "F0 2C" goes
print('=' * 76)
print('1) sub_4024E0 — full body (DriveReset impl)')
print('=' * 76)
for ins in md.disasm(rd(0x24E0, 0x1C0), base+0x24E0):
    print(f'  {ins.address:#x}: {ins.mnemonic:10s} {ins.op_str}')

# 2) Find all callers of the DriveReset export thunk (RVA 0x7D10 in EXE)
print()
print('=' * 76)
print('2) EXE callers of _SMIPtestDriveReset thunk @ RVA 0x7D10')
print('=' * 76)
exe_seg = rd_exe(0x400, min(len(rd_exe(0x400, 0xD0000)), 0xD0000))
# thunk in EXE for the import — find addr
imports = pe.DIRECTORY_ENTRY_IMPORT
for dll in imports:
    if 'SWPtest' in dll.dll.decode():
        for imp in dll.imports:
            if imp.name and b'DriveReset' in imp.name:
                print(f'  Import of DriveReset at IAT VA {imp.address:#x}')
                iat_va = imp.address
                # scan EXE .text for call [iat_va]
                addr_bytes = struct.pack('<I', iat_va)
                i = exe_seg.find(addr_bytes)
                while i >= 0:
                    # any direct call (E8) or FF15/FF25 variants pointing at it
                    # ''FF 15'' is call dword ptr [mem]
                    for back in range(max(0, i-10), i):
                        if exe_seg[back] == 0xFF and back+1 < len(exe_seg) and exe_seg[back+1] == 0x15:
                            candidate = base_exe + 0x400 + back
                            print(f'    call dword ptr [{imp.address:#x}] site: VA {candidate:#x}')
                break