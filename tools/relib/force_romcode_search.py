# force_romcode_search.py — exhaustive search for ForceRomCode paths in the EXE
import pefile, capstone, struct
pe = pefile.PE(r'C:\SM2258XT_MPTool\SM2258XTMPToolQ0816A.exe')
base = pe.OPTIONAL_HEADER.ImageBase
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)

def rd(rva,n):
    for s in pe.sections:
        if s.VirtualAddress <= rva < s.VirtualAddress + s.Misc_VirtualSize:
            return pe.__data__[s.PointerToRawData + rva - s.VirtualAddress:s.PointerToRawData + rva - s.VirtualAddress + n]

# Search for 'force RomCode', 'RomCode', 'RomCodeInit', 'RomLoad' strings
data = pe.__data__
for needle in [b'RomCode', b'RomCd', b'RomCodeMode', b'RomCodeInit', b'ForceRom', b'forceRom',
               b'SMILoadRom', b'SMIForceRom', b'TechnMode', b'TechnoMode', b'SafeMode',
               b'BootISP', b'MPISP', b'SRAM', b'Upload', b'UploadSRAM']:
    i = 0; count = 0
    while True:
        j = data.find(needle, i)
        if j < 0: break
        # Find RVA
        for s in pe.sections:
            if s.PointerToRawData <= j < s.PointerToRawData + s.SizeOfRawData:
                rva = s.VirtualAddress + (j - s.PointerToRawData)
                end = data.find(b'\x00', j)
                snippet = data[j:end][:80].decode('ascii', 'ignore')
                print(f'  "{needle.decode()}"@{rva:#x}: "{snippet}"')
                count += 1
                break
        i = j + 1
    if count > 0:
        pass
    if not count:
        print(f'  "{needle.decode()}": 0 hits')
