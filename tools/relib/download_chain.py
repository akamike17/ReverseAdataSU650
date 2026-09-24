# download_chain.py — where DownloadMPISP actually starts and what it does
import pefile, capstone, struct
pe = pefile.PE(r'C:\SM2258XT_MPTool\SM2258XTMPToolQ0816A.exe')
base = pe.OPTIONAL_HEADER.ImageBase
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)

def rd(rva,n):
    for s in pe.sections:
        if s.VirtualAddress <= rva < s.VirtualAddress + s.Misc_VirtualSize:
            return pe.__data__[s.PointerToRawData + rva - s.VirtualAddress:s.PointerToRawData + rva - s.VirtualAddress + n]
    return None

# The key strings for the DownloadMPISP entry are:
# 'MPISP2258.bin'  
# 'DownloadMPISP'  
# 'MPISP Code'  
# Let's find the function that calls operate based on file read
# Since 'Firmware\2258\MPISP2258.bin' is used as path, search for it:
for needle in [b'Firmware\\2258\\MPISP2258.bin', b'MPISP2258.bin', b'MPISP2258.ROMDEBUG.bin']:
    i = pe.__data__.find(needle)
    while i >= 0:
        for s in pe.sections:
            if s.PointerToRawData <= i < s.PointerToRawData + s.SizeOfRawData:
                rva = s.VirtualAddress + (i - s.PointerToRawData)
                print(f'String "{needle.decode()}" at RVA {rva:#x}  VA {base+rva:#x}')
                break
        i = pe.__data__.find(needle, i+1)
