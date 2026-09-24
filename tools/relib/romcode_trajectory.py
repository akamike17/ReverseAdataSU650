# romcode_trajectory.py — reconstruct execution flow from EXE around DownloadMPISP
import pefile, capstone, struct
pe = pefile.PE(r'C:\SM2258XT_MPTool\SM2258XTMPToolQ0816A.exe')
base = pe.OPTIONAL_HEADER.ImageBase
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)

def rd(rva,n):
    for s in pe.sections:
        if s.VirtualAddress <= rva < s.VirtualAddress + s.Misc_VirtualSize:
            return pe.__data__[s.PointerToRawData + rva - s.VirtualAddress:s.PointerToRawData + rva - s.VirtualAddress + n]
    return None

# Find the DownloadMPISP function entry by looking at the GetProcAddress-address resolution
# In the previous audit we saw the shared helper 0x40197c has 18 + 0x14 args.
# We need to find where the resolved function pointer is stored.
# The pattern is: GetProcAddress(..., '_SMIPtestDownloadMPISP') then store address to a local var
# at runtime.

# Alternative approach: find the string 'MPISP fail' or 'MPISP Mode' and trace back to its caller

# Strings at RVA 0xF83A5 'MPISP fail, ErrorCode=(0x%.2X)/(0x%.2X)' — appears in firmware download
# Let's see the xref:
data = pe.__data__
for needle in [b'MPISP fail, ErrorCode', b'MPISP Mode after download']:
    i = data.find(needle)
    while i >= 0:
        for s in pe.sections:
            if s.PointerToRawData <= i < s.PointerToRawData + s.SizeOfRawData:
                rva = s.VirtualAddress + (i - s.PointerToRawData)
                print(f'String "{needle.decode()}" at RVA {rva:#x}')
                # Now look for xrefs in .text
                for s2 in pe.sections:
                    if s2.Name.startswith(b'.text'):
                        text = pe.__data__[s2.PointerToRawData:s2.PointerToRawData + s2.SizeOfRawData]
                        trva = s2.VirtualAddress
                ptr = struct.pack('<I', base + rva)
                # find in text
                ppos = 0
                while True:
                    j = text.find(ptr, ppos)
                    if j < 0: break
                    # candidate is at .text RVA = trva + j
                    addr = trva + j
                    print(f'    xref to "{needle.decode()}" at VA {base+addr:#x}')
                    ppos = j+1
                break
        i = data.find(needle, i+1)
