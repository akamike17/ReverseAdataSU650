# boot_forcer.py — search the EXE for any SOFTWARE RomCode trigger (precursor to DriveReset)
import pefile, capstone
pe = pefile.PE(r'C:\SM2258XT_MPTool\SM2258XTMPToolQ0816A.exe')
base = pe.OPTIONAL_HEADER.ImageBase
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)

def rd(rva,n):
    for s in pe.sections:
        if s.VirtualAddress <= rva < s.VirtualAddress + s.Misc_VirtualSize:
            return pe.__data__[s.PointerToRawData + rva - s.VirtualAddress:s.PointerToRawData + rva - s.VirtualAddress + n]
    return None

# Look for hex constants that could represent vendor-issued "force RomCode" commands
# We already know:
#   0xE0 — CDB[9] "FORCEROM" constant in sub_171C (0x4D030 vendor payload)
#   Are there other encoded sequences in the EXE?
data = pe.__data__

# Search for byte sequences that look like the CDB prefix F0 2C/E0
# CDB[0] F0, CDB[1] 2C — this is a romcode-mode trigger
targets = [
    (b'\xF0\x2C', 'F0 2C'),       # RomCode trigger + bank
    (b'\xF0\x04', 'F0 04'),       # ReadDriveInfo base
    (b'\xE0\xC8', 'E0 C8'),       # extended vendor cmds
    (b'\xEA\x35', 'EA 35'),       # bootISP marker
]
for needle, label in targets:
    i = 0
    found = []
    while True:
        j = data.find(needle, i)
        if j < 0: break
        for s in pe.sections:
            if s.PointerToRawData <= j < s.PointerToRawData + s.SizeOfRawData:
                rva = s.VirtualAddress + (j - s.PointerToRawData)
                found.append((rva, s.Name))
                break
        i = j + 1
    print(f'{label}: {len(found)} hits')
    for rva, sect in found[:10]:
        print(f'  @{rva:#x} in {sect}')

print()
print('=== Find strings that give hints about MODE trigger ===')
# Search for typical R&D keywords
for kw in [b'power reset', b'power-up', b'poweron', b'JTAG', b'JTAGEN', 
           b'rom_mode invert', b'Soft ROM', b'watchdog reset', b'ColdBoot',
           b'set the mode', b'set mode to', b'Intrusion', b'BootRom',
           b'Part ID', b'PartID', b'ModelNum', b'CpuFreqUnlock']:
    i = 0; count = 0
    while True:
        j = data.find(kw, i)
        if j < 0: break
        # Convert file offset to RVA
        for s in pe.sections:
            if s.PointerToRawData <= j < s.PointerToRawData + s.SizeOfRawData:
                rva = s.VirtualAddress + (j - s.PointerToRawData)
                end = data.find(b'\x00', j)
                snippet = data[j:end][:80].decode('ascii', 'ignore')
                print(f'  "{kw.decode()}" @{rva:#x}: "{snippet}"')
                count += 1
                break
        i = j + 1
    if count == 0:
        print(f'  "{kw.decode()}": 0 hits')
