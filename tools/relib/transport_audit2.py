# transport_audit2.py — resolve caller function identities for sub_171C / sub_165C
import pefile, capstone, struct
p = pefile.PE(r'C:\SM2258XT_MPTool\SWPtest.dll')
base = p.OPTIONAL_HEADER.ImageBase
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)

def rd(rva, n):
    for s in p.sections:
        if s.VirtualAddress <= rva < s.VirtualAddress + s.Misc_VirtualSize:
            return p.__data__[s.PointerToRawData + rva - s.VirtualAddress:
                              s.PointerToRawData + rva - s.VirtualAddress + n]
    raise ValueError(hex(rva))

# Function boundaries for context (known from prior work)
fns = [
    (0x165C, 0x171C, 'sub_165C (SCSI_PASS_THROUGH 0x4D014)'),
    (0x171C, 0x1838, 'sub_171C (SCSI_PASS_THROUGH_DIRECT 0x4D030)'),
    (0x1838, 0x19D8, 'sub_1838 (cmd-translation helper)'),
    (0x19D8, 0x1B84, 'sub_19D8 (cmd-translation helper)'),
    (0x1B84, 0x1D18, 'sub_1B84 (cmd helper)'),
    (0x1D18, 0x1E14, 'sub_1D18 (cmd helper)'),
    (0x1E14, 0x2300, 'sub_1E14 (cmd helper)'),
    (0x2300, 0x24E0, 'sub_2300 (ReadDriveInfo path)'),
    (0x5FB8, 0x6220, 'sub_5FB8 (detection handshake)'),
]

def fn_of(rva):
    for lo, hi, name in fns:
        if lo <= rva < hi:
            return name
    return 'unknown'

# Call-site analysis for each known sub_171C/sub_165C caller
# For each call, walk back ≤ 16 bytes to find pushed immediates
print('=== Detailed caller analysis for sub_171C (0x4D030 — used by Force ROM/downloads) ===\n')
callers_171c = [0x1895, 0x18C5, 0x1A35, 0x1A65, 0x1C51, 0x1D5B, 0x1E7A]
for crva in callers_171c:
    fn = fn_of(crva)
    # disasm window: ~0x30 bytes before the call site to capture pushes
    win_start = crva - 0x30
    print(f'Caller RVA {crva:#x} in {fn}:')
    for i in md.disasm(rd(win_start, 0x35), base+win_start):
        if i.address >= base + crva: break
        print(f'  {i.address:#x}: {i.mnemonic:8s} {i.op_str}')
    print()

print('=== Detailed caller analysis for sub_165C (0x4D014 — detection / RFI) ===\n')
callers_165c = [0x1974, 0x1B20, 0x1CA8, 0x1DAE, 0x1EC9]
for crva in callers_165c:
    fn = fn_of(crva)
    win_start = crva - 0x30
    print(f'Caller RVA {crva:#x} in {fn}:')
    for i in md.disasm(rd(win_start, 0x35), base+win_start):
        if i.address >= base + crva: break
        print(f'  {i.address:#x}: {i.mnemonic:8s} {i.op_str}')
    print()

# The 0x28-byte template at 0x447324 used by sub_171C (rep movsd x 10 dwords)
raw = rd(0x47324, 0x28)
print('=== sub_171C template (40 bytes, VA 0x447324) — SCSI_PASS_THROUGH_DIRECT template ===')
print(' '.join(f'{b:02X}' for b in raw))
print()

# Same for sub_165C init template? Its [ebp-0x2A] is set to 0x70 (112) and pushed as SenseInfoLength
# Print 0x447528 (referenced by helper 0x43CA1C init) and 0x447393 (error string near sub_165C)
for va_off in [0x47524, 0x47393, 0x47350]:
    print(f'[data @ VA {base+va_off:#x}]')
    print(' '.join(f'{b:02X}' for b in rd(va_off, 0x40)))
    print()
