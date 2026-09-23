# exhaustive_writes2.py — find function containing RVA 0x3AD47 / 0x3AD68 + its callers
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

# Disasm back from a known-good boundary: Borland method tables are aligned to 4
# and functions typically start with '55 8B EC' or 'push ebp; mov ebp,esp; sub esp,...'
# Try disasm backwards from RVA 0x3AD47 in chunks of 0x400 until the code parses cleanly
# and reaches a 'ret' boundary earlier.

# Simplest: linear-sweep from way before, find function boundaries
print('=== Linear sweep from 0x3AC00 to 0x3AE00 ===')
code = rd(0x3AC00, 0x200)
for ins in md.disasm(code, base + 0x3AC00):
    print(f'  {ins.address:#x}: {ins.mnemonic:12s} {ins.op_str}')

print()
print('=== Backward-scan for function entry (prologue "55 8B EC") ===')
for back in range(0x3AD47 - 0x200, 0x3AD47 + 1):
    seg = rd(back, 3)
    if len(seg) == 3 and seg[:3] == b'\x55\x8B\xEC':
        # disasm 12 bytes to confirm prologue pattern
        sub = md.disasm(rd(back, 16), base + back)
        for ins in sub:
            print(f'  fn-start @ RVA {back:#x}: {ins.mnemonic} {ins.op_str}')
            if ins.address - base > back + 6:
                break
        break

print()
# Callers of that function = any 'call RVA' targeting it.
# Identify function start precisely first via backward scan, defaulting to 0x3AC00 if not found.
fn_start = 0x3AC00  # heuristic if no clean prologue found
# Real disasm from 0x3AC00 — what's around the writes?
print('=== Confirm: are 0x3AD47/0x3AD68 inside the same function? ===')
# Look for any 'ret' or 'push ebp' between them.
# From output below, examine.
