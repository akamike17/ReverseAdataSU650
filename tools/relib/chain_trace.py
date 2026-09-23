# chain_trace.py — exact chain: sub_5FB8 -> helpers -> CDB -> transport -> response -> mode
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

# --- Callers of sub_5FB8 (used by sub_2300 to write mode byte) ---
seg = rd(0x1000, 0x46000)
def find_callers(target_rva):
    t = base + target_rva
    hits = []
    for i in range(len(seg)-5):
        if seg[i] == 0xE8:
            va_call = base + 0x1000 + i
            rel = struct.unpack_from('<i', seg, i+1)[0]
            if va_call + 5 + rel == t:
                hits.append(0x1000 + i)
    return hits

# sub_5FB8 - detector helper used by sub_2300
print('=== Callers of sub_5FB8 (the marker+string detection) ===')
for r in find_callers(0x5FB8): print(f'  {r:#x}')
print('=== Callers of sub_2300 (the mode-byte producer) ===')
for r in find_callers(0x2300): print(f'  {r:#x}')

# Who calls sub_4827AC (EXE-side equivalent) — already known: 22 sites listed earlier.
# Focus: sub_2300's body — what helper does it call to fetch the response?
print('\n=== sub_2300 body — fully dump for CDB/trace ===')
for i in md.disasm(rd(0x2300, 0x200), base+0x2300):
    print(f'{i.address:#x}: {i.mnemonic:8s} {i.op_str}')
