# map_all_sw_pointers.py — extract EVERY GetProcAddress argument and resolve its function name
import pefile, capstone, struct
pe = pefile.PE(r'C:\SM2258XT_MPTool\SM2258XTMPToolQ0816A.exe')
base = pe.OPTIONAL_HEADER.ImageBase
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)

def rd(rva,n):
    for s in pe.sections:
        if s.VirtualAddress <= rva < s.VirtualAddress + s.Misc_VirtualSize:
            return pe.__data__[s.PointerToRawData + rva - s.VirtualAddress:s.PointerToRawData + rva - s.VirtualAddress + n]
    return None

# all 59 GetProcAddress call sites
ga_sites = [
    0x3277F, 0x327C5, 0x32815, 0x32867, 0x328B0, 0x328F9, 0x32942, 0x3298B, 0x329D4, 0x32A1A,
]

# We need to look at the assembly right BEFORE each call to see what pointer is pushed
# The pattern is always: push <string_ptr>; push <hmod>; call GetProcAddress
# The string_ptr is an immediate dword in the 'push' instruction.
# We decode backwards from each call.

print('=== GetProcAddress call decoder ===')
# Read entire .text into memory for backward scanning
text_rva = next(s.VirtualAddress for s in pe.sections if s.Name.startswith(b'.text'))
text = rd(text_rva, 0xCE000)
text_base = base + text_rva
print(f'text base: {text_base:#x}, size {len(text):#x}')

# For each call, disasm backwards and capture the first 'push imm32' that points into .data
# Estimate string pointer = 0x4F6xxx or similar — but we'll find any push imm32 within 24 bytes before call

# Known good call sites for GetProcAddress have shape:
#   push imm32 (=<string pointer>)
#   mov eax, [ebp+offset]  or  push [ebp+offset]
#   push eax
#   call [GetProcAddress_ptr]
# The immediate ALWAYS appears in the push instruction.

# helper: scan for pattern 'push imm32' within N bytes before the call site
def find_name_before_call(call_rva_in_segment, nbytes=48):
    # Call site VA = text_base + call_rva_in_segment
    call_off = call_rva_in_segment
    start_off = max(0, call_off - nbytes)
    # find last occurrence of 'push imm32' within this window
    result = None
    # byte pattern for push imm32 is 0x68
    for j in range(call_off - 5, start_off - 5, -1):
        if text[j] == 0x68:
            imm = struct.unpack('<I', text[j+1:j+5])[0]
            # if this imm points into .data, it could be a string ptr
            rva = imm - base
            data_rva_start = 0xEC000
            data_rva_end = 0x110000
            if data_rva_start <= rva < data_rva_end:
                result = imm
                break
    if result is None: 
        return None, None
    # resolve string at this va
    rva = result - base
    for s in pe.sections:
        if s.VirtualAddress <= rva < s.VirtualAddress + s.SizeOfRawData:
            off = s.PointerToRawData + (rva - s.VirtualAddress)
            raw = pe.__data__[off:off+256]
            end = raw.find(b'\x00')
            nm = raw[:end].decode('ascii', 'ignore')
            return result, nm
    return result, None

# We have 59 GA sites in total per previous scan; let me re-list them all properly
ga_call_vas = []
# scan for all FF 15 [0x4CF358] in .text
needle = b'\xff\x15' + struct.pack('<I', 0x4CF358)
pos = 0
while True:
    i = text.find(needle, pos)
    if i < 0: break
    # The call instruction starts at i, so its RVA = text_rva + i
    ga_call_vas.append(i)  # offset within .text segment
    pos = i+1
print(f'Total GetProcAddress sites found: {len(ga_call_vas)}')

# Now resolve each name
print()
print(f"{'call_va':<12}{'string_va':<12}{'function_name'}")
print('-'*70)
resolved = {}
for off in ga_call_vas:
    va = text_base + off
    str_va, name = find_name_before_call(off)
    resolved[va] = (str_va, name)
    print(f'{va:#012x}{str_va and hex(str_va) or "":<15}{name or "?"}')

# Save to JSON for analysis
import json
out = {hex(v): {'str_va': hex(sv) if sv else None, 'name': nm} for v,(sv,nm) in resolved.items()}
with open(r'C:\SM2258XT_MPTool\artifacts\re\ga_sites.json', 'w') as f:
    json.dump(out, f, indent=2)
print()
print('saved to artifacts/re/ga_sites.json')
