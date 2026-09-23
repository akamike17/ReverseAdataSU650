# find_passtype_callers.py — trace every call to _SMISetPassThroughType
# In the DLL, the export is _SMISetPassThroughType @ RVA 0x6B04
# In the EXE it would be: LoadLibrary("SWPtest.dll") ; GetProcAddress("_SMISetPassThroughType")
# But the EXE may also statically link or import it.
# We scan BOTH EXE and DLL for any reference to the export address (RVA 0x6B04)
# and for any byte pattern / string reference to '_SMISetPassThroughType'.
import pefile, capstone, struct

for fname, target_rva in [('SWPtest.dll', 0x6B04), ('SM2258XTMPToolQ0816A.exe', None)]:
    try:
        p = pefile.PE(fname)
    except Exception as e:
        print(f'skip {fname}: {e}')
        continue
    base = p.OPTIONAL_HEADER.ImageBase
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)

    # Collect raw .text bytes and .data (for string references)
    def rd(rva, n):
        for s in p.sections:
            if s.VirtualAddress <= rva < s.VirtualAddress + s.Misc_VirtualSize:
                return p.__data__[s.PointerToRawData + rva - s.VirtualAddress:
                                  s.PointerToRawData + rva - s.VirtualAddress + n]
        return b''

    print(f'=== {fname} ===')
    # For EXE we look for callers of the import address (IAT thunk)
    # Typical Borland EXE: GetProcAddress returns to a slot in .idata; callers do 'call dword [IATslot]'
    # For DLL we look for direct 'call <target>' of its own internal export stub
    # First find all exported function addresses, especially _SMISetPassThroughType
    if hasattr(p, 'DIRECTORY_ENTRY_EXPORT'):
        for exp in p.DIRECTORY_ENTRY_EXPORT.symbols:
            if exp.name and b'PassThrough' in exp.name:
                er = exp.address
                ea = base + er
                print(f'  Export @ RVA {er:#x} = VA {ea:#x}')
                # Pattern 1: direct call rel32 to VA
                # Pattern 2: push imm32 VA (then call/ret)
                pat_abs = struct.pack('<I', ea)
                # Scan .text
                text = rd(0x1000, 0x46000)
                hits = []
                i = 0
                while True:
                    j = text.find(pat_abs, i)
                    if j < 0: break
                    hits.append(0x1000 + j)
                    i = j + 1
                for rv in hits:
                    # disasm around
                    code = rd(rv - 5, 0x20)
                    # find instruction that contains the operand
                    for ins in md.disasm(code, base + rv - 5):
                        if rv - (rv-5) >= 1 and rv < rv - 5 + ins.size:
                            pass
                    # tolerate: just print the raw context around the hit
                    ctx = rd(rv - 8, 24)
                    print(f'    VA-ref @ RVA {rv:#x} = VA {base+rv:#x}: '
                          f'ctx: {" ".join(f"{b:02X}" for b in ctx)}')
                # Also search for RVA-only references (call relative) of stub/redirect
                pattern_rva = struct.pack('<I', base + er)
                # Already covered; check for direct 'call imm32' style: E8 <rel32>
                # we want callers OF this address; find all E8 where target = VA
                i = 0
                while True:
                    j = text.find(b'\xE8', i)
                    if j < 0: break
                    if j+5 <= len(text):
                        rel = struct.unpack_from('<i', text, j+1)[0]
                        if base + 0x1000 + j + 5 + rel == ea:
                            hits.append(0x1000 + j)
                    i = j + 1
    print()
