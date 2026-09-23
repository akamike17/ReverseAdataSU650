# sub171c_close.py — resolve which struct is lpInBuffer vs lpOutBuffer
# Definitive evidence: pushes immediately before 'call 0x4461F4' at RVA 0x401818
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

# Locate the kernel32 DeviceIoControl IAT slot to confirm what is being called
print('=== Confirm 0x4461F4 is the kernel32!DeviceIoControl thunk ===')
# In DLL, imports jump through IAT thunk: 0x4461F4 likely FF 15 <iat_addr>
code = rd(0x61F4, 8)
print(f'Bytes at RVA 0x61F4: {" ".join(f"{b:02X}" for b in code)}')
# confirm import
for ent in p.DIRECTORY_ENTRY_IMPORT:
    dll = ent.dll.decode()
    for imp in ent.imports:
        nm = imp.name.decode() if imp.name else f'ord{imp.ordinal}'
        if 'DeviceIoControl' in nm:
            print(f'  IAT slot RVA {imp.address:#x} -> {dll}!{nm}')

print()
print('=== Push-sequence right before call at RVA 0x1818 ===')
for i in md.disasm(rd(0x17FC, 0x1C), base + 0x17FC):
    print(f'  {i.address:#x}: {i.mnemonic:8s} {i.op_str}')

print()
print('=== Decode: cdecl pushes(right-to-left) ===')
print('''
DeviceIoControl prototype:
  BOOL DeviceIoControl(
    HANDLE  hDevice,           ; arg1 = pushed LAST = lowest stack address
    DWORD   dwIoControlCode,   ; arg2
    LPVOID  lpInBuffer,        ; arg3
    DWORD   nInBufferSize,     ; arg4
    LPVOID  lpOutBuffer,       ; arg5
    DWORD   nOutBufferSize,    ; arg6
    LPDWORD lpBytesReturned,   ; arg7
    LPOVERLAPPED lpOverlapped  ; arg8 = pushed FIRST = highest stack address
  );

Reading the disasm:
  0x4017FC: push 0              ; lpOverlapped          (arg8)
  0x4017FE: lea ecx, [ebp-4]    ; ecx = &(bytesRet)
  0x401801: push ecx            ; lpBytesReturned       (arg7)
  0x401802: push 0x28           ; nOutBufferSize        (arg6) = 40 bytes
  0x401804: lea eax, [ebp-0x58] ; eax = &structB (the template at -0x58)
  0x401807: push eax            ; lpOutBuffer           (arg5) = ebp-0x58
  0x401808: push 0x28           ; nInBufferSize         (arg4) = 40 bytes
  0x40180A: lea edx, [ebp-0x30] ; edx = &structA (the populated one)
  0x40180D: push edx            ; lpInBuffer            (arg3) = ebp-0x30
  0x40180E: push 0x4D030        ; dwIoControlCode       (arg2) = IOCTL_SCSI_PASS_THROUGH_DIRECT
  0x401813: mov ecx, [ebp+8]    ; ecx = ptr-to-HANDLE
  0x401816: push dword [ecx]    ; hDevice               (arg1) = *handle
  0x401818: call 0x4461F4       ; DeviceIoControl(...)

CONCLUSION:
- STRUCT B ([ebp-0x58]) is the OUTPUT buffer (40-byte zeroed template; unmodified except
  for the initial rep movsd copying from 0x447324).
- STRUCT A ([ebp-0x30]) is the INPUT buffer — this is the one that builds the CDB.
- They are two different 40-byte regions on the stack.

Therefore the previously confusing uses of [ebp-0x18..-0x11] (CDB[0..3] gated by [ebp+1C]&8)
are still on STRUCT A ([ebp-0x30] based), and they ARE the CDB[0..3] region (struct+0x18
= [ebp-0x30+0x18] = [ebp-0x18] ✓).
''')

print()
print('=== Confirm: which offset on STRUCT A does [ebp-0x14..-0x11] map to? ===')
print('struct A base = ebp - 0x30')
print('  [ebp-0x14] = structA[+0x1C] = Cdb[0]')
print('  [ebp-0x13] = structA[+0x1D] = Cdb[1]')
print('  [ebp-0x12] = structA[+0x1E] = Cdb[2]')
print('  [ebp-0x11] = structA[+0x1F] = Cdb[3]')
print('  [ebp-0x10] = structA[+0x20] = Cdb[4]')
print('  [ebp-0x0F] = structA[+0x21] = Cdb[5]')
print('  [ebp-0x0E] = structA[+0x22] = Cdb[6]')
print('  [ebp-0x0D] = structA[+0x23] = Cdb[7]')
print('  [ebp-0x0C] = structA[+0x24] = Cdb[8]')
print('  [ebp-0x0B] = structA[+0x25] = Cdb[9]  (uchar 0xE0)')
print('  [ebp-0x0A] = structA[+0x26] = Cdb[10] (arg[ebp+C] byte)')
print('  [ebp-0x09] = structA[+0x27] = Cdb[11] (unset -> 0)')

print()
print('=== Confirm: which offset on STRUCT B does [ebp-0x32] map to? ===')
print('struct B base = ebp - 0x58')
print('  [ebp-0x32] = structB[+0x26] = Cdb[10] of the OUT struct')
print('  Success test @ RVA 0x401820: cmp byte ptr [ebp-0x32], 0x50')
print('  => reads Cdb[10] of the OUT struct, expects 0x50 ONLY if the')
print('     kernel GPU parses echoed CDB back. More likely: after PTD,')
print('     the OUT buffer is reused for status response — and the DLL')
print('     tests a custom vendor field that lives at offset 0x26.')
print('  This is NOT standard SCSI ScsiStatus (offset +2); it is custom.')
print()
print('=== Find any code that SETS [ebp-0x32] or near on STRUCT B ===')
# search for writes to [ebp-0x5b] and neighbors within the function body
import re
code = rd(0x171C, 0x11C)
hits=[]
i=0
# patterns: 46 5D XX (inc/dec [ebp-0xX])  - let me just scan for byte combos that would write
# Direct search: any instruction encoding that has [ebp - 0x32] as memory operand
# Encoding: mod=01 reg=X rm=101 disp8=-0xXX - finds all -0x32 uses
needle_enc = b'\x45\xCE'  # [ebp-0x32]; not exactly — mod=01 rm=101 disp8=0xCE is '45 CE'
i = 0
while True:
    j = code.find(needle_enc, i)
    if j < 0: break
    hits.append(0x171C+j-1)  # the instruction start may be -1 back
    i = j+1
print(f'All byte-pattern "mod=01 rm=101 disp8=0xCE" hits relative to sub_171C start: {hits}')

# Better: disasm and filter
print('\nAll [ebp-0xX] accesses between [ebp-0x50..ebp-0x64]:')
for ins in md.disasm(rd(0x171C, 0x11C), base+0x171C):
    op = ins.op_str
    # match [ebp - 0x58 + k]
    import re
    m = re.search(r'\[ebp - 0x([0-9a-f]+)\]', op)
    if m:
        off = int(m.group(1), 16)
        # struct B = [ebp-0x58]
        rel_to_B = 0x58 - off
        rel_to_A = 0x30 - off
        kind = 'WRITE' if ins.mnemonic in ('mov','movzx','movsx','push','pop','stos','xchg') else 'READ'
        print(f'  {ins.address:#x}: {kind} {ins.mnemonic:8s} {op}    '
              f'(to structB: +{rel_to_B:#x}, to structA: +{rel_to_A:#x})')
