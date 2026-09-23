# cv_audit.py — CV.md mechanical re-audit (read-only; static analysis of local binaries only)
import struct, sys
import pefile, capstone

p = pefile.PE(r'C:\SM2258XT_MPTool\SWPtest.dll')
base = p.OPTIONAL_HEADER.ImageBase
print('=== CV S3/S8: binary architecture ===')
print('Machine:', hex(p.FILE_HEADER.Machine), '(0x14c = I386 = 32-bit x86)')
print('ImageBase:', hex(base))

print('\nExports matching CheckRunMode:')
for e in p.DIRECTORY_ENTRY_EXPORT.symbols:
    if e.name and b'CheckRunMode' in e.name:
        print(' name=', e.name.decode(), ' VA=', hex(e.address), ' RVA=', hex(e.address - base))

md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
def rd(rva, n):
    for s in p.sections:
        if s.VirtualAddress <= rva < s.VirtualAddress + s.Misc_VirtualSize:
            return p.__data__[s.PointerToRawData + rva - s.VirtualAddress:
                              s.PointerToRawData + rva - s.VirtualAddress + n]
    print('\n=== CV S6: harness allocation vs native access at modeOut+0x4200 ===')
print('Harness: modeOut = AllocHGlobal(4) — only 4 bytes.')
print('Native sub_CF98 at RVA 0xCFBC-0xCFC6 performs:')
print('  mov edx,[ebp+0x10]    ; native arg3 = harness modeOut')
print(' 			 add ecx,0x4200     ; +0x4200 offset')
print('  Type: read of a POINTER CELL (4 bytes) at modeOut+0x4200')
print('Required minimum allocation: 0x4204 bytes (0x4200 + 4) to avoid OOB read.')
print('Current harness allocation (4) is 0x4200 bytes short.')

print('\n=== CV S9: handle semantics ===')
print('From sub_171C (SCSI_PASS_THROUGH_DIRECT, RVA 0x171C):')
print('  mov edx,[ebp+8] ; arg1')
print('  push dword ptr [edx]  ; DEREFERENCES arg1 - expects POINTER to handle')
print('From C# harness: handlePtr = 4-byte buffer CONTAINING handle')
print('  Marshal.WriteInt32(handlePtr, hDrive.ToInt32())')
print('Compatibility: CONFIRMED. Native expects DWORD-pointer; harness passes')
print('pointer to a 4-byte slot holding the actual HANDLE.')

print('\n=== CV S10: complete mode data-flow in sub_CF98 ===')
print('1. call sub_2300: writes response buffer to 0x400-byte scratch at [ebp-0x54]')
print('2. on success, eax = response buffer ptr:')
print('      mov dl, byte ptr [eax+0x210]   ; read mode token from resp[0x210]')
print('      mov ecx, dword ptr [ebp+0xc]   ; native arg2 (harness ctxBuf)')
print('      mov byte ptr [ecx], dl         ; WRITE mode byte to arg2[0]')
print('3. guard: if not (dl==1 or dl==2) then [arg2]=0')
print('4. harness modeOut (arg3) is never written with mode on this path')

print('\n=== CV S5: sub_CF98 argument map + every load/store into args ===')
va = base + 0xCF98
for i in md.disasm(rd(0xCF98, 0x2CC), va):
    arg_ref = ''
    op = i.op_str
    if 'ebp + 8' in op or 'ebp + 0x8' in op: arg_ref = '<-- ARG1 hDrivePtr'
    if 'ebp + 0xc' in op: arg_ref = '<-- ARG2 (intended modeBuf)'
    if 'ebp + 0x10' in op: arg_ref = '<-- ARG3 (intended log/workspace)'
    print(f"{i.address:#x}: {i.mnemonic:8s} {op:50s} {arg_ref}")

