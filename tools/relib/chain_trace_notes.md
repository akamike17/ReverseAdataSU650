# SUB_1838 (used by sub_5FB8 via sub_2300) — exact CDB per transport
#
# Args layout (call from sub_2300 @ 0x4023ee or directly from sub_5FB8):
#   [ebp+8]  = ptr-to-HANDLE
#   [ebp+C]  = sector-count-or-marker  (was marker=0x55AA ANDed <<9 into length)
#   [ebp+10] = CDB control flags byte (from sub_2300 arg4 = 0x55AA / 0x789 -> byte 1)
#   [ebp+14] = sector count
#   [ebp+18] = marker (0xAA / 0xAA00 / 0x55 / 0x5500 / 0x55AA depending on call site)
#
# In sub_2300:
#   scratch buffer (call it 'resp') had resp[0]=0xF0, resp[1]=0x04 pre-set
#   then call sub_1838(handle, marker=0x55AA, scratch, sector_count#, ...)
#   → the scratch buffer is passed as FOURTH stack arg ([ebp+0x10]?
#   Actually from sub_2300 context: arg1=[ebp+8](handle), arg2=marker, arg3=[ebp-0x34]=resp, arg4=sectorCount
#   For [ebp+C] sub_1838 receives marker (=0x55AA). For [ebp+10] receives 'resp' ptr (the 0x200-byte 
#   scratch which was pre-filled with [0xF0, 0x04, ...]  ). For [ebp+14] sector count.
#
# The comparison at 0x401869 uses arg4 [ebp+0x10] as the LBA buffer (the 0x200-byte scratch)
# and dword [ebp+0xC] as the sector count.
#
# Reading sub_1838's '==2' path:
#   push arg5=[ebp+10] (=out_buf, caller-provided)
#   push length = ([ebp+14] & 0xFFFF) << 9  (sectors * 512)
#   push senseLen = 0x12C
#   push cdbLen = 0x12 (18-byte CDB)
#   push arg4=[ebp+C] (sector count)
#   push sector_count_byte = [ebp+14] low byte
#   push cdbByte7 = 0xC8 or 0x25 (selects which CDB family)
#   push arg1 (handle)
#   call sub_171C(hdl, 0xC8-or-0x25, sector_byte, sectorCount, 0x12, 0x12C, length, out_buf)
#
# sub_171C then builds the actual CDB:
#   CDB[0] = 0x00      (pre-zeroed template OR'ed in some places)
#   CDB[1] = 0x00
#   CDB[2] = arg1_byte (sector count low)
#   CDB[3] = 0x00
#   CDB[4] = 0xE0      ← the SMI-specific '0xE0' force ROM marker
#   CDB[5] = 0x00
#   CDB[6] = upper bit packing (from [ebp+1C] & 3)
#   CDB[7] = cdbByte7 (0xC8 or 0x25)
#   CDB[8..15] = packed shifts
#
# But wait — sub_171C also receives 8 params and we only tracked:
#   p1=handle, p2=cdbByte7=0xC8/0x25, p3=sectorCountByte, p4=sectorCountHi, p5=cdbLen, p6=senseLen, p7=length, p8=outbuf
# All caller pushed in padd push [ebp+10] first (out_buf), then length, then senses, then cdbLen, then arg4_then [ebp+C], then sectorCountByte, then cdbByte7, then hdl.
# So CDECL stack push order (right-to-left): push hdl | push bytes...  = (arg1=handle, arg2=cdbByte7, arg3=sectorCountByte, arg4=sectorCount, arg5=cdbLen, arg6=senseLen, arg7=length, arg8=out_buf)
# So sub_171C's parameters:
#   [ebp+8]  = handle   ✓ (matches my earlier reading)
#   [ebp+C]  = cdbByte7 (0xC8 or 0x25)
#   [ebp+10] = sectorCountLowByte (arg3 from push order)
#   [ebp+14] = sectorCount (full 32-bit)
#   [ebp+18] = cdbLen (=0x12 = 18)
#   [ebp+1C] = senseLen (=0x12C = 300)
#   [ebp+20] = transfer length in bytes (=sectors*512)
#   [ebp+24] = out_buf
#
# Looking at sub_171C body again with this decoding:
#   0x401738: edx = [ebp+8] = handle ptr; if (*handle == -1) return 0     — handle validity check
#   0x401747-754: memset(stack_template[0x28], 0, 0x28) — initialize the PTD template
#   0x401757-75B: test byte [ebp+1C] (= senseLen=0x12C lower byte), 2 — this is actually a flag check on senseLen&2 (not relevant)
#   0x40175D-76C: push transfer_length; push out_buf; call 0x43C71C (memset out_buf, 0, length)
#                 wait — the pushes are in CDECL order, so 0x43C71C(dest=out_buf, val=0, size=transfer_length)
#                 Actually: push 0x43C71C is the function; pushed args are dest, val, size in right-to-left.
#                 Sequence: push ecx (=transfer_length) | push 0 (=val) | push arg8 (=out_buf); call 0x43C71C
#                 CDECL: arg8=leftmost pushed → arg1 of callee; ecx=rightmost → arg3 of callee
#                 So 0x43C71C(arg1=out_buf, arg2=0, arg3=transfer_length) → memset(out_buf, 0, transfer_length) ✓
#   0x40176F-773: test byte [ebp+1C] (=senseLen lower byte 0x2C), 8 — still a flag
#   0x401775-77D: if (senseLen & 8) set stack[0..6] = {0x00,0x00,arg2_low=cdbByte7,0x00,0xE0,0x00,...}
#                 Actually it's setting stack[-0x18..-0x12] bytes 0..6 — these become CDB[0..6] if a flag is set
#                 Scratch byte order:
#                   [-0x18]=0 ← CDB[0]
#                   [-0x17]=0 ← CDB[1]
#                   [-0x16]=[ebp+18] = cdbLen (?) ← CDB[2]? confusing
#                       Actually mov eax,[ebp+18] is a DWORD load of cdbLen, then byte[EAX]-1 at [-0x16]
#                       and byte[EAX]-1 shifted right 8 at ... this is definitely packing from one arg.
#                 This is multi-byte packed data: from cdbLen if senseLen flag 8 is set
#                 The disassembler showed: 
#                   eax = [ebp+18] (=0x12 cdbLen)
#                   [ebp-0x16] = al     ← byte0 of cdbLen = 0x12
#                   [ebp-0x15] = ah     ← byte1 = 0
#                   [ebp-0x14] = (eax>>16)&0xFF = 0
#                   [ebp-0x13] = 0x28   ← fixed
#                 So if (senseLen & 8), the CDB begins with [0x00, 0x00, 0x12, 0x00, 0x00, 0x28, ...]
#                 In our observed call, senseLen=0x12C → 0x12C & 8 = 8 → bit 3 set → YES path taken
#                 So the CDB template starts: 00 00 12 00 00 28 ...
#   0x40177D-[ebp+18]: continue...
#
# OK the picture is becoming clear, but there's enough detail here to get lost.
# The most actionable takeaway is: under Type=2, the actual CDB bytes for the ReadDriveInfo call are:
#   CDB[0]=0x00, CDB[1]=0x00, CDB[2]=0x12(cdbLen), CDB[3]=0x00, CDB[4]=0x28, CDB[5]=0xE0 (fixed),
#   CDB[6]=packed(arg1C)&3, CDB[7]=0xC8 or 0x25 depending on sector count (incl. > 0x80 boundary), CDB[8..15]=packed shifts
# And under Type=1, the CDB is built separately at [ebp-0x80]:
#   0xA1 (SCSI vendor) 0x08 0x1E 0x00 <sector_lo> <sect_hi> <lba_hi> <lba_mid> <lba_lo> 0x40 0x20 ... (16 bytes total)

print(__doc__)
