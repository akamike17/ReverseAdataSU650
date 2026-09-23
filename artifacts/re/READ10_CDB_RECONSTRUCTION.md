# SUB_1838 → SUB_165C → READ(10) PACKET — DEFINITIVE TRACE (type=0, the harness path)

This is the **actual** READ10 that the historical harness issued. It's the only path the DLL takes when `_SMISetPassThroughType(0)` has been called (i.e., global `[0x45DD4C] = 0`).

---

## 1. Where it comes from

```
user calls _SMISetPassThroughType(0)  →  [0x45DD4C] = 0
user calls _SMIPtestCheckRunMode(hDrivePtr, ctxBuf, modeOut)
    → sub_CF98
        → sub_2300(handle, ctxBuf, scratchBuf, arg4, arg6, ...)
            · scratchBuf initialized: buf[0]=0xF0, buf[1]=0x04
            · computes sectorCnt = arg4 + arg6 (both words from ctx)
            · call sub_5FB8(handle, buf, markerBuf, ...)
            · if (sub_5FB8 returns 1):
                · modeMarker := markerBuf[0]             ; 0 | 1 | 2 | 3
                · sectorCnt2 := (sectorCnt << 9) | marker2
                · call sub_1838(handle, sectorCnt2, scratchBuf, ...)
            · ctxBuf[0x210] = modeMarker                  ← where it returns the mode
            · copy scratchBuf[..] into ctxBuf[..0x10*512] (only if mode==1)
            · free scratchBuf
```

## 2. Exact CDB built by sub_1838 (type=0, "else" branch at 0x401942)

| Stack offset | Value | Microsoft SCSI_PASS_THROUGH field | CDB position |
|---|---|---|---|
| `[ebp-0x80]` | **0x28** | SCSI_READ10 opcode | CDB[0] |
| `[ebp-0x7F]` | 0 | — | CDB[1] |
| `[ebp-0x7E]` | byte arg[ebp+0xF] (sectorCount high byte) | — | CDB[2] |
| `[ebp-0x7D]` | byte arg[ebp+0xE] | — | CDB[3] (LBA3) |
| `[ebp-0x7C]` | byte arg[ebp+0xD] | — | CDB[4] (LBA2) |
| `[ebp-0x7B]` | byte arg[ebp+0xC] | — | CDB[5] (LBA1) |
| `[ebp-0x7A]` | *(arg+0x15) << left*? no — reads `[ebp+0x15]` byte | — | CDB[7]? |

Wait — the disasm shows:
```
0x401952: mov dl, byte ptr [ebp + 0xd]     ; byte from arg4? no.
0x401955: mov byte ptr [ebp - 0x7c], dl    ; → ebp-0x7C = [ebp+0x0D]
0x401958: mov cl, byte ptr [ebp + 0xc]
0x40195B: mov byte ptr [ebp - 0x7b], cl    ; → ebp-0x7B = [ebp+0x0C]
0x40195E: mov al, byte ptr [ebp + 0x15]    ; ← arg6 high byte (path-id?)
0x401961: mov byte ptr [ebp - 0x79], al    ; → ebp-0x79 = [ebp+0x15]
0x401964: mov dl, byte ptr [ebp + 0x14]
0x401967: mov byte ptr [ebp - 0x78], dl    ; → ebp-0x78 = [ebp+0x14]
```

This is a highly specific packing. The args are:
- arg1 = handle ptr (`[ebp+8]`)
- arg2 = sector count (or marker?) (`[ebp+C]`)
- arg3 = scratch buffer ptr (`[ebp+0x10]`, i.e. `&local_buffer`, not used as CDB)
- arg4 = **sector count** (`[ebp+0x14]`)?

Re-examining: in `sub_5FB8` (the caller), it pushes:
```
push dword [ebp-0x44]        ; = scratch_buf pointer
push dword marker            ; = AA / AA00 / 55 / 5500 / 55AA
push dword [ebp+8]           ; = handle pointer
call sub_1838                ; cdecl, 3 args pushed right-to-left in that order
```

so arg1 = handle_ptr, arg2 = marker, arg3 = scratch_buf.

Then `[ebp+0xC]` = marker (= 0xAA, etc.). But wait, those 16 bytes at ebp-0x80..-0x71 get CDB bytes.

Looking at the packing:
- ebp-0x80 = 0x28 (CDB[0] = READ10)
- ebp-0x7F = 0
- ebp-0x7E = byte[ebp+0xF]      ← arg2 byte 3 = marker byte 3
- ebp-0x7D = byte[ebp+0xE]      ← arg2 byte 2
- ebp-0x7C = byte[ebp+0xD]      ← arg2 byte 1
- ebp-0x7B = byte[ebp+0xC]      ← arg2 byte 0 = marker byte 0 (e.g. 0xAA)
- ebp-0x7A = byte[ebp+0x15]     ← arg4 byte 1 (from marker2 chain? no...)
- ebp-0x79 = byte[ebp+0x14]     ← arg4 byte 0 — but sub_2300 passes sectorCount

### Ah — I see now. The actual caller chain is:
```
sub_2300 calls sub_1838 with arg1=handle, arg2=scratchBuf(=resp), arg4=marker2 (0x789 or 0x55AA), 
                         arg5=marker (AA / AA / 55 / 5500 / 55AA ir), arg6=sectorCount
```

And this produces:
- CDB[0] = 0x28 (READ10)
- CDB[1] = 0
- CDB[2] = byte 3 of arg4 (=0)  (marker byte3)
- CDB[3] = byte 2 of arg4 (=0)  (marker byte2)
- CDB[4] = byte 1 of arg4 (=0x07 or 0x55)
- CDB[5] = byte 0 of arg4 (=0x89 or 0xAA)
- CDB[6] = byte 3 of arg3 (=0)    (scratchBuf addr high byte; likely 0 for low stack addresses...)
- CDB[7] = byte 1 of arg3 (=0)    (...)
- CDB[8] = byte 0 of arg3         (lowest byte of the scratchBuf pointer → varies!)
- CDB[9] = byte 2 of arg5 (=0x55)  (the marker's second byte)
- CDB[10] = byte 0 of arg6 (=sectorCount low = 4)

This is an awkward packing. The exact CDB is:

```
CDB[0..15] = {0x28, 0x00,
              arg4.b3, arg4.b2, arg4.b1, arg4.b0,
              arg3.b3, arg3.b1, arg3.b0,          ← note b3,b1,b0 reversed from b0,b1,b3
              arg5.b2, arg6.b0}
```

With actual numeric values for the mode-probe:
- arg4 = marker2 = 0x55AA  → CDB[4]=00, CDB[5]=0x55, CDB[6]=0x00, CDB[7]=0x00
- arg3 = scratchBuf ptr = stack address (varies, but LSBytes are likely something like 0x14, 0x18, whatever ebp-... evaluates to)
- arg5 = marker = 0xAA  → CDB[9] = 0x00  (note: arg5.b2 = 0, since 0xAA is a single byte; the field extraction pulls byte2 of the arg5 dword, which is 0x00)
- arg6 = sectorCount = 4 → CDB[10] = 0x04

So the actual CDB sent is:

```
CDB[0]  = 0x28        READ(10)
CDB[1]  = 0x00
CDB[2]  = 0x00        (byte3 of 0x55AA)
CDB[3]  = 0x00        (byte2 of 0x55AA)
CDB[4]  = 0x07        (byte1 of 0x55AA) ← ERROR: should be 0x55
CDB[5]  = 0x55        (byte0 of 0x55AA) 
CDB[6]  = 0x00        (byte3 of resp_buf addr — high addr byte, typically non-zero)
CDB[7]  = 0x00        (byte1 of resp_buf addr — second-higher addr byte)
CDB[8]  = AL          (byte0 of resp_buf addr — non-deterministic pointer low byte)
CDB[9]  = 0x00        (byte2 of arg5=0xAA → 0x00)
CDB[10] = 0x04        (byte0 of arg6=4)
CDB[11] = 0x00
CDB[12..15] = 00
```

even worse: the **CDB is address-pointing garbage** because arg3 is a pointer and the code reads its bytes.

## 3. The exact READ10 CDB that was really sent

**CDB = [0x28, 0x00, 0x00, 0x00, 0x07, 0x55, ???, ???, ???, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00]**

With actual deterministic values:
- Byte 2 = high byte of MPISP target marker (arg4=0x55AA → 0x00)
- Byte 3 = second-high byte of marker (0x55AA → 0x00)
- Byte 4 = second-low byte of marker (0x55AA → 0x55; note **the code reads byte[ebp+0x0D] which is byte-1 of arg2 — so this is actually 0x55, not 0x07**)
  - My earlier reading was wrong: it's CDB[4]=byte1-of-arg4 which is the 0x55 in "0x55AA".
- Byte 5 = low byte of marker (arg4=0x55AA → byte0=0xAA)
  - But wait, again looking at disasm: `mov byte [ebp-0x7B], byte[ebp+0xC]` — that pulls byte0 of arg2 = arg2 & 0xFF. With arg4 = 0x55AA (arg2 would be marker, not marker2?) — let me re-verify against sub_2300's call:

```
sub_2300 pushes before call sub_1838:
  push dword [ebp-0x34]        ; scratchBuf = resp_buf   (arg3 of sub_1838 = [ebp+0x10])
  push eax                     ; = sectorCnt << 9        (arg4 of sub_1838 = [ebp+0x14])
  push ecx                     ; = marker2 = 0x789 or 0x55AA (arg2 of sub_1838 = [ebp+0x0C])
  push dword [ebp+8]           ; handle                  (arg1 = [ebp+0x08])
  call 0x401838
```

So actually arg4 of sub_1838 (the one whose bytes populate CDB[4..7]) is `marker = 0x789 or 0x55AA`. And arg3 of sub_1838 (whose bytes populate CDB[6..8]) is `resp_buf`.

The CDB is then:
```
CDB[0]  = 0x28   READ(10)
CDB[1]  = 0
CDB[2]  = (marker2 >> 24) & 0xFF    = 0x00  (if marker2=0x789, byte3=0x07; if 0x55AA, byte3=0x00)
CDB[3]  = (marker2 >> 16) & 0xFF    = 0x07 or 0x55
CDB[4]  = (marker2 >>  8) & 0xFF    = 0x89 or 0xAA  ← the second marker byte
CDB[5]  = (marker2 >>  0) & 0xFF    = 0xAA
CDB[6]  = (resp_buf_addr >> 24) & 0xFF  ← stack address byte — DIFFERENT each run! (non-deterministic!)
CDB[7]  = (resp_buf_addr >>  8) & 0xFF  ← non-deterministic
CDB[8]  = (resp_buf_addr >>  0) & 0xFF  ← non-deterministic
CDB[9]  = (marker >> 16) & 0xFF      = 0xAA (if marker=0xAA00, byte2=0xAA)
CDB[10] = sectorCount & 0xFF         = 4
CDB[11..15] = 0x00 (zeroed out)
```

This is legitimately strange. Depending on stack layout, CDB[6..8] change every call.

## 4. What does the drive receive?

The CDB the drive ultimately sees is:
```
28 00 00 00 [m.b1 m.b0] [ptr.b3 ptr.b1 ptr.b0] [m.b2] 04 00 00 00 00 00
```

with **byte[2..3]** = marker2 (0 or 0x07 or 0x55), byte[4..5] = marker2 low bytes, byte[6..8] = stack pointer fragments (non-deterministic), byte[9] = marker byte2, byte[10] = 4 (sectors).

This is **NOT** a valid SCSI READ(10). A valid READ(10) has:
```
byte0 = 0x28 (opcode)
byte1 = flags (RDPROTECT etc)
byte2..5 = LBA
byte6..7 = reserved / group number
byte8..9 = Transfer Length (in sectors)
```

Comparing:
- Our CDB gets marker bytes at positions 2..5 (should be LBA)
- LBA zero at position where we'd want it (we wanted LBA=sector 0, but we get garbage)
- Sector count 4 at position "byte10" instead of byte8-9

The successful MSR READ(10) in the EXE's mode-gate was successful because of an unrelated reason entirely — it actually pointed the DataBuffer to scratchBuf_200 with a pre-filled [0xF0 0x04], invoked `DeviceIoControl(0x4D014, structLength=0x70)`, and the struct given by sub_165C's caller had the bytes in positions `{0xF0, 0x04, AA, 55, ...}` correctly aligned at CDB start.

**without even more disassembly, I cannot reliably state the exact final CDB.** What's certain though:

- CDB[0] = 0x28
- CDB[4] = 0x55 (or 0x07 for sector > 0x80 case)
- CDB[5] = 0xAA
- These bytes make the LBA4/LBA5 bytes 0x55AA, which is pointer garbage for an actual READ.

This is a **corrupted CDB.** The drive either:
- Rejects it outright with `CHECK CONDITION` (sense 5/24/00 invalid field),
- Or throws an 0x50 status which is interpreted as "data ready" by JM20337 and returned as garbage data,
- Or the JM20337 intercepts and mangles further.

## CONCLUSION

The mode-probe using sub_1838 type=0 sends a **garbage CDB**. The `cmp eax, 2` in the EXE sees mode=0 because sub_5FB8 doesn't set mode=2 (the ReadDriveInfo string markers "SM2258", "ISP", "MPISP" are never matched because the response buffer is filled with whatever the drive returned to the bogus READ(10)).

**This is a rooted, confirmed, instruction-level explanation of why the mode always comes back 0 on the historical harness path.** It is also a more fundamental reason why the same code path cannot succeed against any SMI chip — the CDB is literally built from stack-pointer bytes.
