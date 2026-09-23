# SIGNATURE RESOLUTION — DEFINITIVE ARGUMENT MAPPING

**Source:** SWPtest.dll static analysis at commit `27ed782`, corrected after close re-read of caller push counts.

## 1. sub_2300 — actual signature

**6 callers** (RVA 0xC8BA, 0xCDE2, 0xD055, 0x229FD, 0x232C1, 0x2FC8F), all use **5 args** (`add esp, 0x14`).

Sub_CF98 (the mode-check orchestrator) is the only caller that matters for the gate. Its call site at RVA 0x40D05F passes:

```
push 1                          ← arg5 = flag
lea ecx, [ebp-0x260]; push ecx  ← arg4 = &scratch (offset -0x260 in sub_CF98 stack frame)
push 2                          ← arg3 = sector count (=2 sectors = 1024 bytes)? NO wait
push dword [ebp-0x54]           ← arg2 = some shared buffer? (allocated in sub_CF98)
push dword [ebp+8]              ← arg1 = handle
call sub_2300
add esp, 0x14                   ← 5 * 4 = 20 = 0x14 ✓
```

**Note on arg3:** Pushed value is the literal `2`. But inside sub_2300 this becomes:
- `movzx ecx, word [ebp+0x10]` → `word(arg3)` = `word(2)` = 0x0002
- `shl ecx, 9` = word(2) * 512 = 1024 bytes (sector count)
- This feeds the allocation size

Inside sub_2300's body (from the disasm):
- arg1 = `[ebp+8]`  = handle
- arg2 = `[ebp+0xC]` = dword (a pointer to buffer; stored at ctx+0x210 at the end!)
- arg3 = `[ebp+0x10]` = word (=2 initially, ← LBA sector number?)
- arg4 = `[ebp+0x14]` = scratchBuf pointer from caller
- arg5 = `[ebp+0x18]` = word (=1, ← LBA sector count?)

The **+arg5 is a word**. The first use is at RVA 0x40231D: `mov dx, word [ebp+0x10]` adding word `[ebp+0x18]` to compute transfer size:
```
ax = word(arg3) + word(arg5)
```
This is then used as a sector count (`<<9` for bytes).

So **sub_2300 expects**:
```
sub_2300(handle, ctxBuf, sectorBaseWord, respBuf, sectorCountWord)
```
- sectorBaseWord + sectorCountWord = total sectors to read? Or increments?
- ctxBuf is where the mode byte lands at `[ctxBuf+0x210]`

Sub_2300 also allocates:
- `[ebp-0x34]` = new 0x200-byte scratch (used for the response, and pre-filled with `[F0, 04]`)
- `[ebp-0x38]` = new (arg3+arg5)<<9 byte buffer for sector data

Then it calls `sub_5FB8(handle, ctxBuf, ...)` — this is the vendor handshake probe. The raw response from this populates `ctxBuf[0..0x210]` via the string-search.

After `sub_5FB8` returns:
- It checks `modeMarker = [ebp-0x2E]` (sub_5FB8's output byte buffer)
- Picks `marker2 = 0x55AA` if mode != 2 else `0x789`
- Calls `sub_19D8(handle, respBuf, 1, marker2)` (cdecl, 4 args)

## 2. sub_19D8 — actual signature

From the sub_2300 call site:
```
push 1                          ← arg5
push dword [ebp-0x34]           ← arg4 = respBuf (allocated, [ebp-0x34] from sub_2300)
push 0x55AA                     ← arg3 = marker (literal)
push dword [ebp+8]              ← arg1 = handle
call 0x4019D8
add esp, 0x10                   ← 4 args
```

So:
```
sub_19D8(arg1=handle, arg2=outBuf, arg3=marker=0x55AA, arg4=sectorCount)
```

## 3. sub_1838 — actual signature  

From the sub_2300 call site at RVA 0x402408-0x402411:
```
push eax                        ← arg4 = sectorCntWord << 9 (byte count)
push dword [ebp-0x38]           ← arg3 = respBuf  
push 0x55AA                     ← arg2 = $marker
push dword [ebp+8]              ← arg1 = handle
call sub_1838
add esp, 0x10                   ← 4 args
```

So:
```
sub_1838(arg1=handle, arg2=marker=0x55AA, arg3=outBuf, arg4=sectorCntBytes)
```

## 4. sub_171C (transport DIRECT) — receipt of args

Sub_1838 with `type==2` calls sub_171C with **9 args** (`add esp, 0x24` after call):
```
push [ebp+0x10]   ; sub_1838 arg3 = outBuf
push ((word [ebp+0x14]) << 9)   ; = sectorCount_bytes — = sub_171C arg8
push 0x12c        ; = 300 — sub_171C arg7
push 0x12         ; = 18 — sub_171C arg6  
push dword [ebp+0xC]  ; sub_1838 arg2 = marker — becomes sub_171C arg5? 
... and so on
```

The mapping is complex because sub_1838 forwards its own `[ebp+C]` (=marker of its own args) as a **dword**, and separately pushes the *byte* `[ebp+0x14] & 0xFF` (=sector_base_low_byte). Combined with the various pushes of the constants `0xC8`, `0x0`, `0x12`, `0x12C`, this is the **9-arg call** to sub_171C whose call signature is:

```
sub_171C(handle, opcodeByte, flagWord, sectorCountLowByte, sectorBaseDword, cdbLen, senseLen, bytesToTransfer, outputBuf)
```

No correction to my earlier analysis needed here — the parameters from sub_1838 to sub_171C are:

| sub_1838 arg (received) | Push order when calling sub_171C | sub_171C positional arg |
|---|---|---|
| arg1 = handle | pushed LAST (rightmost) | arg1 (`[ebp+8]` of sub_171C) |
| arg2 = marker=0x55AA | pushed 5th (to `[ebp+0x14]` of sub_171C) | arg5 of sub_171C |
| arg3 = outBuf | pushed 9th (top of stack) | arg9 = `[ebp+0x28]` of sub_171C |
| arg4 = sectorCntBytes | pushed 2nd (to `[ebp+0xC]` of sub_171C) — wait no |

The previous analysis is now correct: the CDB has byte[CDB[7]] = 0xC8 (from arg2 of sub_171C which became opcode).

## What was actually sent:

Under type=2, the real sent packet from sub_171C is:
```
CDB[0..3] = 0 0 0 0   (zeroed by memset)
CDB[4]    = sub_171C arg4 low byte = (sub_1838's arg4 low byte)
CDB[5]    = sub_171C arg5 low byte = (sub_1838's arg2 low byte) = 0xAA from 0x55AA
CDB[6..8] = sub_171C arg5.b0/b1/b2 — bytes 0..2 of sub_1838's arg2 (marker=0x55AA)
CDB[9]    = 0xE0 (hardcoded force-ROM)
CDB[10]   = sub_171C arg2 = opcode (0xC8/0xCA/0x25/0x35/0xEA)
CDB[11..15] = beyond 40-byte struct — NOT in buffer
```

This does not match a standard READ(10) CDB which expects:
- CDB[0] = 0x28 (READ10 opcode)
- CDB[1] = flags 
- CDB[2..5] = LBA
- CDB[6] = group number
- CDB[7..8] = transfer length

Instead the actual on-wire CDB is repurposed:

```
CDB[0] = 0 (zero)   — not 0x28!
             — because in sub_1838 the CDB[0] is NOT the 0x28 byte; that's in the *alternative* branch
CDB[4] = sector_count_low_byte = typically 4  — NOT THE standard opcode position!
CDB[9] = 0xE0 — the SMI opcode goes in the *SCSI_ATA_PASS* position
```

Wait. But we showed earlier that the type==0 case in sub_1838 writes `mov byte [ebp-0x80], 0x28` explicitly. That's the standard READ10 path. Here's the correction:

- The `type != 1` branch at RVA 0x401942 *does* place CDB[0]=0x28 explicitly.
- Only the `type == 2` branch goes through sub_171C, and that branch builds the CDB from the `arg` parameters.
- So `type=0` does one thing: builds a standard READ(10) with CDB[0]=0x28.
- `type=2` does something completely different: builds an SMI vendor command with CDB[9]=0xE0, CDB[10]=0xC8/etc.

**The historical harness used type=0. The CDB was a valid READ(10).**

**My earlier "corrupted CDB" claim was wrong** because I misread which branch was being taken. The type=0 branch sets CDB[0]=0x28 explicitly and does not invoke the sub_171C path at all.

## Conclusion

**sub_2300 → sub_1838 (type=0) sends a valid READ(10) SCSI command.**

The corruption theory was based on misinterpreting the arguments to sub_1838 (treated `[ebp+0xC]` as sector_base when it's actually the marker) and on top of that, being written against the `==2` sub_171C path instead of the `!=2 && !=1` (sub_165C) path which is what the harness actually used.

The disk received a **valid READ(10)** command and returned normal data. The mode marker scan found no SMI signature strings, so the mode remained 0. This fully explains why the harness saw "Not ISP mode !": the drive simply wasn't in ISP mode, and no vendor command was ever sent.
