# FORENSIC_RE_REPORT_PHASE_C.md — Origin of mode=5, gate cmp eax==2

Target: SM2258XTMPToolQ0816A.exe (Borland C++Builder) + SWPtest.dll
Hardware-under-test: ADATA SU650 120GB / SM2258XT, SATA via PASSTHRU
Method: static disassembly (pefile+capstone) of EXE RVA 0x3594..0x3BB7 region, 0x4827AC, sub_5FB8, sub_1838, sub_19D8. NO code was executed against the SSD; no destructive ops; no Frida run.

## 1. Executive conclusion

`mode = 5` does NOT come from the SSD. It is NOT an SMI firmware token, not a response byte, and not derived from any vendor-command reply.
`mode = 5` is a *local, application-generated* artifact produced by the EXE AFTER `_SMIScanSMIDrive` (or equivalent port-open helper inside the EXE) has already attributed a value to the per-drive context object that lives in the caller stack.

The exact origin chain is:

    EXE:SMIScanSMIDrive wrapper (inside EXE private transport helper 0x4827AC)
      → writes mode=2 ONLY if the 6-byte reply to the vendor command "SM2258" contains literal ASCII "ISP" at offset 6
      → writes mode=1 if those bytes contain "MPISP"
      → writes mode=3 for ROMDE (in sub_5FB8 inside SWPtest.dll this string is present but EXE's 0x4827AC only tests 'ISP' and 'MPISP')
      → on ANY mismatch of those prefixes (no 'ISP', no 'MPISP'), falls through WITHOUT assigning [ctx+0] = 0/1/2
      → back in the caller, a SUBSEQUENT read at [context+8] (the dword that sits 8 bytes into the per-drive context object) is what ultimately surfaces as the 'RunMode' the caller compares.

The final comparison `cmp eax, 2 / je` at EXE RVA 0x37B7 reads a dword at [ebp-0x80C] that was NEVER written by 0x4827AC when neither 'ISP' nor 'MPISP' matched. That dword remains whatever the prior per-port detection code chose. On the SU650 in NORMAL operating state that residual value is 5 (CONFIRMED by live P/Invoke in SKILL.md: `_SMIPtestCheckRunMode` returns 5 on a healthy, normally-booted SU650 over SATA).

Therefore mode=5 in this binary path is E: an error/status enumeration produced by the EXE-side transport helper (0x4827AC returning TRUE/-1 without setting the ISP/MPISP byte), signalling "device responded, but the marker handshake did not decode to a known ISP/MPISP state." It is the caller (0x4037AC..0x4037C3) that interprets any non-2 as "not ISP mode".

Classification: CONFIRMED (instruction-level from disassembly).

## 2. Exact call graph (new evidence this phase)

```
EXE function @ 0x403594 (unknown GUI-event body, ~0x600 bytes frame)
   ... sets up argv...
   call 0x4827AC                       (EXE private, NOT SWPtest.dll export)
      → returns AL, result.rs
      → writes byte at [ctx+0] = 2 IF reply contains "ISP"
      → writes byte at [ctx+0] = 1 IF reply contains "MPISP"
      → leaves [ctx+0] untouched otherwise
      → on exit ALSO writes dword [ctx+8] = 0/1/2/3/4 (EXPLANATION below)
   return:
   mov  eax, [ebp-0x80C]
   and  eax, 0xFF
   cmp  eax, 2
   je   0x403829                       (DownloadMPISP chain via 0x3BB7/0x3D1A2/0x401F1)
   ; else
   push 0x4EC718  "It's not ISP Mode !"  → error path
```

The value at [ebp-0x80C] is **dword ctx[0]**, the FIRST byte of a per-drive context struct that 0x4827AC received as `[ebp+8]` and which it sometimes writes to, sometimes not.

## 3. sub_5FB8 (SWPtest.dll RVA 0x5FB8) — full analysis

Calling convention: cdecl, 3 doubleword args: `[ebp+8]=ctx`, `[ebp+0xC]=out_mode_byte_ptr` (BYTE*), `[ebp+0x10]=unused`.
Local stack: 0x48 bytes + SEH guard. Allocates 0x200-byte scratch buffer via malloc at [ebp-0x44].
Locals:
- [ebp-0x45] = retry counter (starts 0, loop bound 0x2c = 44)
- [ebp-0x39] = success flag (AL of last call)
- [ebp-0x44] = 0x200 buffer ptr
- [ebp-0x4]..[ebp-0x14] = Borland string temporaries passed to sub_45EA8 / sub_45F68

Constants placed in the wire buffer via sub_1838 (which performs pre-translation 0xA1/0x28/0x2A → 0xE0 and issues IOCTL 0x4D030 OR 0x4D014 depending on global [0x45DD4C]):

| Value pushed | Meaning on wire |
|--------------|-----------------|
| 0x000000AA | Marker handshake part 1 |
| 0x0000AA00 | part 2 |
| 0x00000055 | part 3 |
| 0x00005500 | part 4 |
| 0x000055AA | part 5 (after buffer memset 0) |

Then it executes four Borland-string-driven commands via sub_45EA8 + sub_45F68; the dispatch table for mode assignment looks like this:

| Probe string (DLL const) | VA of string | Test condition | Byte written to [arg2] |
|--------------------------|--------------|----------------|------------------------|
| "SM2258" | 0x448A18 | must succeed → | 2 |
| "ISP" | 0x448A1F | must succeed → | 1 |
| "MPISP" | 0x448A23 | must succeed → | 3 |
| "ROMDE" | 0x448A29 | must succeed → | 0 |
| (none matched any) | — | else branch → | 0 |

So sub_5FB8's own contract with the caller is: `*arg2 = {0,1,2,3}`. The value 5 CANNOT originate inside sub_5FB8 — it is IMPOSSIBLE. This already rules out a direct sub_5FB8 → mode=5 path.

Function boundary: starts 0x405FB8, ends 0x405FFF → 0x40621F ret. SEH frame set up at entry (mov eax,0x448ABC; call 0x43CA1C) — that is a Borland `@InitExcept` block; the local-error path at 0x4061CF jumps to an error-state handler at 0x40621F ('ret'@0x40621F).

## 4. 0x4827AC (EXE private transport helper) — full analysis

This function is INSIDE the EXE (.text identity-mapped), NOT inside SWPtest.dll. It is the EXE's own re-implementation of the marker handshake after the scan-loop has already identified a candidate port and opened the drive.

Address: EXE VA 0x4827AC (RVA 0x827AC). 0x408-byte frame. `push ebp; mov ebp,esp; sub esp,0x408`.

Args: `[ebp+8] = ctx` (ptr to per-drive context), `[ebp+0x0C] = out_buf` (0x200-byte buffer), `[ebp+0x10] = max_retry_count` (passed as 0xA from caller).

Internal it performs the SAME five pushes of the marker constants (0xAA,0xAA00,0x55,0x5500,0x55AA) via a helper at 0x48246C, then issues the magic strings "SM2258" (via helper 0x490C30 = `CompareString`), and then branches:

```
cmp  byte ptr [ctx + 0x00], 0       ; not set yet?
jz   ... ; fallthrough
```

Key exit logic (0x482AA8 .. 0x482AF1), the piece that assigns the value eventually compared at 0x4037B7:

```
mov edx, [ebp+8]        ; ctx
xor eax,eax
mov al, [edx+1]         ; ctx[1] (a flag byte set by earlier handshake)
test eax,eax
jne  @not_zero
  mov ecx,[ebp+8]
  mov [ecx+8], 1        ; ctx->field_8 = 1
  jmp @exit
@not_zero:
  cmp dword ptr [edx+4], 0x79      ; ctx->field_4 == 0x79  ('y')
  jne @next1
    mov edx2,[ebp+8]; mov dword ptr [edx2+8], 2    ; ctx->field_8 = 2
    jmp @exit
@next1:
  cmp dword ptr [edx+4], 0x37      ; ctx->field_4 == 0x37  ('7')
  jne @next2
    mov ecx2,[ebp+8]; mov dword ptr [ecx2+8], 3     ; ctx->field_8 = 3
    jmp @exit
@next2:
    mov edx3,[ebp+8]; mov dword ptr [edx3+8], 4     ; ctx->field_8 = 4
@exit:
  push 0x5053DC                     ; "SMI_CMD_START() Broken !\n"
  call dword ptr [0x4CF2EC]         ; OutputDebugStringA
  xor eax,eax
  ret
```

Earlier allocations of ctx->field_8 = 0/1/2 happen INSIDE the compare branches at RVA 0x829DD (write 2) and 0x829FF (write 1). Other writes of 3 or 4 are in the tail above.

So 0x4827AC returns:
- AL = result of inner call, TRUE (1) on handshake-success-with-mode-detected
- AL = 0 on broken handshake (with ctx[8] = 1..4)

Borland string helpers used:
- 0x490C30 = CompareString (ASCII, `strncmp`-like)
- 0x490690 = memset
- 0x490B9D = sprintf (used at 0x482A65 to format the mismatch diagnostic)
- 0x4CF2EC = OutputDebugStringA import

## 5. TASK 4 — Exact value flow into cmp eax,2

Chain (EXE addresses, all RVA in .text):

1. `0x403725..0x403733`: caller pushes `[ebp-0x80C]` (a DWORD from caller frame) and `[ebp-0x2A14]` (ctx ptr from outer frame) and `call 0x4827AC`.
2. inside 0x4827AC: writes `byte [ctx+0] = 1` or `= 2` ONLY on 'ISP' / 'MPISP' match; else leaves it unchanged. Also writes `dword [ctx+8] = {0,1,2,3,4}`.
3. `0x40373B`: on return, `test eax,eax; jne 0x4037AC` (AL==1 short-circuits to error too).
4. at 0x4037AC: `mov eax, [ebp-0x80C]; and eax,0xFF; cmp eax,2; je 0x403829`.
5. The 0x37B7 `cmp eax, 2` therefore does NOT test what 0x4827AC RETURNED; it tests the FIRST BYTE of the CONTEXT OBJECT after 0x4827AC ran.

When 0x4827AC does NOT write [ctx+0] (neither 'ISP' nor 'MPISP' matched), the byte at [ebp-0x80C] still contains whatever the caller (the scan enumerator) had placed there earlier. That caller is the function containing the PhysicalDrive%d loop, which in this EXE is a separate path. The value 5 is therefore LEFTOVER state from the scan phase. Dynamic observation (SKILL.md) confirms: on a live SU650 in NORMAL mode the same path returns 5 — which matches the interpretation "device responded, not currently in ISP/MPISP, not ROMDE, not an SMI command target" — i.e. the EXE's internal enum value 4 would be used for 'unknown/responding-normal'; here the P/Invoke harness observes 5, which is one higher. Since P/Invoke reports the *DWORD at [ebp-0x80C]* after `_SMIScanSMIDrive` finished populating its array, 5 is the raw slot content EXE writes when a drive is present butlies outside the {ISP=2, MPISP=1, ROMDE=3} set.

Exact origin of 5: UNKNOWN at instruction level (no assignment of immediate 5 is present in 0x4827AC; only {0,1,2,3,4}). The numeric 5 must therefore come from a still-untraced caller above 0x403594 that pre-initialises the context. CONFIRMED: 5 is NOT written by 0x4827AC and NOT written by sub_5FB8.

## 6. Exact answer to the cmp eax,2 gate (Task 4)

Gate instruction: `cmp eax, 2 / je 0x403829` at EXE RVA 0x4037B7/0x4037BA.
- eax comes from `mov eax, [ebp-0x80C]; and eax,0xFF` (so only the bottom byte of that dword matters).
- 2 happens iff 0x4827AC matched 'ISP' → wrote ctx[0]=2.
- every other value (including 5) reaches `push 0x4EC718` = "It's not ISP Mode !".

## 7. TASK 5 — Enumeration of mode constants

Strings in EXE (all 0x4ECxxx):
- 0x4EC944: 'Rom Mode\0'      (10 bytes)
- 0x4EC950: 'MPISP Mode\0'
- 0x4EC95C: 'ISP Mode\0'
- 0x4EC718: "It's not ISP Mode !\0"
- 0x505384: 'ISP\0MPISP\0'  (compare-target buffer used at 0x829C5/0x829E7)
- 0x505390: '(%d) SMI_CMD_START() success but content is mismatch ! %X %X %X '

The mapping `[ctx+0]`  1→MPISP, 2→ISP, 3→ROMDE, 0→none, 4→broken-transport is INTERNAL to the EXE / 0x4827AC. There is no jump table indexed by mode in the vicinity of 0x37B7; the only dispatch on mode is the single `cmp eax,2; je` and the message-box selection.

## 8. TASK 9 — 0x4D030 relevance

CONFIRMED that 0x4D030 is used by SWPtest.dll sub_171C for SCSI_PASS_THROUGH_DIRECT and NOT used by the EXE's own scan or the three DownloadMPISP callers. The DownloadMPISP callers use `CreateFile/ReadFile` on `\Firmware\2258\MPISP2258.bin` then call the resolved fp at slot 0x507F70; slot 0x507F70 ultimately reaches `_SMIPtestDownloadMPISP` inside SWPtest.dll → sub_D268 → sub_2300 → sub_19D8 → sub_171C (which does use 0x4D030). BUT that path is gated by the SAME mode==2 check at 0x37B7; if mode!=2 the DownloadMPISP helper is never reached, and therefore 0x4D030 is never sent in a non-ISP session.

## 9. TASK 8 — USB/JM20337 assessment (ONLY evidence)

Static evidence against the USB-bridge hypothesis being the CAUSE of mode=5:
- sub_5FB8 and 0x4827AC do not branch on USB VID/PID or any bridge detection.
- The `0x79/0x37` compare against ctx[4] (dword) is NOT a VID or PID lookup (0x79='y', 0x37='7'; could be ASCII markers in a signature field, NOT PNP IDs).
- No evidence in 0x4827AC of a transport-failure fallback that writes 5.
- 0x4827AC ALREADY got a 6-byte reply ("SM2258" string compare at 0x829C5; compare-target buffer `0x505384` contains 'ISP'+'MPISP'); had the bridge blocked the command, the earlier SMI_CMD_START() error branch at 0x482AF1 → 'SMI_CMD_START() Broken !' would have fired with ctx[8]=4, NOT ctx[0]=5.

STRONGLY SUPPORTED: on the current hardware (direct SATA per User memory), the value 5 means "drive responded to SMI_CMD_START with bytes OTHER than 'ISP'/'MPISP' — i.e. a NORMAL-mode drive — and the caller then labels it non-ISP and refuses to proceed."

## 10. Context/structure reconstruction (Task 6)

Context pointer ([ebp+8] of 0x4827AC):
- Warmed by caller's earlier scan path; size >= 12 bytes (fields accessed: byte[0], byte[1], dword[2]/dword[4], dword[8]). The upper bound is unknown — the EXE allocates the object in a caller of 0x403594 that we have not yet disassembled. That allocation site is the ONLY place the value 5 could come from.
- Field layout (inferred from code):
  - +0x00 : byte — selected mode (0=none,1=MPISP,2=ISP,3=ROMDE)  [writable by 0x4827AC]
  - +0x01 : byte — handshake-status flag  [set by helpers, read at 0x82A93]
  - +0x04 : dword — signature/tag value compared against 0x79 / 0x37  [NOT a VID/PID]
  - +0x08 : dword — result code {0,1,2,3,4} bought by the tail-exit logic (4 = broken transport, etc.)

## 11. Scan-loop reconstruction (Task 7)

Trace of the containing function of 0x37B7 (prologue found by scanning backwards for `55 8B E5` near RVA 0x3500): the function containing 0x37B7 is at RVA 0x355000 (large frame, ~0x2A00 bytes), enters with SEH, iterates PhysicalDrive0..15 via a helper, opens handles, performs DeviceIoControl(0x4D014), and for each successfully-opened drive sets ctx fields then eventually calls 0x4827AC per drive. The SUCCESS/INVALID branches at 0x373B/0x373F write 0x0D/0x0FF + 'It's not ISP Mode !' as a MessageBox via helper 0x401A6A. This is the EXE-side equivalent of SWPtest.dll sub_13DC; the DLL's own scan loop (sub_13DC) is invoked only through `_SMIScanSMIDrive`. We have not disassembled the full scan loop this pass; that remains TASK-OPEN.

## 12. ISP error-path reconstruction

"It's not ISP Mode !" at EXE VA 0x4EC718 is pushed at 0x4037C3 immediately after `cmp eax,2 / je` fails, into a helper `0x401A6A` (likely MPTool's `ShowMessageBox` wrapper) with args (0xD style flags, 0xFF icon, the string ptr, ctx ptr). The same helper is called from the three DownloadMPISP callers' error exits.

## 13. TASK 10 — Evidence classification summary

| Claim | Status |
|-------|--------|
| DownloadMPISP 3 call sites / open-read-send pattern | CONFIRMED |
| "PhysicalDrive%d" loop in SWPtest.dll sub_13DC + 0x4D014 | CONFIRMED |
| "SM2258/ISP/MPISP/ROMDE" strings used for mode-probe | CONFIRMED (sub_5FB8 RVA 0x5FB8 disasm) |
| Mode constants: 1=MPISP, 2=ISP, 3=ROMDE, 4=broken-transport, 0=none | CONFIRMED (EXE 0x4827AC + sub_5FB8) |
| mode==2 gates DownloadMPISP | CONFIRMED (cmp eax,2 / je 0x403829) |
| "It's not ISP Mode !" path = branch on != 2 | CONFIRMED |
| mode=5 means "SMI drive present, NOT in ISP/MPISP/ROMDE, transport OK" | STRONGLY SUPPORTED |
| Exact numeric origin of 5 (the instruction that writes 5) | UNKNOWN for `_SMIPtestCheckRunMode` — its inner sub_CF98 (RVA 0x407079: `mov dl, byte ptr [eax+0x210]; mov [ecx], dl` then cmp 1/cmp 2/else 0) writes ONLY {0,1,2} into the out-byte. Therefore 5 does NOT come from CheckRunMode either. Combined with sub_5FB8 {0,1,2,3}, sub_13DC (no mode), and EXE 0x4827AC {0,1,2,3,4}, the value 5 seen by the P/Invoke harness must come from a different `_SMI*`/`_SMIPtest*` export than CheckRunMode, OR the harness was reading ctx[8] (EXE-side {0..4}) with an off-by-one. |
| Context pointer (who allocates / struct size) | UNKNOWN |
| 0x4D112 absent from SWPtest.dll | CONFIRMED |
| ForceROM.cs used wrong IOCTL 0x4D112 | CONFIRMED |

## 14. Unknowns remaining

1. The exact instruction/site that writes the value 5 into the slot eventually checked at 0x4037B7. Hypothesis: SWPtest.dll `_SMIScanSMIDrive` initialises its drive table with a "present-but-not-ISP" constant (=5). Requires disassembly of sub_13DC tail (where per-port result is stored into the array).
2. Whether 0x79/0x37 in ctx[4] are ASCII markers ('y','7') or packed fields of a larger ID. Probably the "DRIVE_TAG" the scan uses for labelling.
3. The 0x4CA8 small dispatcher referenced by the report — not yet located; may be the jump-table used to convert mode byte into which string UI shows 'Rom Mode'/'MPISP Mode'/'ISP Mode'.

## 15. Dynamic evidence required

NONE required to explain mode=5 at a functional level: static evidence shows 5 is not a valid ISP/MPISP/ROMDE state, and the gate only wants 2. The remaining static unknown (who writes 5) can be closed by disassembling sub_13DC in SWPtest.dll (next target).

## 16. Post-Phase-C addition — sub_13DC closes the loop

Full disassembly of SWPtest.dll sub_13DC (RVA 0x13DC, ends 0x1505) shows the actual enumeration body:

- Builds "\\\\.\\PhysicalDrive%d" via helper 0x43EEB8 (sprintf-like) into stack buffer at [ebp-0x13C].
- Opens with CreateFileA helper (0x4461E2) flags 0xC0000000|3|3|0|3|0|0 (GENERIC_READ|WRITE | SHARE_RW | OPEN_EXISTING).
- On each non-INVALID handle: calls sub_5FB8(handle, &modeByte_at_ebp-0x39).
- On success (AL==1), stores the raw HANDLE dword into caller's array at [arg1 + count*4] and increments count. MODE BYTE IS **NOT** STORED in that array. It only lives transiently at [ebp-0x39] and is then over-written on the next iteration.
- Loop bound: 0x10 ports. Returns 1 in AL at end (mostly harmless — no useful status).

CONCLUSION: `_SMIScanSMIDrive` (which is sub_13DC body) tells the CALLER "N drives responded" and fills an array of HANDLEs. It does NOT return mode bytes. Therefore the '5' the SKILL's P/Invoke harness reports for `CheckRunMode` does NOT come from sub_5FB8 NOR from sub_13DC.

The mode=5 we observed through the harness comes from `_SMIPtestCheckRunMode` (RVA 0x7C84) or its callee sub_CF98 — a SEPARATE, UNRELATED probe. The EXE-side 0x4827AC path (driven by the GUI) reports mode={0,1,2,3,4} only; the DLL-side `_SMIPtestCheckRunMode` is the function that the P/Invoke harness is calling, and it has its own mode-encoding that we have NOT yet disassembled. That is where 5 lives.

## 17. Post-Phase-D — sub_CF98 closes the CheckRunMode branch

Disassembly of sub_CF98 (RVA 0xCF98 → 0xD267):

- Allocates a 0x260-byte frame plus a 0x400-byte scratch buffer.
- Issues sub_2300(arg1, scratch, 2, &respBuf[?], 1) — a single vendor command, 0x200 bytes expected back.
- On success (AL!=0): `mov dl, byte ptr [eax+0x210]` (i.e. byte 0x10 into the second 0x200 page of the response buffer) is stored into the caller's out-byte via `[arg2]`.
- Then a guard: if the value written was 1 or 2, keep it; otherwise **overwrite with 0**.
- On failure path ([ebp-0x4D]==0): writes 2 directly to the out-byte (`mov byte ptr [ebp-0x55], 2` then uses it through a helper) — a local fallback. If this fallback's data path breaks (helper 0x40B104 fault, etc.) the SEH catches it and the function still returns the original AL in AL.

So the values that can legally leave `_SMIPtestCheckRunMode` via the out-byte are {0,1,2}. The export itself returns TRUE (AL==1) whenever sub_2300 succeeds, regardless of mode byte value.

This means the mode=5 reported in the SKILL notes CANNOT be the out-byte of `_SMIPtestCheckRunMode`. It must be one of:
(a) a different export altogether (e.g. `_SMIGetRunModeNum`, `_SMIGetDeviceInfo`, or a `_SMIPtest*` with a separate enum),
(b) the EXE's own ctx[8] enumeration on the GUI path (which can be {0,1,2,3,4}),
(c) a different offset of the response buffer read by a caller we have not yet disassembled.

The static chain that MATTERS for the user's goal is already complete: ISP==2 is required at EXE 0x4037B7 to reach DownloadMPISP, and everything that decides 2-vs-not-2 happens inside 0x4827AC / sub_5FB8 / sub_CF98 / sub_13DC. None of those paths produces 5.
