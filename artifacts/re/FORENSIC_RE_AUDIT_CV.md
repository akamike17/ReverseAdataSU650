# PHASE C/D — SURGICAL RE-AUDIT (per cv.md)

**Target:** SWPtest.dll `_SMIPtestCheckRunMode`, historical `RunMode: 5` from `log/smiflash_crash_20260921_193309.log`, and the DownloadMPISP gate.

**Operating principle throughout:** all conclusions are reported under the four allowed classifications (CONFIRMED / STRONGLY SUPPORTED / HYPOTHESIS / UNKNOWN). Where a previous report claimed too much, this audit narrows the claim to what is instruction-backed.

---

## §3 / §8 — Binary / harness architecture (independent re-verification)

| Property | Value | Source |
|---|---|---|
| SWPtest.dll Machine (COFF) | 0x14C (I386) | pefile on the committed DLL |
| SM2258XTMPToolQ0816A.exe Machine | 0x14C (I386) | same |
| Harness build target | x86 / win-x86 / Prefer32Bit=true | `smiflash_build/smiflash.csproj` |
| As-built `smiflash.exe` Machine | 0x14C | bin/Release/net10.0/smiflash.exe |
| As-built bundled SWPtest.dll Machine | 0x14C | bin/Release/net10.0/SWPtest.dll |

CONFIRMED: harness ran as x86 against an x86 DLL — no 64/32-bit boundary exists. This rules out pointer-width corruption as the cause of the observed 5.

## §3.1 — `_SMIPtestCheckRunMode` export location and calling convention

| Field | Value | Source |
|---|---|---|
| Export name | `_SMIPtestCheckRunMode` | export directory |
| RVA | 0x7C84 | pefile |
| VA (at standard ImageBase) | 0x407C84 | base+RVA |
| Calling convention | cdecl (x86) | callee does NOT clean stack; callers around RVA 0x407CAF run `add esp, 0xC` after `call 0x40CF98` |
| Parameter count | 3 × DWORD | three pushes immediately before the `call`; callee adds `0xC` itself |
| Argument types | pointers (ctx/workspace semantics) | dereference patterns inside callee |

The mapping that the previous phase asserted is CONFIRMED at instruction level by the export's tail-immediates:

```
VA 0x407CA1: push dword [ebp+0x10]   ; export arg3 → becomes callee arg3
VA 0x407CA4: push dword [ebp+0x0C]   ; export arg2 → becomes callee arg2
VA 0x407CA7: push dword [ebp+0x08]   ; export arg1 → becomes callee arg1
VA 0x407CAA: call 0x40CF98           ; sub_CF98
```

After the call: `add esp, 0xC` — the CALLER cleans the stack. cdecl. CONFIRMED.

Argument order is preserved:
- native callee arg1 = export arg1 = harness `hDrivePtr`
- native callee arg2 = export arg2 = harness `_ctxBuf`
- native callee arg3 = export arg3 = harness `modeOut`

## §4 — sub_CF98 (RVA 0xCF98) full argument trace

Frame: `push ebp; mov ebp,esp; add esp,-0x260; push ebx/esi/edi`. SEH via `fs:[0]` at 0x40CFA4-0x40CFA9. Stack frame = 0x260 bytes + 3 saved regs + SEH guard.

Every load/store against incoming arguments, with exact instruction addresses:

| Address | Instruction | Interpretation |
|---|---|---|
| 0x40CFB6 | `mov edx, dword ptr [ebp+0x10]` | read arg3-as-dword (pointer) |
| 0x40CFB9 | `mov dword ptr [ebp-0x60], edx` | stash to local cell |
| 0x40CFBC | `mov ecx, dword ptr [ebp+0x10]` | read arg3 again |
| 0x40CFBF | `add ecx, 0x4200` | compute arg3+0x4200 |
| 0x40CFC5 | `mov dword ptr [ebp-0x5C], ecx` | stash to another cell |
| 0x40CFC8 → 0x40CFF7 | Borland string "Enter PtestCheckRunMode:" + helper 0x40B178 using `[ebp-0x60]` (=arg3) as object | arg3 used as the *receiver object* for a logging helper |
| 0x40D002 → 0x40D012 | malloc(0x400) → store at `[ebp-0x54]` | response scratch buffer |
| 0x40D016 → 0x40D03F | Borland string "rdVndrCmdReadDriveInfo" + helper 0x40B178 using arg3 again | second log record |
| 0x40D044 → 0x40D05A | call sub_2300(arg1=hDrivePtr, arg2=scratch, arg3=2, arg4=&respBuf, arg5=1) | issue read-drive-info vendor command |
| 0x40D05D → 0x40D064 | success flag → `[ebp-0x4D]` → branch if non-zero | |
| 0x40D066 → 0x40D06A | on FAIL: `mov byte ptr [ebp-0x55], 2` then jump | locals only |
| 0x40D06C | `mov eax, dword ptr [ebp-0x54]` | eax = response buffer |
| 0x40D06F | `mov dl, byte ptr [eax+0x210]` | **read mode token from response+0x210** |
| 0x40D075 | `mov ecx, dword ptr [ebp+0x0C]` | ecx = arg2 (=export arg2 = harness `_ctxBuf`) |
| 0x40D078 | `mov byte ptr [ecx], dl` | **write mode byte to arg2[0]** |
| 0x40D07A / 0xD07D / 0xD080 | `cmp byte ptr [arg2], 1; je` | guard: keep if 1 |
| 0x40D082 / 0xD085 / 0xD088 | `cmp byte ptr [arg2], 2; je` | guard: keep if 2 |
| 0x40D08A / 0xD08D | `mov byte ptr [ecx], 0` | otherwise force 0 |
| 0x40D09D / 0x40D09E / 0x40D0A0 | push 5; push arg3; call 0x40B104 | logging call — note literal 5 in the push is a LOG-LEVEL/id, not a mode |
| 0x40D1F6 / 0x40D1F9 | final ret | |

**Argument map (binary-proven):**

```
[ebp+08] = arg1 = hDrivePtr (pointer-to-handle, deref via [arg1] = HANDLE)
[ebp+0C] = arg2 = ModeOut BYTE*   (receives the mode byte at offset 0)
[ebp+10] = arg3 = Context/log block pointer with valid bytes out to +0x4204
```

This matches the expectation stated at cv.md §3.1 (`arg1=hDrivePtr, arg2=modeOut, arg3=ctx`) — meaning the **harness passed arguments in a different order than the native function requires**. The harness P/Invoke signature is:

```csharp
private static extern bool _SMIPtestCheckRunMode(IntPtr hDrivePtr, IntPtr ctx, IntPtr modeOut);
```

But native sub_CF98 treats native-arg2 (position-2) as the BYTE-pointer that receives the mode. The harness passed `_ctxBuf` (4288+ KB) at position 2 — that buffer received the mode byte at `_ctxBuf[0]`. The harness passed a 4-byte base for arg3 — which the native code then treated as an object with bytes valid out to +0x4204, causing OOB reads there.

## §5 — What is arg3 actually?

Evidence:
- arg3 is stored at `[ebp-0x60]`, then `[ebp-0x5C]=arg3+0x4200` and both cells are passed alongside string helpers into `sub_40B178` (log-formatter variant) three times: at entry ("Enter PtestCheckRunMode"), after ReadDriveInfo ("rdVndrCmdReadDriveInfo"), and near the end ("Func:PtestCheckRunMode Error" / "Done!").
- arg3+0x4200 is NOT dereferenced for WRITE during the traced body (no `mov byte ptr [reg+0x4200], X` instructions exist with arg3-derived register here). The reads we found are `mov edx,[ebp+0x10]` / `add ecx,0x4200` — pure address arithmetic PLUS ONE POINTER READ AT arg3, plus a second-instance read into sub_40B178 that uses it as the receiver for AnsiString-Borland-style logging.
- That is consistent with an "audit / status-recorder" object whose +0x4200 sub-buffer receives formatted status text via the logging helper.

STRONGLY SUPPORTED: arg3 is a "log/status buffer" object with an embedded sub-buffer at +0x4200 used by the logging helper at RVA 0x40B178. It is NOT the mode byte destination.

UNKNOWN: the full owner / inheriting vtable / object type of arg3 — proving that would require tracing MPTool.exe's allocation site for this buffer, which sits inside a larger context struct whose first 0x4200 bytes carry state we have not fully mapped.

## §6 — Required allocation size for native arg3

Observed native accesses into arg3 region:

| Address | Access | Type | Requirement |
|---|---|---|---|
| RVA 0xCFB6 | read dword @ arg3+0 | O(4 bytes) | 4 bytes valid |
| RVA 0xCFBF | compute arg3+0x4200 | pointer arithmetic only | none (no deref) |
| RVA 0xCFC5 | stash that pointer | pure store to DLL-local | none |

Inside helper 0x40B178, its second arg is `arg3` and there are further writes into `[arg3+X]` for X unknown without tracing that helper further. We did observe two separate log-helper calls (both 0x40B178) that receive arg3, meaning arg3 must support at least the logging helper's access pattern. Without doing exhaustive analysis of sub_40B178, we state:

- Minimum valid observed native access ON arg3 itself: 4 bytes (the pointer read at RVA 0xCFB6).
- The **log-helper call chain** computes and uses `arg3+0x4200`, implying the native caller (MPTool.exe) allocates arg3 = 0x4200 + (bytes the helper needs at that offset). We have not bounded that helper statically.

UNKNOWN: the precise minimum allocation for the full `_SMIPtestCheckRunMode` call. 4 bytes is *provably insufficient* because the pointer read at arg3+0 alone is satisfied, but the address-arithmetic-then-passed-to-logger on arg3+0x4200 will touch whatever memory follows that address. Whether the helper WRITES there or only READS was not resolved.

UNKNOWN → the previous report's claim that `modeOut = AllocHGlobal(4)` is "incompatible with native expectations" is DOWNGRADED to: "the 4-byte allocation is smaller than what the logging helper's `arg3+0x4200` addressing assumes.

Refined inference chain (no overclaim): the harness's 4-byte modeOut is read as a pointer cell at RVA 0xCFB6 (`mov edx,[ebp+0x10]`) — that dword is whatever bytes we wrote (we wrote 0). The resulting edx=0 is stored and later passed to a logger. The logger's logic — whether it WRITES through that zero pointer or merely takes the address — was not traced here. A fuzz test would resolve this; we do not run it (cv.md §17 prohibits live traffic experiments in this phase).

## §7 — Harness audit summary (re-statement of §12.6)

P/Invoke:
```csharp
[DllImport("SWPtest.dll", CallingConvention = CallingConvention.Cdecl)]
static extern bool _SMIPtestCheckRunMode(IntPtr hDrivePtr, IntPtr ctx, IntPtr modeOut);
```

Caller:
```csharp
handlePtr = AllocHGlobal(4); Marshal.WriteInt32(handlePtr, (int)hDrive);
_ctxBuf   = AllocHGlobal(0x8400);
modeOut   = AllocHGlobal(4); Marshal.WriteInt32(modeOut, 0);
bool ok = _SMIPtestCheckRunMode(handlePtr, _ctxBuf, modeOut);   // returns TRUE
byte mode = Marshal.ReadByte(modeOut);                           // = 5
```

CONFIRMED per smiflash.cs L63-L233.

Memory cleanliness prior to the call: `modeOut[0..4] = 0`, `_ctxBuf` initialised by AllocHGlobal (uninitialised, `AllocHGlobal` does not zero memory).

## §8 — ABI audit (already covered in §3.1): both sides are x86, cdecl. No width/ABI mismatch of size-relevant type. **CONFIRMED**.

## §9 — Handle semantics

Native sub_171C (SCSI_PASS_THROUGH_DIRECT transport, used by the download path) reads:
```
mov edx,[ebp+8]; push dword ptr [edx]   ; deref → HANDLE
```
Therefore the native convention is **DWORD-pointer containing HANDLE** — exactly what the harness passes. CONFIRMED. No bug here.

## §10 — Mode output data-flow

| Stage | Code / Address | Source | Destination | Meaning |
|---|---|---|---|---|
| 1 | inside sub_2300 | `sub_5FB8` returns AL=1 and writes mode ∈ {0,1,2,3} to `[ebp+0xC]` (its own arg2, a 1-byte cell) | caller's scratch +0x210 (RVA 0x402469) | intermediate token from SSD |
| 2 | sub_CF98 RVA 0x40D06F | `[eax+0x210]` (response buffer) | register DL | transport |
| 3 | sub_CF98 RVA 0x40D075-0x40D078 | DL | `[arg2]` (arg2 = harness `_ctxBuf`) | native write to user's arg2 |
| 4 | sub_CF98 RVA 0x40D07D-0x40D088 | `[arg2]` | guard cmp 1/cmp 2 | keep if valid |
| 5 | sub_CF98 RVA 0x40D08A-0x40D08D | — | `[arg2]=0` | forced-zero for any other token |

The value in arg2 at the end of a successful call is ∈ {0,1,2}. **No instruction on this path writes the value 5 to any user-visible buffer.**

## §11 — The REAL mode consumer in MPTool.exe

MPTool.exe function containing the gate (RVA 0x403594 prologue; body around 0x3594→0x3BB7) performs, just before the gate:

```
RVA 0x403725: push dword ptr [ebp-0x2A14]      ; ctx pointer (EXE-side)
RVA 0x40372C: lea ecx, [ebp-0x80C]
RVA 0x403733: call 0x4827AC                    ; EXE private helper
```

After return:
```
RVA 0x4037AC: mov eax, dword ptr [ebp-0x80C]
RVA 0x4037B2: and eax, 0xFF
RVA 0x4037B7: cmp eax, 2
RVA 0x4037BA: je 0x403829                       ; gate passes → DownloadMPISP
```

The consumer reads [ebp-0x80C] (the caller's ctx[0] byte after it was possibly modified by 0x4827AC). That location is the CALLER'S stack frame; the helper wrote through arg1-of-0x4827AC (which equals `[ebp-0x2A14]`), NOT the caller's `[ebp-0x80C]` directly. The two cells coincide ONLY because the caller's `[ebp-0x2A14]` was earlier set to point to its own stack slot at `[ebp-0x80C]`. This aliasing is consistent with the common Borland idiom where the caller address takes its own local; we have not located the precise aliasing instruction in the caller body (would need further disasm above 0x403594). HYPOTHESIS — left for continued work.

## §12 — Forensic origin of the observed 5

What has been definitively ruled out, at instruction level:
- The historical log shows `RunMode: 5` at the C# `Marshal.ReadByte(modeOut)` AFTER a CheckRunMode that returned TRUE.
- No instruction on the native CheckRunMode chain (export → sub_CF98 → sub_2300 → sub_5FB8) writes the literal 5 to any user buffer.
- Full keyword hex sweep for `mov ?,5` on the detection/scan/checkrunmode/download paths found no producer.

What HAS been established:
- The harness passes arguments in a WRONG ORDER relative to native expectation (mode byte lands at arg2[0], not arg3[0]).
- The harness ALLOWS for arg3 (native expects ≥ 4 bytes for pointer read; and address arithmetic lands on arg3+0x4200).
- modeOut[0]=5 is INCONSISTENT with every instruction on the traced call path.

**The exact mechanism by which 5 reached modeOut[0] in the historical run is UNKNOWN.** The following are the candidate mechanisms, none currently provable statically:

  a. allocator residue in the 4-byte block after WriteInt32 — would require the WriteInt32 to be optimized away or to fail, which the harness source does not permit. Cannot be confirmed statically.
  b. a write by the native DLL through an UNTRACED pointer — possible since we did not disassemble sub_40B178 (the logger) or any deeper helpers; any of those may make a deterministic write into the caller's stack/heap that happens to land on modeOut[0]. UNKNOWN until those helpers are audited.
  c. a write by `.NET marshaller` into managed state near modeOut during P/Invoke teardown — UNLIKELY but not ruled out because we have not audited .NET's actual marshalling stubs at runtime.
  d. race with another thread — the harness is single-threaded on this path. REFUTED.

**Required terminology going forward (per cv.md §16):**

CONFIRMED: "The analyzed native CheckRunMode path does not use the harness's modeOut[0] as the native mode destination; the relevant mode byte is written through the second native argument."

STRONGLY SUPPORTED: "The current harness has an ABI/output-buffer interpretation mismatch with the analyzed native function."

UNKNOWN: "The exact mechanism by which the historical value 5 appeared in the harness's four-byte modeOut allocation has not been demonstrated."

NOT ALLOWED (per cv.md §1/§16): "RunMode=5 was definitively caused by marshaling."

## §13 — Sweeps for literal 5 (binary)

- `.text` full sweep for opcode forms `mov ?,5`, `mov ?,05h`, `cmp ?,5`, `lea ?,5` — no candidates that can reach the user-visible out byte.
- Constant `5` IS pushed into the log-helper call at RVA 0x40D09E — but as an immediate second-argument to 0x40B104, whose signature treats it as a log **code/class**, not a data byte. REFUTED as a mode producer.

## §14 — Native mode domain after this audit

| Function | Domain written to caller-visible buffer | Evidence |
|---|---|---|
| `_SMIPtestCheckRunMode` / sub_CF98 | {0,1,2} | RVA 0xD07D-0xD08D (1,2 kept; else forced to 0) |
| `sub_5FB8` (DLL, detection handshake) | {0,1,2,3} | RVAs 0x406110/0x406159/0x40619F/0x4061A7 |
| `sub_13DC` (`_SMIScanSMIDrive`) | no mode returned; only handles/count | sub_13DC disasm |
| EXE `0x4827AC` | ctx[0]∈{0,1,2}; ctx[8]∈{0..4} | EXE disasm |

Global statement allowed by the evidence: **5 is not reachable through the audited CheckRunMode production path.** No stronger claim is made.

## §15 — Consistency table for previous report sections

| Claim in Phase C / Phase C continuation | Evidence | Verdict after this audit |
|---|---|---|
| "mode=5 is harness marshaling error" (Phase C final classification) | ABI mismatch is real; byte-5 mechanism NOT demonstrated | DOWNGRADED from CONFIRMED to STRONGLY SUPPORTED |
| "PHASE C — VERIFIED" | stated because gate-chain was proven; but over-claimed that mode=5 origin was "formally resolved" | REPLACED by "DownloadMPISP gate chain verified; harness-side mode=5 origin remains UNKNOWN" |
| "the value 5 is an allocator artefact in the harness heap" | no evidence | REFUTED as a stated certainty; replaced with UNKNOWN |

## §16 — Final status (per cv.md §16)

PHASE C — CONTINUE REQUIRED

Justification: the native gate is fully traced and its boundaries are proven, but the precise producer of byte 5 into the harness's modeOut[0] has not been demonstrated. Further work to close this narrow question requires either (a) full disassembly of sub_40B178 (the Borland logger) plus its data path, or (b) a static-memory controlled experiment that never touches the physical SSD — e.g. call `_SMIPtestCheckRunMode` with an INVALID handle and inspect buffers for any writes (should be safe if the export's failure path is taken before DeviceIoControl, as it appears to be from RVA 0x40D060's failure-jump).

The legal dynamic experiment for a later phase: P/Invoke with a garbage handle value (e.g. 0xDEADBEEF) so that CreateFile was never called by the harness but the code path inside the DLL still runs far enough to show whether it touches modeOut. That experiment would NOT touch a physical SSD and is NOT prohibited by cv.md §17.

## §19 — Hardware-facing question now isolated

With the harness-vs-native ABI problem isolated, the original recovery question becomes sharper:

CONFIRMED (static): MPTool.exe's gate at RVA 0x4037B7 will reject EVERY mode value produced via `_SMIPtestCheckRunMode`'s success path EXCEPT 2, because value 2 is the only one that survives the sub_CF98 guard at 0x40D07D-0x40D08D AND is the only value the EXE compares against. Therefore the GUI "It's not ISP Mode !" path triggers whenever the drive is in NORMAL/ROMDE/MPISP or when the handshake fundamentally fails.

The hardware-side question to answer in a later READ-ONLY phase (cv.md §20): what exact CDB/scsi-pass-through response corresponds to mode==2 vs mode==5-in-the-wild (i.e. actual ISP detection by native code)?
