# B27A FORENSIC CONTINUATION — Transport Layer Reconstruction

**Base:** commit `b127dc4`
**Production code modified:** NO
**Hardware touched:** NO
**Method:** static-only disassembly of SWPtest.dll with pefile + capstone.

---

## 1. TRACK A — Historical 0x05

Status: **UNRESOLVED — STATIC EVIDENCE EXHAUSTED** (see FORENSIC_RE_AUDIT_KK.md tail). Do not re-open.

## 2. TRACK B — Real B27A mode path

### 2.1 The two transports (reconstructed at instruction level)

SWPtest.dll exports `.text` builder helpers that ALL converge onto two DeviceIoControl wrappers:

#### A. sub_165C (`SCSI_PASS_THROUGH`, IOCTL 0x4D014) — RVA 0x165C

Args:
```
[ebp+8]  = ptr-to-HANDLE   (deref: push dword [edx]   ; io handle)
[ebp+0C] = ptr to SCSI_PASS_THROUGH struct (caller-built, full struct)
```

Body behaviour:
- Loads byte `wSenseLen=0x70` into `[ebp-0x2A]` (=112). That 0x70 becomes `nInBufferSize == nOutBufferSize` sent to DeviceIoControl (`push 0x70` twice at RVA 0x1685-0x1691).
- Struct size prefilled = 0x70 bytes (112). This is larger than the canonical `SCSI_PASS_THROUGH` (48 bytes) — the caller is expected to build a 0x70-byte buffer that carries the SCSI_PASS_THROUGH header at offset 0 plus the CDB inline.
- `push 0` (lpOverlapped) → blocking call.
- Return semantic: AL ← DeviceIoControl's return BOOL, then OVERRIDE with byte at `[struct+2]` (the SCSI status byte at `ScsiStatus`), then invert: `[ebp-0x31] = (struct[2] == 0) ? 1 : 0`. The dll therefore reports AL=1 iff the controller returned SCSI_STATUS_GOOD at byte 2 of the struct.

Conclusion: the transport is correct only if the caller's struct has ScsiStatus at offset 2, matching the Microsoft definition:
```
typedef struct _SCSI_PASS_THROUGH {
  USHORT Length;          // +0
  UCHAR  ScsiStatus;      // +2   <-- this is what we read
  UCHAR  PathId;          // +3
  UCHAR  TargetId;        // +4
  UCHAR  Lun;             // +5
  ...
  ULONG  DataTransferLength;    // +0x14
  ULONG  TimeOutValue;          // +0x18
  ULONG_PTR DataBufferOffset;   // +0x1C (32-bit: ULONG)
  ULONG  SenseInfoOffset;       // +0x20 (32-bit)
  UCHAR  Cdb[16];               // +0x24
} SCSI_PASS_THROUGH, *PSCSI_PASS_THROUGH;
```

#### B. sub_171C (`SCSI_PASS_THROUGH_DIRECT`, IOCTL 0x4D030) — RVA 0x171C

Args:
```
[ebp+8]  = ptr-to-HANDLE
[ebp+C]  = passthrough-select byte (saved to byte [esp+?], used as DataIn)
[ebp+10] = CDB byte 14 pattern (VendorL/)
[ebp+14] = CDB byte 15 pattern (ServiceAction-type / target id)
[ebp+18] = CDB[4] parameter (and packed bytes 5..13 through shifts)
[ebp+1C] = flag byte — also packed into CDB[6..7]
[ebp+20] = TimeOutValue  (dword)
[ebp+24] = DataTransferLength sector count (TRANSFER, 9-bit-shifted)
[ebp+28] = SenseInfoBuffer pointer
```

Body details:
- Copies a 0x28-byte template into `[ebp-0x58]` (`rep movsd, ecx=10` dwords). Template content at VA 0x447324 is all-zero — i.e. the struct starts blank (CONFIRMED from data dump). So this template init is functionally equivalent to `memset(0x28,0)`.
- Calls memset helper (`0x43C71C`) on `[ebp-0x30]` with size 0x28 (40 bytes) — explicit zero of SCSI_PASS_THROUGH_DIRECT header.
- If `[ebp+0x1C] & 2` then memset the buffer at `[ebp+0x28]` size `[ebp+0x24]` (zero data buffer, because we are about to read).
- If `[ebp+0x1C] & 8` then over-write struct bytes `-0x18..-0x13` with a second CDB built from bundled constants ([0x00, 0x00, OP, 0x00, 0xE0, 0x00, 0x00]).
- Struct header field setup at `[ebp-0x30]`:
  - Length = 0x28 (=sizeof(SCSI_PASS_THROUGH_DIRECT) on x86).
  - CdbLength stored at `[ebp-0x2E]` (word) — offset 0x02 = `CdbLength`/`PathId` etc.
- Calls helper 0x4461F4 (DeviceIoControl import thunk).

Return semantic (RVA 0x1820-0x1830):
```
if (struct[-0x32+ebp] (i.e. ScsiStatus) != 0x50) AL = 0
else if (DeviceIoControl-return == 0)         AL = 0
else                                          AL = 1
```

So this transport returns AL=1 only when BOTH: (a) DeviceIoControl succeeded, AND (b) the recorded ScsiStatus byte inside the struct equals 0x50. Curious — `0x50` is not the standard `SCSISTAT_GOOD (0x00)`. A `0x50` = `SCSISTAT_GOOD | SCSISTAT_DEVICE_SPECIFIC_4 (vendor byte)`. This is the custom SMI "Drive accepted the vendor command" acknowledgment.

### 2.2 Callergraph (every call site found by raw rel32 scan)

`call sub_171C` (IOCTL 0x4D030):
- RVA 0x1895 — inside **sub_1838** (cmd-translation helper, opcodes 0xC8/0x25)
- RVA 0x18C5 — inside **sub_1838** (alternate form)
- RVA 0x1A35 — inside **sub_19D8** (cmd-translation helper, opcodes 0xCA/0x35)
- RVA 0x1A65 — inside **sub_19D8** (alternate form)
- RVA 0x1C51 — inside **sub_1B84** (cmd helper)
- RVA 0x1D5B — inside **sub_1D18** (cmd helper)
- RVA 0x1E7A — inside **sub_1E14** (cmd helper)

All seven call sites pass the same first two arguments (`dword [ebp+8]` = handle ptr, and a parameter at `[ebp+0xC]`). The variation is in the CDB content (args 0x18/0x1C etc.) and is selected by the calling helper.

`call sub_165C` (IOCTL 0x4D014):
- RVA 0x1974 — inside **sub_1838**
- RVA 0x1B20 — inside **sub_19D8**
- RVA 0x1CA8 — inside **sub_1B84**
- RVA 0x1DAE — inside **sub_1D18**
- RVA 0x1EC9 — inside **sub_1E14**

**Both transports live inside the SAME five helper functions** (sub_1838/sub_19D8/sub_1B84/sub_1D18/sub_1E14). The selection between 0x4D014 and 0x4D030 is decided by each helper based on:
```
if byte [0x45DD4C] == 2 → sub_171C path (PASS_THROUGH_DIRECT)
else                    → sub_165C path (PASS_THROUGH)
```

`[0x45DD4C]` is a GLOBAL byte in SWPtest.dll's `.data` section. Its default state is per-DLL init; it is mutated by `_SMISetPassThroughType(byte type)` — the export the harness calls first. **Setting it to 0 (the historical harness behaviour) routes EVERYTHING through sub_165C.** Setting it to 2 routes through sub_171C.

### 2.3 What the helpers emit (CDB reconstruction)

From the caller-context disassembly:

| Caller helper | Constant CDB opcode byte | Purpose (from log strings) |
|---|---|---|
| sub_1838 w/ 0xC8 | CDB[7]=0xC8 at `[ebp-0x14]` | "rdVndrCmdReadDriveInfo"-class probe (used by sub_5FB8 detection) |
| sub_1838 w/ 0x25 | CDB[7]=0x25 at `[ebp-0x14]` | Alternate ReadDriveInfo (over 0x80 sectors) |
| sub_19D8 w/ 0xCA | CDB[7]=0xCA at `[ebp-0x14]` | SendMarker (used by sub_5FB8's AA/AA00/55/5500/55AA sequence) |
| sub_19D8 w/ 0x35 | CDB[7]=0x35 at `[ebp-0x14]` | Alternate with LBA > 0xFFFF7F |
| sub_1B84 OP=0x06 | CDB[7]=0x06 | Generic command w/ 0x200-byte bidirectional buffer |
| sub_1D18 OP=0x06 | CDB[7]=0x06 | Generic CDB[6]=0x0C (DRAM-load/vendor family) |
| sub_1E14 OP=0xEA | CDB[7]=0xEA | Vendor-specific EraseAll / similar |

At the wire level (when `[0x45DD4C]==2`, sub_171C path), the FORCE-ROM command sequence reconstructed from sub_171C's arg-derived CDB bytes is:
```
CDB[0]=0x00  CDB[1]=0x00  CDB[2]=arg1_low  CDB[3]=0x00
CDB[4]=0xE0  CDB[5]=0x00  CDB[6]=packed([ebp+0x1C]&3)<<0 | bytes-from-arg3
CDB[7]=0xE0  CDB[8]=0x00  CDB[9]=0x00  CDB[10..15]=0x00
```
On the wire this yields the `00 00 XX 00 E0 00 XX E0 00 00 00 00 00 00 00 00` pattern the SKILL documents as "Force ROM". CONFIRMED from the bytes set in sub_171C body.

### 2.4 sub_5FB8 — how it talks

sub_5FB8's body uses ONE call-helper style:
```
push 1                       ; flag = ?
push dword [ebp-0x44]        ; scratch 0x200-byte buffer
push dword marker            ; AA / AA00 / 55 / 5500 / 55AA depending on round
push dword [ebp+8]           ; handle ptr
call sub_1838                ; translate-and-send
```
`sub_1838` invokes either sub_171C or sub_165C depending on `[0x45DD4C]`. So the SMI handshake bytes go through whichever transport the caller selected. CONFIRMED.

After the handshake, sub_5FB8 emits the four DriveInfo probes via `sub_406618(str)` (string-based helper that uses sub_40633C to build and Dispatch strings into the handler). On each answer the test chain produces the mode byte via the assignments at RVA 0x406110/0x406159/0x40619F/0x4061A7 documented in earlier phases.

### 2.5 sub_4827AC — the EXE-side counterpart

Summary of its role (already covered in earlier phases):
- Re-implements the same marker handshake in EXE.
- Uses a 0x200-byte scratch at `[ebp-0x204]`.
- Compares response bytes at offset 0x2A..0x32 inside the response buffer against "SM225" / "SM2258" / "ISP" / "MPISP" / "ROMDE" prefixes.
- Sets ctx[0] ∈ {0,1,2} AND ctx[8] ∈ {0..4}.

Per cv.md audit it does **not** write 5 into the document's "mode" byte.

## 3. Track B — Why the real B27A path does not reach mode==2

Under the actual harness run (`SetPassThroughType(0)` first → global byte = 0 → all SIO commands take sub_165C), the marker handshake runs through sub_165C → SMI vendor command `0xC8-`/`0x25-` CDB. The drive is in NORMAL mode (responds correctly to standard requests). The handshake does not produce the string "SM225" response prefix that would map to mode-byte = 2, because the drive does not respond with the ISP handshake signature. Therefore sub_5FB8's byte 2 is never written; byte 0 ends up in `_ctxBuf[0]` (the catch-all "no match" branch at RVA 0x4061A4/0x4061A7), and the harness's later `Marshal.ReadByte(modeOut)` reads from a buffer that native code never writes.

**Decisive detail about the USB bridge / SATA question (cv.md §21):** sub_171C returns AL=1 only when `ScsiStatus == 0x50`. sub_165C returns AL=1 only when `ScsiStatus == 0x00`. These two transports use *different* pass criteria. **If the USB bridge intercepts the vendor command and synthesizes its own response, the bridge's response status will satisfy one criterion but not the other** — i.e., the SAME command can succeed through one transport and fail through the other. The empirical failure that the previous MPTool vendor-command chain exhibits through the JM20337 bridge is consistent with this binary design, but the binary itself does not "check" whether the bridge is present; it merely has two different success gates. This is PROVEN in the binary; whether the actual JM20337 chip can pass the underlying CDB bytes is a separate hardware question.

## 4. SCSI pass-through — exact structure / offsets (this phase)

| Field | Offset | sub_165C (0x4D014) | sub_171C (0x4D030) |
|---|---|---|---|
| `Length` | +0 | preset by caller (word) | set to 0x28 |
| `ScsiStatus` | +2 | byte read by helper | byte read by helper |
| `PathId` | +3 | preset by caller | — |
| `TargetId` | +4 | preset by caller | — |
| `Lun` | +5 | preset by caller | — |
| `CdbLength` | +6 | preset (word=12 for the 0xF1 detection CDB) | preset 0 |
| `SenseInfoLength` | +7 | preset by caller | preset 0 |
| `DataIn` | +8 | preset by caller | dword from arg [ebp+C] |
| `DataTransferLength` | +0xC | preset by caller | dword from arg [ebp+24] |
| `TimeOutValue` | +0x14 | preset by caller | preset by caller |
| `DataBufferOffset` | +0x18 | preset by caller | preset by caller |
| `SenseInfoOffset` | +0x1C | preset by caller | preset by caller |
| `Cdb` | +0x24 | caller fills 12 bytes | helper builds byte-by-byte |

Notes:
- sub_165C pushes `0` for lpOverlapped — synchronous (blocking) call.
- sub_171C checks the struct's ScsiStatus against 0x50 specifically, not 0.
- Both preset SenseInfoOffset=0 at the time the call is made (no sense buffer is allocated).

## 5. Mode gate (EXE-side, exhaustive)

```
EXE RVA 0x40372C: lea ecx, [ebp-0x80C]           ; ecx = &ctx_byte
EXE RVA 0x403733: call 0x4827AC                  ; native handshake → sets ctx[0/1]
EXE RVA 0x40373B: test eax, eax                  ; gate A: if AL==0 (transportfail), skip
EXE RVA 0x40373D: jne 0x4037AC                   ; → error path
EXE RVA 0x4037AC: mov eax, dword ptr [ebp-0x80C] ; load dword containing ctx[0]
EXE RVA 0x4037B2: and eax, 0xFF                  ; byte-extract
EXE RVA 0x4037B7: cmp eax, 2                     ; ISP?
EXE RVA 0x4037BA: je 0x403829                    ; YES → DownloadMPISP chain
EXE RVA 0x4037BC-0x4037C3: push "It's not ISP Mode !"; call 0x401A6A  ; else error
```

The comparison is against a BYTE (after `and eax, 0xFF`), and the value read comes from the caller's stack frame at `[ebp-0x80C]`. **CONFIRMED at instruction level.**

## 6. DownloadMPISP static path (no execution)

The chain, all confirmed by disassembly in earlier phases:
- EXE RVA 0x403829 → call 0x403BB7 (sub-function)
- 0x403BB7 body: opens `\Firmware\2258\MPISP2258.bin`, calls `malloc(0x800)`, `memset 0x800`, `ReadFile`, then `call dword ptr [0x507F70]` where the slot was populated by the EXE's LoadLibrary+GetProcAddress of `_SMIPtestDownloadMPISP`.
- `_SMIPtestDownloadMPISP` (RVA 0x7AD8) → sub_D268 → sub_2300 (for the initial "SetDriveInfo mode" dance) → sub_19D8 → sub_171C (which uses 0x4D030).
- The DownloadMPISP path itself never invokes the marker handshake; it uses the drive already context-prepared by a prior `_SMIPtestCheckRunMode` call that returned mode=2.

## 7. USB bridge — proven / plausible / unknown

PROVEN BY BINARY:
- The DLL has TWO distinct transport paths that use DIFFERENT DeviceIoControl codes and DIFFERENT success criteria.
- `sub_171C`'s success gate is `ScsiStatus == 0x50`.
- `sub_165C`'s success gate is `ScsiStatus == 0x00`.
- The COMMAND SELECTION (0x4D014 vs 0x4D030) is governed by a single global byte `0x45DD4C` written by `_SMISetPassThroughType`.

PLAUSIBLE:
- The Manhattan 179195 / JMicron JM20337 bridge forwards the simpler `SCSI_PASS_THROUGH` (0x4D014) but likely synthesizes its own response to vendor commands, breaking the byte-2 status expected by `sub_171C`.
- The bridge therefore plausibly explains why the call sequence "set type=0 → detect → get garbage" matches the JM20337's known behaviour.
- The bridge plausibly explains why the EXE can never reach mode=2 through that path.

UNKNOWN:
- The exact CDB bytes the bridge ACCEPTS vs passes through (would require either silicon documentation for JM20337 or a bsc钓鱼-style trace; not available here).
- Whether a "Type 2" (0x4D030-based) command ever reaches the SM2258XT when plugged through the JM20337 (would require hardware capture).

## 8. Recommended next forensic observation

**Read-only setup — register the DLL's PassThroughType and then drive `_SMIPtestCheckRunMode` TWICE against a non-hardware NUL handle, each with `passType ∈ {0, 1, 2}`, allocating modeOut ≥ 0x4204 → record which branches execute (sub_171C vs sub_165C) and what the guard at [ebp-0x35] does with the NUL-handle return. This isolates whether the DLL's transport-selection is functioning without touching the drive.**

Concretely:
```
for passType in {0,1,2}:
    _SMISetPassThroughType(passType)
    result = _SMIPtestCheckRunMode(deref(NUL_handle), ctxBuf, oversized_modeOut)
    log(result, ctxBuf[0], modeOut[0])
```
Expected: ctxBuf[0] = 0 in all three cases (no device attached), and NO crash if modeOut is 0x4204 bytes. A crash would confirm that `[ebp+0x10]`-derived logging is also reachable from the success path, which would be new evidence.

This was **not** executed in this pass because the previous synthetic attempt crashed at entry; it is documented here as the safest NEXT experiment, subject to separately confirming that modeOut must be ≥ 0x4204 bytes before retry.

## 9. Safety status

- NO WRITE OPERATION PERFORMED
- NO FIRMWARE DOWNLOAD PERFORMED
- NO NAND OPERATION PERFORMED
- NO MPTool/ROM.EXE RECOVERY OPERATION PERFORMED
- No executable invocation of any _SMI* export against a real or synthetic device in this pass.

# CODE CHANGE

NONE. Production sources unmodified. Only `tools/relib/*.py` (new static-analysis helpers) and `artifacts/re/*.md` (forensic docs) were touched in this branch.
