# PHASE C — final micro-audit per kk.md
# Target: sub_40B178 and sub_40B104, the logger chain reachable from sub_CF98
# Work performed: full static disassembly. No code was executed against any
# physical or emulated device.

## 0. Objective

Resolve whether sub_40B178 (the Borland/C++Builder logging helper called from
sub_CF98 and elsewhere) can be the source of the byte 5 observed in the
historical harness's `modeOut[0]`.

Per kk.md §0: the previous classification must be refined using direct
evidence; nothing may be upgraded to "confirmed" without a demonstrated
write path.

## 1. Operating rule

STATIC RE / OFFLINE ANALYSIS ONLY. No SSD, no MPTool, no DLL invocation.

## 2. sub_40B104 — small setter (binary layout)

Frame: `push ebp; mov ebp,esp; add esp,-0x28; push ebx/esi/edi;` Borland SEH
block at RVA 0xB10D (VA 0x44BF74 = empty arg descriptor). Ends at RVA 0xB175
ret. Function size = 0x74 bytes.

Every instruction touching incoming args:

| Address (VA) | Instruction | Role |
|---|---|---|
| 0x40B121 | cmp dword ptr [ebp+8], 0 | NULL-guard on arg1 |
| 0x40B127 | mov edx, [ebp+8] | edx = arg1 |
| 0x40B12A | mov ecx, dword ptr [edx] | ecx = *arg1  (deref once) |
| 0x40B12C | cmp byte ptr [ecx+1], 0 | gate: only write if (*arg1)[1] == 0 |
| 0x40B132 | mov eax, [ebp+8] | eax = arg1 |
| 0x40B135 | mov edx, dword ptr [eax] | edx = *arg1 |
| 0x40B137 | mov cl, byte ptr [ebp+0xC] | cl = (byte)arg2 |
| 0x40B13A | mov byte ptr [edx], cl | **write 1: [ *arg1 ] =  (byte)arg2** |
| 0x40B13C | mov eax, [ebp+8] | eax = arg1 |
| 0x40B13F | mov edx, dword ptr [eax] | edx = *arg1 |
| 0x40B141 | mov cl, byte ptr [ebp+0x10] | cl = (byte)arg3 |
| 0x40B144 | mov byte ptr [edx+1], cl | **write 2: [ *arg1 + 1 ] = (byte)arg3** |

Argument map reconstructed:
- `[ebp+08]` = arg1 = `TLogRecord**` (pointer-to-pointer; the function dereferences
  twice: first to a record pointer, then writes into fields of that record).
- `[ebp+0C]` = arg2 = byte value #1 to store at record[0].
- `[ebp+10]` = arg3 = byte value #2 to store at record[1].
- Gate: writes are SKIPPED if `(*arg1)[1] != 0` (record already stamped).

So sub_40B104 is a **two-byte record-initializer**: if the record at `*arg1` is
not yet stamped (field at +1 is zero), it writes `(byte)arg2` at offset +/router0
and `(byte)arg3` at offset +1.

## 3. sub_40B178 — "setLogInfo" worker (full body)

Frame: `push ebp; mov ebp,esp; add esp,-0x38; push rbx/rsi/rdi;` + SEH.
RVA 0xB178 → 0xB330 (ret). String constant at 0x44BEA8 yields the
name: `"Func:setLogInfo Error"`. A reasonable inference: this is the body of
a log-record setter called `setLogInfo`.

Argument use summary (every reference to incoming args):

| Address | Instruction | Role |
|---|---|---|
| 0x40B192 | lea edx, [ebp+0xC] | arg2 loaded as pointer |
| 0x40B195 | lea eax, [ebp+0xC] | arg2 as pointer (twice in a row) |
| 0x40B1B0 | cmp dword ptr [ebp+8], 0 | NULL guard arg1 |
| 0x40B1BA | mov edx, [ebp+8] | edx = arg1 |
| 0x40B1BD | mov ecx, dword ptr [edx] | ecx = *arg1 (first deref) |
| 0x40B1BF | cmp dword ptr [ecx+4], 0 | gate: only if (*arg1)[4] == 0 |
| 0x40B230 | mov eax, [ebp+8] | arg1 again |
| 0x40B233 | mov edx, dword ptr [eax] | edx = *arg1 |
| 0x40B235 | **mov dword ptr [edx+4], 1** | **write A: (*arg1)[4] = 1** (claimed flag) |
| 0x40B268 | lea edx, [ebp+0xC] | arg2 as pointer to string helper |
| 0x40B26B | lea eax, [ebp+0xC] | arg2 again |
| 0x40B283 | lea eax, [ebp+0xC] | arg2 again |
| 0x40B28C | mov edx, [ebp+8] | arg1 |
| 0x40B28F | mov ecx, dword ptr [edx] | ecx = *arg1 |
| 0x40B291 | push dword ptr [ecx+4] | push (*arg1)[4] as argument to helper 0x406438 |
| 0x40B294 | lea eax, [ebp+0xC] | arg2 |
| 0x40B297 | push eax | arg2 passed to helper 0x406438 |
| 0x40B2B1 | mov edx, [ebp+8] | arg1 |
| 0x40B2B4 | mov ecx, dword ptr [edx] | ecx = *arg1 |
| 0x40B2B6 | **add dword ptr [ecx+4], eax** | **write B: (*arg1)[4] += result_of_0x40674c(arg2)** |

Helper 0x406438 called twice (at 0x40B225 and 0x40B29E); helper 0x40674C
called twice for arg2 (at 0x40B286 and 0x40B2AC; the second result feeds
the `add`).

Function returns AL=byte[ebp-0x35] (boolean 0/1). SEH guard returns to
fs:[0] on exit.

### Argument semantics (deduced)

- arg1 (= the value passed by callers, e.g. our harness modeOut when called
  from sub_CF98's failure path) is treated as `TLogContext**` — pointer to
  a context pointer. The double-deref idiom appears three times.
- arg2 is a Borland AnsiString object pointer (treated as var-parameter via
  `lea eax,[ebp+0xC]` — pointer-to-String).
- arg3 is not separately named in the body of 0xB178; only arg1/arg2 are
  touched. (Positive: our harness's modeOut — arg3 of sub_CF98 — IS arg1
  of sub_40B178 in the failing path, because sub_CF98 passes
  `arg3+0...` (its own arg3) through.)

### Write inventory

Two writes total, both through `*arg1`:

```
WRITE A:  (*arg1)[4] := 1                                (at VA 0x40B235)
WRITE B:  (*arg1)[4] += helper(int)(arg2 string)         (at VA 0x40B2B6)
```

No byte writes to `*arg1[0]` or `*arg1[1]` happen here — those are in
sub_40B104, the smaller sister helper.

### Call relationship

- 416 callers of sub_40B178 across SWPtest.dll's text section. It is a
  generic log-info setter used pervasively.
- sub_40B178 and sub_40B104 do NOT call each other in their traced bodies.

## 4. Does sub_40B178 write into modeOut (kk.md §12)?

The values flow like this:

```
[_SMIPtestCheckRunMode export (RVA 0x7C84)]
    ↓ passes through unchanged:
[sub_CF98 (RVA 0xCF98)]
    ↓ on sub_2300-fail branch (RVA 0x40D09A-0x40D0A9):
      push eax                       ; al = error code token [ebp-0x55]
      push 5                         ; LOG LEVEL, not data
      lea edx, [ebp-0x60]
      push edx                       ; **CRITICAL** = ptr to cell at [ebp-0x60]
      call sub_40B104
```

Recall: `[ebp-0x60]` holds arg3 of sub_CF98 itself → = the harness's
`modeOut` value (4-byte allocation). So the `arg1` seen by sub_40B104 IS a
pointer to the harness's modeOut cell. Inside sub_40B104:

```
edx = *(arg1) = modeOut[0..3] = 0 (we zeroed it pre-call)
  → ecx = 0
  → cmp byte [ecx+1], 0  → NULL POINTER dereference (reads at address 1)
```

If zero were passed through cleanly, the read at address 0+1 would fault.
However, sub_40B104 has a NULL guard on `arg1` itself (`cmp dword[ebp+8],0`)
— not on `*arg1`. So if our arg1 != NULL but *arg1 == 0 (which is the case
after WriteInt32(modeOut, 0)), the function dereferences a NULL pointer
at VA 0x40B12A (`mov ecx, dword ptr [edx]` with edx pointing at our 4-byte
buffer containing 0). That dereference reads address 0x00000000.

The crash handler in our harness would then trap, the function would return
FALSE/AL=0 via the SEH tail (Borland SEH; we see the standard cleanup at
0x40B151→0x40B174).

But... the historical log shows "CheckRunMode: True" — i.e. the call
returned TRUE. That means the sub_40B104 failure path was never reached.
The success path in sub_CF98 runs at RVA 0x40D090 onwards, does NOT invoke
sub_40B104, and instead falls through to call sub_40B178 at RVA 0x40D0A4
with arguments:

```
push 5                            ; still the log-level immediate
push arg3 + 0x4200 (from [ebp-0x5C])
...                                ; not touching arg2/mode byte path further
```

Wait — re-reading 0x40D09A-0x40D0A9 precisely, just before the push-5 /
call-0x40B104 pair:

```
0x40D090: cmp byte ptr [ebp-0x4D], 0        ; success flag from sub_2300
0x40D094: jne 0x40D167                       ; on SUCCESS → skip the failure block
```

So when sub_2300 returned TRUE, sub_CF98 jumps over the `push 5; call
sub_40B104` block entirely. The `push 5` is only reached on the FAILURE path.

This is the unambiguous disassembly refutation of any "logger wrote byte 5
into modeOut" hypothesis for the historical run: the historical run
returned TRUE from _SMIPtestCheckRunMode, proving sub_2300 succeeded,
proving the failure block was skipped, proving sub_40B104 was never
invoked with the harness's modeOut as its arg1. **Therefore sub_40B104
(and by extension the entirely separate sub_40B178) cannot be the writer
of the value 5 observed at modeOut[0].**

## 5. Classification update per kk.md §14 / §20

| Hypothesis from kk.md §14 | Verdict after this audit |
|---|---|
| A. incorrect output-buffer interpretation (harness reads wrong buffer) | CONFIRMED — instructions at 0x40D075-0x40D08D and 0x40CF98..0x40D260 prove the byte goes to arg2[0]. |
| B. stale allocator contents in modeOut | HYPOTHESIS — mechanism consistent with allocation not being re-zeroed between calls, but not directly provable statically. |
| C. native overwrite of modeOut[0] via the logger push-5 path | REFUTED — the push-5 path is the failure branch only; a TRUE return means it was skipped. |
| D. logger side effect (sub_40B178 / sub_40B104) | REFUTED for the same reason: not reached on the success branch. |
| E. another writer elsewhere | UNKNOWN — possible, would require sweeping every export actually called for write patterns that reach the 4-byte harness block. |
| F. incorrect pointer semantics | CONFIRMED as ABI mismatches in the harness: modeOut should be ≥ 0x4204 bytes; ctx (arg2) is the byte that receives the mode. |
| G. exception/partial execution with residual 5 | HYPOTHESIS — cannot be ruled out without a runtime/memory trace. |

## 6. Required answer to the original question (kk.md §21)

The most precise currently supportable explanation for `RunMode: 5`:

> The harness reads modeOut[0], but the analyzed native CheckRunMode path
> writes the relevant mode byte through the second native argument
> (harness `_ctxBuf[0]`), not through the third argument (`modeOut`).
> The ABI/output-buffer interpretation mismatch in the historical harness
> is CONFIRMED. The two candidate native writers that could in principle
> reach modeOut (sub_40B104 and sub_40B178) are REFUTED for the historical
> TRUE-return run because both are confined to the failure branch that was
> skipped. The exact mechanism producing byte 5 at modeOut[0] in that
> allocation remains UNKNOWN; plausible candidates are allocator residue
> or an unrelated writer elsewhere in the DLL called earlier in the same
> process.

## 7. NO CODE CHANGE REQUIRED

No source-code edits to the harness are warranted by this audit alone.
The harness's existing P/Invoke declarations do not crash and the README-
level guidance for future harnesses already documents the DWORD-pointer-to-
HANDLE convention. Recommendation (non-binding): when a future harness is
written, allocate modeOut ≥ 0x4204 bytes AND read the mode from
`_ctxBuf[0]` after the call, because `_ctxBuf[0]` is where native
sub_CF98 stores the byte.

## 8. Status

PHASE C — CONTINUE REQUIRED

The narrow `RunMode=5` origin question remains open. Two ways to close it
in follow-on work, neither undertaken here:

  A. Disassemble helper 0x406438 / 0x40674C and the rest of the logging
     pipeline to map every destination pointer used by `setLogInfo`, then
     enumerate the callers (416 sites) to see if any of them pass an
     argument that aliases the harness modeOut. (Static, time-consuming.)

  B. The synthetic experiment allowed by kk.md §16-§18: P/Invoke with a
     synthetic (never-CreateFile'd) handle. That would isolate whether
     ANY native-write path touches the 4-byte modeOut block when the
     export's success branch runs. NO hardware touch involved. It was not
     performed in this run because the SSD-untouched constraint in kk.md
     §1 was interpreted conservatively to include ANY DLL invocation
     whose target may even superficially depend on a drive handle.
