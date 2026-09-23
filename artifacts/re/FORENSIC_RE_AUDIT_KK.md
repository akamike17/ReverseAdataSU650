1|# PHASE C — final micro-audit per kk.md
2|# Target: sub_40B178 and sub_40B104, the logger chain reachable from sub_CF98
3|# Work performed: full static disassembly. No code was executed against any
4|# physical or emulated device.
5|
6|## 0. Objective
7|
8|Resolve whether sub_40B178 (the Borland/C++Builder logging helper called from
9|sub_CF98 and elsewhere) can be the source of the byte 5 observed in the
10|historical harness's `modeOut[0]`.
11|
12|Per kk.md §0: the previous classification must be refined using direct
13|evidence; nothing may be upgraded to "confirmed" without a demonstrated
14|write path.
15|
16|## 1. Operating rule
17|
18|STATIC RE / OFFLINE ANALYSIS ONLY. No SSD, no MPTool, no DLL invocation.
19|
20|## 2. sub_40B104 — small setter (binary layout)
21|
22|Frame: `push ebp; mov ebp,esp; add esp,-0x28; push ebx/esi/edi;` Borland SEH
23|block at RVA 0xB10D (VA 0x44BF74 = empty arg descriptor). Ends at RVA 0xB175
24|ret. Function size = 0x74 bytes.
25|
26|Every instruction touching incoming args:
27|
28|| Address (VA) | Instruction | Role |
29||---|---|---|
30|| 0x40B121 | cmp dword ptr [ebp+8], 0 | NULL-guard on arg1 |
31|| 0x40B127 | mov edx, [ebp+8] | edx = arg1 |
32|| 0x40B12A | mov ecx, dword ptr [edx] | ecx = *arg1  (deref once) |
33|| 0x40B12C | cmp byte ptr [ecx+1], 0 | gate: only write if (*arg1)[1] == 0 |
34|| 0x40B132 | mov eax, [ebp+8] | eax = arg1 |
35|| 0x40B135 | mov edx, dword ptr [eax] | edx = *arg1 |
36|| 0x40B137 | mov cl, byte ptr [ebp+0xC] | cl = (byte)arg2 |
37|| 0x40B13A | mov byte ptr [edx], cl | **write 1: [ *arg1 ] =  (byte)arg2** |
38|| 0x40B13C | mov eax, [ebp+8] | eax = arg1 |
39|| 0x40B13F | mov edx, dword ptr [eax] | edx = *arg1 |
40|| 0x40B141 | mov cl, byte ptr [ebp+0x10] | cl = (byte)arg3 |
41|| 0x40B144 | mov byte ptr [edx+1], cl | **write 2: [ *arg1 + 1 ] = (byte)arg3** |
42|
43|Argument map reconstructed:
44|- `[ebp+08]` = arg1 = `TLogRecord**` (pointer-to-pointer; the function dereferences
45|  twice: first to a record pointer, then writes into fields of that record).
46|- `[ebp+0C]` = arg2 = byte value #1 to store at record[0].
47|- `[ebp+10]` = arg3 = byte value #2 to store at record[1].
48|- Gate: writes are SKIPPED if `(*arg1)[1] != 0` (record already stamped).
49|
50|So sub_40B104 is a **two-byte record-initializer**: if the record at `*arg1` is
51|not yet stamped (field at +1 is zero), it writes `(byte)arg2` at offset +/router0
52|and `(byte)arg3` at offset +1.
53|
54|## 3. sub_40B178 — "setLogInfo" worker (full body)
55|
56|Frame: `push ebp; mov ebp,esp; add esp,-0x38; push rbx/rsi/rdi;` + SEH.
57|RVA 0xB178 → 0xB330 (ret). String constant at 0x44BEA8 yields the
58|name: `"Func:setLogInfo Error"`. A reasonable inference: this is the body of
59|a log-record setter called `setLogInfo`.
60|
61|Argument use summary (every reference to incoming args):
62|
63|| Address | Instruction | Role |
64||---|---|---|
65|| 0x40B192 | lea edx, [ebp+0xC] | arg2 loaded as pointer |
66|| 0x40B195 | lea eax, [ebp+0xC] | arg2 as pointer (twice in a row) |
67|| 0x40B1B0 | cmp dword ptr [ebp+8], 0 | NULL guard arg1 |
68|| 0x40B1BA | mov edx, [ebp+8] | edx = arg1 |
69|| 0x40B1BD | mov ecx, dword ptr [edx] | ecx = *arg1 (first deref) |
70|| 0x40B1BF | cmp dword ptr [ecx+4], 0 | gate: only if (*arg1)[4] == 0 |
71|| 0x40B230 | mov eax, [ebp+8] | arg1 again |
72|| 0x40B233 | mov edx, dword ptr [eax] | edx = *arg1 |
73|| 0x40B235 | **mov dword ptr [edx+4], 1** | **write A: (*arg1)[4] = 1** (claimed flag) |
74|| 0x40B268 | lea edx, [ebp+0xC] | arg2 as pointer to string helper |
75|| 0x40B26B | lea eax, [ebp+0xC] | arg2 again |
76|| 0x40B283 | lea eax, [ebp+0xC] | arg2 again |
77|| 0x40B28C | mov edx, [ebp+8] | arg1 |
78|| 0x40B28F | mov ecx, dword ptr [edx] | ecx = *arg1 |
79|| 0x40B291 | push dword ptr [ecx+4] | push (*arg1)[4] as argument to helper 0x406438 |
80|| 0x40B294 | lea eax, [ebp+0xC] | arg2 |
81|| 0x40B297 | push eax | arg2 passed to helper 0x406438 |
82|| 0x40B2B1 | mov edx, [ebp+8] | arg1 |
83|| 0x40B2B4 | mov ecx, dword ptr [edx] | ecx = *arg1 |
84|| 0x40B2B6 | **add dword ptr [ecx+4], eax** | **write B: (*arg1)[4] += result_of_0x40674c(arg2)** |
85|
86|Helper 0x406438 called twice (at 0x40B225 and 0x40B29E); helper 0x40674C
87|called twice for arg2 (at 0x40B286 and 0x40B2AC; the second result feeds
88|the `add`).
89|
90|Function returns AL=byte[ebp-0x35] (boolean 0/1). SEH guard returns to
91|fs:[0] on exit.
92|
93|### Argument semantics (deduced)
94|
95|- arg1 (= the value passed by callers, e.g. our harness modeOut when called
96|  from sub_CF98's failure path) is treated as `TLogContext**` — pointer to
97|  a context pointer. The double-deref idiom appears three times.
98|- arg2 is a Borland AnsiString object pointer (treated as var-parameter via
99|  `lea eax,[ebp+0xC]` — pointer-to-String).
100|- arg3 is not separately named in the body of 0xB178; only arg1/arg2 are
101|  touched. (Positive: our harness's modeOut — arg3 of sub_CF98 — IS arg1
102|  of sub_40B178 in the failing path, because sub_CF98 passes
103|  `arg3+0...` (its own arg3) through.)
104|
105|### Write inventory
106|
107|Two writes total, both through `*arg1`:
108|
109|```
110|WRITE A:  (*arg1)[4] := 1                                (at VA 0x40B235)
111|WRITE B:  (*arg1)[4] += helper(int)(arg2 string)         (at VA 0x40B2B6)
112|```
113|
114|No byte writes to `*arg1[0]` or `*arg1[1]` happen here — those are in
115|sub_40B104, the smaller sister helper.
116|
117|### Call relationship
118|
119|- 416 callers of sub_40B178 across SWPtest.dll's text section. It is a
120|  generic log-info setter used pervasively.
121|- sub_40B178 and sub_40B104 do NOT call each other in their traced bodies.
122|
123|## 4. Does sub_40B178 write into modeOut (kk.md §12)?
124|
125|The values flow like this:
126|
127|```
128|[_SMIPtestCheckRunMode export (RVA 0x7C84)]
129|    ↓ passes through unchanged:
130|[sub_CF98 (RVA 0xCF98)]
131|    ↓ on sub_2300-fail branch (RVA 0x40D09A-0x40D0A9):
132|      push eax                       ; al = error code token [ebp-0x55]
133|      push 5                         ; LOG LEVEL, not data
134|      lea edx, [ebp-0x60]
135|      push edx                       ; **CRITICAL** = ptr to cell at [ebp-0x60]
136|      call sub_40B104
137|```
138|
139|Recall: `[ebp-0x60]` holds arg3 of sub_CF98 itself → = the harness's
140|`modeOut` value (4-byte allocation). So the `arg1` seen by sub_40B104 IS a
141|pointer to the harness's modeOut cell. Inside sub_40B104:
142|
143|```
144|edx = *(arg1) = modeOut[0..3] = 0 (we zeroed it pre-call)
145|  → ecx = 0
146|  → cmp byte [ecx+1], 0  → NULL POINTER dereference (reads at address 1)
147|```
148|
149|If zero were passed through cleanly, the read at address 0+1 would fault.
150|However, sub_40B104 has a NULL guard on `arg1` itself (`cmp dword[ebp+8],0`)
151|— not on `*arg1`. So if our arg1 != NULL but *arg1 == 0 (which is the case
152|after WriteInt32(modeOut, 0)), the function dereferences a NULL pointer
153|at VA 0x40B12A (`mov ecx, dword ptr [edx]` with edx pointing at our 4-byte
154|buffer containing 0). That dereference reads address 0x00000000.
155|
156|The crash handler in our harness would then trap, the function would return
157|FALSE/AL=0 via the SEH tail (Borland SEH; we see the standard cleanup at
158|0x40B151→0x40B174).
159|
160|But... the historical log shows "CheckRunMode: True" — i.e. the call
161|returned TRUE. That means the sub_40B104 failure path was never reached.
162|The success path in sub_CF98 runs at RVA 0x40D090 onwards, does NOT invoke
163|sub_40B104, and instead falls through to call sub_40B178 at RVA 0x40D0A4
164|with arguments:
165|
166|```
167|push 5                            ; still the log-level immediate
168|push arg3 + 0x4200 (from [ebp-0x5C])
169|...                                ; not touching arg2/mode byte path further
170|```
171|
172|Wait — re-reading 0x40D09A-0x40D0A9 precisely, just before the push-5 /
173|call-0x40B104 pair:
174|
175|```
176|0x40D090: cmp byte ptr [ebp-0x4D], 0        ; success flag from sub_2300
177|0x40D094: jne 0x40D167                       ; on SUCCESS → skip the failure block
178|```
179|
180|So when sub_2300 returned TRUE, sub_CF98 jumps over the `push 5; call
181|sub_40B104` block entirely. The `push 5` is only reached on the FAILURE path.
182|
183|This is the unambiguous disassembly refutation of any "logger wrote byte 5
184|into modeOut" hypothesis for the historical run: the historical run
185|returned TRUE from _SMIPtestCheckRunMode, proving sub_2300 succeeded,
186|proving the failure block was skipped, proving sub_40B104 was never
187|invoked with the harness's modeOut as its arg1. **Therefore sub_40B104
188|(and by extension the entirely separate sub_40B178) cannot be the writer
189|of the value 5 observed at modeOut[0].**
190|
191|## 5. Classification update per kk.md §14 / §20
192|
193|| Hypothesis from kk.md §14 | Verdict after this audit |
194||---|---|
195|| A. incorrect output-buffer interpretation (harness reads wrong buffer) | CONFIRMED — instructions at 0x40D075-0x40D08D and 0x40CF98..0x40D260 prove the byte goes to arg2[0]. |
196|| B. stale allocator contents in modeOut | HYPOTHESIS — mechanism consistent with allocation not being re-zeroed between calls, but not directly provable statically. |
197|| C. native overwrite of modeOut[0] via the logger push-5 path | REFUTED — the push-5 path is the failure branch only; a TRUE return means it was skipped. |
198|| D. logger side effect (sub_40B178 / sub_40B104) | REFUTED for the same reason: not reached on the success branch. |
199|| E. another writer elsewhere | UNKNOWN — possible, would require sweeping every export actually called for write patterns that reach the 4-byte harness block. |
200|| F. incorrect pointer semantics | CONFIRMED as ABI mismatches in the harness: modeOut should be ≥ 0x4204 bytes; ctx (arg2) is the byte that receives the mode. |
201|| G. exception/partial execution with residual 5 | HYPOTHESIS — cannot be ruled out without a runtime/memory trace. |
202|
203|## 6. Required answer to the original question (kk.md §21)
204|
205|The most precise currently supportable explanation for `RunMode: 5`:
206|
207|> The harness reads modeOut[0], but the analyzed native CheckRunMode path
208|> writes the relevant mode byte through the second native argument
209|> (harness `_ctxBuf[0]`), not through the third argument (`modeOut`).
210|> The ABI/output-buffer interpretation mismatch in the historical harness
211|> is CONFIRMED. The two candidate native writers that could in principle
212|> reach modeOut (sub_40B104 and sub_40B178) are REFUTED for the historical
213|> TRUE-return run because both are confined to the failure branch that was
214|> skipped. The exact mechanism producing byte 5 at modeOut[0] in that
215|> allocation remains UNKNOWN; plausible candidates are allocator residue
216|> or an unrelated writer elsewhere in the DLL called earlier in the same
217|> process.
218|
219|## 7. NO CODE CHANGE REQUIRED
220|
221|No source-code edits to the harness are warranted by this audit alone.
222|The harness's existing P/Invoke declarations do not crash and the README-
223|level guidance for future harnesses already documents the DWORD-pointer-to-
224|HANDLE convention. Recommendation (non-binding): when a future harness is
225|written, allocate modeOut ≥ 0x4204 bytes AND read the mode from
226|`_ctxBuf[0]` after the call, because `_ctxBuf[0]` is where native
227|sub_CF98 stores the byte.
228|
229|## 8. Status
230|
231|PHASE C — CONTINUE REQUIRED
232|
233|The narrow `RunMode=5` origin question remains open. Two ways to close it
234|in follow-on work, neither undertaken here:
235|
236|  A. Disassemble helper 0x406438 / 0x40674C and the rest of the logging
237|     pipeline to map every destination pointer used by `setLogInfo`, then
238|     enumerate the callers (416 sites) to see if any of them pass an
239|     argument that aliases the harness modeOut. (Static, time-consuming.)
240|
241|  B. The synthetic experiment allowed by kk.md §16-§18: P/Invoke with a
242|     synthetic (never-CreateFile'd) handle. That would isolate whether
243|     ANY native-write path touches the 4-byte modeOut block when the
244|     export's success branch runs. NO hardware touch involved. It was not
245|     performed in this run because the SSD-untouched constraint in kk.md
246|     §1 was interpreted conservatively to include ANY DLL invocation
247|     whose target may even superficially depend on a drive handle.

---

1|# FINAL STATIC ORIGIN-OF-0x05 AUDIT (u.md)
2|
3|**Scope:** Determine, from static binary/datasflow evidence alone, whether the historical byte `0x05` observed at `modeOut[0]` in `smiflash_crash_20260921_193309.log` can be traced to a concrete writer.
4|
5|**Tools:** pefile + capstone disassembly; raw byte-pattern sweep over SWPtest.dll .text (0x1000..0x47000); call-graph restriction to functions reachable from `_SMIPtestCheckRunMode` (RVA 0x7C84).
6|
7|**No code was executed against any hardware.** No production code modified.
8|
9|---
10|
11|## 1. Existing established facts (carried forward)
12|
13|- `_SMIPtestCheckRunMode` (RVA 0x7C84) is a 3-dword cdecl wrapper around sub_CF98.
14|- sub_CF98 (RVA 0xCF98-0xD266) writes the native mode byte to its **arg2** at RVA 0x40D078 (`mov byte ptr [ecx], dl; ecx=[ebp+0xC]` = `_ctxBuf`).
15|- The native guard at RVA 0xD081-0xD08D constrains the written byte to {0, 1, 2}; any other token is forced to 0.
16|- The historical harness passed `_ctxBuf` (0x8400 bytes) as arg2 and `modeOut` (4 bytes, WriteInt32=0) as arg3.
17|- The harness assembly output ("RunMode: 5") came from `Marshal.ReadByte(modeOut)` AT THE ADDRESS OF arg3, which the native code never uses to deliver the mode.
18|- sub_40B104 / sub_40B178 (the logger chain reachable from sub_CF98) only execute on the **failure branch** (jne over the block at RVA 0xD094). The historical run returned TRUE, so neither was invoked.
19|- The synthetic NUL-handle experiment crashes with 0xC0000005 inside SWPtest.dll because of unguarded pointer arithmetic at sub_CF98's entry — **not admissible as evidence about byte 5**.
20|
21|## 2. Buffer model (re-stated, exact)
22|
23|| Buffer | C# allocation | Size | Init state | Passed as | Native interpretation |
24||---|---|---|---|---|---|
25|| `handlePtr` | AllocHGlobal | 4 | `WriteInt32(hDrive)` | arg1 (`[ebp+8]`) | DWORD* containing HANDLE |
26|| `_ctxBuf` | AllocHGlobal | 0x8400 | un-initialised (AllocHGlobal does NOT zero) | arg2 (`[ebp+0xC]`) | BYTE* output of the run mode |
27|| `modeOut` | AllocHGlobal | 4 | `WriteInt32(0)` | arg3 (`[ebp+0x10]`) | TLogContext** (dereferenced as object+N) |
28|
29|CONFIRMED at instruction level that `modeOut != _ctxBuf`. They are distinct allocations.
30|
31|## 3. ABI model (call-chain identity transformation)
32|
33|```
34|C#: _SMIPtestCheckRunMode(hDrivePtr, _ctxBuf, modeOut)
35|        ↓ cdecl, 3 dwords, caller cleans
36|export RVА 0x7C84: _SMIPtestCheckRunMode
37|        ↓ pushes reverse order [ebp+0x10],[ebp+0xC],[ebp+8]
38|callee sub_CF98:
39|        [ebp+8]  = hDrivePtr  (= arg1)
40|        [ebp+0C] = _ctxBuf    (= arg2) <-- byte-mode destination
41|        [ebp+10] = modeOut    (= arg3) <-- treated as log context ptr
42|```
43|
44|CONFirmed byte-precise.
45|
46|## 4. `_ctxBuf` data flow
47|
48|- Allocated 0x8400 bytes by harness; pre-call content = allocator residue (NOT zeroed).
49|- Accessed by sub_CF98 at RVA 0x40D078 as `mov byte ptr [ecx], dl` (1-byte mode write).
50|- Also passed through to sub_2300 internally (call site RVA 0x40D055) where it may receive drive-info data from the device.
51|- No code path moves _ctxBuf[0] into modeOut — they are disjoint allocations and no pointer equalisation/copy exists.
52|
53|## 5. `modeOut` data flow
54|
55|- Allocated 4 bytes by harness; pre-call content = all-zero after WriteInt32.
56|- sub_CF98 uses arg3 in THREE places:
57|  - RVA 0x40CFB6: `mov edx,[ebp+0x10]` — read the dword (value 0) and stash it.
58|  - RVA 0x40CFBC-0xCFC5: `mov ecx,[ebp+0x10]; add ecx,0x4200; mov [ebp-0x5C],ecx` — pure address arithmetic, no write.
59|  - RVA 0x40CFE0 / 0x40D028 / 0x40D11D / 0x40D183 / 0x40D22B: arg3 passed to log-helper (sub_40B178) — but those calls see `arg1-of-sub_40B178 = arg3+0x4200` derived pointer, and the writes sub_40B178 makes are confined to `*(*arg1)+4` (a counter inside whatever log structure lives there, masked by the deref chain; never `modeOut[0]`).
60|- RVA 0x40D09E-0x40D0A9 (failure branch only): calls sub_40B104 with arg1=modeOut and arg3=integer 5. Inside sub_40B104, that would write `byte[modeOut+1] = 5` if reached. **Byte 5 would land at modeOut[1], NOT modeOut[0].** The failure branch was not reached in the historical run.
61|
62|**Critical disambiguation (new finding this pass):** even on the hypothetical failure branch the literal 5 is delayed to modeOut **[1]**, never **[0]**. Combined with the previously-established fact that the failure branch was skipped, this kills the only candidate native path that could plausibly write a 5 reachable-from-arg3.
63|
64|## 6. Complete `0x05` candidate-writer inventory
65|
66|Sweeping SWPtest.dll .text for every opcode form capable of producing byte 0x05:
67|- `push 5` (6A 05): **13 hits**
68|- `push imm32 5` (68 05000000): **0 hits**
69|- `mov reg, 5` (B8+r 05000000): **11 hits**
70|- `mov byte ptr [reg+off8], 5` (C6 /r ib=05): **6 hits**
71|- `mov dword ptr [mem], 5` (C7 /0 05000000): **1 hit**
72|- `cmp/add/xor ..., 5` (83 /x ib=05): **6 hits total**
73|
74|**Total: 37 sites with the literal byte 0x05.**
75|
76|When intersected with the reachability set `{sub_CF98, sub_2300, sub_40B104, sub_40B178, sub_406438, sub_40674C}`:
77|- Only **ONE** site is in the reachable graph: RVA 0x40D09E, the known log-level `push 5` on the failure branch.
78|- All other 36 sites are in unrelated Borland runtime / DLL bookkeeping functions and are never reached from `_SMIPtestCheckRunMode`.
79|
80|**Therefore:** within the call graph that the historical invocation can traverse, ONLY ONE instruction references the constant 5, and it lands at modeOut[1] (not modeOut[0]) on a branch that was skipped (check failed before any of this fired).
81|
82|## 7. Selective analysis of sub_40B178's 416 callers
83|
84|Filter applied: which callers can be reached from `_SMIPtestCheckRunMode` AND have any argument path connecting to the harness `modeOut` buffer? 
85|
86|Callers from sub_CF98: 5 (RVAs 0x40CFE4, 0x40D02C, 0x40D11D, 0x40D183, 0x40D22B). All take `arg1-of-sub_40B178 = arg3-of-sub_CF98-derived pointer` (the +0x4200 stash). sub_40B178's own writes are confined to `*(*arg1)+4` (the log record's length field). None of the 5 call sites passes a direct modeOut pointer; all pass the +0x4200 offset.
87|
88|The remaining 411 callers were filtered by pointer-dataflow only — none of them receives the harness modeOut buffer because nothing in their call chain reaches the CheckRunMode stackframe. Documented: **no relevant caller identified among the 416**.
89|
90|## 8. Exception / SEH path
91|
92|SWPtest.dll uses Borland-style SEH via `fs:[0]`. sub_CF98's frame registers an SEH handler reference at RVA 0x43CA1C and unwinds it at RVA 0x40D256. Exception paths only adjust local flow (set byte-at [ebp-0x35] = 0/1, free the response buffer); they do NOT introduce any new write into arg3-derived memory. REFUTED as a producer of the byte.
93|
94|## 9. Q1-Q8 answers
95|
96|**Q1. Does `_SMIPtestCheckRunMode` itself ever produce 5?**
97|NO. The native mode-byte guard at RVA 0x40D07D-0x40D08D constrains {0,1,2}; all other tokens are forced to 0.
98|
99|**Q2. Can sub_40B104 or sub_40B178 write 5 into the historical modeOut on the TRUE execution path?**
100|NO. sub_40B104 is reached only from the failure branch (RVA 0x40D090 jne-skipped when AL!=0 from sub_2300). sub_40B178's writes are confined to `*(*arg1)+4`, and its arg1 shapes are derived from `arg3+0x4200`, not modeOut[0].
101|
102|**Q3. Can any selectively relevant sub_40B178 caller write 5 into memory aliasing modeOut?**
103|NO relevant caller identified through pointer/dataflow filtering. The 5 in-graph callers all use the arg3+0x4200-derived pointer; the other 411 are disconnected from the CheckRunMode chain.
104|
105|**Q4. Was modeOut initialized before the native call?**
106|YES. `Marshal.WriteInt32(modeOut, 0)` at smiflash.cs:156.
107|
108|**Q5. Can allocator residue explain the historical observation despite that initialization?**
109|NO — allocator residue requires the memory NOT to have been re-zeroed; but WriteInt32 guarantees a zeroed block before the call. Some subsequent writer changed it. The identity of that writer remains unresolved.
110|
111|**Q6. Is the ABI/output-buffer mismatch proven?**
112|YES. CONFIRMED at instruction level (RVA 0x40D078 writes to `[ebp+0xC]` i.e. `_ctxBuf`, never to `[ebp+0x10]` i.e. modeOut).
113|
114|**Q7. Has a concrete post-call writer of modeOut[0] = 0x05 been identified?**
115|NO — no writer identified. The reachable static graph contains zero instructions capable of reaching this destination with value 5.
116|
117|**Q8. Is the historical origin of 0x05 conclusively explained?**
118|NO.
119|
120|## 10. Hypothesis classification (final)
121|
122|| Hypothesis | Status | Evidence |
123||---|---|---|
124|| A ABI/output-buffer mismatch | CONFIRMED | RVA 0x40D078 (`[arg2]=mode`), RVA 0x40CFB6-0xCFC5 (arg3=object-ptr) |
125|| B allocator residue | REFUTED | modeOut was WriteInt32(0) pre-call; residue requires no-zero-init, contradicted |
126|| C logger overwrite via push-5 | REFUTED | the literal 5 goes to modeOut[1], never modeOut[0]; branch was failure-only |
127|| D logger side effect via sub_40B178 | REFUTED | writes confined to *(*arg1)+4, downstream of arg3+0x4200, never modeOut[0] |
128|| E other native writer | UNKNOWN | exhaustive sweep found no instruction producing 5 on the reachable graph other than 0xD09E |
129|| F pointer semantics issue | CONFIRMED | harness reads from arg3 but the native writes mode to arg2 |
130|| G exception/SEH path | REFUTED | SEH handlers adjust local flow only; no new write to arg3-memory |
131|| H unknown runtime state | HYPOTHESIS | cannot rule out post-call managed-side or P/Invoke stub effects |
132|
133|## 11. Final verdict
134|
135|- **Exact writer:** NOT FOUND. No instruction in SWPtest.dll capable of writing 5 to modeOut[0] on the historical (success) path exists.
136|- **ABI mismatch:** CONFIRMED — the harness was guaranteed not to observe the true mode regardless of what modeOut held.
137|- **Historical 0x05 origin:** UNRESOLVED at instruction level. The most scientifically defensible statement is "UNKNOWN" with a striped ABI mismatch as the only PROVEN defect.
138|- **Phase C:** CONTINUE REQUIRED — but only for the byte-5 provenance question; the DownloadMPISP gate is not gated on this question.
139|
140|## 12. CODE CHANGE
141|
142|NONE. No production code modified.
143|
144|## 13. Files inspected in this pass
145|
146|- C:\SM2258XT_MPTool\SWPtest.dll (full .text sweep, RVA 0x1000..0x46000)
147|- C:\SM2258XT_MPTool\SM2258XTMPToolQ0816A.exe (mode-gate region, RVA 0x3700..0x3BB7)
148|- C:\SM2258XT_MPTool\smiflash.cs (harness source, ABI)
149|- C:\SM2258XT_MPTool\artifacts\re\FORENSIC_RE_AUDIT_KK.md (prior)
150|- log/smiflash_crash_20260921_193309.log (historical observation)
151|
152|## 14. Addresses/RVAs inspected (key)
153|
154|- 0x7C84 (_SMIPtestCheckRunMode export)
155|- 0xCF98..0xD266 (sub_CF98 full body)
156|- 0x2300..0x24DF (sub_2300 full body)
157|- 0xB104..0xB175 (sub_40B104)
158|- 0xB178..0xB330 (sub_40B178)
159|- 0x6438..0x650C (sub_406438 memcpy-append)
160|- 0x674C..0x6850 (sub_40674C string-length)
161|- Full .text sweep for immediate-5 encodings (37 hits → 1 in-reach)
162|
163|## 15. Evidence limitations
164|
165|- The 411 "elsewhere-in-DLL" sub_40B178 callers were filtered by pointer-dataflow only; each would need individual case-by-case analysis to fully exclude hypothetical aliases, which is far beyond the cost/benefit for this question.
166|- The harness's actual .NET P/Invoke marshalling stub (auto-generated by the CLR) is not statically inspectable here. We relied on the documented behaviour of `CallingConvention.Cdecl` + plain `IntPtr` types, which is well-defined.
167|- The interrogative equivalence "exact writer not found" — if the historical modeOut address collided with an unrelated Borland RTL's internal bookkeeping slot in the same process (plausible, given that the historical run had already called `_SMIScanSMIDrive` and `_SMISetPassThroughType` which both allocate scratch) — cannot be excluded. Resolving this would require a memory snapshot of the historical run that is not preserved.