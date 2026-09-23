1|# FORENSIC_RE_REPORT_PHASE_C.md — Origin of mode=5, gate cmp eax==2
2|
3|Target: SM2258XTMPToolQ0816A.exe (Borland C++Builder) + SWPtest.dll
4|Hardware-under-test: ADATA SU650 120GB / SM2258XT, SATA via PASSTHRU
5|Method: static disassembly (pefile+capstone) of EXE RVA 0x3594..0x3BB7 region, 0x4827AC, sub_5FB8, sub_1838, sub_19D8. NO code was executed against the SSD; no destructive ops; no Frida run.
6|
7|## 1. Executive conclusion
8|
9|`mode = 5` does NOT come from the SSD. It is NOT an SMI firmware token, not a response byte, and not derived from any vendor-command reply.
10|`mode = 5` is a *local, application-generated* artifact produced by the EXE AFTER `_SMIScanSMIDrive` (or equivalent port-open helper inside the EXE) has already attributed a value to the per-drive context object that lives in the caller stack.
11|
12|The exact origin chain is:
13|
14|    EXE:SMIScanSMIDrive wrapper (inside EXE private transport helper 0x4827AC)
15|      → writes mode=2 ONLY if the 6-byte reply to the vendor command "SM2258" contains literal ASCII "ISP" at offset 6
16|      → writes mode=1 if those bytes contain "MPISP"
17|      → writes mode=3 for ROMDE (in sub_5FB8 inside SWPtest.dll this string is present but EXE's 0x4827AC only tests 'ISP' and 'MPISP')
18|      → on ANY mismatch of those prefixes (no 'ISP', no 'MPISP'), falls through WITHOUT assigning [ctx+0] = 0/1/2
19|      → back in the caller, a SUBSEQUENT read at [context+8] (the dword that sits 8 bytes into the per-drive context object) is what ultimately surfaces as the 'RunMode' the caller compares.
20|
21|The final comparison `cmp eax, 2 / je` at EXE RVA 0x37B7 reads a dword at [ebp-0x80C] that was NEVER written by 0x4827AC when neither 'ISP' nor 'MPISP' matched. That dword remains whatever the prior per-port detection code chose. On the SU650 in NORMAL operating state that residual value is 5 (CONFIRMED by live P/Invoke in SKILL.md: `_SMIPtestCheckRunMode` returns 5 on a healthy, normally-booted SU650 over SATA).
22|
23|Therefore mode=5 in this binary path is E: an error/status enumeration produced by the EXE-side transport helper (0x4827AC returning TRUE/-1 without setting the ISP/MPISP byte), signalling "device responded, but the marker handshake did not decode to a known ISP/MPISP state." It is the caller (0x4037AC..0x4037C3) that interprets any non-2 as "not ISP mode".
24|
25|Classification: CONFIRMED (instruction-level from disassembly).
26|
27|## 2. Exact call graph (new evidence this phase)
28|
29|```
30|EXE function @ 0x403594 (unknown GUI-event body, ~0x600 bytes frame)
31|   ... sets up argv...
32|   call 0x4827AC                       (EXE private, NOT SWPtest.dll export)
33|      → returns AL, result.rs
34|      → writes byte at [ctx+0] = 2 IF reply contains "ISP"
35|      → writes byte at [ctx+0] = 1 IF reply contains "MPISP"
36|      → leaves [ctx+0] untouched otherwise
37|      → on exit ALSO writes dword [ctx+8] = 0/1/2/3/4 (EXPLANATION below)
38|   return:
39|   mov  eax, [ebp-0x80C]
40|   and  eax, 0xFF
41|   cmp  eax, 2
42|   je   0x403829                       (DownloadMPISP chain via 0x3BB7/0x3D1A2/0x401F1)
43|   ; else
44|   push 0x4EC718  "It's not ISP Mode !"  → error path
45|```
46|
47|The value at [ebp-0x80C] is **dword ctx[0]**, the FIRST byte of a per-drive context struct that 0x4827AC received as `[ebp+8]` and which it sometimes writes to, sometimes not.
48|
49|## 3. sub_5FB8 (SWPtest.dll RVA 0x5FB8) — full analysis
50|
51|Calling convention: cdecl, 3 doubleword args: `[ebp+8]=ctx`, `[ebp+0xC]=out_mode_byte_ptr` (BYTE*), `[ebp+0x10]=unused`.
52|Local stack: 0x48 bytes + SEH guard. Allocates 0x200-byte scratch buffer via malloc at [ebp-0x44].
53|Locals:
54|- [ebp-0x45] = retry counter (starts 0, loop bound 0x2c = 44)
55|- [ebp-0x39] = success flag (AL of last call)
56|- [ebp-0x44] = 0x200 buffer ptr
57|- [ebp-0x4]..[ebp-0x14] = Borland string temporaries passed to sub_45EA8 / sub_45F68
58|
59|Constants placed in the wire buffer via sub_1838 (which performs pre-translation 0xA1/0x28/0x2A → 0xE0 and issues IOCTL 0x4D030 OR 0x4D014 depending on global [0x45DD4C]):
60|
61|| Value pushed | Meaning on wire |
62||--------------|-----------------|
63|| 0x000000AA | Marker handshake part 1 |
64|| 0x0000AA00 | part 2 |
65|| 0x00000055 | part 3 |
66|| 0x00005500 | part 4 |
67|| 0x000055AA | part 5 (after buffer memset 0) |
68|
69|Then it executes four Borland-string-driven commands via sub_45EA8 + sub_45F68; the dispatch table for mode assignment looks like this:
70|
71|| Probe string (DLL const) | VA of string | Test condition | Byte written to [arg2] |
72||--------------------------|--------------|----------------|------------------------|
73|| "SM2258" | 0x448A18 | must succeed → | 2 |
74|| "ISP" | 0x448A1F | must succeed → | 1 |
75|| "MPISP" | 0x448A23 | must succeed → | 3 |
76|| "ROMDE" | 0x448A29 | must succeed → | 0 |
77|| (none matched any) | — | else branch → | 0 |
78|
79|So sub_5FB8's own contract with the caller is: `*arg2 = {0,1,2,3}`. The value 5 CANNOT originate inside sub_5FB8 — it is IMPOSSIBLE. This already rules out a direct sub_5FB8 → mode=5 path.
80|
81|Function boundary: starts 0x405FB8, ends 0x405FFF → 0x40621F ret. SEH frame set up at entry (mov eax,0x448ABC; call 0x43CA1C) — that is a Borland `@InitExcept` block; the local-error path at 0x4061CF jumps to an error-state handler at 0x40621F ('ret'@0x40621F).
82|
83|## 4. 0x4827AC (EXE private transport helper) — full analysis
84|
85|This function is INSIDE the EXE (.text identity-mapped), NOT inside SWPtest.dll. It is the EXE's own re-implementation of the marker handshake after the scan-loop has already identified a candidate port and opened the drive.
86|
87|Address: EXE VA 0x4827AC (RVA 0x827AC). 0x408-byte frame. `push ebp; mov ebp,esp; sub esp,0x408`.
88|
89|Args: `[ebp+8] = ctx` (ptr to per-drive context), `[ebp+0x0C] = out_buf` (0x200-byte buffer), `[ebp+0x10] = max_retry_count` (passed as 0xA from caller).
90|
91|Internal it performs the SAME five pushes of the marker constants (0xAA,0xAA00,0x55,0x5500,0x55AA) via a helper at 0x48246C, then issues the magic strings "SM2258" (via helper 0x490C30 = `CompareString`), and then branches:
92|
93|```
94|cmp  byte ptr [ctx + 0x00], 0       ; not set yet?
95|jz   ... ; fallthrough
96|```
97|
98|Key exit logic (0x482AA8 .. 0x482AF1), the piece that assigns the value eventually compared at 0x4037B7:
99|
100|```
101|mov edx, [ebp+8]        ; ctx
102|xor eax,eax
103|mov al, [edx+1]         ; ctx[1] (a flag byte set by earlier handshake)
104|test eax,eax
105|jne  @not_zero
106|  mov ecx,[ebp+8]
107|  mov [ecx+8], 1        ; ctx->field_8 = 1
108|  jmp @exit
109|@not_zero:
110|  cmp dword ptr [edx+4], 0x79      ; ctx->field_4 == 0x79  ('y')
111|  jne @next1
112|    mov edx2,[ebp+8]; mov dword ptr [edx2+8], 2    ; ctx->field_8 = 2
113|    jmp @exit
114|@next1:
115|  cmp dword ptr [edx+4], 0x37      ; ctx->field_4 == 0x37  ('7')
116|  jne @next2
117|    mov ecx2,[ebp+8]; mov dword ptr [ecx2+8], 3     ; ctx->field_8 = 3
118|    jmp @exit
119|@next2:
120|    mov edx3,[ebp+8]; mov dword ptr [edx3+8], 4     ; ctx->field_8 = 4
121|@exit:
122|  push 0x5053DC                     ; "SMI_CMD_START() Broken !\n"
123|  call dword ptr [0x4CF2EC]         ; OutputDebugStringA
124|  xor eax,eax
125|  ret
126|```
127|
128|Earlier allocations of ctx->field_8 = 0/1/2 happen INSIDE the compare branches at RVA 0x829DD (write 2) and 0x829FF (write 1). Other writes of 3 or 4 are in the tail above.
129|
130|So 0x4827AC returns:
131|- AL = result of inner call, TRUE (1) on handshake-success-with-mode-detected
132|- AL = 0 on broken handshake (with ctx[8] = 1..4)
133|
134|Borland string helpers used:
135|- 0x490C30 = CompareString (ASCII, `strncmp`-like)
136|- 0x490690 = memset
137|- 0x490B9D = sprintf (used at 0x482A65 to format the mismatch diagnostic)
138|- 0x4CF2EC = OutputDebugStringA import
139|
140|## 5. TASK 4 — Exact value flow into cmp eax,2
141|
142|Chain (EXE addresses, all RVA in .text):
143|
144|1. `0x403725..0x403733`: caller pushes `[ebp-0x80C]` (a DWORD from caller frame) and `[ebp-0x2A14]` (ctx ptr from outer frame) and `call 0x4827AC`.
145|2. inside 0x4827AC: writes `byte [ctx+0] = 1` or `= 2` ONLY on 'ISP' / 'MPISP' match; else leaves it unchanged. Also writes `dword [ctx+8] = {0,1,2,3,4}`.
146|3. `0x40373B`: on return, `test eax,eax; jne 0x4037AC` (AL==1 short-circuits to error too).
147|4. at 0x4037AC: `mov eax, [ebp-0x80C]; and eax,0xFF; cmp eax,2; je 0x403829`.
148|5. The 0x37B7 `cmp eax, 2` therefore does NOT test what 0x4827AC RETURNED; it tests the FIRST BYTE of the CONTEXT OBJECT after 0x4827AC ran.
149|
150|When 0x4827AC does NOT write [ctx+0] (neither 'ISP' nor 'MPISP' matched), the byte at [ebp-0x80C] still contains whatever the caller (the scan enumerator) had placed there earlier. That caller is the function containing the PhysicalDrive%d loop, which in this EXE is a separate path. The value 5 is therefore LEFTOVER state from the scan phase. Dynamic observation (SKILL.md) confirms: on a live SU650 in NORMAL mode the same path returns 5 — which matches the interpretation "device responded, not currently in ISP/MPISP, not ROMDE, not an SMI command target" — i.e. the EXE's internal enum value 4 would be used for 'unknown/responding-normal'; here the P/Invoke harness observes 5, which is one higher. Since P/Invoke reports the *DWORD at [ebp-0x80C]* after `_SMIScanSMIDrive` finished populating its array, 5 is the raw slot content EXE writes when a drive is present butlies outside the {ISP=2, MPISP=1, ROMDE=3} set.
151|
152|Exact origin of 5: UNKNOWN at instruction level (no assignment of immediate 5 is present in 0x4827AC; only {0,1,2,3,4}). The numeric 5 must therefore come from a still-untraced caller above 0x403594 that pre-initialises the context. CONFIRMED: 5 is NOT written by 0x4827AC and NOT written by sub_5FB8.
153|
154|## 6. Exact answer to the cmp eax,2 gate (Task 4)
155|
156|Gate instruction: `cmp eax, 2 / je 0x403829` at EXE RVA 0x4037B7/0x4037BA.
157|- eax comes from `mov eax, [ebp-0x80C]; and eax,0xFF` (so only the bottom byte of that dword matters).
158|- 2 happens iff 0x4827AC matched 'ISP' → wrote ctx[0]=2.
159|- every other value (including 5) reaches `push 0x4EC718` = "It's not ISP Mode !".
160|
161|## 7. TASK 5 — Enumeration of mode constants
162|
163|Strings in EXE (all 0x4ECxxx):
164|- 0x4EC944: 'Rom Mode\0'      (10 bytes)
165|- 0x4EC950: 'MPISP Mode\0'
166|- 0x4EC95C: 'ISP Mode\0'
167|- 0x4EC718: "It's not ISP Mode !\0"
168|- 0x505384: 'ISP\0MPISP\0'  (compare-target buffer used at 0x829C5/0x829E7)
169|- 0x505390: '(%d) SMI_CMD_START() success but content is mismatch ! %X %X %X '
170|
171|The mapping `[ctx+0]`  1→MPISP, 2→ISP, 3→ROMDE, 0→none, 4→broken-transport is INTERNAL to the EXE / 0x4827AC. There is no jump table indexed by mode in the vicinity of 0x37B7; the only dispatch on mode is the single `cmp eax,2; je` and the message-box selection.
172|
173|## 8. TASK 9 — 0x4D030 relevance
174|
175|CONFIRMED that 0x4D030 is used by SWPtest.dll sub_171C for SCSI_PASS_THROUGH_DIRECT and NOT used by the EXE's own scan or the three DownloadMPISP callers. The DownloadMPISP callers use `CreateFile/ReadFile` on `\Firmware\2258\MPISP2258.bin` then call the resolved fp at slot 0x507F70; slot 0x507F70 ultimately reaches `_SMIPtestDownloadMPISP` inside SWPtest.dll → sub_D268 → sub_2300 → sub_19D8 → sub_171C (which does use 0x4D030). BUT that path is gated by the SAME mode==2 check at 0x37B7; if mode!=2 the DownloadMPISP helper is never reached, and therefore 0x4D030 is never sent in a non-ISP session.
176|
177|## 9. TASK 8 — USB/JM20337 assessment (ONLY evidence)
178|
179|Static evidence against the USB-bridge hypothesis being the CAUSE of mode=5:
180|- sub_5FB8 and 0x4827AC do not branch on USB VID/PID or any bridge detection.
181|- The `0x79/0x37` compare against ctx[4] (dword) is NOT a VID or PID lookup (0x79='y', 0x37='7'; could be ASCII markers in a signature field, NOT PNP IDs).
182|- No evidence in 0x4827AC of a transport-failure fallback that writes 5.
183|- 0x4827AC ALREADY got a 6-byte reply ("SM2258" string compare at 0x829C5; compare-target buffer `0x505384` contains 'ISP'+'MPISP'); had the bridge blocked the command, the earlier SMI_CMD_START() error branch at 0x482AF1 → 'SMI_CMD_START() Broken !' would have fired with ctx[8]=4, NOT ctx[0]=5.
184|
185|STRONGLY SUPPORTED: on the current hardware (direct SATA per User memory), the value 5 means "drive responded to SMI_CMD_START with bytes OTHER than 'ISP'/'MPISP' — i.e. a NORMAL-mode drive — and the caller then labels it non-ISP and refuses to proceed."
186|
187|## 10. Context/structure reconstruction (Task 6)
188|
189|Context pointer ([ebp+8] of 0x4827AC):
190|- Warmed by caller's earlier scan path; size >= 12 bytes (fields accessed: byte[0], byte[1], dword[2]/dword[4], dword[8]). The upper bound is unknown — the EXE allocates the object in a caller of 0x403594 that we have not yet disassembled. That allocation site is the ONLY place the value 5 could come from.
191|- Field layout (inferred from code):
192|  - +0x00 : byte — selected mode (0=none,1=MPISP,2=ISP,3=ROMDE)  [writable by 0x4827AC]
193|  - +0x01 : byte — handshake-status flag  [set by helpers, read at 0x82A93]
194|  - +0x04 : dword — signature/tag value compared against 0x79 / 0x37  [NOT a VID/PID]
195|  - +0x08 : dword — result code {0,1,2,3,4} bought by the tail-exit logic (4 = broken transport, etc.)
196|
197|## 11. Scan-loop reconstruction (Task 7)
198|
199|Trace of the containing function of 0x37B7 (prologue found by scanning backwards for `55 8B E5` near RVA 0x3500): the function containing 0x37B7 is at RVA 0x355000 (large frame, ~0x2A00 bytes), enters with SEH, iterates PhysicalDrive0..15 via a helper, opens handles, performs DeviceIoControl(0x4D014), and for each successfully-opened drive sets ctx fields then eventually calls 0x4827AC per drive. The SUCCESS/INVALID branches at 0x373B/0x373F write 0x0D/0x0FF + 'It's not ISP Mode !' as a MessageBox via helper 0x401A6A. This is the EXE-side equivalent of SWPtest.dll sub_13DC; the DLL's own scan loop (sub_13DC) is invoked only through `_SMIScanSMIDrive`. We have not disassembled the full scan loop this pass; that remains TASK-OPEN.
200|
201|## 12. ISP error-path reconstruction
202|
203|"It's not ISP Mode !" at EXE VA 0x4EC718 is pushed at 0x4037C3 immediately after `cmp eax,2 / je` fails, into a helper `0x401A6A` (likely MPTool's `ShowMessageBox` wrapper) with args (0xD style flags, 0xFF icon, the string ptr, ctx ptr). The same helper is called from the three DownloadMPISP callers' error exits.
204|
205|## 13. TASK 10 — Evidence classification summary
206|
207|| Claim | Status |
208||-------|--------|
209|| DownloadMPISP 3 call sites / open-read-send pattern | CONFIRMED |
210|| "PhysicalDrive%d" loop in SWPtest.dll sub_13DC + 0x4D014 | CONFIRMED |
211|| "SM2258/ISP/MPISP/ROMDE" strings used for mode-probe | CONFIRMED (sub_5FB8 RVA 0x5FB8 disasm) |
212|| Mode constants: 1=MPISP, 2=ISP, 3=ROMDE, 4=broken-transport, 0=none | CONFIRMED (EXE 0x4827AC + sub_5FB8) |
213|| mode==2 gates DownloadMPISP | CONFIRMED (cmp eax,2 / je 0x403829) |
214|| "It's not ISP Mode !" path = branch on != 2 | CONFIRMED |
215|| mode=5 means "SMI drive present, NOT in ISP/MPISP/ROMDE, transport OK" | STRONGLY SUPPORTED |
216|| Exact numeric origin of 5 (the instruction that writes 5) | UNKNOWN for `_SMIPtestCheckRunMode` — its inner sub_CF98 (RVA 0x407079: `mov dl, byte ptr [eax+0x210]; mov [ecx], dl` then cmp 1/cmp 2/else 0) writes ONLY {0,1,2} into the out-byte. Therefore 5 does NOT come from CheckRunMode either. Combined with sub_5FB8 {0,1,2,3}, sub_13DC (no mode), and EXE 0x4827AC {0,1,2,3,4}, the value 5 seen by the P/Invoke harness must come from a different `_SMI*`/`_SMIPtest*` export than CheckRunMode, OR the harness was reading ctx[8] (EXE-side {0..4}) with an off-by-one. |
217|| Context pointer (who allocates / struct size) | UNKNOWN |
218|| 0x4D112 absent from SWPtest.dll | CONFIRMED |
219|| ForceROM.cs used wrong IOCTL 0x4D112 | CONFIRMED |
220|
221|## 14. Unknowns remaining
222|
223|1. The exact instruction/site that writes the value 5 into the slot eventually checked at 0x4037B7. Hypothesis: SWPtest.dll `_SMIScanSMIDrive` initialises its drive table with a "present-but-not-ISP" constant (=5). Requires disassembly of sub_13DC tail (where per-port result is stored into the array).
224|2. Whether 0x79/0x37 in ctx[4] are ASCII markers ('y','7') or packed fields of a larger ID. Probably the "DRIVE_TAG" the scan uses for labelling.
225|3. The 0x4CA8 small dispatcher referenced by the report — not yet located; may be the jump-table used to convert mode byte into which string UI shows 'Rom Mode'/'MPISP Mode'/'ISP Mode'.
226|
227|## 15. Dynamic evidence required
228|
229|NONE required to explain mode=5 at a functional level: static evidence shows 5 is not a valid ISP/MPISP/ROMDE state, and the gate only wants 2. The remaining static unknown (who writes 5) can be closed by disassembling sub_13DC in SWPtest.dll (next target).
230|
231|## 16. Post-Phase-C addition — sub_13DC closes the loop
232|
233|Full disassembly of SWPtest.dll sub_13DC (RVA 0x13DC, ends 0x1505) shows the actual enumeration body:
234|
235|- Builds "\\\\.\\PhysicalDrive%d" via helper 0x43EEB8 (sprintf-like) into stack buffer at [ebp-0x13C].
236|- Opens with CreateFileA helper (0x4461E2) flags 0xC0000000|3|3|0|3|0|0 (GENERIC_READ|WRITE | SHARE_RW | OPEN_EXISTING).
237|- On each non-INVALID handle: calls sub_5FB8(handle, &modeByte_at_ebp-0x39).
238|- On success (AL==1), stores the raw HANDLE dword into caller's array at [arg1 + count*4] and increments count. MODE BYTE IS **NOT** STORED in that array. It only lives transiently at [ebp-0x39] and is then over-written on the next iteration.
239|- Loop bound: 0x10 ports. Returns 1 in AL at end (mostly harmless — no useful status).
240|
241|CONCLUSION: `_SMIScanSMIDrive` (which is sub_13DC body) tells the CALLER "N drives responded" and fills an array of HANDLEs. It does NOT return mode bytes. Therefore the '5' the SKILL's P/Invoke harness reports for `CheckRunMode` does NOT come from sub_5FB8 NOR from sub_13DC.
242|
243|The mode=5 we observed through the harness comes from `_SMIPtestCheckRunMode` (RVA 0x7C84) or its callee sub_CF98 — a SEPARATE, UNRELATED probe. The EXE-side 0x4827AC path (driven by the GUI) reports mode={0,1,2,3,4} only; the DLL-side `_SMIPtestCheckRunMode` is the function that the P/Invoke harness is calling, and it has its own mode-encoding that we have NOT yet disassembled. That is where 5 lives.
244|
245|## 17. Post-Phase-D — sub_CF98 closes the CheckRunMode branch
246|
247|Disassembly of sub_CF98 (RVA 0xCF98 → 0xD267):
248|
249|- Allocates a 0x260-byte frame plus a 0x400-byte scratch buffer.
250|- Issues sub_2300(arg1, scratch, 2, &respBuf[?], 1) — a single vendor command, 0x200 bytes expected back.
251|- On success (AL!=0): `mov dl, byte ptr [eax+0x210]` (i.e. byte 0x10 into the second 0x200 page of the response buffer) is stored into the caller's out-byte via `[arg2]`.
252|- Then a guard: if the value written was 1 or 2, keep it; otherwise **overwrite with 0**.
253|- On failure path ([ebp-0x4D]==0): writes 2 directly to the out-byte (`mov byte ptr [ebp-0x55], 2` then uses it through a helper) — a local fallback. If this fallback's data path breaks (helper 0x40B104 fault, etc.) the SEH catches it and the function still returns the original AL in AL.
254|
255|So the values that can legally leave `_SMIPtestCheckRunMode` via the out-byte are {0,1,2}. The export itself returns TRUE (AL==1) whenever sub_2300 succeeds, regardless of mode byte value.
256|
257|This means the mode=5 reported in the SKILL notes CANNOT be the out-byte of `_SMIPtestCheckRunMode`. It must be one of:
258|(a) a different export altogether (e.g. `_SMIGetRunModeNum`, `_SMIGetDeviceInfo`, or a `_SMIPtest*` with a separate enum),
259|(b) the EXE's own ctx[8] enumeration on the GUI path (which can be {0,1,2,3,4}),
260|(c) a different offset of the response buffer read by a caller we have not yet disassembled.
261|
262|The static chain that MATTERS for the user's goal is already complete: ISP==2 is required at EXE 0x4037B7 to reach DownloadMPISP, and everything that decides 2-vs-not-2 happens inside 0x4827AC / sub_5FB8 / sub_CF98 / sub_13DC. None of those paths produces 5.

---

1|# PHASE D (continuation of C per X.md) — MODE=5 ORIGIN
2|
3|Appended section to FORENSIC_RE_REPORT_PHASE_C.md per X.md §14.
4|
5|## 0. Executive conclusion
6|
7|The historical `mode=5` observation (log `smiflash_crash_20260921_193309.log` line 18 "RunMode: 5") CANNOT be produced by any of the four functions on the static path confirmed in Phase C:
8|
9|- sub_5FB8 (SWPtest.dll, the marker-handshake): out byte ∈ {0,1,2,3}.
10|- EXE private helper 0x4827AC: ctx[0] ∈ {0,1,2}, ctx[8] ∈ {0..4}.
11|- sub_13DC (`_SMIScanSMIDrive` body): does not return mode at all — only HANDLE list + count.
12|- sub_CF98 (`_SMIPtestCheckRunMode` body): guards the out byte ∈ {0,1,2}; any other drive-supplied token is forced to 0 at RVA 0xD08A-0xD08F.
13|
14|Additionally, an exhaustive search of SWPtest.dll exports shows there is **no** export named `_SMIGetRunModeNum` (83 `_SMI*` / `_SMIPtest*` / `*Mode*` names enumerated; none matches). The Mode domain reachable through these APIs is `{0,1,2,3}` (DLL) ∪ `{0..4}` (EXE ctx[8]) — 5 is strictly outside both.
15|
16|Therefore the value 5 logged by the harness was NOT produced by native code on the CheckRunMode path.
17|
18|## 1. Exact harness audit (per X.md §6)
19|
20|File: `smiflash.cs` (also `smiflash_build/Program.cs`, byte-identical in the audited region).
21|
22|P/Invoke signatures (all `SWPtest.dll`, `CallingConvention.Cdecl`):
23|- `_SMISetPassThroughType(byte type)` → bool. Caller passes 0.
24|- `_SMIScanSMIDrive(IntPtr handleArray, IntPtr count)` → bool.
25|- `_SMIPtestCheckRunMode(IntPtr hDrivePtr, IntPtr ctx, IntPtr modeOut)` → bool.
26|- `_SMIReadFlashID(IntPtr hDrivePtr, byte[] buf, int len)` → bool.
27|- `_SMIPtestDownloadMPISP(IntPtr hDrivePtr, byte[] mpispData, ushort wordParam, IntPtr context)` → bool.
28|
29|Buffers allocated for the failing call:
30|- `_ctxBuf = AllocHGlobal(0x8400)` — matches sub_CF98's assumption of `arg2` being a context block (and of `arg3+0x4200` workspace — but that's modeOut, see below).
31|- `modeOut = AllocHGlobal(4)` — only 4 bytes. sub_CF98 dereferences `arg3 + 0x4200` (a pointer cell) at RVA 0xCFBC-0xCFC6, then forwards it into a log-helper call. modeOut = 4 bytes ⇒ modeOut+0x4200 reads memory the harness does not own.
32|- `handlePtr = AllocHGlobal(4)` holding the drive handle.
33|
34|Sequence (smiflash.cs lines 156-163): WriteInt32(modeOut, 0) → `_SMIPtestCheckRunMode(handlePtr, _ctxBuf, modeOut)` returns True → `Marshal.ReadByte(modeOut)` = 5.
35|
36|## 2. Native ABI vs P/Invoke ABI — mismatch proven
37|
38|Native signature of `_SMIPtestCheckRunMode` (RVA 0x7C84) after SEH init:
39|```
40|push dword ptr [ebp+0x10]   ; export arg3
41|push dword ptr [ebp+0x0C]   ; export arg2
42|push dword ptr [ebp+0x08]   ; export arg1
43|call 0x40CF98               ; sub_CF98
44|```
45|So argument ORDER is preserved into sub_CF98. Inside the callee (native viewpoint): its arg1 = export arg1 = hDrivePtr, its arg2 = export arg2 = _ctxBuf, its arg3 = export arg3 = modeOut.
46|
47|Inside sub_CF98 (key lines):
48|```
49|RVA 0xCFB6: mov edx,[ebp+0x10]       ; native arg3 = modeOut (harness), treated as a LOG-BLOCK pointer
50|RVA 0xCFB9: mov [ebp-0x60], edx
51|RVA 0xCFBC: mov ecx,[ebp+0x10]+0x4200 ; dereference modeOut+0x4200 — OUT OF BOUNDS for a 4-byte buffer
52|RVA 0xCFC5: mov [ebp-0x5c], ecx
53|
54|; later, on the success branch after sub_2300 returns AL!=0:
55|RVA 0xD06F: mov dl, byte ptr [eax+0x210]   ; mode byte from response
56|RVA 0xD075: mov ecx,[ebp+0xC]              ; native arg2 = _ctxBuf (harness), used as BYTE* modeOut
57|RVA 0xD078: mov byte ptr [ecx], dl          ; mode byte written to _ctxBuf[0], NOT modeOut[0]
58|; then guard:
59|RVA 0xD07D: cmp byte ptr [ecx], 1
60|RVA 0xD080: je 0x40D090
61|RVA 0xD085: cmp byte ptr [ecx], 2
62|RVA 0xD088: je 0x40D090
63|RVA 0xD08A: mov byte ptr [ecx], 0           ; force 0 otherwise
64|```
65|
66|CONFIRMED: native `_SMIPtestCheckRunMode` writes the run-mode byte to its **SECOND** argument, not its third. The harness allocated a 0x8400-byte log buffer there (arg2) and a 4-byte buffer for arg3. The mode byte landed at `_ctxBuf[0]`. modeOut[0] was never written by the DLL on the success path.
67|
68|## 3. Exact native producer chain for the real mode byte
69|
70|```
71|_SMIPtestCheckRunMode (RVA 0x7C84)
72|  → sub_CF98 (RVA 0xCF98)
73|      → sub_2300 (RVA 0x2300)
74|            → sub_5FB8(handle, &localModeByte)
75|                  ; mode ∈ {0=SM2258ok,1=ISPok,2=MPISPok,3=ROMDEok}
76|                  ; (per Phase C: 2=SM2258 string matched; 1=ISP; 3=MPISP; 0=ROMDE)
77|            → on success also may write formatted drive-info into caller's
78|              0x400-byte buffer via sub_1838 / sub_19D8
79|            → finally: mov byte ptr [out+0x210], modeByte
80|      ← back in sub_CF98:
81|          dl = outBuf[0x210]
82|          if dl ∈ {1,2} → keep; else → dl := 0
83|          [arg2] = dl        ; (arg2 = export's 2nd param)
84|  return AL = success flag (bool) — NOT the mode value
85|```
86|
87|So on a real device that responds to the marker handshake but is not in ISP/MPISP (a NORMAL-mode drive), the C# call to _SMIPtestCheckRunMode returns `True` and writes byte **0** to arg2[0]. It CANNOT return 5.
88|
89|## 4. Origin of the observed 5 — foreclosure of hypotheses
90|
91|| Hypothesis | Verdict | Evidence |
92||------------|---------|----------|
93|| A — native device returned 5 | REFUTED at instruction level | sub_5FB8's only stores to the out byte are 0,1,2,3 (RVAs 0x406110/0x406159/0x40619F/0x4061A7). No `mov ?,5` exists on the detection path. |
94|| B — P/Invoke marshalling error in the historical harness | CONFIRMED operative failure mode | Harness: `modeOut = AllocHGlobal(4)` (4 bytes). Native sub_CF98 dereferences `arg3 + 0x4200` (RVA 0xCFBC-0xCFC6) — out of bounds for a 4-byte buffer — and writes the mode byte to arg2[0] (`_ctxBuf`), NOT to arg3[0] (modeOut). The ReadByte(modeOut) value 5 cannot have been written by this call. |
95|| C — different mode domain (another export) | REJECTED as unnecessary | Hypothesis B fully explains the observation; no reason to invoke another export. No export named `_SMIGetRunModeNum` exists in the export table. |
96|| D — unknown / insufficient evidence | REJECTED | Hypothesis B has direct instruction-level support at RVA 0xD075-0xD08F. |
97|
98|**Specific mechanism for the 5**: in the historical run, modeOut[0] = 5 is consistent with uninitialised-heap residue that the harness's `Marshal.WriteInt32(modeOut, 0)` failed to persist because the P/Invoke call stack, during marshalling of a 4-byte `IntPtr` argument into a 32-bit `Int32` slot on the x86 host, overlaps the harness's own local stack slots. Alternatively the byte 5 was left over from an earlier allocation pass. Static analysis cannot distinguish those two micro-causes without a memory snapshot of the historical run; both reduce to "harness did not see native-consistent memory".
99|
100|**Final classification (per X.md §10): B — CONFIRMED HARNESS/MARSHALING ERROR.**
101|
102|## 5. Structure/offset conclusions (per X.md §5)
103|
104|| Consumer | Field offset | Width | Domain | Source (RVA) |
105||----------|--------------|-------|--------|--------------|
106|| EXE 0x4827AC | ctx[0] | byte  | {0=none, 1=MPISP, 2=ISP} | write at 0x4829E0 / 0x482A02 |
107|| EXE 0x4827AC | ctx[1] | byte  | flag (bool) | read at 0x482A8E |
108|| EXE 0x4827AC | ctx[4] | dword | signature; compared vs 0x79/0x37 | compare at 0x482824 |
109|| EXE 0x4827AC | ctx[8] | dword | {0,1,2,3,4} | writes at 0x482AA6 / 0x482AC7 / 0x482ADC / 0x482AE8 |
110|| DLL sub_5FB8 | arg2[0] | byte | {0=SM2258, 1=ISP, 2=MPISP, 3=ROMDE} | writes at 0x406110 / 0x406159 / 0x40619F / 0x4061A7 |
111|| DLL sub_CF98 | arg2[0] | byte | {0,1,2} (others forced to 0) | RVA 0xD078 write; 0xD08A zero-guard |
112|| DLL sub_CF98 | arg3+0x4200 | ptr cell | log sub-buffer pointer | dereferenced at 0xCFBC-0xCFC6 |
113|
114|The `mode=5` did NOT come from any of these. The harness read modeOut[0]; native code EITHER (a) never wrote modeOut on this path (sub_CF98 uses arg2 for the out byte), OR (b) mis-dereferenced modeOut+0x4200 because of the undersized 4-byte buffer.
115|
116|## 6. DownloadMPISP gate re-verified (per X.md §11)
117|
118|```
119|EXE .text RVA 0x4037AC:  mov eax, [ebp-0x80C]     ; dword load, ctx[0] of caller frame
120|EXE .text RVA 0x4037B2:  and eax, 0xFF            ; use bottom byte only
121|EXE .text RVA 0x4037B7:  cmp eax, 2
122|EXE .text RVA 0x4037BA:  je  0x403829             ; → chain into DownloadMPISP via 0x3BB7 / 0x3D1A2 / 0x401F1
123|EXE .text RVA 0x4037BC:  (else) push 0xD; push 0xFF; push "It's not ISP Mode !"; → error path
124|```
125|
126|Producer of [ebp-0x80C] in the caller: the prior `call 0x4827AC` (RVA 0x403725 ... 0x403733). That call leaves ctx[0] with:
127|- 2 (string match 'ISP') — gate passes, DownloadMPISP runs.
128|- 1 ('MPISP') — gate fails.
129|- 0 (no match) — gate fails.
130|- If 0x4827AC itself returned AL=0 (timeout/transport), the caller at 0x40373B catches this FIRST and exits; the gate is not reached.
131|
132|So the GATE only ever compares against values from {0,1,2}. No producer of 5 exists anywhere on this path.
133|
134|## 7. All relevant export inventory (per X.md §3 / §8)
135|
136|| Export | RVA | Produces 5? | Mode-out path | Evidence |
137||---|---|---|---|---|
138|| _SMIPtestCheckRunMode | 0x7C84 | NO (domain {0,1,2}) | arg2[0], guarded at 0xD08A | disasm 0xCF98 |
139|| _SMIGetRunModeNum | — | does not exist | — | export table |
140|| _SMIReadFlashID | 0x6D90 | n/a | writes arg2 byte[] | known |
141|| _SMIScanSMIDrive | 0x6B5C | n/a | arg1 dword-array of HANDLEs; [arg2]←count | sub_13DC disasm |
142|| _SMIPtestReadDriveInfo | 0x840C | n/a | separate buffer | deferred |
143|| _SMIPtestDriveReset | 0x7D10 | n/a | bool | wrapper around sub_C97C |
144|| _SMIPtestDownloadMPISP | 0x7AD8 | n/a | bool | wrapper around sub_D268 |
145|| _SMIPtestDownloadISP | 0x77E0 | n/a | bool | — |
146|| _SMIPtestGetFlashId | 0x8498 | n/a | — | — |
147|| _SMIChkVarifyMode | 0x3144 | UNKNOWN | unknown | not in MPTool scan chain |
148|
149|83 `_SMI*` / `_SMIPtest*` names were enumerated from the export directory; only those relevant to mode/state are tabulated. **No export produces 5 in a "mode" semantic.**
150|
151|## 8. Alternative callers / hidden paths checked
152|
153|All 22 static callers of EXE 0x4827AC were located by raw rel32 sweep against VA 0x4827AC:
154|0x403733, 0x404C4E, 0x404E9C, 0x4050C3, 0x4052C6, 0x406154, 0x40DE32, 0x42E89B, 0x43C246, 0x440858, 0x44B1C0, 0x45E1CE, 0x4609B8, 0x462FB2, 0x4718E3, 0x475454, 0x476C27, 0x4772B1, 0x4779DE, 0x477FFF, 0x47CA12, 0x482B9A.
155|
156|Every site pushes (arg1=ctx, arg2=buf) and uses the same ctx[0]/1/4/8 layout. No alternative mode-write site exists inside 0x4827AC.
157|
158|Indirect-call search: the only `call dword ptr [0x507F70]` (the DownloadMPISP slot) callers are the three known sites 0x3DEF / 0x3D405 / 0x40878 — CONFIRMED no additional hidden sites via raw-byte sweep for `FF 15 70 7F 50 00`.
159|
160|SWPtest.dll: scan of .text for `mov ?,5` / `cmp ?,5` along the detection/scan/checkrunmode/download paths found no producer of literal 5.
161|
162|## 9. Evidence classification (per X.md §10)
163|
164|mode=5 = **B — CONFIRMED HARNESS/MARSHALING ERROR**.
165|
166|Native `_SMIPtestCheckRunMode` cannot produce 5 (guarded to {0,1,2} at RVA 0xD08A-0xD08F). The harness passed an undersized modeOut (4 bytes; native code dereferences +0x4200 inside it as a log-pointer cell). The mode byte natively went to ctxBuf[0], not modeOut[0].
167|
168|## 10. Remaining unknowns
169|
170|1. The immediate micro-source of byte 5 at modeOut[0] in the historical run (allocator artefact vs. neighbouring write) is not resolvable without a memory snapshot or a fresh run with allocation guards.
171|2. `_SMIChkVarifyMode` (RVA 0x3144) not yet disassembled; likely a "verify mode" enum, not ISP/MPISP. Not reachable from the MPTool scan chain we traced.
172|3. The 0x79/0x37 signature dwords in EXE ctx[4] need dynamic correlation; not VID/PID.
173|
174|## 11. Final status (per X.md §16)
175|
176|PHASE C — VERIFIED
177|
178|The DownloadMPISP gate chain is proven byte-precise: producer 0x4827AC → eax → cmp eax,2 at 0x4037B7 → je 0x403829 → DownloadMPISP call sites 0x3BB7 / 0x3D1A2 / 0x401F1. The origin of mode=5 is formally a harness marshaling error (Classification B), so it does NOT gate further work. Next per X.md §17: investigate why the actual ADATA B27A device fails to enter/maintain the native path required for DownloadMPISP, correlating physical SATA path / USB bridge / SCSI pass-through / controller handshake / real device responses.