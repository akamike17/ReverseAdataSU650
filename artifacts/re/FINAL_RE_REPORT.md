# FINAL_RE_REPORT.md — Surgical RE: ADATA SU650 120GB / SM2258XT

Generated: tools/analyze_swp_dynamic.py (static phases A–F)

## A. Target
- Device: ADATA SU650 120GB
- Controller: SM2258XT
- Bus: SATA
- Status: CONFIRMED (project scope declared by the user)

## B. MPTool
- EXE: SM2258XTMPToolQ0816A.exe
- DLL: Dll/SWPtest.dll (405,504 B, sha256 in module_map.json)
- Hashes are in artifacts/re/module_map.json
- Status: CONFIRMED

## C. DownloadMPISP — `_SMIPtestDownloadMPISP`
- RVA 0x7AD8 (CONFIRMED, via PE export table)
- Caller slots resolved in EXE via GetProcAddress store analysis.
  See artifacts/re/callers_downloadmpisp.json.
- Three call sites found in MPTool EXE through slot 0x507f70:
  RVA 0x3DEF, 0x3D405, 0x40878 (CONFIRMED by static x-ref).
  (Decimal in json: 15855, 250885, 264696)
- Calling convention: cdecl (caller-cleans evidenced by `add esp, N`
  after calls; full confirmation requires a live capture — PHASE G).
- Actual arguments: UNKNOWN until dynamic capture.

## D. Context (workspace for DownloadMPISP)
- Static access candidates in artifacts/re/context_accesses.json:
  2185 register+offset memory ops reached from DownloadMPISP graph.
- Allocation site: UNKNOWN statically — this requires a run with
  HeapAlloc / memset tracing (PHASE G/H).
- Status: HYPOTHESIS — do not trust specific offsets; the crash at
  SWPtest RVA 0x6496 (`mov byte ptr [edx+eax], cl`) confirms the
  context layout is richer than a flat zeroed buffer.

## E. SCSI transport
- Two transport subroutines, both calling DeviceIoControl:
  - sub_165C (call site RVA 0x169F): IOCTL **0x4D014** = SCSI_PASS_THROUGH
    (CONFIRMED by `push 0x4D014` immediately before the thunk call).
  - sub_171C (call site RVA 0x1818): IOCTL **0x4D030** =
    SCSI_PASS_THROUGH_DIRECT (CONFIRMED by `push 0x4D030`).
- IOCTL 0x4D112 (used by ForceROM/Program.cs) is **NOT** referenced
  anywhere in SWPtest.dll. ForceROM.cs is therefore wrong and is
  QUARANTINED.
- Actual CDB bytes: UNKNOWN statically — see cdb_candidates in
  scsi_candidates.json (2 HYPOTHESIS-class patterns only).

## F. MPTool state machine (partial)
Observed statically:
    Open PhysicalDrive -> LoadLibrary SWPtest.dll -> GetProcAddress
        each _SMI* export -> store in .data slots -> call via slots.
Order of Scan / CheckRunMode / ReadFlashID / DownloadMPISP:
UNKNOWN until dynamic trace.

## G. Evidence classification
| Item                                | Status      | Where |
|-------------------------------------|-------------|-------|
| Target = SU650 120GB                | CONFIRMED   | scope |
| SWPtest.dll sha256                  | CONFIRMED   | module_map.json |
| DownloadMPISP RVA 0x7AD8            | CONFIRMED   | exports.json |
| DownloadMPISP caller slot 0x507F70  | CONFIRMED   | callers_downloadmpisp.json |
| DownloadMPISP call sites (3)        | CONFIRMED   | callers_downloadmpisp.json |
| SCSI transport IOCTLs               | CONFIRMED   | scsi_candidates.json |
| IOCTL 0x4D112 in ForceROM.cs        | WRONG       | not in DLL |
| Calling convention cdecl            | OBSERVED    | needs dynamic confirm |
| CDB bytes / 0xE0 meaning            | HYPOTHESIS  | scsi_candidates.json |
| RunMode=5 meaning                   | UNKNOWN     | not traced |
| FlashID=00 meaning                  | UNKNOWN     | not traced |
| Context allocation site             | UNKNOWN     | needs dynamic |
| Context layout / critical offsets   | UNKNOWN     | needs dynamic |
| BootISP2258.bin usage               | UNKNOWN     | not in this pass |

## H. Where to go next
Phases G/H/I (dynamic capture with debugger hooks on the EXE's
three DownloadMPISP call sites) are required to close items marked
UNKNOWN. ForceROM.exe must NOT be run until that evidence exists.
