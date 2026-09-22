# SM2258XT PoC — DownloadMPISP Phase
**Date:** 2026-09-21 20:37 UTC-6  
**Status:** PARTIAL — Verification succeeded, DownloadMPISP failed (context structure)

## VERIFIED

| Step | Result | Evidence |
|------|--------|----------|
| Open PhysicalDrive1 | ✅ PASS | Handle 0x318 opened |
| SetPassThroughType(0) | ✅ TRUE | SWPtest.dll responded |
| ScanSMIDrive | ✅ TRUE | Found 0 SMI drives (expected in NORMAL) |
| CheckRunMode | ✅ TRUE | Mode = 5 (unknown code, not 1/2) |
| ReadFlashID | ✅ TRUE | Returned 00-00-00-00-00-00 (normal mode = no NAND access) |
| File verify | ✅ PASS | BootISP2258.bin SHA256 verified |

## FAILED

| Step | Error | Root Cause |
|------|-------|-----------|
| DownloadMPISP | ❌ 0xC0000005 | Context structure not initialized (expects MPTool.exe's internal state) |

**Crash analysis:**
- Addr: 0x08556496 (SWPtest.dll internal)
- Access: WRITE
- Fault: 0x143E6590 (wild address — context buffer too small or wrong layout)

## KEY FINDINGS

1. **RunMode = 5** — Not documented. Not NORMAL(1) or ROM(2). Possibly 5 = "Normal with SMART" or similar.

2. **NAND ID = zeros** — Confirms drive is NOT in ISP mode. NAND ID only accessible after successful MPISP download puts drive in ISP state.

3. **Context structure required** — DownloadMPISP calls internal functions that access context+0x4200 and other offsets. We allocated 0x8400 bytes but the context needs specific initialization from MPTool.exe startup.

## WHAT WOULD UNBLOCK

The context passed to DownloadMPISP must contain:
- Valid function pointers for logging callbacks  
- Pre-allocated buffers at specific offsets
- Drive state structures

This requires either:
1. **API Monitor capture** of MPTool.exe calling DownloadMPISP (to see exact stack/params)
2. **x64dbg breakpoint** at _SMIPtestDownloadMPISP to dump the context memory layout
3. **Manual MPTool GUI flow** — the only way to get a valid context today

## CONCLUSION

- ✅ PhysicalDrive access: **VERIFIED**
- ✅ SWPtest.dll communication: **VERIFIED**  
- ✅ CheckRunMode/ReadFlashID: **VERIFIED**
- ❌ DownloadMPISP: **BLOCKED** (context structure unknown)
- ❌ ISP mode entry: **BLOCKED** (depends on DownloadMPISP)

**The PoC proves the communication layer works but cannot complete flash without MPTool's internal initialization.**
