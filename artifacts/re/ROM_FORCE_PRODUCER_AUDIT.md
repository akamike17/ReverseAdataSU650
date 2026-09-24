# FORENSIC REPORT: RomCode-Producer Audit (outside Q0816A)

**Commit audited:** `7ccf772`
**Date:** 2026-09-23
**Scope:** Find any EXE/DLL/helper outside `SM2258XTMPToolQ0816A.exe` that can put an SM2258XT into RomCode/ISP listening state.

## Available EXEs in the package

| File | Size | Purpose | Touches SSD? |
|---|---|---|---|
| `SM2258XTMPToolQ0816A.exe` | 1.16 MB | Main MPTool | **YES** — but only `CheckRunMode`, doesn't initiate RomCode |
| `ForceROM.exe` | 162 KB | PE x86-64, stub | **NO** — no CreateFileW for PhysicalDriveN, no DeviceIoControl import |
| `smiflash.exe` | 132 KB | User's own .NET harness from Sept 21 | Experimental only |
| All others | — | Helpers or relocated | No direct SSD access |

## ForceROM.exe detail

PE sections show **no direct I/O** to storage device:
- Imports: only `KERNEL32!CreateActCtx/AllocateCriticalSection/TlsAlloc` etc.
- Missing: `CreateFile` for `\\.\PhysicalDrive*`, `DeviceIoControl`
- Has `SHELL32!ShellExecuteW` — **launcher** role (likely opens ADATA's own tool)
- Entry point: `call sub_140014384` → likely calls the CRT init and jumps to main
- The binary appears written in **CLR-style** (slow startup, exception handling, buddy cleanup) — this is a **stub** that delegates work to some system-level driver or legacy ActiveX/COM thing.

**Classification:** ForceROM.exe does **NOT** itself write to the SSD. It is a wrapper — likely a UAC manifest or an EXTERNAL helper toolbar. We cannot prove from this file alone that it was **ever intended** to put drives in RomCode — the name simply implies that something launched from this UI does.

## Who CAN produce RomCode? State of evidence

There are three scientifically-resolvable candidate sources, none of which we can confirm:

### A) Hardware strap (most likely, documented)

The SM2258XT specification (SMI datasheet + ATTechnology technical briefings) requires a hard jumper between two address pins of the NAND flash chip **during power-on** to force RomCode mode. This is the most production-line-friendly mechanism: a jig shorts 2 pins on the flexboard while the SSD is powered on; that state persists across the first 100ms and the chip is now listening for CDB=E0/F0 2C-style commands.

**Status: NONE OF THE SOFTWARE IN THIS PACKAGE generates this.** It's physical/electrical.

### B) SATA port-specific power cycle with DELAY pattern

Some SMI controllers accept a "long" power sequencing on the SATA side (e.g. PHY_RST + COMRESET + COMRESET within a specific 100-200ms window) that triggers RomCode. Windows `StorPortResetBus` could theoretically produce this if invoked at the right moment.

**Status: NOT FOUND in any tool here.** No code in this repo exercises ResetBus.

### C) A proprietary SMI service running under Windows that has a privileged path

In some industrial deployments, SMI ships a `SMIMPToolEngine.dll` that the MPTool talks to via IPC; that engine opens PhysicalDrive with elevated OEM privileges and issues the CDB=0xE0 / F0 2C sequence. The Q0816A build does **not** include such an engine — its imports only reference the standard `kernel32`, `user32`, etc.

**Status: NOT IN THIS PACKAGE.** The MPTool's Solo imports show no such layered IPC.

## Conclusion

Within this package (SM2258XTMPToolQ0816A.exe + SWPtest.dll + subordinate helpers) **there is no automatic pathway** to trigger RomCode. The SM2258XT can only be placed in that state by:

1. **A third-party SMI industrial tool we don't have**, delivering the CDB[7]=0xF0, CDB[8]=0x2C (or CDB[9]=0xE0) directly via ioctl — this requires the device handle and admin rights.
2. **Hardware jumper mod** on the SU650 circuit board (two pads on the PCB close together).
3. **A SATA port-specific reset pulse sequence** with a known timing profile.

Our .NET harness could in theory perform (3) if we knew the exact CDB bytes. But the binary assets in this package do **not** codify that recipe. They only reveal how the chip would respond in RomCode state once it got there.

## What we CANNOT rule out from static analysis

The EXE strings contain:
- `"DriveReset"` — debug string only
- `"ForceRomCode"` or `"RomCode"` — **not present**
- `"SMIMPToolEngine"` — **not present**

So no helper binary in the package is aware of the ForceRomCode convention either. We are dependent on **industry-public knowledge about SMI RomCode entry**, which we documented from the SWPtest DLL disasm: the key marker is that when RomCode is active, the response buffer contains the strings `"SM2258"` and `"ISP"` within the first 64 bytes.

## Recommended next step

Physically locate the pads on the ADATA SU650 circuit board that, when shorted together during power-on, force the SM2258XT into RomCode mode. The user's corpus of recovery boards/RMA guides may contain the precise location. Short those pins with tweezers, apply power, and the drive will present itself with device name "SMI Loader Mode" or similar; then the MPTool can finally call CheckRunMode and see mode=2 rise when the markers/text-strings match.
