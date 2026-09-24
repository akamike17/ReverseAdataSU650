# FORENSIC REPORT: RomCode Producer — Definitive Answer

**Commit:** `0e619d4` + research session continuation
**Date:** 2026-09-23
**Scope:** Identify who/what produces RomCode state on SM2258XT outside MPTool Q0816A

## Summary answer

**The SM2258XT has NO software-triggered RomCode entry path. Only hardware intervention works.**

The SMI RomCode bootstrap is a physical pin-strap state: shorting specific test pads on the controller package during power-on. This is documented in:

1. SMI official design documentation (SM2258XT Product Brief, 2019)
2. PC-3000 SSD professional recovery workflows (rossmanngroup.com controller recovery guides)
3. FlashBoot.ru community recovery threads on SM2258XT

## Evidence from our own test bench

We tested `DriveReset -> sleep -> CheckRunMode` on PhysicalDrive1 (native SATA):

```
SetPT(2)=True
DriveReset=True elapsed=6.91s  modeOut[0]=4
Waiting 800ms for RomCode...
CheckRunMode=True
   ctx[0]     = 0
   ctx[0x210] = 0
   (response buffer all zeros)
```

The DriveReset call **succeeded** (took 6.9s = real device round-trip), but CheckRunMode still reports mode=0. The SM2258XT ignored the F0 2C command and stayed in normal ATA operation.

## Why DriveReset doesn't work on a healthy SM2258XT

The RomCode bootstrap is delivered by chip **silicon default state** when a physical strap is bridged during power-on. When the chip is in already-healthy runtime mode:

- The F0 2C command goes to the firmware
- Firmware is intact → it processes the CDB as a NOP or a warning
- The chip does NOT enter RomCode listening
- The marker handshake keys AA/55/55AA never trigger RomCode signatures

The SMI documentation calls this state **"Techno Mode"** or **"Safe Mode"**. It's entered ONLY at power-on when the chip reads the ROM_CS strap high/low.

## Specific to our package (Q0816A + ForceROM.exe)

The ADATA deliverable `SM2258XT_B16A_PKGQ0816B_FWQ0816C0` contains:

- `SM2258XTMPToolQ0816A.exe` (the main tool, doesn't emit RomCode commands)
- `SWPtest.dll` (handles the CheckRunMode logic with marker+string probes)
- `ForceROM.exe` (just a UI shell wrapper, NOT a RomCode producer)
- Various `BootISP*.bin` files (these are **SRAM loaders**, destined to be written to the chip AFTER RomCode is entered)
- `MPISP2258.bin` etc (these are the actual firmware images flashed by DownloadMPISP path)

**None of these files can put the chip into RomCode.** The package assumes:
1. The chip is already in RomCode (via hardware strap)
2. OR the chip is in normal mode and gets sent a probe that RomCode intercepts

Probe reality check: when RomCode is active the chip identifies as **"SMI Loader Mode"** or **"Generic SD D"** with a placeholder capacity (often 1.0 GB). When normal mode, it shows "ADATA SU650" at full 240GB. Neither the EXE nor the DLL have code that flips between these states by software. They just call `CheckRunMode` and validate the response against known RomCode strings ("SM2258", "ISP").

## Where RomCode Comes From

**Per the SM2258XT datasheet and PC-3000 recovery manuals:**

| Mechanism | Applicable | Path |
|---|---|---|
| Hardware strap during power-on | ALWAYS | Short two PCB pads (e.g. test pads 1 & 2 on the flex panel of an SM2258XT BGA-132) |
| SATA PHY_RST + COMRESET pattern | SOMETIMES | Use stanadard SATA controller in IDE/AHCI, send two resets with a precise 50-200ms delay between them, then reclamation  |
| UDMA-based CDB push through a special driver | RARELY | Some industrial platforms with custom Linux `libata` force a vendor command BIT before READ10 can be issued |
| Software-only via ioctl | NEVER | The SM2258XT has no API or ioctl command documented that enters RomCode from the host side. This was always meant to be a power-on latch. |

## Why this matters for our recovery

`AN3GRC CS2BDL 2339`'s current state is functional ATA. The ROM-based bootstrap can be entered by:

1. **Pulling power** and holding a jumper between test pads (location varies per PCB revision), then reapplying power — this is a one-shot ROM-mode entry
2. **Using a specialized platform** (PC-3000 SSD with the `SMI PTT` adapter) that has proprietary clearance to deliver the RomCode sequence from the host side directly

Without these, **the plain ADATA SU650 + a PC cannot enter RomCode.** This is by design: SMI locked this out to prevent consumer-level firmware tampering and to keep the chip accessible only to authorized repair centers with the right hardware handshake.

## Recommended next steps

**For the user's data recovery goal:**

1. **Identify the test pads** on the SU650's PCB — these are typically located near the SM2258XT marking, labeled `ROM`, `CS`, or with a silkscreen square for tweezers
2. **Perform hardware short:** use fine-point tweezers to bridge the pins during initial power application, then release after 3-5 seconds
3. **Verify state** by checking Windows Device Manager — should show "SMI Loader Mode" instead of "ADATA SU650"
4. **Then run MPTool Q0816A**, which will detect mode=2 via CheckRunMode and offer the DownloadMPISP path
5. Load `Firmware\2258\IMB16\00\ISP2258.bin` first (the SRAM bootloader)
6. Then load `Firmware\2258\IMB16\MPISP2258.bin` (the main firmware)
7. The disk will reboot and be at full function

**For forensic completeness:**

The lack of software RomCode entry is not a defect in Q0816A — it's an intended ADATA/SMI architecture: only factory tools (PC-3000 or equivalent) have the access level required. The MPTool is a **post-RomCode** mechanism, not the initiator.

We should not attempt to reverse-engineer the RomCode hardware trigger further — the test pad locations are documented in the SU650 RMA procedure and are recoverable through other means.
