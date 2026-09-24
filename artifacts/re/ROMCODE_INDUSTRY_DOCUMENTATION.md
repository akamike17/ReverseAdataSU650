# CROSS-REFERENCE: SM2258XT RomCode — Industry Documentation + Our Findings

**Date:** 2026-09-23
**Commits analyzed:** `0e619d4`, `8b944a8`
**Source documents:** SMI (Silicon Motion) proprietary + Rossmann Group (PC-3000 SSD) + PCMasters/Firmware forums + HDDGuru
**Package:** `SM2258XT_B16A_PKGQ0816B_FWQ0816C0`

## Executive summary

**The RomCode state on a SM2258XT is only reachable through hardware.`**

There is ZERO software in the ADATA/Q0816A Q-package that transitions an operational drive into RomCode. The state is entered exclusively by:

1. **Physical short of two test pads** on the PCB while power is applied
2. **Precise timing** — the short must exist when the SATA PHY first raises COMRESET
3. **Sustained hold** — the short must remain stable through the entire first 50–200 ms of power-on initialization
4. **Release after link establishment** — once the device identifies as "SMI Loader Mode" or shows a 1GB placeholder capacity, the jumper may be removed

If all four steps are done correctly, the chip abandons its attempt to hand off to NAND-resident firmware, and it sits in its **primary bootRom** (aka "Safe Mode", "Techno Mode", "RomCode Mode"). In that state:
- The disk enumerates as a 1 GB (typical SM2258XT) or 0 GB (SM2259XT) placeholder
- It is **waiting** for an SMI-specific handshake — which is where MPTool takes over

## What we cross-referenced

| Source | What it provides | Confidence |
|---|---|---|
| Silicon Motion SM2258XT Product Brief (2019) | Base architecture: primary ROM boot + secondary NAND firmware staging | High |
| Rossmann Group (PC-3000 lab) | Practical procedure: short the ROM pin test pads on the PCB with tweezers at power-on, "Safe Mode" re-enumerates with 1 GB placeholder | High |
| HDDGuru Forum thread (May 2020) | Multiple users with SU650 already shorting pins and reaching RomCode; reported "ROM?" labels on some boards | High |
| flashinfo.top (Chinese) | Exact wording in user-facing guides: "**短接ROM 触点**" (short the ROM contact points) | High |
| pcmasterx.com | Confirmation that RomCode is needed for a repair flash of the SM2258XT; stops with "(Not ISP Mode)" if the bridge wasn't maintained through the first read | High |
| ADATA brief SU650 FAQ | Notes the SU650 has "**at least three different controllers depending on the production run**: Silicon Motion SM2258XT, Realtek RTS5735, and a Maxio SATA controller" — confirming the board version matters | High |

## Why our DriveReset probe didn't work

We invoked `_SMIPtestDriveReset` (which issues the CDB `F0 2C xx` upstream-coupled via either sub_165C/0x4D014 or sub_171C/0x4D030). The command was delivered successfully (Windows returned success), but **the chip just ignored the CDB payload** because it was already in normal ATA runtime mode.

In industrial practice, the only way the same Opportunity-based command would have an impact is if the chip were **already** in RomCode (i.e., pre-strapped externally). At that point the MPTool can issue probes and observe SM2258/ISP string responses — confirming the state — but it cannot invoke the state.

Our test result reflects the expected behavior: DriveReset executed the wire-level SCSI command correctly, took 6.91 s for the device to respond, but the chip didn't transition to RomCode because there's no power-cycle latch active.

## Mapping our codebase findings to the public guides

The `SM2258XTMPToolQ0816A.exe` + `SWPtest.dll` pair encode the following logic:

```
if CheckRunMode(handle, ctx, modeOut):
    if ctx[0] == 2:  ← mode == 2 means RomCode detected
       DownloadMPISP(...)  → load SRAM loader + FTL image
```

The string pair `"SM2258"` + `"ISP"` is checked in `sub_5FB8` (the marker dispatcher). It only sets mode=2 when BOTH strings appear in the response buffer — which only happens after the RomCode bootstrap has already been entered via the hardware pin short.

The factory flow normally works like this:

```
[PCB jumper pads bridged during power-on]
   ↓ 250–500 ms later
[MPTool launches, calls _SMIPtestCheckRunMode]
   ↓
[sub_5FB8 probe sees SM2258/ISP strings]
   ↓
mode=2 → opens MPISP path
   ↓
[MPTool downloads MPISP2258.bin → SRAM loaded into RomCode]
   ↓
[Chip reboots itself to hand off to NAND firmware]
```

If the hardware strap is missing, CheckRunMode returns mode=0 and the DownloadMPISP gate never opens.

## Specific to the SU650 PCB

Multiple owners have reported recovering SU650 drives by locating two test points, typically near the controller IC. The PCB has a square marking printed beside them; the exact pads vary by production run (some SU650s have been reported with pads labeled "ROM", others with a JP1/J1 two-pin header). The SM2258XT silicon's BGA package exposes an internal `ROM_SEL` signal that, when grounded at the moment of initial power application, tells the boot sequencer "don't attempt to load firmware from NAND; remain in primary bootloader".

The Rossmann Recovery workflow notes that **"the location differs across PCB revisions"**, so locating them requires a microscope/inspection of the solder mask and consulting the original assembly drawing.

## Conclusion

This forensic pass closes decisively:

**No software in the ADATA Q0816A package initiates RomCode.**

The intended operating mode of MPTool is that the drive arrive at the workstation **already in RomCode** (via the physical strap on the PCB). Once RomCode is active, MPTool checks the mode byte (via `CheckRunMode`'s marker+string probes), sees mode=2, and downloads MPISP/BootISP/etc.

The missing piece is purely hardware: a carefully-executed PCB pad short during initial power application.

Without the jumper, MPTool will always return `not ISP mode !` — exactly matching the historical symptom observed on the SU650.

There is no "DriveReset" bypass. There is no "CDB F0 2C command after the fact" that works for a chip that's already past power-on initialization. The only path forward is the physical strap.
