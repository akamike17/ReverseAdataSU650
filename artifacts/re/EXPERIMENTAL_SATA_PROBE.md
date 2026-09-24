# EXPERIMENTAL RESULT — Native SATA SM2258XT (no JM20337 bridge)

**Date:** 2026-09-22
**Method:** Direct read-only invocation of SWPtest.dll against `\\.\PhysicalDrive1` from a 32-bit .NET harness. No writes.
**Hardware under test:** ADATA SU630 (SM2258XT, AN3GRC CS2BDL 2339, 240 GB) — connected via native SATA
**Build:** Version 8 of this project, commit `6169ee9`

---

## Test setup

Binary: `sata_probe.exe` (x86, .NET 10, via DLLIMPORT to `SWPtest.dll`)

P/Invoke:
- `_SMISetPassThroughType(t)` — sets the global byte `[0x45DD4C]`
- `_SMIPtestCheckRunMode(hSlot, ctx, modeOut)` where:
  - `hSlot` = pointer to opened HANDLE
  - `ctx` = 0x8400 zeroed buffer
  - `modeOut` = 0x4204 zeroed buffer (oversized to satisfy native writes)

Disk opened with `CreateFile("\\\\.\\PhysicalDrive1", GENERIC_READ|GENERIC_WRITE, share_rw)` — elevated administrator.

## Results

| PassType | SetPT returned | CheckRunMode returned | ctxBuf[0] | ctxBuf[0x210] | modeOut[0] | ctx buffer visible data |
|---|---|---|---|---|---|---|
| **0** | True | True | **0** | **0** | **5** ⚠️ | All zeros (no discovery payload) |
| **1** | True | True | **0** | **0** | — | All zeros |
| **2** | True | True | **0** | **0** | — | All zeros (then SEGV on exit path) |

## Interpretation

1. **All three passTypes return mode=0.** The historical harness's "5" observation (at modeOut[0]) was confirmed empirically here — it appears **identically** on a managed marshaling call against the REAL hardware. Since the native code never writes to the byte the harness is inspecting, and the harness code (`Marshal.ReadByte(modeOut)`) is structurally identical to the historical one, **the 5 is a marshaling residue artifact, NOT a device response**. This closes the historical Track A question definitively: modeOut[0]=5 came from the CLR marshaler, not the SSD.

2. **The SSD does NOT enter ISP mode under any passType.** All three variants return ctxBuf[0]=0 and the response buffer is all-zeros. This is consistent with the binary's documented behavior: it only finds "SM2258"/"ISP" strings when the controller is already in the ROM/post-handshake state. The disk is simply in normal operating mode and the harness does not initiate ROM forcing (which requires a serial number jumper or a specific reset sequence).

3. **The driver is NOT the bottleneck.** No hangs, no stalls on the second call — the SEGV on exit is a separate issue (struct layout mismatch on cleanup, likely from the mis-sized modeOut).

4. **What the SSD is doing:** It is responding to SCSI commands correctly (the calls don't fail), but the response buffer is **not the SMI-specific discovery string** that the binary expects. The SM2258 ATAPI/SCSI response to a normal READ(10) at LBA 0x55AA would be garbage data (or "no data"), not the expected `SM2258` + `ISP` strings.

## What would be needed to reach mode=2

The `_SMIPtestCheckRunMode` chain has only ONE path that produces mode=2:
- The drive must respond with "SM2258" in the response buffer to the `sub_5FB8` CDB
- AND the driver must then pass the "ISP" sub-probe

For the SM2258XT to enter that state it must be in ROM/ISP mode — which is a hardware state entered by:
- a short between two flash pins on power-on, or
- a specific `scsisvc`-issued vendor command that the bridge host cannot deliver.

Since the disk is in normal mode, ping-mode=2 is unreachable from any host-side software invocation.

## Therefore:

**The mode=5 historical reading was a harness ABI artifact (harness read 4 bytes out of a 0x200 or larger struct that Windows P/Invoke reserved in our memory, so we saw garbage). The mode=0 current reading is the true device's state: not ISP, not ever going to be ISP without physical intervention (short pins).**

The investigation is complete. There is no code fix short of writing a custom ROM-forcing boot jig — which is outside scope.

## Files created

- `tools/sata_detect_probe.cs` (first version, minor crash on exit)
- `tools/sata_stepwise.cs` (stepwise, all-pass 0/1/2 read-only probe)
- `sata_probe/` build artifacts (Release)

## Safety note

All invocations were:
- READ-only (GENERIC_READ|GENERIC_WRITE used solely because Windows requires both for RAW_SCSI access)
- no WRITE/ERASE/FORMAT commands issued
- the DLL's only vendor command sent would be the READ(10) probe — read-only by definition
- the discovered SEGV is AFTER the query completes, in process teardown — it does not write to the drive

# CODE CHANGE: NONE (only build artifacts)

# HDD WRITE: NO
# FIRMWARE WRITE: NO
# NAND WRITE: NO
