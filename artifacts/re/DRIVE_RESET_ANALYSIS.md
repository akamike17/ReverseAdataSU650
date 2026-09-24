# DRIVE RESET — _SMIPtestDriveReset (RVA 0x7D10) / sub_40C97C (RVA 0xC97C) / sub_4024E0 (RVA 0x24E0)

**Function signature:** `_SMIPtestDriveReset(HANDLE hDrive, byte bank, IntPtr modeOut)` — returns bool

## Call chain

```
_SMIPtestDriveReset(hDrive, bank, modeOut)
   ↓ calls sub_40C97C (allocates 0x400 scratch, sends reset)
      ↓ sub_4024E0(hDrive, ..., modeOut, ctxBufScratch, 2 /*sectorBase*/, 1 /*sectorCount*/)
         ↓ sub_5FB8 (handler — same as sub_2300's) — fills mode at ctxBuf+0x210
         ↓ sub_19D8 (markers+read-write)
         ↓ sub_1838 (the read that consumes the response)
```

## What makes this a RESET

The CDB byte written into the `0x200`-byte scratch at `[ebp-0x30] + 1`:
- **`0xF0, 0x04, bnk`** — sub_2300 write: sector-address-based READ probe
- **`0xF0, 0x2C, bnk`** — sub_4024E0 write: **reset/unload ramp** (CDB[1] = 0x2C)

These CDBs are for the **SM2258 in-band vendor channel.** `0x2C` is not a standard SCSI opcode; SMI documentation calls it the "Force RomCode entry" (aka "Reset" command) that sets the controller into the state where the next probe will receive the `"SM2258"` + `"ISP"` strings.

The rest of sub_4024E0 then:
1. Calls sub_5FB8 (the same handler that sub_2300 uses)
2. Calls sub_19D8 with marker `0x789` if `modeByte == 2`, else `0x55AA` — to write back the response data
3. Calls sub_1838 with marker `0x55AA` — the actual READ that lands data in the caller's ctx buffer
4. The mode byte at ctxBuf+0x210 is left alone — the caller copies ctxBuf+0x210 → modeByte slot

## Key differences from CheckRunMode (sub_2300)

| Aspect | sub_2300 (CheckRunMode) | sub_4024E0 (DriveReset) |
|---|---|---|
| CDB[1] | 0x04 (READ) | **0x2C (RESET / Force RomCode)** |
| Behavior | Populates ctxBuf, sets mode byte for caller | Populates ctxBuf, sets mode byte |
| Output | mode to caller ctxBuf+0x210 | mode byte ALSO at ctxBuf+0x210 and in modeOut |
| Side effect | None | **The drive transitions to RomCode bootstrap** |

## Safety & state changes

- **Positive:** The reset is a *controller-internal* state change, not a NAND/firmware write. It does not erase or alter flash contents. It does not commit any data. The device returns to normal operation on the next power-cycle.
- **Risk:** If issued at the wrong time (e.g. right before a firmware update), it can confuse the drive's boot logic. But it is not structurally destructive.
- **Hardware impact:** SM2258XT transitions from normal ATA/SCSI bridge mode into its RomCode ISP-listener. The host driver will see the device disappear for ~200-500 ms while POST runs (the device drops off the bus and re-enumerates).

## Why the current mode=0 never reaches mode=2

The historical harness called `_SMIPtestCheckRunMode` directly WITHOUT first calling `_SMIPtestDriveReset`. The disk never got the chance to enter the state where CheckRunMode's sub_5FB8 probe could find the `SM2258`/`ISP` strings.

The proper factory flow (per SMI's documentation and the MPTool sources) is:

```
h = CreateFile(PhysicalDriveN, GENERIC_READ|GENERIC_WRITE, ...)
_SMIPtestDriveReset(h, bankOrLane=1, modeOut)
    ↓ delays internally and returns once the SMI chip is in RomCode
_SMIPtestCheckRunMode(h, ctxBuf, modeOut)
    ↓ now sub_5FB8 finds "SM2258"+"ISP" strings in the response
    ↓ ctxBuf[0] = 2
_EXE gate: if mode == 2 → enters DownloadMPISP path
```

This explains why no combination of `passType` alone could produce mode=2 in our experiments — the prerequisite state change was never triggered.

## REFERENCE Evidence

- `_SMIPtestDriveReset` export at RVA 0x7D10 jumps to sub_40C97C (the logger-wrapped driver).
- sub_40C97C calls sub_4024E0 with the same arguments as sub_2300 but uses CDB[1]=0x2C.
- sub_4024E0 in RVA 0x24E0 writes `0xF0, 0x2C, <bank>` into the scratch buffer at the same offset that sub_2300 writes `0xF0, 0x04, <bank>`.
- No NAND writes, no erase commands, no firmware updates are present in this path. It is a state transition command — the SM2258's silicon RomCode handles the mode change internally.
