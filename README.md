# SM2258XT SSD Firmware Reverse Engineering - Complete Documentation

## Project Overview
Target: ADATA SU650 120GB SSD with SM2258XT controller (SATA, not USB)
Goal: evidence-based reconstruction of the MPTool -> SWPtest.dll call path
Status: STATIC analysis only; dynamic capture (callers, context) still OPEN

NOTE: ForceROM/Program.cs was found to use IOCTL 0x4D112 which does NOT
match the value observed in SWPtest.dll (0x4D030). It is QUARANTINED.

Evidence classification: [CONFIRMED] static byte pattern or traced ref;
[OBSERVED] real runtime value seen previously; [HYPOTHESIS] candidate
not yet proven; [UNKNOWN] missing evidence.

## Architecture Analysis

### SWPtest.dll Exports (93 functions)
Key functions identified through static analysis:

| Function | RVA | Purpose | Call Chain |
|----------|-----|---------|------------|
| `_SMIPtestDownloadMPISP` | 0x7AD8 | Download MPISP firmware | sub_D268 → sub_2300 → sub_19D8 |
| `_SMIPtestCheckRunMode` | 0x7C84 | Check current mode | sub_CF98 |
| `_SMIPtestDriveReset` | 0x7D10 | Reset drive | sub_C97C → sub_2300 |
| `_SMIReadFlashID` | 0x6D90 | Read NAND flash ID | sub_33F0 |
| `_SMIScanSMIDrive` | 0x6B5C | Scan for drives | sub_131F |

### Call Chain Analysis
Complete trace of _SMIPtestDownloadMPISP:

```
_SMIPtestDownloadMPISP (0x7AD8)
```
  ↓
```
sub_D268 (0xD268) - Main ISP download logic
  → sub_2300 (0x2300) - Parameter validation
  → sub_19D8 (0x19D8) - Command translation
  → sub_1558 (0x1558) - Final error handling
```

### Command Translation (sub_19D8)
The critical function that translates vendor codes:

```
Input (Pre-translation): 0xA1, 0x2A, 0x28
↓
sub_19D8
↓
Output (Wire): 0xE0 (Force ROM)
```

## Known Commands

### Force ROM Command (0xE0)
From `sub_19D8` disassembly:
```
CDB: 00 00 00 00 E0 00 E0 00 00 00 00 00 00 00 00 00
IOCTL: 0x4D030 (SCSI_PASS_THROUGH_DIRECT)
DataIn: 0 (OUT)
```

### CheckRunMode Command (0xF1)
From `_SMIPtestCheckRunMode` call chain:
```
CDB: F1 00 00 00 00 00 00 00 00 00 00 00
IOCTL: 0x4D014 (SCSI_PASS_THROUGH)
DataIn: 1 (IN)
```

## Context Structure Hypothesis

Based on crash analysis at 0xC0000005:
- Crash at `mov byte ptr [edx+eax], cl`
- Writing to invalid memory accessed via EDX+ offset
- Suggests context structure has calculated fields

## Files Generated

See `analysis/` directory for:
- `full_analysis_*.log` - Complete call chain traces
- `analysis_results.txt` - Summary of export analysis

## Next Steps

1. Capture dynamic state during real flash operation
2. Verify context structure hypothesis
3. Build automated flasher

## References

- SMI MPTool Documentation
- NAND Flash specifications (Micron B16A/B27A)
- x64dbg dynamic analysis
3. Reconstruct MPTool.exe's context preparation code

## Status: IN PROGRESS

[Phase 1: Static Analysis] ✓ COMPLETE
[Phase 2: Dynamic Capture] ⚠ IN PROGRESS
[Phase 3: Automation] ⏳ PENDING

## Safety Notes

- All analysis is READ-ONLY
- No firmware modifications performed
- No destructive operations attempted
- Test environment isolated from production systems
</content>
</invoke>
