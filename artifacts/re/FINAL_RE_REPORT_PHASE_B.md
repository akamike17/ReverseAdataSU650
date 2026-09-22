# FINAL_RE_REPORT_PHASE_B.md — Static reverse-walk evidence

Target: ADATA SU650 120GB / SM2258XT (SATA)

## 1. EXE Callers of _SMIPtestDownloadMPISP

**Slot 0x507F70:**
- **0x3DEF** in function `0x3BB7` (prologue at 0x3BB7)
- **0x3D405** in function `0x3D1A2` (prologue at 0x3D1A2)
- **0x40878** in function `0x401F1` (prologue at 0x401F1)

### Function 0x3BB7
- Opens `\Firmware\2258\MPISP2258.bin` (string at 0x4EC760/0x4EC780)
- Calls:   Open → malloc(0x800) → memset(0x800) → ReadFile
-        → `_SMIPtestDownloadMPISP(buffer, length, handle?, context?)`
- Errors: "Download MPISP fail (1)" / "Download MPISP fail (2)"

### Function 0x3D1A2
- Same pattern but errors: "Can't open %s..." + "Can't allocate memory..."

### Function 0x401F1
- Larger stack frame (0x2E9C); also calls 0x3BB7 via 0x401E3

## 2. Enum/Detection Path (SWPtest.dll)

### `_SMIScanSMIDrive` → `sub_13DC` (scan loop)
- Str: `\\.\PhysicalDrive%d` (0x447350 in DLL, i.e. RVA 0x47350)
- Loop: `PhysicalDrive0` .. `PhysicalDrive0xF` (0x10 ports)
- Per port: `CreateFile` → `DeviceIoControl(0x4D014)`, `Cdb=F1`
- If success: stores handle, increments counter

### `sub_5FB8` (validates which ports are SMI)
- Allocates 0x200 buffer
- Sends vendor commands: 0xAA, 0xAA00, 0x55, 0x5500, 0x55AA
- These values go through `sub_1838` → `sub_19D8` (opcode translation)
- On wire (SATA): `CDB` with `0xE0` (Force ROM)

## 3. How the flow reaches DownloadMPISP

`0x3594` (function containing 0x2548 → 0x3BB7) is called by external code.
The EXE likely has GUI event → thread → Scan → DownloadMPISP flow.

**Gate conditions observed inside download path:**
- `cmp byte ptr [ebp-0x80c], 2` → branch to `call 0x3BB7`
- If mode == 2 (handled as a binary value at that memory offset)
  → calls DownloadMPISP-related function
- If mode != 2 → `push 0x4ec718` ("It's not ISP Mode !") + error path

**Interpretation:** the `mode` value must equal 2 to proceed. Strings suggest:
- Rom Mode → 0x4EC944
- MPISP Mode → 0x4EC950
- ISP Mode → 0x4EC95C

But `cmp eax, 2 / je` means the value must be exactly **2**.
Whether "Rom/MPISP/ISP" is indexed by that value in a switch/jump-table
is UNKNOWN without dynamic evidence or tracing the surrounding jumps.

## 4. Why enumeration might not reach DownloadMPISP on our SSD

**Observed in runtime (RUN_A):**
- `0x2d1080` (IOCTL_STORAGE_QUERY_PROPERTY) called 3× — OS enumeration
- `0x390008` (MOUNTMGR) called 1×
- No `0x4D014` or `0x4D030` calls seen
- No `caller_hit` events on DownloadMPISP sites

**Implication:**
- The SSD is either:
  (a) Not appearing as PhysicalDrive0-15
  (b) Not responding to CreateFile
  (c) Not responding to DeviceIoControl(0x4D014)
  (d) Responding but with unexpected data (vendor rejected)

**Static evidence alone cannot determine which.** Dynamic capture required.

## 5. ForceROM.cs vs binary reality

- ForceROM uses IOCTL 0x4D112 (absolute value)
- SWPtest.dll uses 0x4D014 and 0x4D030 (relative toDeviceIoControl()
- **0x4D112 does NOT appear in SWPtest.dll**

## 6. Open questions still requiring dynamic capture

1. Exact caller sequence: which function calls 0x3594
2. Exact argument values passed to `_SMIPtestDownloadMPISP`
3. Exact context pointer and size
4. Why enumeration fails for our SSD
5. Exact CDB bytes for Force ROM
6. Whether `RunMode=5` means ISP or another state

## 7. Evidence classification

| Item                          | Status  | Where |
|-------------------------------|---------|-------|
| DownloadMPISP 3 callers       | CONFIRMED| static cross-reference + disassembly |
| Open → malloc → memset → read → DownloadMPISP | CONFIRMED | function disassembly |
| `PhysicalDrive%d` loop        | CONFIRMED | string + code in DLL   |
| `0x4D014` / `0x4D030` IOCTLs  | CONFIRMED | CSI candidates + function disassembly |
| Mode == 2 required to reach DownloadMPISP | CONFIRMED | cmp/je + call chain
| ForceROM IOCTL 0x4D112 wrong  | CONFIRMED | never appears in DLL   |
| Strings indicating modes      | CONFIRMED | strings + code         |
| Dynamic call sequence         | UNKNOWN   | requires capture       |
| Context pointer/structure     | UNKNOWN   | requires capture       |
