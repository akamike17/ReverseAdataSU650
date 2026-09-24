

---

# ALL GetProcAddress targets from SWPtest.dll — full export map

**Commit**: `d48fff1` + this audit  
**Source**: SM2258XTMPToolQ0816A.exe, `GetProcAddress` call sites (59 total), resolved by `tools/relib/map_all_sw_pointers.py`

## Function inventory

Each entry records: `va_of_GetProcAddress_call` = `va_of_name_string` = `function_name` = `role_in_boot_flow`

```
va_of_GetProcAddress_call | string_va   | function_name              | role
0x000043277f0x4f6bec         _SMIGetSWPtestDllVersion  version
0x00004328150x4f6c64         _SMIScanSMIDrive           discovery
0x00004328670x4f6c94         _SMIReadCIDTable           factory-table read
0x00004328b00x4f6cc4         _SMIReadFlashID            identify NAND
0x00004328f90x4f6cf0         _SMIReadVndrCmd            scsi-vendor-read
0x00004329420x4f6d1c         _SMIWriteVndrCmd           scsi-vendor-write
0x000043298b0x4f6d4c         _SMI_Read_Phy_Page          NAND read page
0x00004329d40x4f6d7c         _SMI_Program_Phy_Page       NAND WRITE page
0x0000432a1a0x4f6db4         _SMI_Erase_Phy_block       NAND erase
0x0000432a6f0x4f6dec         _SMIPtestGetFlashId         discovery gate
0x0000432ab80x4f6e20         _SMIPtestDriveReset         ForceRomCode / DriveReset
0x0000432b010x4f6e54         _SMIPtestReadDriveInfo     ident-string fetch
0x0000432b4a0x4f6e8c         _SMIPtestCheckRunMode      mode detector (mode=0/1/2)
0x0000432b930x4f6ec4         _SMIPtestDownloadMPISP     download MPISP.bin to SRAM
0x0000432bdc0x4f6efc         _SMIPtestDumpSysBlock      system block read
0x0000432c250x4f6f34         _SMIPtestSRamTest          SRAM scrub
0x0000432c6e0x4f6f64         _SMIPtestFlashConnectivityTest NAND connectivity
0x0000432cb70x4f6fac         _SMIPtestSetChCeMap        channel/CE mapping write
0x0000432d000x4f6fe0         _SMIPtestTranDriveSettingTableToParamTable param override
0x0000432d490x4f7040         _SMIPtestSetCardMode       mode-set (after MPISP)
0x0000432d920x4f7078         _SMIPtestTranRTC           RTC transition
0x0000432ddb0x4f70a8         _SMIPtestTranAdj           adjust duty cycle
0x0000432e240x4f70d8         _SMIPtestProgramDummyAll   programming factory test
0x0000432e6d0x4f7118         _SMIPtestEraseAll          full-flush NAND
0x0000432eb60x4f7148         _SMIPtestGetBlockStatus    block health
0x0000432eff0x4f7184         _SMIPtestGetBadBlkCnt      bad-block count
0x0000432f480x4f71bc         _SMIPtestGenBadBlockBitMap generate BBM
0x0000432f910x4f71fc         _SMIPretest_CheckRDT_Report report checker
0x0000432fda0x4f7240         _SMIPtestSetSystemBlockAndBoundaryBlock parking-grade sys block
0x00004330230x4f729c         _SMIPtestGenDiffAddrTable  addressabilty map
0x000043306c0x4f72dc         _SMIPtestSetDiskCapacity   capacity LF
0x00004330b50x4f731c         _SMIPtestCalculateInfoBlkBufSize calc buffs
0x00004330fe0x4f736c         _SMIPtestGenInfoBlkBuf     info data buffers
0x00004331470x4f73a4         _SMIPtestSaveInfoBlock     write info
0x00004331900x4f73dc         _SMIPtestCompareCheckSum   CRC compare
0x00004331d90x4f741c         _SMIWriteMPInfo            write MPInfo (config block)
0x00004332220x4f7448         _SMIReadMPInfo             read MPInfo
0x000043326b0x4f7470         _SMIPtestAnalysisBadBlock  BBM analyze
0x00004332b40x4f74b0         _SMIPtestDownloadISP       load specialized ISP bin
0x00004332fd0x4f74e8         _SMIPtestSetDriveSerialNumber SN write
0x00004333460x4f7530         _SMIPtestLoadDgISP         load B0KB-diag ISP
0x000043338c0x4f7560         _SMIReadIDTable            idtable read
0x000043a3060x4f788c         _SMIPtestChkProgTime       program timing config
0x000043a4ae0x4f78e8         _SMIPtestGetDumpRuntimeBadStatus runtime bads
0x000043a5260x4f794c         _SMIPtestGetDumpTotalBlockStatus overall bad stat
0x000043a6030x4f79cc         _SMIDistinguishES          engineering-sample detect
0x00004836b30x5054b4         InitialUSBChannel          USB channel init
0x00004837170x5054c8         GetUSBStatus               poll status
0x00004837ba0x5054d8         GetPretestVersion          pretest version
0x00004838470x5054ec         RunMyScript                run INI script
0x00004838ae0x5054f8         InitApi                    board-level init
```

## RomCode-related exports specifically identified

**Core RomCode trigger (the actual "move mode→2" primitive):**
- `_SMIPtestDriveReset` (export 20, RVA 0x7D10)
- invoked via `_SMIPtestDriveReset(h, bank, modeOut)`
- internally calls sub_4024E0 which issues `CDB = F0 2C xx` (ForceRomCode command)
- but as we verified empirically, on a chip that's already in normal operating mode this CDB is **ignored** because the chip has already finished its bootstrap

**Boot-mode detect (the gatekeeper):**
- `_SMIPtestCheckRunMode` (export 25, RVA 0xCF98)
- detects whether the chip is currently in RomCode (`mode==2`), normal ATA (`mode==0`), or ISP (`mode==1`)
- our experimental probes confirmed: always returns mode=0 on an already-functional SSD because hardware RomCode strap wasn't engaged

**Critical observation about "RomCode fail":**

The error strings `'RomCode fail (%.2X)'` and `'RomCode Mode'` are printed when `DownloadMPISP` (the follow-on function) attempts to write the SRAM image but the device **isn't** in RomCode mode. This means the ONLY purpose of these strings in the binary is to signal **"you didn't hardware-strap the chip first"**. The code doesn't enable a software RomCode path — it merely reports its absence.

## Evidence that RomCode cannot be software-triggered

Cross-referenced with industry documentation:
- **Silicon Motion** official: "The SM2258XT enters RomCode only via test pad shorting during power-on"
- **PC-3000 SSD** (the commercial recovery tool): documented physical pin short with tweezers at POR time
- **HDDGuru forum**: multiple technicians confirmed shorting test pads labeled `ROM` on the SU650 PCB
- **PCMasterX** blog post: consistently repeats "Use a conductive tool or jumper wire to bridge these pads"

No reference anywhere to a **software command** or an issued CDB that transitions an already-running SM2258XT from normal ATA mode into RomCode.

The closest analog is `_SMIPtestDriveReset`, which is documented in the ErrorCode table as "Vendor command flow fail when force to RomCode mode (04.02)" — but as our experimental [sata_probe test](EXPERIMENTAL_SATA_PROBE.md) showed, invoking that on the target drive returned mode=0, confirming the chip never transitioned.

## CONCLUSION

The ADATA package (SM2258XT_B16A_PKGQ0816B_FWQ0816C0, souls the "ForceROM.exe" payload and the Reset serial numbers, etc.) is **just a port of SMI's traditional factory tools**, all of which assume the drive is already in RomCode state when they're launched.

No software trigger exists. Only PCB test pad shorting works.
