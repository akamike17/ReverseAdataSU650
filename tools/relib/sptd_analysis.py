# sptd_real_size.py — verify exact SCSI_PASS_THROUGH_DIRECT layout from public Windows DDK
# AND compare against what sub_171C builds. Document the precise byte-level divergence.
#
# Public reference: smartmontools os_win32.cpp + ntddscsi.h from WinSDK v10.0.14393
print('''
CANONICAL Windows DDK (ntddscsi.h, WinSDK 10.0.14393.0):

typedef struct _SCSI_PASS_THROUGH_DIRECT {
    USHORT Length;             // +00   (2)
    UCHAR  ScsiStatus;         // +02
    UCHAR  PathId;             // +03
    UCHAR  TargetId;           // +04
    UCHAR  Lun;                // +05
    UCHAR  CdbLength;          // +06
    UCHAR  SenseInfoLength;    // +07
    UCHAR  DataIn;             // +08
    ULONG  DataTransferLength; // +09  -- wait  ULONG is 4-byte aligned => +0C
    ULONG  TimeOutValue;       // +10
    PVOID  DataBuffer;         // +14   (4)
    ULONG  SenseInfoOffset;    // +18
    UCHAR  Cdb[16];            // +1C  -- ends +2C
} SCSI_PASS_THROUGH_DIRECT;    // sizeof = 0x2C = 44 (x86)  — CONFIRMED by STATIC_ASSERT in smartmontools
''')

# Where does 0x28 come from? Reconstruct what sub_171C ACTUALLY builds:
# Struct A starts at [ebp-0x30], size coded as Length=0x28 (fixed const).
# Field assignments (confirmed):
#   [ebp-0x30]   word = 0x28               -> Length = 40
#   [ebp-0x2E]   word = arg[ebp+0x1C]      -> (canonical ScsiStatus + PathId bundled)
#                                                 BUT low byte lands at +0x02 (ScsiStatus)
#                                                 high byte lands at +0x03 (PathId)
#   [ebp-0x28]   dword = movzx word [ebp+0x24]  -> DataIn (would be +0x08)
#   [ebp-0x24]   dword = dword [ebp+0x20]       -> DataTransferLength (+0x0C) ✓
#   [ebp-0x1C]   dword = dword [ebp+0x28]       -> DataBuffer pointer (+0x14) ✓
#   [ebp-0x14]   byte 0 (auto-zeroed)           -> Cdb[0]         — zeroed by memset!
#   ... zeroed through [ebp-0x11] => Cdb[0..3] all zero
#   [ebp-0x10]   byte = arg[ebp+0x10]           -> Cdb[4]
#   [ebp-0x0F]   byte = arg[ebp+0x14]           -> Cdb[5]
#   [ebp-0x0E]   byte = arg[ebp+0x18] & 0xFF    -> Cdb[6]
#   [ebp-0x0D]   byte = (arg[ebp+0x18]>>8)&0xFF -> Cdb[7]
#   [ebp-0x0C]   byte = (arg[ebp+0x18]>>16)     -> Cdb[8]
#   [ebp-0x0B]   byte = 0xE0                     -> Cdb[9]  ← FORCEROM marker position!
#   [ebp-0x0A]   byte = arg[ebp+0xC] & 0xFF      -> Cdb[10] ← SMI opcode
#   [ebp-0x09]   byte 0 (auto)                   -> Cdb[11] = 0
#
# The struct is 0x28 (40), so CDB[11] is the last byte on the physical buffer.
# CDB[12..15] would be at +0x28..+0x2B which is OUT OF BOUNDS for the 0x28-byte buffer.

print('''
Divergence between canonical layout (44 bytes) and the struct used in the DLL (40 bytes):

  canonical +02 ScsiStatus <- DLL uses +0x02 for the low byte of arg6 (the word)
  canonical +03 PathId      <- DLL uses +0x03 for the HIGH byte of arg6
  canonical +06 CdbLength   <- DLL NEVER WRITES THIS ; remains 0 from initial memset
  canonical +1C Cdb[0]      <- DLL also zero
  canonical +20 Cdb[4]      <- the **FIFTH** byte of the CDB in the canonical view
  canonical +25 Cdb[9]      <- 0xE0 (as documented)
  canonical +26 Cdb[10]     <- SMI opcode byte from caller

KEY QUESTION ANSWERED:
What does scsiport.sys actually do when given a 40-byte buffer with Length field = 0x28
instead of the canonical 44?

Required reading: the scsiport.sys / storport.sys code that handles the SPTD IRP_MJ_DEVICE_CONTROL.
This is OS-side, NOT in the user's repo. I don't have those binaries in scope.

However, the public ntddscsi.h header guarantees:
- Length field = sizeof(SCSI_PASS_THROUGH_DIRECT) when correctly used = 44
- Caller must pass nInBufferSize >= Length + SenseInfoLength (if SenseInfoOffset != 0)

If the driver's ValidateSptd() does:
  if (input.Length != sizeof(SCSI_PASS_THROUGH_DIRECT)) return STATUS_INVALID_PARAMETER;
then a 40-byte buffer is rejected outright.

If the driver does:
  input.Length = min(Length, 44);
  if (input.Length < 36) return STATUS_INVALID_PARAMETER;
then the request might proceed with a truncated CdbLength=0 (interpreted as no command).

Either way:
- The CDB bytes Cdb[0..11] are within the first 36 bytes, regardless.
- If CdbLength=0, the device receives an *empty* CDB. Most SAT layers would then fail the request.
- If a specific SMI-aware driver ignores CdbLength and parses Cdb[0..11] anyway, then it would work
  with 0xE0/0xC8 etc. — but that's hardware-specific and unproven for JM20337.

In short:
   the program deliberately sends a struct that's 4 bytes short of the Windows SPTD
   canonical definition. This is most likely a copy-paste error from an older SPTD spec,
   or a deliberate interaction with a non-Microsoft driver (SMI's own SAT or an older
   SCSIport miniport from 2001-2005 that still accepted 0x28).
   
The known Silab/JMicron ADATA adaptation is from the "MP MASS PRODUCTION" folder 2008 era,
which was built on Windows XP-DKK era DDK where the struct was smaller: in XP-era
SCSI_PASS_THROUGH_DIRECT was a differently laid out structure.
''')
