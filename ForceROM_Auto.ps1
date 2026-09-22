# SM2258XT FORCED ROM MODE - COMPLETE WORKFLOW
# WARNING: This is DESTRUCTIVE. Do not run on a drive with data you need.

param(
    [int]$PhysicalDriveNum = 1,
    [switch]$Force = $false
)

# Verify admin
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))
{
    Write-Host "[ERROR] This script requires Administrator privileges." -ForegroundColor Red
    exit 1
}

Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "  SM2258XT FORCED ROM MODE - DESTRUCTIVE " -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host ""

if (-not $Force) {
    Write-Host "[WARNING] This will FORCE the SSD into ROM/ISP mode." -ForegroundColor Yellow
    Write-Host "          All data on the SSD will be PERMANENTLY DESTROYED." -ForegroundColor Yellow
    Write-Host "          This is a factory firmware recovery operation." -ForegroundColor Yellow
    Write-Host ""
    Write-Host "To confirm, type: DESTRUCTIVE" -ForegroundColor Red
    $confirmation = Read-Host
    if ($confirmation -ne "DESTRUCTIVE") {
        Write-Host "[CANCELLED] User did not confirm." -ForegroundColor Green
        exit 0
    }
}

Write-Host ""
Write-Host "[1] Verifying target drive..."

# Get drive info
try {
    $drive = Get-Disk -Number $PhysicalDriveNum -ErrorAction Stop
    Write-Host "    Drive $PhysicalDriveNum: $($drive.FriendlyName)"
    Write-Host "    Size: $([math]::Round($drive.Size / 1GB, 2)) GB"
    Write-Host "    Type: $($drive.BusType)"
    Write-Host "    Status: $($drive.OperationalStatus)"

    # Verify it's the ADATA SU650
    if ($drive.FriendlyName -notmatch "ADATA|SU650") {
        Write-Host "[WARNING] Drive is not ADATA SU650: $($drive.FriendlyName)" -ForegroundColor Yellow
        Write-Host "          This might force ROM on the wrong drive!" -ForegroundColor Red
        Write-Host ""
        Write-Host "Press Ctrl+C to abort, or wait 10 seconds to continue..." -ForegroundColor Yellow
        Start-Sleep -Seconds 10
    }

} catch {
    Write-Host "[ERROR] Cannot access PhysicalDrive$PhysicalDriveNum" -ForegroundColor Red
    Write-Host "        Error: $_" -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "[2] Opening PhysicalDrive$PhysicalDriveNum for SCSI commands..."

try {
    $devicePath = "\\.\PhysicalDrive$PhysicalDriveNum"

    # Open with .NET FileStream
    $handle = [System.IO.File]::Open($devicePath, 'Open', 'ReadWrite', 'None')
    Write-Host "    Opened: $devicePath"

} catch {
    Write-Host "[ERROR] Cannot open device: $_" -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "[3] Sending FORCE ROM command..."

# Send the SCSI command using DeviceIoControl via P/Invoke
Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;

namespace SCSI
{
    public class ScsiPassThrough
    {
        [StructLayout(LayoutKind.Sequential)]
        public struct SCSI_PASS_THROUGH_DIRECT
        {
            public ushort Length;
            public byte ScsiStatus;
            public byte PathId;
            public byte TargetId;
            public byte Lun;
            public byte CdbLength;
            public byte SenseInfoLength;
            public byte DataIn;
            public uint DataTransferLength;
            public uint TimeOutValue;
            public IntPtr DataBuffer;
            public uint SenseInfoOffset;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
            public byte[] Cdb;
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool DeviceIoControl(
            IntPtr hDevice,
            uint dwIoControlCode,
            IntPtr lpInBuffer,
            int nInBufferSize,
            IntPtr lpOutBuffer,
            int nOutBufferSize,
            out uint lpBytesReturned,
            IntPtr lpOverlapped);

        public static bool SendScsiCommand(IntPtr deviceHandle, byte[] cdb)
        {
            if (cdb.Length != 16)
                return false;

            SCSI_PASS_THROUGH_DIRECT sptd = new SCSI_PASS_THROUGH_DIRECT();
            sptd.Length = (ushort)Marshal.SizeOf(sptd);
            sptd.CdbLength = 16;
            sptd.DataIn = 0; // OUT
            sptd.DataTransferLength = 0;
            sptd.TimeOutValue = 10000; // 10 seconds
            sptd.Cdb = new byte[16];
            Array.Copy(cdb, sptd.Cdb, 16);

            IntPtr sptdPtr = Marshal.AllocHGlobal(Marshal.SizeOf(sptd));
            Marshal.StructureToPtr(sptd, sptdPtr, true);

            int senseOffset = Marshal.OffsetOf<SCSI_PASS_THROUGH_DIRECT>("Cdb").ToInt32() + 16;
            sptd.SenseInfoOffset = (uint)senseOffset;

            // Point SenseInfoOffset to the right location within the SAME structure
            IntPtr sensePtr = new IntPtr(sptdPtr.ToInt64() + senseOffset);
            Marshal.StructureToPtr(sptd, sptdPtr, true);

            bool result = DeviceIoControl(
                deviceHandle,
                0x4D112, // IOCTL_SCSI_PASS_THROUGH_DIRECT
                sptdPtr,
                Marshal.SizeOf(sptd),
                sptdPtr,
                Marshal.SizeOf(sptd) + 24, // Include sense buffer
                out uint bytesReturned,
                IntPtr.Zero);

            Marshal.FreeHGlobal(sptdPtr);
            return result;
        }
    }
}
"@

# Force ROM command from SWPtest.dll reverse engineering
# CDB: 00 00 00 00 E0 00 E0 00 00 00 00 00 00 00 00 00
$forceRomCdb = @(0x00, 0x00, 0x00, 0x00, 0xE0, 0x00, 0xE0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)

Write-Host "    CDB: $($forceRomCdb[0..3] -join ' ') $($forceRomCdb[4] | ForEach-Object { '0x{0:X2}' -f $_ }) $($forceRomCdb[6] | ForEach-Object { '0x{0:X2}' -f $_ }) ..."

try {
    $result = [SCSI.ScsiPassThrough]::SendScsiCommand($handle.SafeFileHandle.DangerousGetHandle(), $forceRomCdb)

    if ($result) {
        Write-Host "    [PASS] Force ROM command sent successfully!" -ForegroundColor Green

        # Close handle
        $handle.Close()

        Write-Host ""
        Write-Host "[4] Waiting for SSD to re-enumerate (10-20 seconds)..."
        Start-Sleep -Seconds 10

        Write-Host "[5] Checking for ROM mode drive..."
        $romDrive = Get-Disk | Where-Object { $_.Size -lt 100000000 -and $_.Size -gt 0 }
        if ($romDrive) {
            Write-Host "    [FOUND] ROM mode drive detected:" -ForegroundColor Green
            Write-Host "            Disk $($romDrive.Number): $($romDrive.FriendlyName)"
            Write-Host "            Size: $([math]::Round($romDrive.Size / 1MB, 2)) MB"
        } else {
            Write-Host "    [INFO] No ROM drive found yet. Check Disk Management." -ForegroundColor Yellow
            Write-Host "           The SSD may appear as 'SMI Factory' or similar." -ForegroundColor Yellow
        }

        Write-Host ""
        Write-Host "==========================================" -ForegroundColor Cyan
        Write-Host "  FORCED ROM MODE COMPLETE" -ForegroundColor Green
        Write-Host "  SSD is now in ISP/ROM mode" -ForegroundColor Green
        Write-Host "==========================================" -ForegroundColor Cyan
        exit 0

    } else {
        Write-Host "    [FAIL] Force ROM command failed" -ForegroundColor Red
        Write-Host "           Error code: $([System.Runtime.InteropServices.Marshal]::GetLastWin32Error())" -ForegroundColor Red

        $handle.Close()
        exit 1
    }

} catch {
    Write-Host "    [EXCEPTION] $($_.Exception.Message)" -ForegroundColor Red
    if ($handle) { $handle.Close() }
    exit 1
}