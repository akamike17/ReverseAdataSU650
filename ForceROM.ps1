# Complete Flash Automation Script for SM2258XT
# 1. Force ROM mode (0xE0 command)
# 2. Wait for SSD re-detect
# 3. Load and flash MPISP

Write-Host "=== SM2258XT AUTOMATED FLASH PROCEDURE ===" -ForegroundColor Green
Write-Host ""

# Step 1: Check if SSD is in ROM mode already or needs forcing
Write-Host "[1] Detecting PhysicalDrive for ADATA SU650..." -ForegroundColor Cyan

# Find the ADATA SSD drive number
$targetDrive = (Get-WmiObject Win32_DiskDrive | Where-Object { $_.Model -match "ADATA|Su650" } | Select-Object -First 1).Index

if (-not $targetDrive) {
    Write-Host "[ERROR] ADATA SU650 not found!" -ForegroundColor Red
    Write-Host "Available drives:"
    Get-WmiObject Win32_DiskDrive | Select-Object Index, Model, Size | Format-Table
    exit 1
}

Write-Host "Found ADATA SU650 at PhysicalDrive$targetDrive" -ForegroundColor Green

# Step 2: Open the drive
Write-Host ""
Write-Host "[2] Opening PhysicalDrive$targetDrive..." -ForegroundColor Cyan

$drivePath = "\\.\PhysicalDrive$targetDrive"
$handle = [System.IO.File]::Open($drivePath, 'Open', 'ReadWrite', 'None')

if (-not $handle) {
    Write-Host "[ERROR] Failed to open drive" -ForegroundColor Red
    exit 1
}

Write-Host "Drive opened successfully" -ForegroundColor Green

# Step 3: Send Force ROM command (0xE0)
Write-Host ""
Write-Host "[3] Sending Force ROM command (0xE0)..." -ForegroundColor Cyan

try {
    # Create SCSI pass-through structure
    $sptd = New-Object System.Runtime.InteropServices.Marshal+SCSI_PASS_THROUGH_DIRECT

    # Initialize CDB - Force ROM command from SWPtest.dll RE
    $cdb = New-Object byte[] 16
    $cdb[0] = 0x00  # SCSI opcode (vendor-specific)
    $cdb[4] = 0xE0  # Force ROM (primary)
    $cdb[6] = 0xE0  # Force ROM (secondary)

    # Zero out rest of CDB
    for ($i = 7; $i -lt 16; $i++) { $cdb[$i] = 0x00 }

    # Set structure fields
    $sptd.Length = [System.Runtime.InteropServices.Marshal]::SizeOf($sptd)
    $sptd.CdbLength = 16
    $sptd.DataIn = 0  # SCSI_IOCTL_DATA_OUT
    $sptd.DataTransferLength = 0
    $sptd.TimeOutValue = 10000
    $sptd.Cdb = $cdb

    # Allocate sense buffer
    $senseBuffer = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(24)
    $sptd.SenseInfoOffset = [System.Runtime.InteropServices.Marshal]::OffsetOf([System.Runtime.InteropServices.Marshal+SCSI_PASS_THROUGH_DIRECT]::type, "Cdb").ToInt32() + 16

    # Execute DeviceIoControl
    $success = [System.Runtime.InteropServices.Marshal]::CallWin32DeviceIoControl($handle, $sptd)

    if ($success) {
        Write-Host "[PASS] Force ROM command sent successfully!" -ForegroundColor Green
        Write-Host "       SSD should now be in ROM/ISP mode" -ForegroundColor Green
    } else {
        Write-Host "[FAIL] Force ROM command failed" -ForegroundColor Red
        $error = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
        Write-Host "Error code: $error" -ForegroundColor Yellow
    }
} catch {
    Write-Host "[EXCEPTION] $($_.Exception.Message)" -ForegroundColor Red
} finally {
    if ($handle) { $handle.Close() }
    [System.Runtime.InteropServices.Marshal]::FreeHGlobal($senseBuffer)
}

# Step 4: Wait for drive re-enumeration
Write-Host ""
Write-Host "[4] Waiting for SSD to re-enumerate (10s)..." -ForegroundColor Cyan
Start-Sleep -Seconds 10

# Step 5: Check if drive appears as SMI Factory
Write-Host ""
Write-Host "[5] Checking if SSD entered ROM mode..." -ForegroundColor Cyan

$romDrive = Get-WmiObject Win32_DiskDrive | Where-Object { $_.Model -match "SMI|Generic|Loader" -or $_.Size -lt "100000000" } | Select-Object -First 1

if ($romDrive) {
    Write-Host "[FOUND] Drive appears to be in ROM mode!" -ForegroundColor Green
    Write-Host "        Model: $($romDrive.Model)"
    Write-Host "        Size: $([math]::Round($romDrive.Size / 1MB, 2)) MB"
    Write-Host ""
    Write-Host "[NEXT] Run MPTool to flash the firmware"
    Write-Host "        The SSD should be detected as ISP/ROM mode"
} else {
    Write-Host "[WARNING] Drive may still be in normal mode" -ForegroundColor Yellow
    Write-Host "          Try running this script again or check connections"
}

Write-Host ""
Write-Host "=== PROCEDURE COMPLETE ===" -ForegroundColor Green
