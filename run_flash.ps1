# SM2258XT MPTool GUI Automation via PowerShell + Windows API
# Requires: Run as Administrator
# Usage: powershell.exe -ExecutionPolicy Bypass -File run_flash.ps1

param(
    [switch]$AutoElevate = $true
)

$ErrorActionPreference = "Continue"

# Check if running as admin
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin -and $AutoElevate) {
    Write-Host "Not running as admin. Attempting auto-elevation..."
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = "powershell.exe"
    $psi.Arguments = "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`" -AutoElevate:`$false"
    $psi.Verb = "runas"
    $psi.WorkingDirectory = Get-Location
    try {
        [System.Diagnostics.Process]::Start($psi) | Out-Null
        Write-Host "Elevated process started. Check the new window."
        exit 0
    } catch {
        Write-Host "ERROR: Could not elevate: $_"
        exit 1
    }
}

if (-not $isAdmin) {
    Write-Host "ERROR: This script requires Administrator privileges"
    Write-Host "Please run as Administrator or use -AutoElevate"
    exit 1
}

# === ADMIN PRIVILEGES CONFIRMED ===

$LogDir = "C:\SM2258XT_MPTool\log"
$Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$LogFile = "$LogDir\flash_auto_$Timestamp.log"

New-Item -ItemType Directory -Path $LogDir -Force -ErrorAction SilentlyContinue | Out-Null
Start-Transcript -Path $LogFile -Append

Write-Host "=== SM2258XT FLASH AUTOMATION ==="
Write-Host "Start: $(Get-Date)"
Write-Host "Running as: $(whoami)"
Write-Host "Admin: $isAdmin"
Write-Host ""

# Step 0: Verify files
Write-Host "[0] VERIFYING PACKAGE FILES..."
$required = @(
    "Dll\SWPtest.dll",
    "Firmware\2258\IMB16\BootISP2258.bin",
    "Firmware\2258\IMB16\00\ISP2258.bin",
    "Firmware\2258\IMB16\00\DgISP\DgISP_VendorCmd.bin",
    "FlashDB\2258\Flash.SET"
)

$allOk = $true
foreach ($f in $required) {
    $path = "C:\SM2258XT_MPTool\$f"
    if (Test-Path $path) {
        $size = (Get-Item $path).Length
        Write-Host "  OK: $f ($size bytes)"
    } else {
        Write-Host "  MISSING: $f"
        $allOk = $false
    }
}

if (-not $allOk) {
    Write-Host "ERROR: Missing required files"
    Stop-Transcript
    exit 1
}

# Step 1: Verify target drive
Write-Host ""
Write-Host "[1] VERIFYING TARGET DRIVE..."
$targetDrive = Get-WmiObject Win32_DiskDrive | Where-Object { $_.Model -like "*ADATA*" -and $_.Model -like "*SU650*" }
if (-not $targetDrive) {
    Write-Host "ERROR: ADATA SU650 not found"
    Stop-Transcript
    exit 1
}
Write-Host "  Found: $($targetDrive.Model) on PhysicalDrive$($targetDrive.Index)"
Write-Host "  Size: $($targetDrive.Size) bytes"
Write-Host "  Firmware: $($targetDrive.FirmwareRevision)"

# Step 2: Check current mode (can we read SMART?)
Write-Host ""
Write-Host "[2] CHECKING DRIVE MODE..."
try {
    $smart = Get-WmiObject -Namespace root\wmi -Class MSStorageDriver_FailurePredictStatus -ErrorAction Stop | 
             Where-Object { $_.InstanceName -like "*ADATA*" }
    if ($smart) {
        Write-Host "  Drive is in NORMAL mode (SMART accessible)"
        Write-Host "  PredictFailure: $($smart.PredictFailure)"
    }
} catch {
    Write-Host "  Drive may be in ROM/LOADER mode (SMART not accessible)"
}

# Step 3: Launch MPTool
Write-Host ""
Write-Host "[3] LAUNCHING MPTOOL..."
$mptoolPath = "C:\SM2258XT_MPTool\SM2258XTMPToolQ0816A.exe"
$mptoolDir = "C:\SM2258XT_MPTool"

# Kill any existing MPTool processes
Get-Process -Name "SM2258XTMPTool*" -ErrorAction SilentlyContinue | Stop-Process -Force

$process = Start-Process -FilePath $mptoolPath -WorkingDirectory $mptoolDir -PassThru
Write-Host "  Started PID: $($process.Id)"

# Wait for window
$timeout = 30
$sw = [System.Diagnostics.Stopwatch]::StartNew()
$mainWindow = $null

while ($sw.Elapsed.TotalSeconds -lt $timeout) {
    $process.Refresh()
    if ($process.MainWindowHandle -ne 0) {
        $mainWindow = $process.MainWindowHandle
        break
    }
    Start-Sleep -Milliseconds 500
}

if (-not $mainWindow -or $mainWindow -eq 0) {
    Write-Host "ERROR: MPTool window not found after $timeout seconds"
    $process.Kill()
    Stop-Transcript
    exit 1
}

Write-Host "  Window handle: $mainWindow"
Write-Host "  Window title: $($process.MainWindowTitle)"

# Step 4: UI Automation using Windows API
Write-Host ""
Write-Host "[4] ATTEMPTING UI AUTOMATION..."

# Add Windows API types
Add-Type @"
using System;
using System.Runtime.InteropServices;
using System.Text;

public class WinAPI {
    [DllImport("user32.dll", SetLastError = true)]
    public static extern IntPtr FindWindow(string lpClassName, string lpWindowName);
    
    [DllImport("user32.dll", SetLastError = true)]
    public static extern IntPtr FindWindowEx(IntPtr hwndParent, IntPtr hwndChildAfter, string lpszClass, string lpszWindow);
    
    [DllImport("user32.dll", SetLastError = true)]
    public static extern bool SetForegroundWindow(IntPtr hWnd);
    
    [DllImport("user32.dll", SetLastError = true)]
    public static extern IntPtr SendMessage(IntPtr hWnd, uint Msg, IntPtr wParam, IntPtr lParam);
    
    [DllImport("user32.dll", SetLastError = true)]
    public static extern bool PostMessage(IntPtr hWnd, uint Msg, IntPtr wParam, IntPtr lParam);
    
    [DllImport("user32.dll", SetLastError = true)]
    public static extern int GetWindowText(IntPtr hWnd, StringBuilder text, int count);
    
    [DllImport("user32.dll", SetLastError = true)]
    public static extern bool EnumChildWindows(IntPtr hwndParent, EnumWindowsProc lpEnumFunc, IntPtr lParam);
    
    public delegate bool EnumWindowsProc(IntPtr hWnd, IntPtr lParam);
    
    public const uint BM_CLICK = 0x00F5;
    public const uint WM_GETTEXT = 0x000D;
    public const uint WM_GETTEXTLENGTH = 0x000E;
}
"@

# Function to get window text
function Get-WindowText($hwnd) {
    $length = [WinAPI]::SendMessage($hwnd, [WinAPI]::WM_GETTEXTLENGTH, [IntPtr]::Zero, [IntPtr]::Zero)
    if ($length -gt 0) {
        $sb = New-Object System.Text.StringBuilder($length + 1)
        [WinAPI]::SendMessage($hwnd, [WinAPI]::WM_GETTEXT, $length + 1, $sb) | Out-Null
        return $sb.ToString()
    }
    return ""
}

# Bring window to front
[WinAPI]::SetForegroundWindow($mainWindow)
Start-Sleep 2

# Try to enumerate child windows to find controls
$script:childWindows = @()
$enumProc = {
    param($hwnd, $lParam)
    $text = Get-WindowText $hwnd
    $script:childWindows += @{
        Handle = $hwnd
        Text = $text
    }
    return $true
}

# Note: This is a simplified approach. For full control, we need
# actual window class names and control IDs from the MPTool executable.
# Without UI Spy or similar tools, we're limited to:
# 1. Sending keystrokes (Tab, Enter, Space)
# 2. Mouse clicks at coordinates
# 3. Waiting for specific text in window title/content

Write-Host "  Window text: $(Get-WindowText $mainWindow)"

# Attempt to trigger Scan via keyboard (common shortcut: F5 or Ctrl+S or just wait for auto-scan)
Write-Host "  Sending F5 (Scan refresh)..."
[WinAPI]::SetForegroundWindow($mainWindow)
Start-Sleep -Milliseconds 500
[System.Windows.Forms.SendKeys]::SendWait("{F5}")
Start-Sleep 3

# Check if drive appears (window text changes)
$newText = Get-WindowText $mainWindow
Write-Host "  Window text after F5: $newText"

# If we see SM2258XT or NAND ID in window, proceed
if ($newText -match "SM2258|2258XT|2C.*A4.*08") {
    Write-Host "  Drive detected in window!"
} else {
    Write-Host "  WARNING: Could not confirm drive detection in window text"
}

# At this point, without precise control mapping, we cannot reliably:
# - Click specific buttons
# - Check specific checkboxes
# - Read specific status fields

# What we CAN do:
# 1. Leave MPTool running and let user interact manually
# 2. Use image recognition (requires AutoIt/AutoHotkey)
# 3. Use coordinate-based clicking (fragile, resolution-dependent)

Write-Host ""
Write-Host "[LIMIT] GUI automation requires window inspection tools"
Write-Host "The MPTool window is open but precise control requires:"
Write-Host "  - AutoIt/AutoHotkey with control IDs"
Write-Host "  - Or manual interaction with MPTool GUI"
Write-Host ""
Write-Host "MPTool is running. Please:"
Write-Host "  1. Click 'Scan' to detect the drive"
Write-Host "  2. Verify it shows SM2258XT with NAND ID 2C A4 08 32 A1 00"
Write-Host "  3. Click 'Config' to verify settings (Auto, 120GB)"
Write-Host "  4. Click 'Start' to begin flash"
Write-Host "  5. Wait for 'PASS' status"
Write-Host ""
Write-Host "Log will continue in: $LogFile"

# Keep MPTool running for manual interaction
Write-Host "Waiting 60 seconds for manual operation..."
Start-Sleep -Seconds 60

# Check MPTool log files for results
$mptoolLogs = Get-ChildItem "$mptoolDir\Log file\*.log" -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 1
if ($mptoolLogs) {
    Write-Host ""
    Write-Host "[5] MPTOOL LOG FILE DETECTED:"
    Write-Host "  File: $($mptoolLogs.FullName)"
    Write-Host "  Last 20 lines:"
    Get-Content $mptoolLogs.FullName | Select-Object -Last 20 | ForEach-Object { Write-Host "    $_" }
}

Write-Host ""
Write-Host "=== END AUTOMATION ==="
Write-Host "Log: $LogFile"
Stop-Transcript
