# X32DBG FINAL CAPTURE - Working method
# 1. Launch x32dbg GUI with MPTool loaded
# 2. User clicks Scan in MPTool
# 3. Breakpoint fires, we capture context

param(
    [switch]$Auto = $false
)

$mptool = "C:\SM2258XT_MPTool\SM2258XTMPToolQ0816A.exe"
$x32dbgDir = "C:\Users\Admin\Downloads\snapshot_2026-05-27_12-11\release\x32"
$x32dbg = "$x32dbgDir\x32dbg.exe"
$logDir = "C:\SM2258XT_MPTool\log"
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"

Write-Host "=== X32DBG GUI CAPTURE ===" -ForegroundColor Cyan

# Kill any existing processes
Get-Process -Name "x32dbg","SM2258XTMPTool*" -ErrorAction SilentlyContinue | Stop-Process -Force

# Launch x32dbg with MPTool
Write-Host "Launching x32dbg with MPTool..."
$proc = Start-Process -FilePath $x32dbg -ArgumentList "`"$mptool`"" -WorkingDirectory $x32dbgDir -PassThru

Write-Host "x32dbg PID: $($proc.Id)"
Write-Host "MPTool will be loaded in debugger"
Write-Host ""

# Wait for x32dbg to initialize
Write-Host "Waiting 15 seconds for debugger initialization..."
Start-Sleep -Seconds 15

Write-Host ""
Write-Host "=== INSTRUCTIONS ===" -ForegroundColor Yellow
Write-Host ""
Write-Host "1. In x32dbg window:"
Write-Host "   - Wait for 'System breakpoint reached'"
Write-Host "   - Go to 'Debug' menu -> 'Run' (or press F9)"
Write-Host "   - Wait for SWPtest.dll to load (check Log window)"
Write-Host ""
Write-Host "2. Set breakpoint on DownloadMPISP:"
Write-Host "   - Go to 'View' -> 'Symbols'"
Write-Host "   - Find SWPtest.dll in left panel"
Write-Host "   - Find '_SMIPtestDownloadMPISP' in right panel"
Write-Host "   - Double-click to go to address, then press F2"
Write-Host "   OR use Command bar at bottom: bp SWPtest.dll:7AD8"
Write-Host ""
Write-Host "3. Continue execution (F9)"
Write-Host ""
Write-Host "4. In MPTool window (may need to Alt+Tab):"
Write-Host "   - Click 'Scan' button (top left area)"
Write-Host "   - Drive should appear"
Write-Host "   - Click 'Start' or 'Auto Run'"
Write-Host ""
Write-Host "5. When breakpoint hits, x32dbg will pause"
Write-Host "   - DO NOT continue execution"
Write-Host "   - Copy all register values and stack"
Write-Host "   - Screenshot the entire window"
Write-Host ""
Write-Host "6. Report back with the screenshot"
Write-Host ""

if (-not $Auto) {
    Write-Host "Press any key to continue after capture..."
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}

Write-Host ""
Write-Host "=== CAPTURE WINDOW STILL ACTIVE ==="
Write-Host "Close x32dbg when done to stop debugging"
