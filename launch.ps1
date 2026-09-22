$x32 = "C:\Users\Admin\Downloads\snapshot_2026-05-27_12-11\release\x32\x32dbg.exe"
$mptool = "C:\SM2258XTMPTool\SM2258XTMPToolQ0816A.exe"

# Kill anything that might be running
Get-Process x32dbg,SM2258XTMPToolQ0816A -ErrorAction SilentlyContinue | Stop-Process -Force
Start-Sleep -Seconds 2

Write-Host "Launching x32dbg with MPTool..."

# Start process with the x32dbg window visible
$psi = New-Object System.Diagnostics.ProcessStartInfo
$psi.FileName = $x32
$psi.Arguments = '"' + $mptool + '"'
$psi.WorkingDirectory = Split-Path $x32

try {
    $proc = [System.Diagnostics.Process]::Start($psi)
    Write-Host "Started x32dbg PID: $($proc.Id)"
    Start-Sleep -Seconds 15
    
    Write-Host "Process state:"
    $proc.Refresh()
    Write-Host "  - Responding: $($proc.Responding)"
    Write-Host "  - MainWindowTitle: $($proc.MainWindowTitle)"
    Write-Host "  - MainWindowHandle: $($proc.MainWindowHandle)"
    Write-Host "  - HasExited: $($proc.HasExited)"
} catch {
    Write-Host "Error: $_"
}
