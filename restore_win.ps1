param([int]$ProcId = (Get-Process x32dbg -ErrorAction SilentlyContinue | Select-Object -First 1 -ExpandProperty Id))
$src = @"
using System;
using System.Runtime.InteropServices;
public class U32 {
  [DllImport("user32.dll")] public static extern bool ShowWindowAsync(IntPtr h, int cmd);
  [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr h);
  [DllImport("user32.dll")] public static extern bool IsIconic(IntPtr h);
}
"@
Add-Type -TypeDefinition $src
$p = Get-Process -Id $ProcId
Write-Host "Handle: $($p.MainWindowHandle)"
[U32]::ShowWindowAsync($p.MainWindowHandle, 9) | Out-Null   # SW_RESTORE
[U32]::SetForegroundWindow($p.MainWindowHandle) | Out-Null
Start-Sleep -Milliseconds 600
$p.Refresh()
Write-Host "Iconic: $([U32]::IsIconic($p.MainWindowHandle))"
Write-Host "Title: $($p.MainWindowTitle)"
