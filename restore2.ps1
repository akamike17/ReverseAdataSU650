$src = @"
using System;
using System.Runtime.InteropServices;
public class U32X {
  [DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr h, int cmd);
  [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr h);
  [DllImport("user32.dll")] public static extern bool BringWindowToTop(IntPtr h);
  [DllImport("user32.dll")] public static extern bool IsIconic(IntPtr h);
  [DllImport("user32.dll")] public static extern IntPtr GetForegroundWindow();
}
"@
Add-Type -TypeDefinition $src -Force
$p = Get-Process -Id 11192
$h = $p.MainWindowHandle
Write-Host "handle=$h iconic=$([U32X]::IsIconic($h))"
[U32X]::ShowWindow($h, 1) | Out-Null   # SW_SHOWNORMAL
[U32X]::ShowWindow($h, 9) | Out-Null   # SW_RESTORE
[U32X]::BringWindowToTop($h) | Out-Null
[U32X]::SetForegroundWindow($h) | Out-Null
Start-Sleep -Milliseconds 800
$p.Refresh()
Write-Host "after: iconic=$([U32X]::IsIconic($h)) fg=$([U32X]::GetForegroundWindow())"
