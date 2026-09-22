$h = (Get-Process -Id 11192).MainWindowHandle
Write-Host "handle=$h"

# Use SwitchToThisWindow which works for minimized windows
$code = @'
using System;
using System.Runtime.InteropServices;
public enum SCmd : int { Hide=0, ShowNormal=1, ShowMinimized=2, Maximize=3, ShowNoActivate=4, Show=5, Minimize=6, ShowMinNoActive=7, ShowNA=8, Restore=9 }
public class W32 {
  [DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr h, int cmd);
  [DllImport("user32.dll")] public static extern bool ShowWindowAsync(IntPtr h, int cmd);
  [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr h);
  [DllImport("user32.dll")] public static extern bool SetActiveWindow(IntPtr h);
  [DllImport("user32.dll")] public static extern bool BringWindowToTop(IntPtr h);
  [DllImport("user32.dll")] public static extern void SwitchToThisWindow(IntPtr h, bool fAltTab);
  [DllImport("user32.dll")] public static extern bool IsIconic(IntPtr h);
  [DllImport("user32.dll")] public static extern IntPtr GetForegroundWindow();
  [DllImport("user32.dll")] public static extern bool SetWindowPos(IntPtr h, IntPtr hAfter, int x, int y, int cx, int cy, uint flags);
}
'@
Add-Type -TypeDefinition $code -ErrorAction SilentlyContinue

$hwnd = [IntPtr]$h
Write-Host "before: iconic=$([W32]::IsIconic($hwnd))"

# Try multiple methods
[W32]::ShowWindow($hwnd, 9) | Out-Null   # SW_RESTORE
[W32]::ShowWindowAsync($hwnd, 9) | Out-Null
[W32]::SwitchToThisWindow($hwnd, $true)  # Alt+Tab equivalent
Start-Sleep -Milliseconds 400
[W32]::SetWindowPos($hwnd, [IntPtr]::Zero, 100, 100, 868, 600, 0x0040) | Out-Null  # NoSize|NoMove|ShowWindow
[W32]::BringWindowToTop($hwnd) | Out-Null
[W32]::SetForegroundWindow($hwnd) | Out-Null

Start-Sleep -Milliseconds 800
Write-Host "after: iconic=$([W32]::IsIconic($hwnd)) fg=$([W32]::GetForegroundWindow())"
