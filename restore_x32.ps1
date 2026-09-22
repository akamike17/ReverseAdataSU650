$h = (Get-Process x32dbg -ErrorAction SilentlyContinue | Select-Object -First 1).MainWindowHandle
Write-Host "handle=$h"
Add-Type -AssemblyName System.Windows.Forms
$sig = @"
using System;
using System.Runtime.InteropServices;
public class W { 
  [DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr h, int c);
  [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr h);
  [DllImport("user32.dll")] public static extern bool SwitchToThisWindow(IntPtr h, bool a);
}
"@
Add-Type -TypeDefinition $sig
[W]::ShowWindow($h, 9) | Out-Null
[W]::SwitchToThisWindow($h, $true)
[W]::SetForegroundWindow($h) | Out-Null
Start-Sleep -Milliseconds 500
Write-Host "Restored, handle=$h"
