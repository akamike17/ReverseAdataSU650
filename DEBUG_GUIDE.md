<#
  SM2258XT MPTool Debugging Guide
  
  x32dbg Steps (Manual):
  
  1. Launch x32dbg as Administrator:
     Start-Process "C:\Users\Admin\Downloads\snapshot_2026-05-27_12-11\release\x32\x32dbg.exe" -ArgumentList 'C:\SM2258XT_MPTool\SM2258XTMPToolQ0816A.exe' -Verb RunAs
  
  2. In x32dbg Command bar (bottom), type:
     bpdll SWPtest.dll
  
  3. Press F9 (Run) or click Run button
  -> Log should show "DLL Loaded: <address> C:\SM2258XT_MPTool\Dll\SWPtest.dll"
     -> Note down the address (ImageBase)
  
  4. Press F9 again or click Run to continue
  -> MPTool GUI should open
  
  5. In MPTool, you'll see a "Test" tab with a "Start" or "Scan" button
  
  6. In x32dbg, the process will be running normally
  
  7. To capture DownloadMPISP:
     - In x32dbg Command bar: bp SWPtest._SMIPtestDownloadMPISP
     OR use: bp modulename._FunctionName
     OR find Module Address from Memory Map and add offset:
       bp [ModuleAddress] + 0x7AD8
  
  8. Click "Start" or "Scan" in MPTool - this should trigger the breakpoint
  
  9. When breakpoint hits, screenshot the LLAMADA window (it shows in the stack)
     - Look at the stack panel for the call instruction
     - Look at the memory dump area for parameters
  
  10. All process information will be saved
  
  To exit:
  - In x32dbg: Debug -> Stop (Alt+F4) or close window
  - If MPTool is still open, close it normally
  
  Alternatively, use Python smiflash.cs (already works):
  - The PoC already calls ReadFlashID successfully
  - Only DownloadMPISP fails due to missing context
  - The working cases are: OpenDrive + SetPassThroughType + CheckRunMode + ReadFlashID
#>

Write-Host "=== SM2258XT MPTool x32dbg Debugging ==="
Write-Host "Run this script in CMD (not PowerShell) as Administrator"
Write-Host ""
