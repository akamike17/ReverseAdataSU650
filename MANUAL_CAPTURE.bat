@echo off
echo ============================================
echo  MANUAL X32DBG CAPTURE - NO GUI AUTO
echo ============================================
echo.

set X32DBG=C:\Users\Admin\Downloads\snapshot_2026-05-27_12-11\release\x32\x32dbg.exe
set MPTOOL=C:\SM2258XT_MPTool\SM2258XTMPToolQ0816A.exe

echo Step 1: Kill existing processes
taskkill /F /IM x32dbg.exe 2>nul
taskkill /F /IM SM2258XTMPToolQ0816A.exe 2>nul
timeout /t 2 /nobreak >nul

echo Step 2: Launching x32dbg with MPTool...
start "" "%X32DBG%" "%MPTOOL%"

echo.
echo Step 3: WAIT for x32dbg GUI to appear (should take 5-10 seconds)
echo          Then follow these steps IN X32DBG:
echo.
echo          a) When you see "System breakpoint reached" in Log:
echo             - Press F9 (or Debug -^> Run) to continue
echo.
echo          b) MPTool GUI will open - look for "SM2258XT MPTool" window
echo.
echo          c) In x32dbg, go to View -^> Symbols (or Alt+F5)
echo             - Find "SWPtest.dll" in the list
echo             - Look for "_SMIPtestDownloadMPISP" in exports
echo             - Press F2 to toggle breakpoint on it
echo.
echo          d) Return to MPTool window
echo             - Click "Scan" button (top left area)
echo             - If breakpoint hits, copy ALL registers and stack
echo.
echo          e) To exit: In x32dbg, go to Debug -^> Stop (Alt+F4)
echo.
echo ============================================
pause
