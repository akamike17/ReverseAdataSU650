# CAPTURE DownloadMPISP - Direct Script for CMD
# This works in CMD as Administrator, no automation complexity

set "MP_DIR=C:\SM2258XT_MPTool"
set "X32DBG=C:\Users\Admin\Downloads\snapshot_2026-05-27_12-11\release\x32\x32dbg.exe�los.exe"

# Kill any existing processes
taskkill /F /IM x32dbg.exe 2>nul
taskkill /F /IM SM2258XTMPToolQ0816A.exe 2>nul
timeout /t 2 /nobreak >nul

# Launch x32dbg with MPTool
start "" "%X32DBG%" "%MP_DIR%\SM2258XTMPToolQ0816A.exe"

# Wait for it to initialize
timeout /t 8 /nobreak >nul

# At this point:
# - x32dbg should be open with "System breakpoint reached" 
# - Press F9 to continue until "SWPtest.dll" loads
# - When it shows "DLL Loaded: ...", write down that address
# - Then in MPTool window, press "Scan" button
# - The call to DownloadMPISP will happen automatically
# 
# To capture full registers and stack:
# - When breakpoint hits in x32dbg, screenshot everything
# - Copy the register panel and stack panel
# - Save as C:\SM2258XT_MPTool\captured\breakpoint_DownloadMPISP.txt

echo Process should now be running. 
echo Check x32dbg window for breakpoints.
echo Press Enter when done...
pause