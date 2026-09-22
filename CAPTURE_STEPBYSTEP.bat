@echo off
title X32DBG CAPTURE MANAGER
echo [1] Kill old processes
taskkill /F /IM x32dbg.exe 2>nul
taskkill /F /IM SM2258XTMPToolQ0816A.exe 2>nul
timeout /t 2 /nobreak >nul

echo [2] Launch x32dbg with MPTool
start "" "C:\Users\Admin\Downloads\snapshot_2026-05-27_12-11\release\x32\x32dbg.exe" "C:\SM2258XT_MPTool\SM2258XTMPToolQ0816A.exe"

echo [3] Waiting for debugger to load MPTool...
timeout /t 8 /nobreak >nul

echo [4] Type in command bar: bpdll SWPtest.dll
echo [5] Type in command bar: run
echo [6] When SWPtest loads, type: run
echo [7] When MPTool GUI appears, click Scan or Start
echo [8] If DownloadMPISP breakpoint hits, copy all data to C:\SM2258XT_MPTool\capture\
echo.
echo READY - Press any key when done...
pause