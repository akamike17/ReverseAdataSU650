@echo off
REM SM2258XT Flash Automation - Single Command Execution
REM Right-click -> Run as Administrator

echo ========================================
echo SM2258XT FLASH AUTOMATION
echo ========================================
echo.

REM Check admin
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo ERROR: This script requires Administrator privileges
    echo Right-click and select "Run as Administrator"
    pause
    exit /b 1
)

echo Running with Administrator privileges - OK
echo.

REM Set working directory
cd /d C:\SM2258XT_MPTool
if errorlevel 1 (
    echo ERROR: Cannot access C:\SM2258XT_MPTool
    pause
    exit /b 1
)

echo Working directory: %CD%
echo.

REM Create log directory
if not exist log mkdir log

REM Step 1: Identify SSD
echo [STEP 1] Identifying SSD...
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0identify_ssd.ps1"
if errorlevel 1 (
    echo ERROR: SSD identification failed
    pause
    exit /b 1
)

echo.
echo [STEP 2] Running flash automation...
echo.

REM Step 2: Run the GUI automation script
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0run_flash.ps1" -AutoElevate:$false

echo.
echo ========================================
echo FLASH PROCESS COMPLETE
echo Check log files in: C:\SM2258XT_MPTool\log\
echo ========================================
pause
