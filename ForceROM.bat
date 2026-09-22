@echo off
:: SM2258XT Force ROM - Software-Only ISP Mode Entry
:: Usage: Run as Admin -> double click OR from PS: .\ForceROM_Auto.bat

:: Check admin
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Run as Administrator: Right-click -^> Run as administrator
    pause
    exit /b 1
)

:: PhysicalDrive number (default 1 for most systems - change if needed)
set DRIVE=1

echo ==========================================
echo SM2258XT Force ROM - Software Method
echo ==========================================
echo.
echo Running ForceROM on PhysicalDrive%DRIVE%
echo.

:: Use the compiled executable
C:\SM2258XT_MPTool\ForceROM\bin\Release\net10.0\ForceROM.exe %DRIVE%

if %errorlevel% equ 0 (
    echo.
    echo [SUCCESS] Force ROM command executed.
    echo.
    echo Wait ~10 seconds, then run MPTool to flash firmware.
    echo The SSD should appear as "SMI Factory" ~1GB in Disk Management.
    echo.
) else (
    echo.
    echo [FAILED] Check that:
    echo  - You're running as Admin
    echo  - PhysicalDrive number is correct
    echo  - SSD is connected via SATA (not USB dock)
)

pause