; AutoIt3 script for SM2258XT MPTool GUI automation
; Run: AutoIt3.exe SMIFlash.au3
; Or compile: Aut2Exe.exe /in SMIFlash.au3 /out SMIFlash.exe

#include <MsgBoxConstants.au3>
#include <FileConstants.au3>
#include <WinAPIFiles.au3>

; Configuration
Local $sMPToolPath = "C:\SM2258XT_MPTool\SM2258XTMPToolQ0816A.exe"
Local $sLogDir = "C:\SM2258XT_MPTool\log\"
Local $sLogFile = $sLogDir & "mptool_auto_" & @YEAR & @MON & @MDAY & "_" & @HOUR & @MIN & @SEC & ".log"

; Ensure log directory exists
If Not FileExists($sLogDir) Then DirCreate($sLogDir)

_Log("=== SM2258XT MPTOOL GUI AUTOMATION ===")
_Log("Start: " & @YEAR & "-" & @MON & "-" & @MDAY & " " & @HOUR & ":" & @MIN & ":" & @SEC)

; Check MPTool exists
If Not FileExists($sMPToolPath) Then
    _Log("ERROR: MPTool not found at " & $sMPToolPath)
    MsgBox($MB_ICONERROR, "Error", "MPTool not found at " & $sMPToolPath)
    Exit 1
EndIf

_Log("Found MPTool: " & $sMPToolPath)

; Launch MPTool
_Log("Launching MPTool...")
Local $iPID = Run($sMPToolPath, "C:\SM2258XT_MPTool", @SW_SHOW)
If @error Then
    _Log("ERROR: Failed to launch MPTool")
    Exit 1
EndIf

_Log("MPTool PID: " & $iPID)

; Wait for window
Local $sWindowTitle = "SM2258XT" ; Partial title match
Local $iTimeout = 30 ; seconds
Local $hWnd = WinWait($sWindowTitle, "", $iTimeout)

If $hWnd = 0 Then
    _Log("ERROR: MPTool window not found after " & $iTimeout & " seconds")
    ; Try to find any window from the process
    Local $aWinList = WinList()
    For $i = 1 To $aWinList[0][0]
        If WinGetProcess($aWinList[$i][1]) = $iPID Then
            _Log("Found window: " & $aWinList[$i][0] & " Handle: " & $aWinList[$i][1])
            $hWnd = $aWinList[$i][1]
            ExitLoop
        EndIf
    Next
EndIf

If $hWnd = 0 Then
    _Log("ERROR: Could not find MPTool window")
    ProcessClose($iPID)
    Exit 1
EndIf

_Log("Found window handle: " & $hWnd)

; Activate window
WinActivate($hWnd)
Sleep(500)

; Wait for initialization
_Log("Waiting for MPTool initialization...")
Sleep(3000)

; Look for Scan button and click it
; Note: This uses image search or coordinate-based clicking as fallback
; For robust production use, use ControlCommand with specific control IDs

_Log("Looking for Scan button...")

; Method 1: Try to find by text
Local $sButtonText = "Scan"
If ControlClick($hWnd, "", "[TEXT:" & $sButtonText & "]") Then
    _Log("Clicked Scan button (by text)")
Else
    _Log("Scan button not found by text, trying alternative methods...")
    
    ; Method 2: Try keyboard shortcut (F5 or similar)
    Send("{F5}")
    Sleep(500)
    _Log("Sent F5 key")
EndIf

; Wait for scan to complete (look for drive info in window)
_Log("Waiting for scan to complete...")
Sleep(5000)

; Check if drive was detected by reading window text
Local $sWindowText = WinGetText($hWnd)
If StringInStr($sWindowText, "SM2258") Or StringInStr($sWindowText, "2258XT") Or StringInStr($sWindowText, "2C A4") Then
    _Log("SUCCESS: Drive detected in window")
    _Log("Window text snippet: " & StringLeft($sWindowText, 500))
Else
    _Log("WARNING: Could not confirm drive detection in window text")
    _Log("Window text: " & $sWindowText)
EndIf

; At this point, we would:
; 1. Click Config tab
; 2. Set parameters (Auto, capacity, etc.)
; 3. Click OK/Save
; 4. Go back to Main tab
; 5. Check Erase All, Format options
; 6. Click Start
; 7. Wait for completion
; 8. Verify PASS

; For now, report what we found and exit
_Log("GUI automation would continue with: Config -> Start -> Wait -> Verify")
_Log("This requires precise window/control mapping for the specific MPTool version")

; Cleanup
ProcessClose($iPID)
_Log("=== END ===")
_Log("Log: " & $sLogFile)

Exit 0

Func _Log($sMessage)
    Local $sLine = "[" & @HOUR & ":" & @MIN & ":" & @SEC & "." & @MSEC & "] " & $sMessage
    ConsoleWrite($sLine & @CRLF)
    FileWriteLine($sLogFile, $sLine)
EndFunc
