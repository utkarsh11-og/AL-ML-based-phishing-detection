@echo off
echo ==========================================================
echo   NEXORA PhishGuard - Launching Browser with Extension
echo ==========================================================
echo.

set EXT_PATH=E:\AL ML based phishing detection\extension

:: Try Chrome first
start "" chrome.exe --load-extension="%EXT_PATH%" "http://127.0.0.1:8000/dashboard/" 2>nul
if %errorlevel% equ 0 goto success

:: Fallback to Microsoft Edge
start "" msedge.exe --load-extension="%EXT_PATH%" "http://127.0.0.1:8000/dashboard/" 2>nul
if %errorlevel% equ 0 goto success

:: Fallback to default browser
start "" "http://127.0.0.1:8000/dashboard/"

:success
echo [SUCCESS] Browser launched with NEXORA PhishGuard extension loaded!
