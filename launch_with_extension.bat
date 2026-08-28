@echo off
title NEXORA PhishGuard - Extension Launcher
color 0a

echo ==========================================================
echo   NEXORA PhishGuard - Launching Browser with Extension
echo ==========================================================
echo.

cd /d "%~dp0"
set EXT_PATH=%~dp0extension

:: Ensure trailing slash is removed
if "%EXT_PATH:~-1%"=="\" set EXT_PATH=%EXT_PATH:~0,-1%

echo [*] Extension path: "%EXT_PATH%"
echo [*] Launching browser...

:: Try Microsoft Edge first
start "" msedge.exe --load-extension="%EXT_PATH%" "http://127.0.0.1:8000/dashboard/" 2>nul
if %errorlevel% equ 0 goto success

:: Fallback to Chrome
start "" chrome.exe --load-extension="%EXT_PATH%" "http://127.0.0.1:8000/dashboard/" 2>nul
if %errorlevel% equ 0 goto success

:: Fallback to default browser
start "" "http://127.0.0.1:8000/dashboard/"

:success
echo [SUCCESS] Browser launched with NEXORA PhishGuard extension loaded!
