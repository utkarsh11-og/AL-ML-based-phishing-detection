@echo off
echo =======================================================
echo   NEXORA PhishGuard - Desktop Shortcut Generator
echo =======================================================
echo.

set SCRIPT="%TEMP%\%RANDOM%-%RANDOM%-%RANDOM%-%RANDOM%.vbs"

echo Set oWS = WScript.CreateObject("WScript.Shell") >> %SCRIPT%
echo sLinkFile = oWS.SpecialFolders("Desktop") ^& "\NEXORA PhishGuard.url" >> %SCRIPT%
echo Set oUrlLink = oWS.CreateShortcut(sLinkFile) >> %SCRIPT%
echo oUrlLink.TargetPath = "http://127.0.0.1:8000/dashboard/" >> %SCRIPT%
echo oUrlLink.Save >> %SCRIPT%

cscript /nologo %SCRIPT%
del %SCRIPT%

echo [SUCCESS] Desktop Shortcut created successfully on your Windows Desktop!
echo File: "%USERPROFILE%\Desktop\NEXORA PhishGuard.url"
echo.
pause
