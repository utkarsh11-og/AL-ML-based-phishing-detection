@echo off
title NEXORA PhishGuard - Launcher
color 0b

echo =====================================================================
echo       NEXORA PhishGuard - AI/ML Phishing Detection Platform
echo                     Engineered by Team NEXORA
echo =====================================================================
echo.

cd /d "%~dp0"

:: 1. Check Python installation
where python >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Python is not installed or not in PATH.
    echo Please install Python 3.10+ from https://www.python.org/
    echo Be sure to check "Add Python to PATH" during installation.
    pause
    exit /b 1
)

:: 2. Create Virtual Environment if missing
if not exist "venv\Scripts\python.exe" (
    echo [*] Creating isolated Python virtual environment (venv)...
    python -m venv venv
)

:: 3. Install Dependencies
echo [*] Checking and installing required dependencies...
.\venv\Scripts\python.exe -m pip install --upgrade pip --quiet
.\venv\Scripts\python.exe -m pip install -r requirements.txt --quiet

:: 4. Verify/Train Model if missing
if not exist "ml\models\phishing_model_v1.joblib" (
    echo [*] Training initial champion ML models on live threat feeds...
    .\venv\Scripts\python.exe ml\datasets\fetch_realtime_data.py
)

:: 5. Create Desktop Shortcut
call create_desktop_shortcut.bat >nul 2>&1

:: 6. Launch Server & Open Dashboard
echo.
echo =====================================================================
echo  [SUCCESS] Starting NEXORA AI Engine on http://127.0.0.1:8000
echo  [INFO] Dashboard URL: http://127.0.0.1:8000/dashboard/
echo  [INFO] API Docs URL : http://127.0.0.1:8000/docs
echo =====================================================================
echo.

:: Launch browser in 2 seconds in background
start "" cmd /c "timeout /t 2 /nobreak >nul & start http://127.0.0.1:8000/dashboard/"

:: Start FastAPI Backend Server
.\venv\Scripts\python.exe -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8000
pause
