@echo off
title Baize Traffic Analysis - http://127.0.0.1:8000
cd /d "%~dp0"

echo ============================================================
echo    Baize Traffic Analysis Platform  v0.1
echo    Website :  http://127.0.0.1:8000
echo    --------------------------------------------------------
echo    Keep this window OPEN while using the platform.
echo    Close this window to STOP the service (port 8000 freed).
echo ============================================================
echo.

REM ---------- 1. check Python ----------
where python >nul 2>nul
if errorlevel 1 (
    echo [ERROR] Python not found. Install Python 3.11+ and
    echo         check "Add python.exe to PATH" during setup.
    echo.
    pause
    exit /b 1
)

REM ---------- 2. check / install dependencies ----------
python -c "import fastapi, uvicorn, sqlalchemy, scapy, yaml, jsonschema, regex" >nul 2>nul
if errorlevel 1 (
    echo [INFO] Installing dependencies on first run, please wait...
    python -m pip install -r requirements.txt
    if errorlevel 1 (
        echo [ERROR] Dependency installation failed. Check network and retry.
        echo.
        pause
        exit /b 1
    )
)

REM ---------- 3. port 8000 check ----------
netstat -ano | findstr ":8000 " | findstr LISTENING >nul 2>nul
if not errorlevel 1 (
    echo The platform is already running at:  http://127.0.0.1:8000
    start http://127.0.0.1:8000
    echo NOTE: closing this window does not stop that running service.
    echo.
    pause
    exit /b 0
)

REM ---------- 4. start service in foreground ----------
echo Starting service...
echo.
echo    Access : http://127.0.0.1:8000
echo    Data   : %~dp0data
echo    Stop   : close this window (port 8000 released automatically)
echo.
echo    Opening browser in 4 seconds...
start "" /b cmd /c "ping -n 5 127.0.0.1 >nul & start http://127.0.0.1:8000"
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000

echo.
echo Service stopped. You can close this window now.
pause