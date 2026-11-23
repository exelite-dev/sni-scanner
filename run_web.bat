@echo off
chcp 65001 >nul
cd /d "%~dp0"
title SNI Scanner Pro - Web Dashboard
color 0b

echo ========================================================
echo        ⚡️ V O R T E X   S N I   H U N T E R   P R O
echo               Universal VLESS Reality Scanner
echo ========================================================
echo.

:: Check python installation
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Python is not installed or not in PATH!
    echo Please install Python 3.10+ from python.org and check "Add Python to PATH".
    pause
    exit /b 1
)

:: Check and install requirements if needed
echo [1/2] Checking dependencies...
python -c "import fastapi, uvicorn, aiohttp, dnspython" >nul 2>&1
if %errorlevel% neq 0 (
    echo [INFO] Installing required packages...
    pip install -r requirements.txt
)

echo [2/2] Launching Web Dashboard at http://127.0.0.1:8787 ...
echo.
timeout /t 2 /nobreak >nul
start http://127.0.0.1:8787
python -m uvicorn web.app:app --host 127.0.0.1 --port 8787

pause
