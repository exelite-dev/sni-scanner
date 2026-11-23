@echo off
chcp 65001 >nul
cd /d "%~dp0"
title Vortex SNI Hunter Pro - CLI Scanner
color 0a

echo ========================================================
echo        ⚡️ V O R T E X   S N I   H U N T E R   P R O
echo           Terminal CLI Mega-Pool Scanner
echo ========================================================
echo.

python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Python is not installed or not in PATH!
    pause
    exit /b 1
)

python -c "import rich, dnspython, aiohttp" >nul 2>&1
if %errorlevel% neq 0 (
    echo [INFO] Installing required packages...
    pip install -r requirements.txt
)

echo [INFO] Starting CLI scan (Sorted by lowest ping)...
python cli.py --category auto --limit 100 --sort-by latency
pause
