@echo off
REM ============================================================
REM Honeypot Lab — One-Command Installer (Windows)
REM ============================================================
echo.
echo ^🍯^  Honeypot Lab — Windows Installer
echo ===================================
echo.

REM Check Python
python --version >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo ^❌^ Python not found! Install Python 3.10+ from python.org
    pause
    exit /b 1
)

REM Create venv
echo ^📦^ Creating virtual environment...
python -m venv venv
call venv\Scripts\activate.bat

REM Install deps
echo ^📥^ Installing Python packages...
pip install -r requirements.txt

echo.
echo ^✅^ Install complete!
echo.
echo ^🚀^ Start:  python start_all.py
echo ^📊^ Dashboard: python dashboard.py  --^>^  http://localhost:5000
echo ^🎯^ Test: python tools\test_scanner.py
echo ^🛑^ Stop: python stop_all.py
echo.
pause
