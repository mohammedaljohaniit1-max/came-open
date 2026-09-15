@echo off
REM ================================================================
REM  CAMRADAR - Attack Surface Intelligence Platform (Windows launcher)
REM ================================================================
title CAMRADAR

echo ================================================================
echo   CAMRADAR - OSINT Camera Aggregator ^& Availability Validator
echo ================================================================

REM Create venv on first run
if not exist ".venv" (
    echo [*] Creating virtual environment...
    python -m venv .venv
)

call .venv\Scripts\activate.bat

echo [*] Installing dependencies...
pip install -q -r requirements.txt

echo [*] Launching CAMRADAR on http://localhost:5000 ...
python app.py

pause
