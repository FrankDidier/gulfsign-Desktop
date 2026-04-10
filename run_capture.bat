@echo off
where python >nul 2>nul
if %errorlevel%==0 (
    pip install cryptography >nul 2>nul
    python capture_openid.py
) else (
    echo Python not found. Please install Python 3.8+ from https://www.python.org/downloads/
    echo Make sure to check "Add Python to PATH" during installation.
)
pause
