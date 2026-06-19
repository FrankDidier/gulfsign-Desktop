@echo off
chcp 65001 >nul
setlocal enabledelayedexpansion

REM ============================================================
REM   竞品全程录制 · 一键启动 (请右键 → 以管理员身份运行)
REM ============================================================

REM ---- 自动申请管理员权限 ----
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo 正在申请管理员权限，请在弹出的窗口点【是】...
    powershell -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b
)

cd /d "%~dp0"

echo ================================================================
echo                  竞品全程录制 . 一键启动
echo ================================================================
echo.

REM ---- 查找 Python ----
set "PY="
where python >nul 2>&1 && set "PY=python"
if not defined PY (
    where py >nul 2>&1 && set "PY=py"
)

if not defined PY (
    echo [X] 没有检测到 Python。
    echo.
    echo     请先安装 Python 3：https://www.python.org/downloads/
    echo     安装时务必勾选 "Add Python to PATH"，装完后重新运行本文件。
    echo.
    pause
    exit /b
)

echo [OK] 已检测到 Python (%PY%)
echo.
echo 正在安装/检查所需组件（首次需要联网下载，请稍候）...
echo ----------------------------------------------------------------
%PY% -m pip install --upgrade pip >nul 2>&1
%PY% -m pip install cryptography requests certifi
if errorlevel 1 (
    echo.
    echo [X] 组件安装失败，请检查网络后重试。
    echo     如果电脑无法联网，请联系我们获取离线安装包。
    echo.
    pause
    exit /b
)
echo ----------------------------------------------------------------
echo [OK] 组件已就绪，正在启动录制程序...
echo.

%PY% "%~dp0capture_competitor.py"

echo.
echo （如本窗口未自动关闭，可直接关闭）
pause >nul
endlocal
