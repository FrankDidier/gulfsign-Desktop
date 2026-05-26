@echo off
echo ========================================
echo 湾流签约助手客户端版 v3.1.0
echo ========================================
echo.

REM 检查Python
python --version >nul 2>&1
if errorlevel 1 (
    echo 错误: Python未安装或未添加到PATH
    echo 请安装Python 3.8或更高版本
    pause
    exit /b 1
)

REM 安装依赖
echo 安装依赖包...
pip install -r core_modules/requirements.txt

REM 启动应用程序
echo 启动应用程序...
python core_modules/app.py

pause
