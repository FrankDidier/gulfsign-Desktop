@echo off
chcp 65001 >nul 2>&1
echo ============================================
echo   湾流签约助手 - Windows EXE 打包工具
echo ============================================
echo.

echo [1/3] 安装依赖...
pip install -r requirements.txt
if errorlevel 1 (
    echo 依赖安装失败！请检查 Python 和 pip 是否正确安装。
    pause
    exit /b 1
)

echo.
echo [2/3] 打包 EXE...
pyinstaller --onefile --windowed --name "GulfSign" --hidden-import gmssl --hidden-import gmssl.sm4 --hidden-import gmssl.sm3 --hidden-import gmssl.func --hidden-import cryptography --add-data "hc_api.py;." --add-data "proxy_capture.py;." app.py
if errorlevel 1 (
    echo 打包失败！
    pause
    exit /b 1
)

echo.
echo [3/3] 完成!
echo.
echo EXE 文件位置: dist\GulfSign.exe
echo.
echo 可将 dist\GulfSign.exe 复制到任意目录使用。
echo.
pause
