#!/bin/bash
echo "========================================"
echo "湾流签约助手客户端版 v3.1.0"
echo "========================================"
echo ""

# 检查Python
if ! command -v python3 &> /dev/null; then
    echo "错误: Python3未安装"
    echo "请安装Python 3.8或更高版本"
    exit 1
fi

# 安装依赖
echo "安装依赖包..."
python3 -m pip install -r core_modules/requirements.txt

# 启动应用程序
echo "启动应用程序..."
python3 core_modules/app.py
