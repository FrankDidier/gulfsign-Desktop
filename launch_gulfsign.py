#!/usr/bin/env python3
"""
湾流签约助手启动脚本
用于启动综合版应用程序
"""

import os
import sys
import subprocess
import platform
from pathlib import Path

def check_python_version():
    """检查Python版本"""
    version = sys.version_info
    if version.major < 3 or (version.major == 3 and version.minor < 8):
        print(f"错误: Python版本过低 ({version.major}.{version.minor}.{version.micro})")
        print("需要Python 3.8或更高版本")
        return False
    return True

def check_dependencies():
    """检查依赖"""
    print("检查依赖包...")
    
    required_packages = [
        "requests",
        "gmssl", 
        "cryptography",
        "tkinter"
    ]
    
    missing = []
    for package in required_packages:
        try:
            __import__(package)
            print(f"  ✓ {package}")
        except ImportError:
            missing.append(package)
            print(f"  ✗ {package} (缺失)")
    
    if missing:
        print(f"\n缺少以下依赖包: {', '.join(missing)}")
        print("请运行: pip install " + " ".join(missing))
        return False
    
    return True

def install_missing_dependencies():
    """安装缺失的依赖"""
    print("安装依赖包...")
    
    requirements_file = Path(__file__).parent / "requirements.txt"
    if requirements_file.exists():
        print(f"从 {requirements_file} 安装依赖...")
        try:
            subprocess.check_call([sys.executable, "-m", "pip", "install", "-r", str(requirements_file)])
            print("依赖安装完成")
            return True
        except subprocess.CalledProcessError as e:
            print(f"依赖安装失败: {e}")
            return False
    else:
        print("requirements.txt 文件不存在")
        return False

def create_shortcut():
    """创建快捷方式"""
    system = platform.system()
    
    if system == "Windows":
        # Windows快捷方式
        import winshell
        from win32com.client import Dispatch
        
        desktop = winshell.desktop()
        shortcut_path = os.path.join(desktop, "湾流签约助手.lnk")
        
        target = sys.executable
        wDir = str(Path(__file__).parent)
        icon = str(Path(__file__).parent / "icon.ico")
        
        shell = Dispatch('WScript.Shell')
        shortcut = shell.CreateShortCut(shortcut_path)
        shortcut.Targetpath = target
        shortcut.Arguments = f'"{Path(__file__).parent / "gulfsign_comprehensive_app.py"}"'
        shortcut.WorkingDirectory = wDir
        if os.path.exists(icon):
            shortcut.IconLocation = icon
        shortcut.save()
        
        print(f"桌面快捷方式已创建: {shortcut_path}")
    
    elif system == "Darwin":  # macOS
        # macOS应用程序包
        app_name = "湾流签约助手.app"
        app_path = Path.home() / "Applications" / app_name
        
        # 创建简单的app bundle结构
        app_contents = app_path / "Contents"
        app_macos = app_contents / "MacOS"
        app_resources = app_contents / "Resources"
        
        app_macos.mkdir(parents=True, exist_ok=True)
        app_resources.mkdir(parents=True, exist_ok=True)
        
        # 创建启动脚本
        launch_script = app_macos / "launch.sh"
        with open(launch_script, 'w') as f:
            f.write(f'''#!/bin/bash
cd "{Path(__file__).parent}"
"{sys.executable}" "{Path(__file__).parent / "gulfsign_comprehensive_app.py"}"
''')
        
        os.chmod(launch_script, 0o755)
        
        # 创建Info.plist
        info_plist = app_contents / "Info.plist"
        with open(info_plist, 'w') as f:
            f.write(f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleExecutable</key>
    <string>launch.sh</string>
    <key>CFBundleIdentifier</key>
    <string>com.gulfstream.gulfsign</string>
    <key>CFBundleName</key>
    <string>湾流签约助手</string>
    <key>CFBundleVersion</key>
    <string>3.1.0</string>
    <key>CFBundleShortVersionString</key>
    <string>3.1.0</string>
    <key>LSMinimumSystemVersion</key>
    <string>10.15</string>
</dict>
</plist>
''')
        
        print(f"应用程序包已创建: {app_path}")
    
    else:  # Linux
        # Linux桌面文件
        desktop_file = Path.home() / ".local" / "share" / "applications" / "gulfsign.desktop"
        desktop_file.parent.mkdir(parents=True, exist_ok=True)
        
        with open(desktop_file, 'w') as f:
            f.write(f'''[Desktop Entry]
Name=湾流签约助手
Comment=家庭医生签约自动化工具
Exec={sys.executable} "{Path(__file__).parent / "gulfsign_comprehensive_app.py"}"
Icon={Path(__file__).parent / "icon.png"}
Terminal=false
Type=Application
Categories=Utility;
''')
        
        os.chmod(desktop_file, 0o755)
        print(f"桌面文件已创建: {desktop_file}")

def show_welcome():
    """显示欢迎信息"""
    print("=" * 60)
    print("湾流签约助手 v3.1.0 - 综合版")
    print("=" * 60)
    print("功能概述:")
    print("  1. 自动化家庭医生签约系统")
    print("  2. 年龄验证绕行功能")
    print("  3. 状态转换探索工具")
    print("  4. 实名认证ID修改分析")
    print("  5. 家庭成员移除业务规则分析")
    print("  6. sjfx API字段名发现工具")
    print("  7. 渗透测试模拟框架")
    print("  8. 高级攻击模拟场景")
    print("  9. 全面安全评估报告")
    print("  10. 批量处理引擎")
    print("  11. Excel日志记录")
    print("  12. 许可证验证系统")
    print("  13. 配置迁移工具")
    print()
    print("系统要求:")
    print("  - Python 3.8+")
    print("  - 网络连接（访问公卫3.0和健康卡平台）")
    print("  - 适当的系统权限")
    print()

def main():
    """主函数"""
    # 显示欢迎信息
    show_welcome()
    
    # 检查Python版本
    if not check_python_version():
        sys.exit(1)
    
    # 检查依赖
    if not check_dependencies():
        print("\n尝试自动安装依赖...")
        if not install_missing_dependencies():
            print("\n请手动安装依赖后重试")
            sys.exit(1)
    
    # 询问是否创建快捷方式
    system = platform.system()
    if system in ["Windows", "Darwin", "Linux"]:
        create_shortcut_option = input("是否创建桌面快捷方式？ (y/n): ").strip().lower()
        if create_shortcut_option == 'y':
            try:
                create_shortcut()
            except Exception as e:
                print(f"创建快捷方式失败: {e}")
                print("将继续启动应用程序...")
    
    # 启动应用程序
    print("\n启动湾流签约助手...")
    print("-" * 40)
    
    try:
        # 导入并运行应用程序
        sys.path.insert(0, str(Path(__file__).parent))
        from gulfsign_comprehensive_app import main as app_main
        
        print("应用程序启动成功!")
        print("请按照界面提示操作")
        print()
        
        # 运行应用程序
        app_main()
        
    except ImportError as e:
        print(f"导入应用程序失败: {e}")
        print("请确保所有文件都在正确的位置")
        sys.exit(1)
    except Exception as e:
        print(f"应用程序运行错误: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()