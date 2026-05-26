#!/usr/bin/env python3
"""
简化版EXE生成脚本
生成包含所有新功能的可执行文件
"""

import os
import sys
import subprocess
import shutil
import json
from datetime import datetime
from pathlib import Path

# 项目根目录
PROJECT_ROOT = Path(__file__).parent
BUILD_DIR = PROJECT_ROOT / "build"
DIST_DIR = PROJECT_ROOT / "dist"

# 主要Python文件
MAIN_APP = "app.py"

def clean_build_dirs():
    """清理构建目录"""
    print("清理构建目录...")
    for dir_path in [BUILD_DIR, DIST_DIR]:
        if dir_path.exists():
            try:
                shutil.rmtree(dir_path)
                print(f"  已删除: {dir_path}")
            except Exception as e:
                print(f"  删除失败 {dir_path}: {e}")

def check_dependencies():
    """检查依赖"""
    print("检查依赖包...")
    
    required_packages = [
        "requests",
        "gmssl", 
        "cryptography",
        "PyInstaller"
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

def create_exe():
    """创建EXE文件"""
    print("开始创建EXE文件...")
    
    # 构建命令 - 使用简单配置
    cmd = [
        sys.executable, "-m", "PyInstaller",
        "--name=gulfsign_desktop_v3",
        "--onefile",
        "--windowed",  # 不显示控制台窗口
        "--clean",
        "--hidden-import=Crypto",
        "--hidden-import=Crypto.Cipher",
        "--hidden-import=Crypto.PublicKey",
        "--hidden-import=Crypto.Signature",
        "--hidden-import=Crypto.Hash",
        "--hidden-import=Crypto.Util",
        "--hidden-import=Crypto.Random",
        "--add-data=gulfsign_config.json:.",
        "--add-data=使用说明.txt:.",
        "--add-data=使用说明_最终版.txt:.",
        "--add-data=快速上手指南.txt:.",
        "--add-data=操作教程.txt:.",
        MAIN_APP
    ]
    
    print(f"执行命令: {' '.join(cmd)}")
    
    try:
        result = subprocess.run(cmd, check=True, capture_output=True, text=True)
        print("构建输出:")
        if result.stdout:
            print(result.stdout[:500])  # 只显示前500字符
        
        if result.stderr:
            print("构建警告/错误:")
            print(result.stderr[:500])
        
        return True
    except subprocess.CalledProcessError as e:
        print(f"构建失败: {e}")
        if e.stdout:
            print(f"标准输出: {e.stdout[:500]}")
        if e.stderr:
            print(f"标准错误: {e.stderr[:500]}")
        return False

def verify_build():
    """验证构建结果"""
    print("验证构建结果...")
    
    # 在macOS上，PyInstaller会生成.app或可执行文件
    # 检查dist目录中的内容
    if not DIST_DIR.exists():
        print(f"错误: 构建目录不存在: {DIST_DIR}")
        return False
    
    # 列出dist目录内容
    print(f"dist目录内容:")
    for item in DIST_DIR.iterdir():
        print(f"  - {item.name}")
    
    # 检查是否有可执行文件
    exe_files = list(DIST_DIR.glob("gulfsign_desktop_v3*"))
    if not exe_files:
        print("错误: 未找到可执行文件")
        return False
    
    for exe_file in exe_files:
        print(f"找到文件: {exe_file}")
        if exe_file.is_file():
            size_mb = exe_file.stat().st_size / 1024 / 1024
            print(f"  大小: {size_mb:.2f} MB")
    
    return True

def create_deployment_package():
    """创建部署包"""
    print("创建部署包...")
    
    deploy_dir = PROJECT_ROOT / "gulfsign_deployment_package"
    if deploy_dir.exists():
        shutil.rmtree(deploy_dir)
    
    deploy_dir.mkdir(exist_ok=True)
    
    # 复制可执行文件
    exe_files = list(DIST_DIR.glob("gulfsign_desktop_v3*"))
    for exe_file in exe_files:
        shutil.copy2(exe_file, deploy_dir)
        print(f"复制: {exe_file.name}")
    
    # 复制配置文件
    config_files = [
        "gulfsign_config.json",
        "使用说明.txt",
        "使用说明_最终版.txt",
        "快速上手指南.txt",
        "操作教程.txt",
    ]
    
    for config_file in config_files:
        config_path = PROJECT_ROOT / config_file
        if config_path.exists():
            shutil.copy2(config_path, deploy_dir)
            print(f"复制: {config_file}")
    
    # 创建版本信息
    version_info = {
        "application": "湾流签约助手桌面版",
        "version": "3.1.0",
        "build_date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "platform": sys.platform,
        "python_version": sys.version,
        "features": [
            "自动化家庭医生签约系统",
            "年龄验证绕行功能",
            "状态转换探索工具",
            "实名认证ID修改分析",
            "家庭成员移除业务规则分析",
            "sjfx API字段名发现工具",
            "渗透测试模拟框架",
            "高级攻击模拟场景",
            "全面安全评估报告",
            "批量处理引擎",
            "Excel日志记录",
            "许可证验证系统",
            "配置迁移工具"
        ]
    }
    
    version_file = deploy_dir / "version_info.json"
    with open(version_file, 'w', encoding='utf-8') as f:
        json.dump(version_info, f, indent=2, ensure_ascii=False)
    
    print(f"版本信息已创建: {version_file}")
    
    # 创建部署说明
    deploy_readme = deploy_dir / "DEPLOYMENT_README.txt"
    with open(deploy_readme, 'w', encoding='utf-8') as f:
        f.write(f"""湾流签约助手桌面版 v3.1.0 - 部署说明

部署时间: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}

包含文件:
1. 主程序: gulfsign_desktop_v3 (可执行文件)
2. 配置文件: gulfsign_config.json
3. 使用说明文档
4. 版本信息: version_info.json

系统要求:
- 网络连接（访问公卫3.0和健康卡平台）
- 适当的系统权限

使用步骤:
1. 确保所有文件在同一目录
2. 运行 gulfsign_desktop_v3
3. 按照使用说明配置系统
4. 开始自动化签约

注意事项:
- 首次运行需要配置机构代码和账号信息
- 确保网络连接正常
- 定期备份配置文件

技术支持:
请参考随附的使用说明文档

免责声明:
本工具仅用于合法的家庭医生签约自动化，使用者需遵守相关法律法规。
""")
    
    print(f"部署说明已创建: {deploy_readme}")
    print(f"部署包位置: {deploy_dir}")
    
    return deploy_dir

def main():
    """主函数"""
    print("=" * 60)
    print("湾流签约助手EXE生成工具 (简化版)")
    print("=" * 60)
    print(f"项目目录: {PROJECT_ROOT}")
    print(f"Python路径: {sys.executable}")
    print(f"平台: {sys.platform}")
    print()
    
    # 检查主应用文件
    if not (PROJECT_ROOT / MAIN_APP).exists():
        print(f"错误: 主应用文件不存在: {MAIN_APP}")
        return False
    
    # 步骤1: 清理构建目录
    clean_build_dirs()
    
    # 步骤2: 检查依赖
    if not check_dependencies():
        print("依赖检查失败")
        return False
    
    # 步骤3: 构建EXE
    print("\n开始构建...")
    if not create_exe():
        print("构建失败")
        return False
    
    # 步骤4: 验证构建
    if not verify_build():
        print("构建验证失败")
        return False
    
    # 步骤5: 创建部署包
    deploy_dir = create_deployment_package()
    
    # 输出结果
    print("\n" + "=" * 60)
    print("构建成功完成!")
    print("=" * 60)
    print(f"部署包位置: {deploy_dir}")
    
    # 显示部署包内容
    print("\n部署包内容:")
    for item in deploy_dir.iterdir():
        size_kb = item.stat().st_size / 1024
        print(f"  - {item.name} ({size_kb:.1f} KB)")
    
    print("\n下一步:")
    print("1. 将整个部署包文件夹复制到目标计算机")
    print("2. 运行主程序文件")
    print("3. 按照使用说明配置系统")
    print("4. 开始自动化签约")
    
    return True

if __name__ == "__main__":
    try:
        success = main()
        sys.exit(0 if success else 1)
    except KeyboardInterrupt:
        print("\n构建被用户中断")
        sys.exit(1)
    except Exception as e:
        print(f"\n构建过程中发生错误: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)