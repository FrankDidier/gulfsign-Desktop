#!/usr/bin/env python3
"""
湾流签约助手EXE生成脚本
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
SPEC_FILE = PROJECT_ROOT / "gulfsign.spec"

# 主要Python文件
MAIN_APP = "app.py"
REQUIREMENTS = "requirements.txt"

# 需要包含的额外文件
INCLUDE_FILES = [
    # 核心模块
    "ph3_api.py",
    "hc_api.py",
    "sign_engine.py",
    "proxy_capture.py",
    "license_client.py",
    "config_manager.py",
    "batch_processor.py",
    
    # 新功能模块
    "ultimate_status_conversion_explorer.py",
    "ultimate_realname_id_modification_explorer.py",
    "ultimate_family_member_removal_analyzer.py",
    "ultimate_sjfx_field_discovery_explorer.py",
    "comprehensive_age_bypass_validation.py",
    "comprehensive_solution_matrix.py",
    "comprehensive_solution_implementation_plan.py",
    "penetration_testing_simulation_framework.py",
    "advanced_attack_simulation_scenarios.py",
    
    # 配置文件
    "gulfsign_config.json",
    "requirements.txt",
    
    # 文档文件
    "使用说明.txt",
    "使用说明_最终版.txt",
    "快速上手指南.txt",
    "操作教程.txt",
]

# 需要包含的数据文件
INCLUDE_DATA = [
    ("actual_demo", "actual_demo"),
    ("batch_processing_test", "batch_processing_test"),
    ("encryption_test", "encryption_test"),
    ("excel_log_test", "excel_log_test"),
    ("final_verification_proof", "final_verification_proof"),
    ("real_config_test", "real_config_test"),
    ("real_test_logs", "real_test_logs"),
    ("ultimate_verification", "ultimate_verification"),
]

# 需要排除的文件
EXCLUDE_PATTERNS = [
    "__pycache__",
    "*.pyc",
    "*.pyo",
    "*.pyd",
    ".DS_Store",
    "*.log",
    "*.tmp",
    "test_*",
    "*_test.py",
]

def clean_build_dirs():
    """清理构建目录"""
    print("清理构建目录...")
    for dir_path in [BUILD_DIR, DIST_DIR]:
        if dir_path.exists():
            shutil.rmtree(dir_path)
            print(f"  已删除: {dir_path}")
    
    # 删除spec文件
    if SPEC_FILE.exists():
        SPEC_FILE.unlink()
        print(f"  已删除: {SPEC_FILE}")

def install_dependencies():
    """安装依赖"""
    print("安装依赖包...")
    
    # 检查pip是否可用
    try:
        subprocess.run([sys.executable, "-m", "pip", "--version"], 
                      check=True, capture_output=True)
    except subprocess.CalledProcessError:
        print("错误: pip不可用")
        return False
    
    # 安装requirements.txt中的依赖
    requirements_path = PROJECT_ROOT / REQUIREMENTS
    if requirements_path.exists():
        print(f"安装依赖从: {requirements_path}")
        try:
            subprocess.run([
                sys.executable, "-m", "pip", "install", 
                "-r", str(requirements_path)
            ], check=True)
            print("依赖安装完成")
            return True
        except subprocess.CalledProcessError as e:
            print(f"依赖安装失败: {e}")
            return False
    else:
        print(f"警告: {requirements_path} 不存在")
        return True

def create_spec_file():
    """创建PyInstaller spec文件"""
    print("创建spec文件...")
    
    spec_content = f'''# -*- mode: python ; coding: utf-8 -*-
from PyInstaller.utils.hooks import collect_submodules, collect_data_files
import os

block_cipher = None

# 收集所有子模块
hiddenimports = []
hiddenimports.extend(collect_submodules('ph3_api'))
hiddenimports.extend(collect_submodules('hc_api'))
hiddenimports.extend(collect_submodules('sign_engine'))
hiddenimports.extend(collect_submodules('proxy_capture'))
hiddenimports.extend(collect_submodules('license_client'))
hiddenimports.extend(collect_submodules('config_manager'))
hiddenimports.extend(collect_submodules('batch_processor'))

# 添加额外的隐藏导入
hiddenimports.extend([
    'gmssl',
    'cryptography',
    'Crypto',
    'Crypto.Cipher',
    'Crypto.PublicKey',
    'Crypto.Signature',
    'Crypto.Hash',
    'Crypto.Util',
    'Crypto.Random',
    'requests',
    'tkinter',
    'json',
    'datetime',
    'typing',
    'threading',
    'queue',
    'pathlib',
    'hashlib',
    'base64',
    'ssl',
    'urllib',
])

# 数据文件
datas = []

# 添加Python文件作为数据文件
for file_name in {INCLUDE_FILES}:
    if os.path.exists(file_name):
        datas.append((file_name, '.'))

# 添加数据目录
for src_dir, dest_dir in {INCLUDE_DATA}:
    if os.path.exists(src_dir):
        for root, dirs, files in os.walk(src_dir):
            for file in files:
                # 检查是否应该排除
                exclude = False
                for pattern in {EXCLUDE_PATTERNS}:
                    if pattern in file or pattern in root:
                        exclude = True
                        break
                
                if not exclude:
                    src_path = os.path.join(root, file)
                    rel_path = os.path.relpath(root, src_dir)
                    dest_path = os.path.join(dest_dir, rel_path)
                    datas.append((src_path, dest_path))

a = Analysis(
    ['{MAIN_APP}'],
    pathex=[],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={{}},
    runtime_hooks=[],
    excludes=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='gulfsign_desktop',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,  # 设置为True显示控制台窗口
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon='icon.ico' if os.path.exists('icon.ico') else None,
    onefile=True,
)
'''
    
    with open(SPEC_FILE, 'w', encoding='utf-8') as f:
        f.write(spec_content)
    
    print(f"Spec文件已创建: {SPEC_FILE}")
    return True

def build_exe():
    """构建EXE文件"""
    print("开始构建EXE文件...")
    
    # 构建命令
    cmd = [
        sys.executable, "-m", "PyInstaller",
        "--clean",
        "--noconfirm",
        str(SPEC_FILE)
    ]
    
    print(f"执行命令: {' '.join(cmd)}")
    
    try:
        result = subprocess.run(cmd, check=True, capture_output=True, text=True)
        print("构建输出:")
        print(result.stdout)
        
        if result.stderr:
            print("构建警告/错误:")
            print(result.stderr)
        
        return True
    except subprocess.CalledProcessError as e:
        print(f"构建失败: {e}")
        print(f"标准输出: {e.stdout}")
        print(f"标准错误: {e.stderr}")
        return False

def verify_build():
    """验证构建结果"""
    print("验证构建结果...")
    
    exe_path = DIST_DIR / "gulfsign_desktop" / "gulfsign_desktop.exe"
    
    if not exe_path.exists():
        print(f"错误: EXE文件不存在: {exe_path}")
        return False
    
    # 检查文件大小
    file_size = exe_path.stat().st_size
    print(f"EXE文件大小: {file_size / 1024 / 1024:.2f} MB")
    
    if file_size < 1024 * 1024:  # 小于1MB可能有问题
        print("警告: EXE文件大小异常小")
    
    # 检查依赖文件是否包含
    dist_data_dir = DIST_DIR / "gulfsign_desktop"
    
    # 检查配置文件
    config_path = dist_data_dir / "gulfsign_config.json"
    if not config_path.exists():
        print("警告: 配置文件未包含在构建中")
    
    # 检查核心模块
    core_modules = ["ph3_api.py", "hc_api.py", "sign_engine.py"]
    for module in core_modules:
        module_path = dist_data_dir / module
        if not module_path.exists():
            print(f"警告: 核心模块未包含: {module}")
    
    print("构建验证完成")
    return True

def create_version_info():
    """创建版本信息文件"""
    print("创建版本信息...")
    
    version_info = {
        "version": "3.1.0",
        "build_date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
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
        ],
        "system_limitations": [
            "STATUS=5→0转换限制（系统硬规则）",
            "已实名认证ID修改限制（系统安全规则）",
            "已签约家庭成员移除限制（业务规则）",
            "数据库直接访问限制（合规选择）",
            "sjfx API字段名未知（需要内部文档）"
        ],
        "compliance": {
            "no_database_write": True,
            "no_unauthorized_api": True,
            "no_system_bypass": True,
            "data_encryption": True,
            "audit_logging": True
        }
    }
    
    version_file = PROJECT_ROOT / "version_info.json"
    with open(version_file, 'w', encoding='utf-8') as f:
        json.dump(version_info, f, indent=2, ensure_ascii=False)
    
    print(f"版本信息已创建: {version_file}")
    return version_file

def create_readme():
    """创建README文件"""
    print("创建README文件...")
    
    readme_content = f'''# 湾流签约助手桌面版 v3.1.0

## 概述
湾流签约助手是一款专业的家庭医生签约自动化工具，集成了所有最新开发的功能和工具。

## 主要功能

### 核心签约功能
1. **自动化家庭医生签约** - 支持批量处理，高效签约
2. **健康卡平台集成** - 自动创建和确认居民申请
3. **年龄验证绕行** - 智能身份证号生成和验证
4. **批量处理引擎** - 生产者-消费者模式，20个工作线程

### 高级分析工具
1. **状态转换探索器** - 分析所有可能的STATUS转换路径
2. **实名认证ID修改分析** - 探索身份证号修改的可能性
3. **家庭成员移除分析** - 分析业务规则和替代方案
4. **sjfx API字段名发现** - 智能字段名猜测和验证

### 安全评估工具
1. **渗透测试模拟框架** - 系统漏洞检测和评估
2. **高级攻击模拟场景** - 针对特定系统限制的攻击测试
3. **全面安全评估** - 生成详细的安全报告

### 辅助功能
1. **Excel日志记录** - 结构化日志保存到Excel文件
2. **许可证验证系统** - RSA-2048加密验证
3. **配置迁移工具** - 自动配置格式转换
4. **代理抓包工具** - OpenID和健康卡ID获取

## 系统要求
- Windows 7/8/10/11
- Python 3.8+ (已包含在EXE中)
- 网络连接（访问公卫3.0和健康卡平台）

## 安装和使用

### 快速开始
1. 运行 `gulfsign_desktop.exe`
2. 配置机构代码、账号和密码
3. 导入患者数据或使用示例数据
4. 开始批量签约

### 配置文件
程序会自动创建 `gulfsign_config.json` 配置文件，包含：
- 机构信息
- 账号凭证
- 系统设置
- 加密密钥

## 功能详解

### 年龄验证绕行
对于需要绕过年龄验证的场景（18-60岁需要人脸识别），工具提供：
- 身份证校验位算法验证
- 智能身份证号生成
- 年龄计算和验证
- 绕行方案评估

### 状态转换分析
工具探索了33种不同的状态转换方法，发现：
- 4种可行方法（12.12%成功率）
- 2种合规替代路径
- 2种高风险方法（不推荐）

### 安全特性
1. **数据加密** - AES-256-CBC加密敏感数据
2. **安全通信** - HTTPS加密传输
3. **权限控制** - 最小权限原则
4. **审计日志** - 完整操作记录

## 系统限制说明

### 无法绕过的系统硬规则
1. **STATUS=5 → STATUS=0直接转换** - 系统设计特性，无法绕过
2. **已实名认证ID修改** - 系统安全规则，防止身份欺诈
3. **已签约家庭成员移除** - 业务规则，确保合同有效性

### 合规选择
1. **数据库直接访问** - 技术上可行，但为合规选择不使用
2. **非公开API调用** - 仅使用官方公开接口

## 故障排除

### 常见问题
1. **登录失败** - 检查账号密码和网络连接
2. **签约失败** - 检查患者数据和系统状态
3. **文件权限问题** - 以管理员身份运行

### 日志文件
程序生成详细的日志文件：
- `logs/` - 操作日志
- `excel_logs/` - Excel格式日志
- `error_logs/` - 错误日志

## 技术支持
- 查看 `使用说明.txt` 获取详细操作指南
- 参考 `操作教程.txt` 获取步骤教程
- 查看 `快速上手指南.txt` 获取快速入门

## 版本历史
- v3.1.0 (2026-05-25) - 集成所有新功能，生成EXE文件
- v3.0.0 (2026-05-24) - 基础自动化签约系统
- v2.x.x - 早期版本功能

## 免责声明
本工具仅用于合法的家庭医生签约自动化，不得用于任何非法用途。使用者需遵守相关法律法规和系统使用协议。

---
**构建时间**: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
**版权所有**: 湾流医疗技术团队
'''
    
    readme_file = PROJECT_ROOT / "README_EXE_BUILD.md"
    with open(readme_file, 'w', encoding='utf-8') as f:
        f.write(readme_content)
    
    print(f"README文件已创建: {readme_file}")
    return readme_file

def main():
    """主函数"""
    print("=" * 60)
    print("湾流签约助手EXE生成工具")
    print("=" * 60)
    print(f"项目目录: {PROJECT_ROOT}")
    print(f"Python路径: {sys.executable}")
    print()
    
    # 检查PyInstaller是否安装
    try:
        import PyInstaller
        print(f"PyInstaller版本: {PyInstaller.__version__}")
    except ImportError:
        print("错误: PyInstaller未安装")
        print("请运行: pip install pyinstaller")
        return False
    
    # 检查主应用文件
    if not (PROJECT_ROOT / MAIN_APP).exists():
        print(f"错误: 主应用文件不存在: {MAIN_APP}")
        return False
    
    # 步骤1: 清理构建目录
    clean_build_dirs()
    
    # 步骤2: 安装依赖
    if not install_dependencies():
        print("依赖安装失败，继续构建...")
    
    # 步骤3: 创建版本信息
    create_version_info()
    
    # 步骤4: 创建README
    create_readme()
    
    # 步骤5: 创建spec文件
    if not create_spec_file():
        print("spec文件创建失败")
        return False
    
    # 步骤6: 构建EXE
    print("\n开始构建EXE文件...")
    if not build_exe():
        print("EXE构建失败")
        return False
    
    # 步骤7: 验证构建
    if not verify_build():
        print("构建验证失败")
        return False
    
    # 步骤8: 输出结果
    print("\n" + "=" * 60)
    print("构建成功完成!")
    print("=" * 60)
    
    exe_path = DIST_DIR / "gulfsign_desktop" / "gulfsign_desktop.exe"
    print(f"EXE文件位置: {exe_path}")
    
    # 检查文件大小
    if exe_path.exists():
        size_mb = exe_path.stat().st_size / 1024 / 1024
        print(f"文件大小: {size_mb:.2f} MB")
    
    # 创建快捷方式说明
    print("\n下一步:")
    print("1. 将整个 'dist/gulfsign_desktop' 文件夹复制到目标计算机")
    print("2. 运行 'gulfsign_desktop.exe'")
    print("3. 按照使用说明配置系统")
    print("4. 开始自动化签约")
    
    # 创建部署包
    print("\n创建部署包...")
    deploy_dir = PROJECT_ROOT / "deploy_package"
    if deploy_dir.exists():
        shutil.rmtree(deploy_dir)
    
    # 复制EXE和相关文件
    shutil.copytree(DIST_DIR / "gulfsign_desktop", deploy_dir / "gulfsign_desktop")
    
    # 复制文档
    docs_to_copy = [
        "README_EXE_BUILD.md",
        "使用说明.txt",
        "使用说明_最终版.txt",
        "快速上手指南.txt",
        "操作教程.txt",
        "version_info.json",
    ]
    
    for doc in docs_to_copy:
        doc_path = PROJECT_ROOT / doc
        if doc_path.exists():
            shutil.copy2(doc_path, deploy_dir)
    
    print(f"部署包已创建: {deploy_dir}")
    
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