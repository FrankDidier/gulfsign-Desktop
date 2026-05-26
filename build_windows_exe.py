#!/usr/bin/env python3
"""
Windows EXE 构建脚本
生成可直接分享给客户端的可执行文件
"""

import os
import sys
import json
import shutil
import subprocess
import platform
from datetime import datetime
from pathlib import Path
import zipfile

class WindowsEXEBuilder:
    """Windows EXE 构建器"""
    
    def __init__(self):
        self.project_root = Path(__file__).parent
        self.build_dir = self.project_root / "build_windows"
        self.dist_dir = self.project_root / "dist_windows"
        self.deploy_dir = self.project_root / "gulfsign_client_package"
        
        # 主应用程序文件
        self.main_app = "app.py"
        
        # 需要包含的文件
        self.include_files = [
            "ph3_api.py",
            "hc_api.py", 
            "sign_engine.py",
            "proxy_capture.py",
            "license_client.py",
            "config_manager.py",
            "batch_processor.py",
            "gulfsign_config.json",
            "requirements.txt",
            "使用说明.txt",
            "使用说明_最终版.txt",
            "快速上手指南.txt",
            "操作教程.txt",
        ]
        
        # 需要包含的数据目录
        self.include_data_dirs = [
            "actual_demo",
            "batch_processing_test",
            "encryption_test",
            "excel_log_test",
            "final_verification_proof",
            "real_config_test",
            "real_test_logs",
            "ultimate_verification",
        ]
        
        # 排除模式
        self.exclude_patterns = [
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
    
    def clean_build_dirs(self):
        """清理构建目录"""
        print("清理构建目录...")
        
        dirs_to_clean = [self.build_dir, self.dist_dir, self.deploy_dir]
        for dir_path in dirs_to_clean:
            if dir_path.exists():
                try:
                    shutil.rmtree(dir_path)
                    print(f"  ✓ 已删除: {dir_path.name}")
                except Exception as e:
                    print(f"  ✗ 删除失败 {dir_path.name}: {e}")
        
        return True
    
    def check_environment(self):
        """检查构建环境"""
        print("检查构建环境...")
        
        # 检查操作系统
        current_os = platform.system()
        print(f"  当前操作系统: {current_os}")
        
        if current_os != "Windows":
            print("  ⚠ 警告: 非Windows环境，构建的EXE可能不完全兼容")
            print("  建议在Windows系统上进行最终构建")
        
        # 检查Python版本
        python_version = sys.version_info
        print(f"  Python版本: {python_version.major}.{python_version.minor}.{python_version.micro}")
        
        if python_version.major < 3 or (python_version.major == 3 and python_version.minor < 8):
            print("  ✗ 错误: Python版本过低，需要3.8或更高版本")
            return False
        
        # 检查PyInstaller
        try:
            import PyInstaller
            print(f"  ✓ PyInstaller版本: {PyInstaller.__version__}")
        except ImportError:
            print("  ✗ 错误: PyInstaller未安装")
            print("  请运行: pip install pyinstaller")
            return False
        
        # 检查主应用文件
        if not (self.project_root / self.main_app).exists():
            print(f"  ✗ 错误: 主应用文件不存在: {self.main_app}")
            return False
        
        print("  ✓ 环境检查通过")
        return True
    
    def install_dependencies(self):
        """安装依赖"""
        print("安装依赖包...")
        
        requirements_file = self.project_root / "requirements.txt"
        if not requirements_file.exists():
            print("  ⚠ 警告: requirements.txt 不存在")
            return True
        
        try:
            print(f"  从 {requirements_file.name} 安装依赖...")
            subprocess.check_call([
                sys.executable, "-m", "pip", "install", 
                "-r", str(requirements_file)
            ])
            print("  ✓ 依赖安装完成")
            return True
        except subprocess.CalledProcessError as e:
            print(f"  ✗ 依赖安装失败: {e}")
            return False
    
    def create_spec_file(self):
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
for file_name in {self.include_files}:
    if os.path.exists(file_name):
        datas.append((file_name, '.'))

# 添加数据目录
for src_dir in {self.include_data_dirs}:
    if os.path.exists(src_dir):
        for root, dirs, files in os.walk(src_dir):
            for file in files:
                # 检查是否应该排除
                exclude = False
                for pattern in {self.exclude_patterns}:
                    if pattern in file or pattern in root:
                        exclude = True
                        break
                
                if not exclude:
                    src_path = os.path.join(root, file)
                    rel_path = os.path.relpath(root, src_dir)
                    dest_path = os.path.join(src_dir, rel_path)
                    datas.append((src_path, dest_path))

a = Analysis(
    ['{self.main_app}'],
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
    name='GulfSign_Client',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,  # 不显示控制台窗口
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon='icon.ico' if os.path.exists('icon.ico') else None,
)

coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name='GulfSign_Client',
)
'''
        
        spec_file = self.project_root / "gulfsign_windows.spec"
        with open(spec_file, 'w', encoding='utf-8') as f:
            f.write(spec_content)
        
        print(f"  ✓ Spec文件已创建: {spec_file.name}")
        return spec_file
    
    def build_exe(self):
        """构建EXE文件"""
        print("构建EXE文件...")
        
        spec_file = self.create_spec_file()
        
        # 构建命令
        cmd = [
            sys.executable, "-m", "PyInstaller",
            "--clean",
            "--noconfirm",
            str(spec_file)
        ]
        
        print(f"  执行命令: {' '.join(cmd)}")
        
        try:
            result = subprocess.run(cmd, check=True, capture_output=True, text=True)
            
            if result.stdout:
                print("  构建输出:")
                for line in result.stdout.split('\n')[:10]:  # 只显示前10行
                    if line.strip():
                        print(f"    {line}")
            
            if result.stderr:
                print("  构建警告/错误:")
                for line in result.stderr.split('\n')[:10]:
                    if line.strip():
                        print(f"    {line}")
            
            print("  ✓ EXE构建完成")
            return True
            
        except subprocess.CalledProcessError as e:
            print(f"  ✗ EXE构建失败: {e}")
            if e.stdout:
                print("  标准输出:")
                print(e.stdout[:500])
            if e.stderr:
                print("  标准错误:")
                print(e.stderr[:500])
            return False
    
    def create_icon_file(self):
        """创建图标文件（如果不存在）"""
        print("创建图标文件...")
        
        icon_file = self.project_root / "icon.ico"
        
        if icon_file.exists():
            print(f"  ✓ 图标文件已存在: {icon_file.name}")
            return True
        
        # 创建一个简单的ICO文件（使用Python生成）
        try:
            # 这里可以添加生成ICO文件的代码
            # 暂时创建一个空文件作为占位符
            with open(icon_file, 'wb') as f:
                f.write(b'')  # 空文件
            
            print(f"  ⚠ 创建了空的图标文件: {icon_file.name}")
            print("  建议: 请提供专业的ICO图标文件以获得更好的用户体验")
            return True
        except Exception as e:
            print(f"  ✗ 创建图标文件失败: {e}")
            return False
    
    def create_deployment_package(self):
        """创建部署包"""
        print("创建部署包...")
        
        # 确保部署目录存在
        self.deploy_dir.mkdir(exist_ok=True)
        
        # 复制EXE文件
        exe_source = self.dist_dir / "GulfSign_Client" / "GulfSign_Client.exe"
        if exe_source.exists():
            exe_dest = self.deploy_dir / "GulfSign_Client.exe"
            shutil.copy2(exe_source, exe_dest)
            print(f"  ✓ 复制EXE文件: {exe_dest.name}")
        else:
            print(f"  ✗ EXE文件不存在: {exe_source}")
            return False
        
        # 复制配置文件
        config_files = [
            "gulfsign_config.json",
            "使用说明.txt",
            "使用说明_最终版.txt",
            "快速上手指南.txt",
            "操作教程.txt",
        ]
        
        for config_file in config_files:
            source = self.project_root / config_file
            if source.exists():
                dest = self.deploy_dir / config_file
                shutil.copy2(source, dest)
                print(f"  ✓ 复制配置文件: {config_file}")
        
        # 创建版本信息文件
        self.create_version_info_file()
        
        # 创建安装说明
        self.create_installation_guide()
        
        # 创建ZIP压缩包
        self.create_zip_package()
        
        print(f"  ✓ 部署包创建完成: {self.deploy_dir}")
        return True
    
    def create_version_info_file(self):
        """创建版本信息文件"""
        version_info = {
            "application": "湾流签约助手客户端版",
            "version": "3.1.0",
            "build_date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "platform": "Windows",
            "python_version": f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
            "features": [
                "自动化家庭医生签约系统",
                "年龄验证绕行功能",
                "批量处理引擎",
                "Excel日志记录",
                "许可证验证系统",
                "配置迁移工具",
            ],
            "system_requirements": [
                "Windows 7/8/10/11",
                "网络连接（访问公卫3.0和健康卡平台）",
                "适当的系统权限",
            ],
            "installation": [
                "1. 解压ZIP文件到任意目录",
                "2. 运行 GulfSign_Client.exe",
                "3. 按照界面提示配置系统",
                "4. 开始使用",
            ],
            "support": [
                "技术支持: 请参考随附的使用说明文档",
                "故障排除: 查看程序生成的日志文件",
                "更新: 定期检查新版本",
            ],
            "disclaimer": "本工具仅用于合法的家庭医生签约自动化，使用者需遵守相关法律法规。",
        }
        
        version_file = self.deploy_dir / "version_info.json"
        with open(version_file, 'w', encoding='utf-8') as f:
            json.dump(version_info, f, indent=2, ensure_ascii=False)
        
        print(f"  ✓ 创建版本信息文件: {version_file.name}")
        return version_file
    
    def create_installation_guide(self):
        """创建安装指南"""
        guide_content = f'''湾流签约助手客户端版 - 安装指南
========================================

版本: 3.1.0
构建日期: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}

概述
----
湾流签约助手是一款专业的家庭医生签约自动化工具，帮助医疗机构高效完成批量签约工作。

系统要求
--------
- 操作系统: Windows 7/8/10/11 (64位)
- 网络连接: 可访问公卫3.0系统和健康卡平台
- 磁盘空间: 至少100MB可用空间
- 权限: 管理员权限（推荐）

安装步骤
--------
1. 解压下载的ZIP文件到任意目录（建议: C:\\Program Files\\GulfSign）
2. 双击运行 GulfSign_Client.exe
3. 首次运行需要配置以下信息：
   - 机构代码
   - 账号
   - 密码
4. 测试系统连接
5. 保存配置
6. 开始使用

快速开始
--------
1. 导入患者数据（支持JSON格式）
2. 配置签约参数
3. 开始批量签约
4. 查看签约结果和日志

功能特性
--------
1. 自动化签约系统
   - 支持批量处理
   - 自动创建居民申请
   - 自动确认签约

2. 年龄验证绕行
   - 智能身份证号生成
   - 年龄计算和验证
   - 绕行方案评估

3. 批量处理引擎
   - 生产者-消费者模式
   - 20个工作线程
   - 高效并发处理

4. 日志记录系统
   - Excel格式日志
   - 详细操作记录
   - 错误追踪

配置文件
--------
程序会自动创建以下文件：
- gulfsign_config.json - 主配置文件
- logs/ - 日志目录
- excel_logs/ - Excel日志目录

故障排除
--------
1. 登录失败
   - 检查网络连接
   - 验证账号密码
   - 确认系统状态

2. 签约失败
   - 检查患者数据完整性
   - 验证系统状态
   - 查看错误日志

3. 文件权限问题
   - 以管理员身份运行
   - 检查文件读写权限
   - 更改工作目录

技术支持
--------
- 使用说明: 请参考随附的文档文件
- 问题反馈: 查看程序生成的日志
- 版本更新: 定期检查新版本

免责声明
--------
本工具仅用于合法的家庭医生签约自动化，使用者需遵守相关法律法规和系统使用协议。

========================================
构建时间: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
版权所有: 湾流医疗技术团队
'''

        guide_file = self.deploy_dir / "安装指南.txt"
        with open(guide_file, 'w', encoding='utf-8') as f:
            f.write(guide_content)
        
        print(f"  ✓ 创建安装指南: {guide_file.name}")
        return guide_file
    
    def create_zip_package(self):
        """创建ZIP压缩包"""
        print("创建ZIP压缩包...")
        
        zip_filename = self.project_root / "GulfSign_Client_v3.1.0_Windows.zip"
        
        # 如果ZIP文件已存在，删除它
        if zip_filename.exists():
            zip_filename.unlink()
        
        # 创建ZIP文件
        with zipfile.ZipFile(zip_filename, 'w', zipfile.ZIP_DEFLATED) as zipf:
            # 添加部署目录中的所有文件
            for file_path in self.deploy_dir.rglob('*'):
                if file_path.is_file():
                    arcname = file_path.relative_to(self.deploy_dir)
                    zipf.write(file_path, arcname)
                    print(f"    ✓ 添加: {arcname}")
        
        zip_size = zip_filename.stat().st_size / (1024 * 1024)  # MB
        print(f"  ✓ ZIP压缩包创建完成: {zip_filename.name} ({zip_size:.2f} MB)")
        
        return zip_filename
    
    def verify_build(self):
        """验证构建结果"""
        print("验证构建结果...")
        
        # 检查EXE文件
        exe_file = self.dist_dir / "GulfSign_Client" / "GulfSign_Client.exe"
        if not exe_file.exists():
            print(f"  ✗ EXE文件不存在: {exe_file}")
            return False
        
        exe_size = exe_file.stat().st_size / (1024 * 1024)  # MB
        print(f"  ✓ EXE文件大小: {exe_size:.2f} MB")
        
        # 检查部署包
        if not self.deploy_dir.exists():
            print(f"  ✗ 部署包目录不存在: {self.deploy_dir}")
            return False
        
        # 检查必要文件
        required_files = [
            "GulfSign_Client.exe",
            "gulfsign_config.json",
            "使用说明.txt",
            "安装指南.txt",
            "version_info.json",
        ]
        
        for file_name in required_files:
            file_path = self.deploy_dir / file_name
            if not file_path.exists():
                print(f"  ✗ 必要文件缺失: {file_name}")
                return False
        
        print("  ✓ 构建验证通过")
        return True
    
    def run(self):
        """运行构建过程"""
        print("=" * 60)
        print("湾流签约助手 - Windows EXE 构建工具")
        print("=" * 60)
        
        # 步骤1: 清理构建目录
        print("\n[步骤1] 清理构建目录")
        if not self.clean_build_dirs():
            return False
        
        # 步骤2: 检查环境
        print("\n[步骤2] 检查构建环境")
        if not self.check_environment():
            return False
        
        # 步骤3: 安装依赖
        print("\n[步骤3] 安装依赖包")
        if not self.install_dependencies():
            print("  ⚠ 依赖安装失败，尝试继续构建...")
        
        # 步骤4: 创建图标文件
        print("\n[步骤4] 创建图标文件")
        self.create_icon_file()
        
        # 步骤5: 构建EXE
        print("\n[步骤5] 构建EXE文件")
        if not self.build_exe():
            return False
        
        # 步骤6: 创建部署包
        print("\n[步骤6] 创建部署包")
        if not self.create_deployment_package():
            return False
        
        # 步骤7: 验证构建
        print("\n[步骤7] 验证构建结果")
        if not self.verify_build():
            return False
        
        # 输出结果
        print("\n" + "=" * 60)
        print("构建成功完成!")
        print("=" * 60)
        
        # 显示文件信息
        print("\n生成的文件:")
        print("-" * 40)
        
        # EXE文件
        exe_file = self.dist_dir / "GulfSign_Client" / "GulfSign_Client.exe"
        if exe_file.exists():
            exe_size = exe_file.stat().st_size / (1024 * 1024)
            print(f"  • GulfSign_Client.exe")
            print(f"    大小: {exe_size:.2f} MB")
            print(f"    位置: {exe_file}")
        
        # ZIP压缩包
        zip_file = self.project_root / "GulfSign_Client_v3.1.0_Windows.zip"
        if zip_file.exists():
            zip_size = zip_file.stat().st_size / (1024 * 1024)
            print(f"\n  • GulfSign_Client_v3.1.0_Windows.zip")
            print(f"    大小: {zip_size:.2f} MB")
            print(f"    位置: {zip_file}")
        
        # 部署包目录
        print(f"\n  • 部署包目录")
        print(f"    位置: {self.deploy_dir}")
        
        # 列出部署包内容
        print(f"\n部署包内容:")
        for item in self.deploy_dir.iterdir():
            if item.is_file():
                size_kb = item.stat().st_size / 1024
                print(f"    - {item.name} ({size_kb:.1f} KB)")
        
        print("\n" + "=" * 60)
        print("部署说明:")
        print("=" * 60)
        print("1. 将 'GulfSign_Client_v3.1.0_Windows.zip' 发送给客户端")
        print("2. 客户端解压ZIP文件到任意目录")
        print("3. 运行 GulfSign_Client.exe")
        print("4. 按照安装指南配置系统")
        print("5. 开始自动化签约")
        print("=" * 60)
        
        return True

def main():
    """主函数"""
    try:
        builder = WindowsEXEBuilder()
        success = builder.run()
        sys.exit(0 if success else 1)
    except KeyboardInterrupt:
        print("\n构建被用户中断")
        sys.exit(1)
    except Exception as e:
        print(f"\n构建过程中发生错误: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()