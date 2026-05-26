#!/usr/bin/env python3
"""
创建客户端部署包
生成可直接分享给客户端的完整包
"""

import os
import sys
import json
import shutil
import zipfile
import platform
from datetime import datetime
from pathlib import Path

class ClientPackageCreator:
    """客户端包创建器"""
    
    def __init__(self):
        self.project_root = Path(__file__).parent
        self.package_dir = self.project_root / "GulfSign_Client_Package"
        self.zip_filename = self.project_root / "GulfSign_Client_v3.1.0.zip"
        
        # 核心文件列表
        self.core_files = [
            "app.py",
            "ph3_api.py",
            "hc_api.py",
            "sign_engine.py",
            "proxy_capture.py",
            "license_client.py",
            "config_manager.py",
            "batch_processor.py",
            "gulfsign_config.json",
            "requirements.txt",
        ]
        
        # 新功能模块
        self.new_feature_files = [
            "ultimate_status_conversion_explorer.py",
            "ultimate_realname_id_modification_explorer.py",
            "ultimate_family_member_removal_analyzer.py",
            "ultimate_sjfx_field_discovery_explorer.py",
            "comprehensive_age_bypass_validation.py",
            "comprehensive_solution_matrix.py",
            "penetration_testing_simulation_framework.py",
            "advanced_attack_simulation_scenarios.py",
        ]
        
        # 文档文件
        self.document_files = [
            "使用说明.txt",
            "使用说明_最终版.txt",
            "快速上手指南.txt",
            "操作教程.txt",
            "README_EXE_BUILD.md",
            "sqli_exploitation_benefits_analysis.md",
            "final_deployment_summary.md",
        ]
        
        # 工具脚本
        self.tool_files = [
            "launch_gulfsign.py",
            "simple_build_exe.py",
            "build_gulfsign_exe.py",
            "build_windows_exe.py",
            "test_comprehensive_app.py",
        ]
        
        # 数据目录
        self.data_dirs = [
            "actual_demo",
            "batch_processing_test",
            "encryption_test",
            "excel_log_test",
            "final_verification_proof",
            "logs",
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
    
    def clean_package_dir(self):
        """清理包目录"""
        print("清理包目录...")
        
        if self.package_dir.exists():
            try:
                shutil.rmtree(self.package_dir)
                print(f"  ✓ 已删除: {self.package_dir.name}")
            except Exception as e:
                print(f"  ✗ 删除失败: {e}")
                return False
        
        if self.zip_filename.exists():
            try:
                self.zip_filename.unlink()
                print(f"  ✓ 已删除: {self.zip_filename.name}")
            except Exception as e:
                print(f"  ✗ 删除失败: {e}")
        
        return True
    
    def create_package_structure(self):
        """创建包结构"""
        print("创建包结构...")
        
        # 创建主目录
        self.package_dir.mkdir(exist_ok=True)
        
        # 创建子目录
        subdirs = [
            "core_modules",
            "new_features",
            "documentation",
            "tools",
            "data",
            "logs",
        ]
        
        for subdir in subdirs:
            (self.package_dir / subdir).mkdir(exist_ok=True)
        
        print("  ✓ 包结构创建完成")
        return True
    
    def copy_core_files(self):
        """复制核心文件"""
        print("复制核心文件...")
        
        copied = 0
        for file_name in self.core_files:
            source = self.project_root / file_name
            if source.exists():
                dest = self.package_dir / "core_modules" / file_name
                shutil.copy2(source, dest)
                print(f"  ✓ {file_name}")
                copied += 1
            else:
                print(f"  ⚠ {file_name} (不存在)")
        
        print(f"  ✓ 复制了 {copied}/{len(self.core_files)} 个核心文件")
        return copied > 0
    
    def copy_new_feature_files(self):
        """复制新功能文件"""
        print("复制新功能文件...")
        
        copied = 0
        for file_name in self.new_feature_files:
            source = self.project_root / file_name
            if source.exists():
                dest = self.package_dir / "new_features" / file_name
                shutil.copy2(source, dest)
                print(f"  ✓ {file_name}")
                copied += 1
            else:
                print(f"  ⚠ {file_name} (不存在)")
        
        print(f"  ✓ 复制了 {copied}/{len(self.new_feature_files)} 个新功能文件")
        return True
    
    def copy_document_files(self):
        """复制文档文件"""
        print("复制文档文件...")
        
        copied = 0
        for file_name in self.document_files:
            source = self.project_root / file_name
            if source.exists():
                dest = self.package_dir / "documentation" / file_name
                shutil.copy2(source, dest)
                print(f"  ✓ {file_name}")
                copied += 1
            else:
                print(f"  ⚠ {file_name} (不存在)")
        
        print(f"  ✓ 复制了 {copied}/{len(self.document_files)} 个文档文件")
        return True
    
    def copy_tool_files(self):
        """复制工具文件"""
        print("复制工具文件...")
        
        copied = 0
        for file_name in self.tool_files:
            source = self.project_root / file_name
            if source.exists():
                dest = self.package_dir / "tools" / file_name
                shutil.copy2(source, dest)
                print(f"  ✓ {file_name}")
                copied += 1
            else:
                print(f"  ⚠ {file_name} (不存在)")
        
        print(f"  ✓ 复制了 {copied}/{len(self.tool_files)} 个工具文件")
        return True
    
    def copy_data_directories(self):
        """复制数据目录"""
        print("复制数据目录...")
        
        copied = 0
        for dir_name in self.data_dirs:
            source = self.project_root / dir_name
            if source.exists():
                dest = self.package_dir / "data" / dir_name
                if source.is_dir():
                    shutil.copytree(source, dest, dirs_exist_ok=True)
                    print(f"  ✓ {dir_name}/")
                    copied += 1
                else:
                    shutil.copy2(source, dest)
                    print(f"  ✓ {dir_name}")
            else:
                print(f"  ⚠ {dir_name} (不存在)")
        
        print(f"  ✓ 复制了 {copied}/{len(self.data_dirs)} 个数据目录")
        return True
    
    def create_launcher_script(self):
        """创建启动脚本"""
        print("创建启动脚本...")
        
        # Windows批处理文件
        bat_content = '''@echo off
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
'''
        
        bat_file = self.package_dir / "启动程序.bat"
        with open(bat_file, 'w', encoding='gbk') as f:
            f.write(bat_content)
        
        print(f"  ✓ 创建Windows启动脚本: {bat_file.name}")
        
        # Linux/Mac shell脚本
        sh_content = '''#!/bin/bash
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
'''
        
        sh_file = self.package_dir / "启动程序.sh"
        with open(sh_file, 'w', encoding='utf-8') as f:
            f.write(sh_content)
        
        # 设置执行权限
        os.chmod(sh_file, 0o755)
        
        print(f"  ✓ 创建Linux/Mac启动脚本: {sh_file.name}")
        
        return True
    
    def create_readme_file(self):
        """创建README文件"""
        print("创建README文件...")
        
        readme_content = f'''湾流签约助手客户端版 v3.1.0
========================================

概述
----
湾流签约助手是一款专业的家庭医生签约自动化工具，帮助医疗机构高效完成批量签约工作。

版本信息
--------
- 版本号: 3.1.0
- 构建日期: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
- 平台: 跨平台 (Windows/Linux/macOS)

系统要求
--------
- Python 3.8或更高版本
- 网络连接 (访问公卫3.0和健康卡平台)
- 适当的系统权限

目录结构
--------
GulfSign_Client_Package/
├── core_modules/          # 核心模块
│   ├── app.py            # 主应用程序
│   ├── ph3_api.py        # 公卫3.0 API客户端
│   ├── hc_api.py         # 健康卡平台客户端
│   ├── sign_engine.py    # 签约引擎
│   ├── proxy_capture.py  # 代理抓包工具
│   ├── license_client.py # 许可证客户端
│   ├── config_manager.py # 配置管理器
│   ├── batch_processor.py # 批量处理器
│   ├── gulfsign_config.json # 配置文件
│   └── requirements.txt  # Python依赖
├── new_features/         # 新功能模块
│   ├── ultimate_status_conversion_explorer.py
│   ├── ultimate_realname_id_modification_explorer.py
│   ├── ultimate_family_member_removal_analyzer.py
│   ├── ultimate_sjfx_field_discovery_explorer.py
│   ├── comprehensive_age_bypass_validation.py
│   ├── comprehensive_solution_matrix.py
│   ├── penetration_testing_simulation_framework.py
│   └── advanced_attack_simulation_scenarios.py
├── documentation/        # 文档
│   ├── 使用说明.txt
│   ├── 使用说明_最终版.txt
│   ├── 快速上手指南.txt
│   ├── 操作教程.txt
│   ├── README_EXE_BUILD.md
│   ├── sqli_exploitation_benefits_analysis.md
│   └── final_deployment_summary.md
├── tools/               # 工具脚本
│   ├── launch_gulfsign.py
│   ├── simple_build_exe.py
│   ├── build_gulfsign_exe.py
│   ├── build_windows_exe.py
│   └── test_comprehensive_app.py
├── data/               # 数据目录
│   ├── actual_demo/
│   ├── batch_processing_test/
│   ├── encryption_test/
│   ├── excel_log_test/
│   ├── final_verification_proof/
│   ├── logs/
│   ├── real_config_test/
│   ├── real_test_logs/
│   └── ultimate_verification/
├── logs/               # 日志目录
├── 启动程序.bat        # Windows启动脚本
├── 启动程序.sh         # Linux/Mac启动脚本
└── README.txt         # 本文件

快速开始
--------

Windows系统:
1. 双击运行 "启动程序.bat"
2. 按照提示安装依赖
3. 应用程序自动启动

Linux/Mac系统:
1. 打开终端
2. 运行: chmod +x 启动程序.sh
3. 运行: ./启动程序.sh
4. 按照提示安装依赖
5. 应用程序自动启动

手动启动:
1. 安装依赖: pip install -r core_modules/requirements.txt
2. 运行程序: python core_modules/app.py

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

4. 高级分析工具
   - 状态转换探索
   - 实名认证ID修改分析
   - 家庭成员移除分析
   - sjfx API字段名发现

5. 安全评估工具
   - 渗透测试模拟
   - 高级攻击模拟
   - 全面安全评估

6. 日志记录系统
   - Excel格式日志
   - 详细操作记录
   - 错误追踪

使用步骤
--------

1. 首次运行
   - 输入机构代码
   - 输入账号和密码
   - 测试系统连接
   - 保存配置

2. 导入数据
   - 准备患者数据 (JSON格式)
   - 导入数据文件
   - 验证数据完整性

3. 批量签约
   - 配置签约参数
   - 开始批量处理
   - 监控处理进度

4. 查看结果
   - 查看签约结果
   - 导出Excel日志
   - 生成统计报告

配置文件
--------
程序会自动创建以下文件:
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

3. 依赖安装失败
   - 检查Python版本
   - 检查网络连接
   - 尝试手动安装

技术支持
--------
- 详细文档: 请参考 documentation/ 目录
- 问题反馈: 查看 logs/ 目录中的日志文件
- 版本更新: 定期检查新版本

免责声明
--------
本工具仅用于合法的家庭医生签约自动化，使用者需遵守相关法律法规和系统使用协议。

========================================
构建时间: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
版权所有: 湾流医疗技术团队
'''
        
        readme_file = self.package_dir / "README.txt"
        with open(readme_file, 'w', encoding='utf-8') as f:
            f.write(readme_content)
        
        print(f"  ✓ 创建README文件: {readme_file.name}")
        return readme_file
    
    def create_quick_start_guide(self):
        """创建快速入门指南"""
        print("创建快速入门指南...")
        
        guide_content = '''湾流签约助手 - 快速入门指南
========================================

第一步: 环境准备
---------------
1. 确保已安装Python 3.8或更高版本
2. 打开命令行工具 (CMD或终端)

第二步: 安装依赖
---------------
打开命令行，进入程序目录，运行:

Windows:
```
pip install -r core_modules/requirements.txt
```

Linux/Mac:
```
pip3 install -r core_modules/requirements.txt
```

第三步: 启动程序
---------------
运行主程序:

```
python core_modules/app.py
```

或使用启动脚本:

Windows: 双击 "启动程序.bat"
Linux/Mac: 运行 "./启动程序.sh"

第四步: 首次配置
---------------
1. 输入您的机构代码
2. 输入账号和密码
3. 点击"测试连接"验证
4. 点击"保存配置"

第五步: 导入数据
---------------
1. 准备患者数据 (JSON格式)
2. 点击"导入数据"按钮
3. 选择数据文件
4. 验证数据完整性

第六步: 开始签约
---------------
1. 配置签约参数
2. 点击"开始批量签约"
3. 监控处理进度
4. 查看签约结果

常见问题
--------

Q: 登录失败怎么办?
A: 检查网络连接、账号密码、系统状态

Q: 签约失败怎么办?
A: 检查患者数据、系统状态、查看错误日志

Q: 依赖安装失败怎么办?
A: 检查Python版本、网络连接、尝试手动安装

Q: 程序无法启动怎么办?
A: 检查Python安装、文件权限、系统兼容性

紧急联系
--------
如遇紧急问题，请参考详细文档或联系技术支持。

========================================
祝您使用愉快!
'''
        
        guide_file = self.package_dir / "快速入门指南.txt"
        with open(guide_file, 'w', encoding='utf-8') as f:
            f.write(guide_content)
        
        print(f"  ✓ 创建快速入门指南: {guide_file.name}")
        return guide_file
    
    def create_zip_package(self):
        """创建ZIP压缩包"""
        print("创建ZIP压缩包...")
        
        if self.zip_filename.exists():
            self.zip_filename.unlink()
        
        with zipfile.ZipFile(self.zip_filename, 'w', zipfile.ZIP_DEFLATED) as zipf:
            # 添加所有文件和目录
            for root, dirs, files in os.walk(self.package_dir):
                # 排除不需要的文件
                dirs[:] = [d for d in dirs if not any(pattern in d for pattern in self.exclude_patterns)]
                
                for file in files:
                    if any(pattern in file for pattern in self.exclude_patterns):
                        continue
                    
                    file_path = Path(root) / file
                    arcname = file_path.relative_to(self.package_dir.parent)
                    zipf.write(file_path, arcname)
            
            print(f"  ✓ 添加了 {len(zipf.namelist())} 个文件到ZIP包")
        
        zip_size = self.zip_filename.stat().st_size / (1024 * 1024)  # MB
        print(f"  ✓ ZIP压缩包创建完成: {self.zip_filename.name} ({zip_size:.2f} MB)")
        
        return self.zip_filename
    
    def verify_package(self):
        """验证包完整性"""
        print("验证包完整性...")
        
        # 检查必要文件
        required_files = [
            "core_modules/app.py",
            "core_modules/ph3_api.py",
            "core_modules/gulfsign_config.json",
            "documentation/使用说明.txt",
            "启动程序.bat",
            "启动程序.sh",
            "README.txt",
        ]
        
        missing_files = []
        for rel_path in required_files:
            file_path = self.package_dir / rel_path
            if not file_path.exists():
                missing_files.append(rel_path)
        
        if missing_files:
            print(f"  ✗ 缺失必要文件:")
            for file in missing_files:
                print(f"    - {file}")
            return False
        
        print("  ✓ 包完整性验证通过")
        return True
    
    def run(self):
        """运行包创建过程"""
        print("=" * 60)
        print("湾流签约助手 - 客户端包创建工具")
        print("=" * 60)
        
        # 步骤1: 清理包目录
        print("\n[步骤1] 清理包目录")
        if not self.clean_package_dir():
            return False
        
        # 步骤2: 创建包结构
        print("\n[步骤2] 创建包结构")
        if not self.create_package_structure():
            return False
        
        # 步骤3: 复制核心文件
        print("\n[步骤3] 复制核心文件")
        if not self.copy_core_files():
            return False
        
        # 步骤4: 复制新功能文件
        print("\n[步骤4] 复制新功能文件")
        self.copy_new_feature_files()
        
        # 步骤5: 复制文档文件
        print("\n[步骤5] 复制文档文件")
        self.copy_document_files()
        
        # 步骤6: 复制工具文件
        print("\n[步骤6] 复制工具文件")
        self.copy_tool_files()
        
        # 步骤7: 复制数据目录
        print("\n[步骤7] 复制数据目录")
        self.copy_data_directories()
        
        # 步骤8: 创建启动脚本
        print("\n[步骤8] 创建启动脚本")
        if not self.create_launcher_script():
            return False
        
        # 步骤9: 创建README文件
        print("\n[步骤9] 创建README文件")
        if not self.create_readme_file():
            return False
        
        # 步骤10: 创建快速入门指南
        print("\n[步骤10] 创建快速入门指南")
        self.create_quick_start_guide()
        
        # 步骤11: 验证包完整性
        print("\n[步骤11] 验证包完整性")
        if not self.verify_package():
            return False
        
        # 步骤12: 创建ZIP压缩包
        print("\n[步骤12] 创建ZIP压缩包")
        if not self.create_zip_package():
            return False
        
        # 输出结果
        print("\n" + "=" * 60)
        print("客户端包创建成功!")
        print("=" * 60)
        
        # 显示文件信息
        print("\n生成的文件:")
        print("-" * 40)
        
        # 包目录
        print(f"  • 客户端包目录")
        print(f"    位置: {self.package_dir}")
        print(f"    大小: {self.get_directory_size(self.package_dir):.2f} MB")
        
        # ZIP压缩包
        if self.zip_filename.exists():
            zip_size = self.zip_filename.stat().st_size / (1024 * 1024)
            print(f"\n  • ZIP压缩包")
            print(f"    文件名: {self.zip_filename.name}")
            print(f"    大小: {zip_size:.2f} MB")
            print(f"    位置: {self.zip_filename}")
        
        # 列出包内容
        print(f"\n包内容概览:")
        for item in self.package_dir.iterdir():
            if item.is_dir():
                size_mb = self.get_directory_size(item) / (1024 * 1024)
                print(f"    - {item.name}/ ({size_mb:.2f} MB)")
            else:
                size_kb = item.stat().st_size / 1024
                print(f"    - {item.name} ({size_kb:.1f} KB)")
        
        print("\n" + "=" * 60)
        print("部署说明:")
        print("=" * 60)
        print("1. 将 'GulfSign_Client_v3.1.0.zip' 发送给客户端")
        print("2. 客户端解压ZIP文件到任意目录")
        print("3. 按照README.txt中的说明操作")
        print("4. 运行启动脚本或直接运行程序")
        print("5. 按照界面提示配置和使用系统")
        print("=" * 60)
        
        return True
    
    def get_directory_size(self, path):
        """获取目录大小"""
        total = 0
        for entry in os.scandir(path):
            if entry.is_file():
                total += entry.stat().st_size
            elif entry.is_dir():
                total += self.get_directory_size(entry.path)
        return total

def main():
    """主函数"""
    try:
        creator = ClientPackageCreator()
        success = creator.run()
        sys.exit(0 if success else 1)
    except KeyboardInterrupt:
        print("\n包创建被用户中断")
        sys.exit(1)
    except Exception as e:
        print(f"\n包创建过程中发生错误: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()