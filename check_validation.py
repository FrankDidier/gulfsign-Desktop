#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
检查验证逻辑
"""

import os
import sys
from pathlib import Path

# 添加项目根目录到 Python 路径
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

# 检查 config_manager.py 文件路径
config_manager_path = project_root / "GulfSign_Client_Package/core_modules/config_manager.py"
print(f"配置文件路径: {config_manager_path}")
print(f"文件存在: {config_manager_path.exists()}")

if config_manager_path.exists():
    # 读取文件内容
    with open(config_manager_path, 'r', encoding='utf-8') as f:
        content = f.read()
    
    # 查找 _validate_config 方法
    if 'def _validate_config' in content:
        start = content.find('def _validate_config')
        # 找到方法结束（下一个 def 或 class）
        next_def = content.find('\n    def ', start + 1)
        next_class = content.find('\nclass ', start + 1)
        
        end = min(next_def, next_class) if next_def != -1 and next_class != -1 else max(next_def, next_class)
        if end == -1:
            end = len(content)
        
        method_content = content[start:end]
        print("\n_validate_config 方法内容:")
        print("=" * 60)
        print(method_content)
        print("=" * 60)
        
        # 检查是否包含 password 检查
        if "'password'" in method_content:
            print("\n⚠ 警告: 方法中仍然包含 'password' 字段检查!")
        else:
            print("\n✓ 方法中不包含 'password' 字段检查")
        
        # 检查必需字段
        if "required_fields = ['username']" in method_content:
            print("✓ 必需字段只包含 'username'")
        else:
            print("⚠ 必需字段配置可能不正确")
    else:
        print("\n✗ 未找到 _validate_config 方法")
else:
    print("\n✗ 配置文件不存在")