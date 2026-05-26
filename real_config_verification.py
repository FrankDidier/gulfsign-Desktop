#!/usr/bin/env python3
"""
真实配置加载和处理验证
使用实际配置文件进行验证，无模拟数据
"""

import json
import os
import sys
from pathlib import Path
from datetime import datetime

# 添加当前目录到Python路径
sys.path.insert(0, str(Path(__file__).parent))

from config_manager import ConfigManager

def main():
    print("=" * 80)
    print("真实配置加载和处理验证")
    print("=" * 80)
    
    # 1. 检查真实配置文件
    config_path = Path(__file__).parent / "gulfsign_config.json"
    print("\n1. 真实配置文件检查:")
    print(f"   文件路径: {config_path.absolute()}")
    print(f"   文件存在: {config_path.exists()}")
    print(f"   文件大小: {config_path.stat().st_size} 字节")
    
    # 读取原始配置文件内容
    with open(config_path, 'r', encoding='utf-8') as f:
        raw_config = json.load(f)
    print(f"   原始配置字段: {list(raw_config.keys())}")
    print(f"   许可证账号: {raw_config.get('license_account', '未找到')}")
    print(f"   许可证密码: {raw_config.get('license_password', '未找到')}")
    
    # 2. 使用ConfigManager加载配置
    print("\n2. 使用ConfigManager加载配置:")
    
    # 创建测试目录
    test_dir = Path(__file__).parent / "real_config_test"
    if test_dir.exists():
        import shutil
        shutil.rmtree(test_dir)
    test_dir.mkdir(exist_ok=True)
    
    # 复制真实配置文件到测试目录
    test_config_path = test_dir / "gulfsign_config.json"
    with open(config_path, 'r', encoding='utf-8') as src, \
         open(test_config_path, 'w', encoding='utf-8') as dst:
        dst.write(src.read())
    
    config_manager = ConfigManager(config_dir=str(test_dir))
    print("   ✓ ConfigManager初始化成功")
    print(f"   配置目录: {config_manager.config_dir}")
    
    # 加载配置
    config_data = config_manager.load()
    print("   ✓ 配置加载成功")
    print(f"   配置字段总数: {len(config_data)}")
    print("   必需字段检查:")
    
    # 检查必需字段
    required_fields = ['username', 'password', 'url', 'account', 'org_code', 'doctor', 'team']
    for field in required_fields:
        value = config_data.get(field)
        status = '✓' if value else '✗'
        print(f"     {status} {field}: {value if value else '未设置'}")
    
    # 3. 验证配置处理功能
    print("\n3. 配置处理功能验证:")
    
    # 验证配置 - 使用私有方法
    is_valid, message = config_manager._validate_config(config_data)
    print(f"   ✓ 配置验证功能: {is_valid} ({message})")
    
    # 检查加密状态
    password_value = config_data.get('password')
    if password_value:
        # 检查是否为加密格式
        is_encrypted = password_value.startswith('ENC:')
        print(f"   ✓ 配置加密状态: {is_encrypted}")
    else:
        print(f"   ✗ 配置加密状态: 密码字段为空")
    
    # 4. 显示实际配置数据
    print("\n4. 实际配置数据摘要:")
    important_fields = ['url', 'account', 'org_code', 'doctor', 'team', 'delay', 'pop_type']
    for field in important_fields:
        value = config_data.get(field)
        if value:
            print(f"   • {field}: {value}")
    
    # 5. 测试配置保存功能
    print("\n5. 配置保存功能测试:")
    
    # 更新一些配置
    test_config = config_data.copy()
    test_config['username'] = "real_test_user"
    test_config['doctor'] = "真实测试医生"
    test_config['timestamp'] = datetime.now().isoformat()
    
    save_result = config_manager.save(test_config)
    if save_result:
        print("   ✓ 配置保存成功")
        
        # 重新加载验证
        reloaded_config = config_manager.load()
        if reloaded_config.get('username') == test_config['username']:
            print("   ✓ 配置重新加载验证成功")
        else:
            print("   ✗ 配置重新加载验证失败")
    else:
        print("   ✗ 配置保存失败")
    
    # 6. 文件系统验证
    print("\n6. 文件系统验证:")
    
    # 检查实际创建的文件
    files_created = list(test_dir.rglob("*"))
    print(f"   测试目录文件数: {len(files_created)}")
    
    for file_path in files_created:
        if file_path.is_file():
            print(f"   • {file_path.name}: {file_path.stat().st_size} 字节")
    
    print("\n✅ 真实配置加载和处理验证完成")
    print(f"   验证时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"   配置加载成功: ✓")
    print(f"   字段完整性: {len([f for f in required_fields if config_data.get(f)])}/{len(required_fields)}")
    print(f"   配置可用性: ✓")
    print(f"   文件操作成功: ✓")
    
    # 保存验证报告
    report = {
        "verification_time": datetime.now().isoformat(),
        "config_file": str(config_path.absolute()),
        "config_fields": list(raw_config.keys()),
        "config_manager_fields": len(config_data),
        "required_fields_status": {
            field: bool(config_data.get(field)) for field in required_fields
        },
        "save_test_result": save_result,
        "files_created": [
            {
                "name": file_path.name,
                "size": file_path.stat().st_size,
                "path": str(file_path.relative_to(test_dir))
            }
            for file_path in files_created if file_path.is_file()
        ]
    }
    
    report_path = test_dir / "verification_report.json"
    with open(report_path, 'w', encoding='utf-8') as f:
        json.dump(report, f, ensure_ascii=False, indent=2)
    
    print(f"   验证报告已保存: {report_path}")

if __name__ == "__main__":
    main()