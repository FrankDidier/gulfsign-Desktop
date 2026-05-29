#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
测试配置恢复功能
"""

import tkinter as tk
from app import GulfSignApp

print("验证配置恢复功能...")
print("=" * 60)

try:
    # 创建应用程序实例
    app = GulfSignApp()
    
    print("1. 检查配置恢复:")
    
    # 检查var_url是否设置了正确的值
    expected_url = "https://ggws.hnhfpc.gov.cn"
    actual_url = app.var_url.get()
    print(f"   var_url 期望值: {expected_url}")
    print(f"   var_url 实际值: {actual_url}")
    if actual_url == expected_url:
        print("   ✓ 匹配")
    else:
        print("   ✗ 不匹配")
    
    # 检查var_account是否设置了正确的值
    expected_account = "431122012"
    actual_account = app.var_account.get()
    print(f"   var_account 期望值: {expected_account}")
    print(f"   var_account 实际值: {actual_account}")
    if actual_account == expected_account:
        print("   ✓ 匹配")
    else:
        print("   ✗ 不匹配")
    
    # 检查PH3Client base_url是否设置
    expected_client_url = "https://ggws.hnhfpc.gov.cn"
    actual_client_url = app.client.base_url
    print(f"   PH3Client base_url 期望值: {expected_client_url}")
    print(f"   PH3Client base_url 实际值: {actual_client_url}")
    if actual_client_url == expected_client_url:
        print("   ✓ 匹配")
    else:
        print("   ✗ 不匹配")
    
    print("\n2. 检查配置完整性:")
    
    # 检查配置是否包含必需字段
    required_fields = ["username", "ggws_base_url"]
    missing_fields = []
    
    for field in required_fields:
        if field not in app._cfg or not app._cfg[field]:
            missing_fields.append(field)
    
    if missing_fields:
        print(f"   ✗ 缺失字段: {missing_fields}")
    else:
        print(f"   ✓ 所有必需字段都存在")
    
    print("\n3. 测试保存配置:")
    
    # 测试保存当前配置
    try:
        app._save_current_config()
        print("   ✓ 配置保存成功")
    except Exception as e:
        print(f"   ✗ 配置保存失败: {e}")
    
    print("\n" + "=" * 60)
    print("验证完成！")
    
except Exception as e:
    print(f"错误: {e}")
    import traceback
    traceback.print_exc()