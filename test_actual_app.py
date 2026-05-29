#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
测试实际应用程序启动
验证应用程序启动时配置是否正确加载和设置
"""

import os
import sys
import json
import threading
from pathlib import Path

# 添加项目根目录到 Python 路径
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

def test_actual_application_start():
    print("=" * 80)
    print("测试实际应用程序启动")
    print("=" * 80)
    
    print("\n重要: 这个测试将尝试启动应用程序主窗口")
    print("      如果出现任何错误对话框，请记录错误信息")
    print("=" * 80)
    
    try:
        # 导入应用程序模块
        from app import GulfSignApp, load_config
        
        print("\n1. 加载配置...")
        config = load_config()
        
        print(f"   加载的配置:")
        print(f"     username: {config.get('username')}")
        print(f"     ggws_base_url: {config.get('ggws_base_url')}")
        print(f"     org_code: {config.get('org_code', '未设置')}")
        
        print("\n2. 创建应用程序实例...")
        
        # 创建应用程序实例但不启动主循环
        import tkinter as tk
        
        root = tk.Tk()
        root.withdraw()  # 隐藏主窗口
        
        app = GulfSignApp(root)
        
        print(f"   应用程序创建成功")
        print(f"   客户端 base_url: {app.client.base_url}")
        print(f"   账号变量值: {app.var_account.get()}")
        print(f"   URL 变量值: {app.var_url.get()}")
        print(f"   机构代码变量值: {app.var_org.get()}")
        
        # 测试 URL 构建
        test_path = "/FormMain.aspx"
        test_url = app.client._url(test_path)
        print(f"\n3. 测试 URL 构建 ('{test_path}'): {test_url}")
        
        if test_url.startswith("https://"):
            print(f"   ✓ URL 构建正确")
        else:
            print(f"   ✗ URL 构建不正确: {test_url}")
            print(f"     这可能就是用户看到的 'InvalidURL /FormMain.aspx' 错误")
        
        # 检查配置完整性诊断
        print("\n4. 运行配置完整性诊断...")
        
        # 模拟诊断
        missing = []
        if not app._cfg.get("username"):
            missing.append("账号")
        if not app._cfg.get("ggws_base_url"):
            missing.append("3.0系统地址")
        # org_code 不是必需字段
        
        if missing:
            print(f"   ✗ 配置不完整: 缺失 {', '.join(missing)}")
        else:
            print(f"   ✓ 配置完整")
        
        print("\n5. 问题诊断:")
        
        # 检查可能的问题
        issues = []
        
        # 检查 base_url 是否设置
        if not app.client.base_url:
            issues.append("PH3Client base_url 未设置")
        
        # 检查配置字段
        if not app._cfg.get("username"):
            issues.append("配置中缺少 username 字段")
        
        if not app._cfg.get("ggws_base_url"):
            issues.append("配置中缺少 ggws_base_url 字段")
        
        # 检查变量值
        if not app.var_account.get():
            issues.append("账号变量值为空")
        
        if not app.var_url.get():
            issues.append("URL 变量值为空")
        
        if issues:
            print(f"   发现以下问题:")
            for issue in issues:
                print(f"     - {issue}")
        else:
            print(f"   ✓ 所有检查通过")
        
        # 清理
        root.destroy()
        
        print("\n" + "=" * 80)
        print("测试完成")
        print("=" * 80)
        
        return True
        
    except Exception as e:
        print(f"\n✗ 测试失败: {e}")
        import traceback
        traceback.print_exc()
        
        print("\n" + "=" * 80)
        print("测试失败")
        print("=" * 80)
        
        return False

if __name__ == "__main__":
    success = test_actual_application_start()
    sys.exit(0 if success else 1)