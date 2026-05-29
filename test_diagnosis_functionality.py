#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
测试诊断功能
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import tkinter as tk
from app import GulfSignApp
import json

def test_diagnosis_functionality():
    """测试诊断功能"""
    print("🔍 测试诊断功能")
    print("="*60)
    
    # 创建根窗口
    root = tk.Tk()
    root.withdraw()  # 隐藏主窗口
    
    # 创建应用实例
    app = GulfSignApp()
    
    print("1. 检查UI变量...")
    
    # 检查主UI变量
    main_variables = [
        ("var_url", app.var_url),
        ("var_account", app.var_account),
        ("var_password", app.var_password),
        ("var_org", app.var_org),
        ("var_doctor", app.var_doctor),
        ("var_team", app.var_team),
    ]
    
    all_main_vars_ok = True
    for name, var in main_variables:
        if hasattr(var, 'get'):
            print(f"   ✅ {name}: 存在")
        else:
            print(f"   ❌ {name}: 不存在")
            all_main_vars_ok = False
    
    # 检查增强登录UI变量
    enhanced_variables = [
        ("enhanced_url_var", app.enhanced_url_var),
        ("enhanced_account_var", app.enhanced_account_var),
        ("enhanced_connection_status_var", app.enhanced_connection_status_var),
        ("enhanced_status_var", app.enhanced_status_var),
    ]
    
    all_enhanced_vars_ok = True
    for name, var in enhanced_variables:
        if hasattr(app, name):
            print(f"   ✅ {name}: 存在")
        else:
            print(f"   ❌ {name}: 不存在")
            all_enhanced_vars_ok = False
    
    # 测试配置加载
    print(f"\n2. 测试配置加载...")
    config_file = "gulfsign_config.json"
    
    if os.path.exists(config_file):
        with open(config_file, 'r', encoding='utf-8') as f:
            config = json.load(f)
        
        print(f"   配置文件存在")
        print(f"   账号: {config.get('username', '未设置')}")
        print(f"   系统地址: {config.get('ggws_base_url', '未设置')}")
        print(f"   机构代码: {config.get('org_code', '未设置')}")
        
        # 检查必需字段
        missing = []
        if not config.get("username"):
            missing.append("账号")
        if not config.get("ggws_base_url"):
            missing.append("系统地址")
        
        if missing:
            print(f"   ⚠️  缺失必需字段: {', '.join(missing)}")
        else:
            print(f"   ✅ 配置完整")
    else:
        print(f"   ❌ 配置文件不存在")
    
    # 测试诊断方法
    print(f"\n3. 测试诊断方法...")
    
    # 检查诊断方法是否存在
    methods = [
        "_perform_login_diagnosis",
        "_display_login_diagnostics",
        "_run_login_diagnosis",
        "_perform_detailed_diagnosis",
        "_display_detailed_diagnostics",
        "_run_detailed_diagnosis",
    ]
    
    all_methods_ok = True
    for method in methods:
        if hasattr(app, method):
            print(f"   ✅ {method}: 存在")
        else:
            print(f"   ❌ {method}: 不存在")
            all_methods_ok = False
    
    # 运行基础诊断
    print(f"\n4. 运行基础诊断...")
    try:
        diagnostics = app._perform_login_diagnosis()
        
        print(f"   诊断完成，共 {len(diagnostics)} 项检查")
        
        all_passed = True
        for name, success, message in diagnostics:
            icon = "✅" if success else "❌"
            if not success:
                all_passed = False
            
            print(f"   {icon} {name}: {message}")
        
        if all_passed:
            print(f"   ✅ 所有诊断测试通过")
        else:
            print(f"   ⚠️  部分诊断测试失败")
        
    except Exception as e:
        print(f"   ❌ 诊断执行失败: {str(e)}")
        all_methods_ok = False
    
    # 清理
    root.destroy()
    
    print(f"\n" + "="*60)
    if all_main_vars_ok and all_enhanced_vars_ok and all_methods_ok:
        print("✅ 诊断功能测试通过")
        return True
    else:
        print("❌ 诊断功能测试失败")
        return False

if __name__ == "__main__":
    success = test_diagnosis_functionality()