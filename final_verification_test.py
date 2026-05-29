#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
最终验证测试
验证所有修复和功能是否正常工作
"""
import os
import sys
import json
import time
import tkinter as tk
from tkinter import ttk, messagebox

# 添加当前目录到路径
sys.path.append('.')

def run_final_verification():
    """运行最终验证测试"""
    print("=" * 70)
    print("湾流签约助手 - 最终验证测试")
    print("=" * 70)
    
    all_tests_passed = True
    test_results = []
    
    # 测试1: 配置文件检查
    print("\n1. 配置文件检查...")
    try:
        config_path = "gulfsign_config.json"
        if os.path.exists(config_path):
            with open(config_path, 'r', encoding='utf-8') as f:
                config = json.load(f)
            
            required_fields = ['username', 'password', 'ggws_base_url']
            missing_fields = []
            
            for field in required_fields:
                if field not in config:
                    missing_fields.append(field)
                else:
                    value = config[field]
                    print(f"   {field}: {value if field != 'password' else '***'}")
            
            if missing_fields:
                print(f"   ✗ 缺少字段: {missing_fields}")
                test_results.append(("配置文件完整性", "失败", f"缺少字段: {missing_fields}"))
                all_tests_passed = False
            else:
                print("   ✓ 配置文件完整")
                test_results.append(("配置文件完整性", "通过", "所有必需字段都存在"))
                
            # 验证具体值
            if config.get('username') == '431122012':
                print("   ✓ 账号正确: 431122012")
                test_results.append(("账号配置", "通过", "账号设置为431122012"))
            else:
                print(f"   ✗ 账号不正确: {config.get('username')}")
                test_results.append(("账号配置", "失败", f"账号设置为{config.get('username')}"))
                all_tests_passed = False
                
            if config.get('password') == 'wei1147609775@':
                print("   ✓ 密码正确")
                test_results.append(("密码配置", "通过", "密码正确设置"))
            else:
                print("   ✗ 密码不正确或未设置")
                test_results.append(("密码配置", "失败", "密码未正确设置"))
                all_tests_passed = False
                
            if config.get('ggws_base_url') == 'https://ggws.hnhfpc.gov.cn':
                print("   ✓ 系统地址正确")
                test_results.append(("系统地址配置", "通过", "系统地址正确设置"))
            else:
                print(f"   ✗ 系统地址不正确: {config.get('ggws_base_url')}")
                test_results.append(("系统地址配置", "失败", f"系统地址设置为{config.get('ggws_base_url')}"))
                all_tests_passed = False
                
        else:
            print("   ✗ 配置文件不存在")
            test_results.append(("配置文件存在", "失败", "gulfsign_config.json不存在"))
            all_tests_passed = False
            
    except Exception as e:
        print(f"   ✗ 配置文件检查失败: {e}")
        test_results.append(("配置文件检查", "失败", str(e)))
        all_tests_passed = False
    
    # 测试2: 应用程序启动测试
    print("\n2. 应用程序启动测试...")
    try:
        root = tk.Tk()
        root.withdraw()
        
        from app import GulfSignApp
        app = GulfSignApp()
        
        # 检查UI变量
        required_vars = ['var_url', 'var_account', 'var_password']
        missing_vars = []
        
        for var_name in required_vars:
            if not hasattr(app, var_name):
                missing_vars.append(var_name)
            else:
                var_value = getattr(app, var_name).get()
                print(f"   {var_name}: {var_value if var_name != 'var_password' else '***'}")
        
        if missing_vars:
            print(f"   ✗ 缺少UI变量: {missing_vars}")
            test_results.append(("UI变量初始化", "失败", f"缺少变量: {missing_vars}"))
            all_tests_passed = False
        else:
            print("   ✓ UI变量初始化正常")
            test_results.append(("UI变量初始化", "通过", "所有UI变量正常创建"))
        
        # 验证配置恢复
        if app.var_account.get() == '431122012':
            print("   ✓ 账号配置恢复正常")
            test_results.append(("账号配置恢复", "通过", "账号正确恢复为431122012"))
        else:
            print(f"   ✗ 账号配置恢复失败: {app.var_account.get()}")
            test_results.append(("账号配置恢复", "失败", f"恢复的账号为{app.var_account.get()}"))
            all_tests_passed = False
            
        if app.var_url.get() == 'https://ggws.hnhfpc.gov.cn':
            print("   ✓ 系统地址配置恢复正常")
            test_results.append(("系统地址配置恢复", "通过", "系统地址正确恢复"))
        else:
            print(f"   ✗ 系统地址配置恢复失败: {app.var_url.get()}")
            test_results.append(("系统地址配置恢复", "失败", f"恢复的系统地址为{app.var_url.get()}"))
            all_tests_passed = False
        
        app.destroy()
        root.destroy()
        
    except Exception as e:
        print(f"   ✗ 应用程序启动测试失败: {e}")
        test_results.append(("应用程序启动", "失败", str(e)))
        all_tests_passed = False
    
    # 测试3: 配置保存测试
    print("\n3. 配置保存测试...")
    try:
        root = tk.Tk()
        root.withdraw()
        
        from app import GulfSignApp
        app = GulfSignApp()
        
        # 设置新值
        app.var_account.set('test_account')
        app.var_password.set('test_password')
        app.var_url.set('https://test.example.com')
        
        # 保存配置
        app._save_current_config()
        
        # 重新加载验证
        from config_manager import ConfigManager
        config_manager = ConfigManager()
        saved_config = config_manager.load()
        
        if saved_config.get('username') == 'test_account':
            print("   ✓ 账号保存正常")
            test_results.append(("账号保存", "通过", "账号正确保存"))
        else:
            print(f"   ✗ 账号保存失败: {saved_config.get('username')}")
            test_results.append(("账号保存", "失败", f"保存的账号为{saved_config.get('username')}"))
            all_tests_passed = False
            
        if saved_config.get('password') == 'test_password':
            print("   ✓ 密码保存正常")
            test_results.append(("密码保存", "通过", "密码正确保存"))
        else:
            print("   ✗ 密码保存失败")
            test_results.append(("密码保存", "失败", "密码未正确保存"))
            all_tests_passed = False
            
        if saved_config.get('ggws_base_url') == 'https://test.example.com':
            print("   ✓ 系统地址保存正常")
            test_results.append(("系统地址保存", "通过", "系统地址正确保存"))
        else:
            print(f"   ✗ 系统地址保存失败: {saved_config.get('ggws_base_url')}")
            test_results.append(("系统地址保存", "失败", f"保存的系统地址为{saved_config.get('ggws_base_url')}"))
            all_tests_passed = False
        
        # 恢复原始配置
        app.var_account.set('431122012')
        app.var_password.set('wei1147609775@')
        app.var_url.set('https://ggws.hnhfpc.gov.cn')
        app._save_current_config()
        
        app.destroy()
        root.destroy()
        
    except Exception as e:
        print(f"   ✗ 配置保存测试失败: {e}")
        test_results.append(("配置保存", "失败", str(e)))
        all_tests_passed = False
    
    # 测试4: 依赖模块检查
    print("\n4. 依赖模块检查...")
    required_modules = [
        'tkinter',
        'requests',
        'pandas',
        'Crypto.Cipher',
        'ph3_api',
        'hc_api',
        'sign_engine',
        'config_manager'
    ]
    
    for module in required_modules:
        try:
            if module == 'Crypto.Cipher':
                from Crypto.Cipher import AES
                print(f"   ✓ {module}: 可用")
                test_results.append((f"{module}导入", "通过", "模块可用"))
            elif module == 'tkinter':
                import tkinter
                print(f"   ✓ {module}: 可用")
                test_results.append((f"{module}导入", "通过", "模块可用"))
            else:
                __import__(module)
                print(f"   ✓ {module}: 可用")
                test_results.append((f"{module}导入", "通过", "模块可用"))
        except ImportError as e:
            print(f"   ✗ {module}: 不可用 - {e}")
            test_results.append((f"{module}导入", "失败", str(e)))
            all_tests_passed = False
    
    # 总结报告
    print("\n" + "=" * 70)
    print("测试结果总结")
    print("=" * 70)
    
    print(f"\n总测试数: {len(test_results)}")
    passed = sum(1 for _, status, _ in test_results if status == "通过")
    failed = sum(1 for _, status, _ in test_results if status == "失败")
    
    print(f"通过: {passed}")
    print(f"失败: {failed}")
    
    print("\n详细结果:")
    for test_name, status, details in test_results:
        status_symbol = "✓" if status == "通过" else "✗"
        print(f"  {status_symbol} {test_name}: {status} - {details}")
    
    print("\n" + "=" * 70)
    if all_tests_passed:
        print("✅ 所有测试通过！应用程序已准备好进行实际使用。")
        print("\n下一步:")
        print("1. 运行应用程序: python app.py")
        print("2. 使用账号431122012和密码wei1147609775@登录")
        print("3. 测试完整的签约工作流程")
    else:
        print("❌ 部分测试失败，需要进一步修复。")
        print("\n失败的项目:")
        for test_name, status, details in test_results:
            if status == "失败":
                print(f"  - {test_name}: {details}")
    
    print("=" * 70)
    
    return all_tests_passed

if __name__ == "__main__":
    success = run_final_verification()
    sys.exit(0 if success else 1)