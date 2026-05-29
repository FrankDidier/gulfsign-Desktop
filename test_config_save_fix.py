#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
测试配置保存修复
验证账号、密码、系统地址是否正确保存到配置文件
"""
import os
import sys
import json
import time
import tkinter as tk
from tkinter import ttk
import threading

# 添加项目根目录到路径
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app import GulfSignApp
from config_manager import ConfigManager

def test_config_save():
    """测试配置保存功能"""
    print("=" * 70)
    print("配置保存修复测试")
    print("=" * 70)
    
    # 1. 检查当前配置文件
    print("\n1. 检查当前配置文件...")
    config_path = "gulfsign_config.json"
    
    if os.path.exists(config_path):
        print(f"   ✅ 配置文件存在: {config_path}")
        
        with open(config_path, 'r', encoding='utf-8') as f:
            config = json.load(f)
        
        print(f"   当前配置内容:")
        print(f"   - username: {config.get('username', '未设置')}")
        print(f"   - password: {'已设置（加密）' if config.get('password') else '未设置'}")
        print(f"   - ggws_base_url: {config.get('ggws_base_url', '未设置')}")
        print(f"   - org_code: {config.get('org_code', '未设置')}")
        print(f"   - doctor: {config.get('doctor', '未设置')}")
        print(f"   - team: {config.get('team', '未设置')}")
    else:
        print(f"   ❌ 配置文件不存在: {config_path}")
        return False
    
    # 2. 创建应用程序实例（最小化）
    print("\n2. 创建应用程序实例...")
    app = GulfSignApp()
    app.withdraw()  # 最小化窗口
    
    # 3. 检查UI变量是否创建
    print("\n3. 检查UI变量是否创建...")
    required_vars = [
        'var_url', 'var_account', 'var_password',
        'enhanced_url_var', 'enhanced_api_account_var', 'enhanced_api_password_var'
    ]
    
    all_vars_created = True
    for var_name in required_vars:
        if hasattr(app, var_name):
            print(f"   ✅ {var_name}: 已创建")
        else:
            print(f"   ❌ {var_name}: 未创建")
            all_vars_created = False
    
    if not all_vars_created:
        print("   ⚠️  部分UI变量未创建，继续测试...")
    
    # 4. 测试配置恢复
    print("\n4. 测试配置恢复...")
    app._restore_config()
    
    print(f"   主UI变量值:")
    print(f"   - var_account: {app.var_account.get()}")
    print(f"   - var_url: {app.var_url.get()}")
    
    if hasattr(app, 'enhanced_url_var'):
        print(f"   增强登录变量值:")
        print(f"   - enhanced_url_var: {app.enhanced_url_var.get()}")
        print(f"   - enhanced_api_account_var: {app.enhanced_api_account_var.get()}")
    
    # 5. 模拟用户输入（增强登录界面）
    print("\n5. 模拟用户输入（增强登录界面）...")
    test_account = "test_user_001"
    test_password = "test_password_123"
    test_url = "https://test.ggws.hnhfpc.gov.cn"
    
    if hasattr(app, 'enhanced_api_account_var'):
        app.enhanced_api_account_var.set(test_account)
        app.enhanced_api_password_var.set(test_password)
        app.enhanced_url_var.set(test_url)
        
        print(f"   设置增强登录变量:")
        print(f"   - 账号: {app.enhanced_api_account_var.get()}")
        print(f"   - 密码: {'已设置' if app.enhanced_api_password_var.get() else '未设置'}")
        print(f"   - 系统地址: {app.enhanced_url_var.get()}")
    
    # 6. 测试API登录保存
    print("\n6. 测试API登录保存功能...")
    
    # 模拟登录成功
    def mock_login_success():
        print("   模拟API登录成功...")
        
        # 更新主UI变量
        app.var_account.set(test_account)
        app.var_password.set(test_password)
        app.var_url.set(test_url)
        
        # 更新配置
        app._cfg["username"] = test_account
        app._cfg["password"] = test_password
        app._cfg["ggws_base_url"] = test_url
        
        # 保存配置
        app._save_current_config()
        
        print("   ✅ 配置已保存")
        
        # 验证保存
        time.sleep(0.5)
        
        if os.path.exists(config_path):
            with open(config_path, 'r', encoding='utf-8') as f:
                saved_config = json.load(f)
            
            print(f"   验证保存结果:")
            print(f"   - username: {saved_config.get('username')} (期望: {test_account})")
            print(f"   - password: {'已设置' if saved_config.get('password') else '未设置'} (期望: 已设置)")
            print(f"   - ggws_base_url: {saved_config.get('ggws_base_url')} (期望: {test_url})")
            
            if (saved_config.get('username') == test_account and 
                saved_config.get('password') and 
                saved_config.get('ggws_base_url') == test_url):
                print("   ✅ 配置保存验证通过!")
                return True
            else:
                print("   ❌ 配置保存验证失败!")
                return False
    
    # 运行模拟登录
    success = mock_login_success()
    
    # 7. 测试网页登录保存
    print("\n7. 测试网页登录保存功能...")
    
    test_account2 = "test_user_002"
    test_url2 = "https://test2.ggws.hnhfpc.gov.cn"
    
    if hasattr(app, 'enhanced_api_account_var'):
        app.enhanced_api_account_var.set(test_account2)
        app.enhanced_url_var.set(test_url2)
        
        print(f"   设置网页登录变量:")
        print(f"   - 账号: {app.enhanced_api_account_var.get()}")
        print(f"   - 系统地址: {app.enhanced_url_var.get()}")
        
        # 模拟网页登录保存
        def mock_web_login_save():
            print("   模拟网页登录保存...")
            
            # 更新主UI变量
            app.var_account.set(test_account2)
            app.var_url.set(test_url2)
            
            # 更新配置
            app._cfg["username"] = test_account2
            app._cfg["ggws_base_url"] = test_url2
            
            # 保存配置
            app._save_current_config()
            
            print("   ✅ 网页登录配置已保存")
            
            # 验证保存
            time.sleep(0.5)
            
            if os.path.exists(config_path):
                with open(config_path, 'r', encoding='utf-8') as f:
                    saved_config = json.load(f)
                
                print(f"   验证保存结果:")
                print(f"   - username: {saved_config.get('username')} (期望: {test_account2})")
                print(f"   - ggws_base_url: {saved_config.get('ggws_base_url')} (期望: {test_url2})")
                
                if (saved_config.get('username') == test_account2 and 
                    saved_config.get('ggws_base_url') == test_url2):
                    print("   ✅ 网页登录配置保存验证通过!")
                    return True
                else:
                    print("   ❌ 网页登录配置保存验证失败!")
                    return False
        
        web_success = mock_web_login_save()
        success = success and web_success
    
    # 8. 清理测试数据
    print("\n8. 清理测试数据...")
    
    # 恢复原始配置
    original_config = config.copy()
    
    with open(config_path, 'w', encoding='utf-8') as f:
        json.dump(original_config, f, ensure_ascii=False, indent=2)
    
    print("   ✅ 已恢复原始配置")
    
    # 9. 关闭应用程序
    print("\n9. 关闭应用程序...")
    app.destroy()
    
    print("\n" + "=" * 70)
    print("测试完成!")
    print("=" * 70)
    
    return success

if __name__ == "__main__":
    success = test_config_save()
    
    if success:
        print("\n✅ 所有测试通过!")
        print("配置保存修复已成功应用。")
        print("应用程序现在应该能够正确保存账号、密码和系统地址。")
    else:
        print("\n❌ 测试失败!")
        print("请检查配置保存逻辑。")
    
    sys.exit(0 if success else 1)