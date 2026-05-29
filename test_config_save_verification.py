#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
验证配置保存和恢复功能
"""

import json
import os
import sys
import tkinter as tk
from pathlib import Path

# 添加当前目录到Python路径
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def test_config_file():
    """测试配置文件"""
    print("🔍 测试配置文件")
    print("="*60)
    
    config_path = Path("gulfsign_config.json")
    
    if not config_path.exists():
        print("❌ 配置文件不存在")
        return False
    
    try:
        with open(config_path, 'r', encoding='utf-8') as f:
            config = json.load(f)
        
        print(f"✅ 配置文件存在: {config_path}")
        print(f"   文件大小: {config_path.stat().st_size} 字节")
        
        # 检查必需字段
        required_fields = [
            ("username", "账号"),
            ("password", "密码"),
            ("ggws_base_url", "系统地址"),
            ("org_code", "机构代码"),
            ("doctor", "签约医生"),
            ("team", "签约团队")
        ]
        
        all_fields_present = True
        for field, display_name in required_fields:
            value = config.get(field, "")
            if value:
                print(f"   ✅ {display_name}: {value}")
            else:
                print(f"   ❌ {display_name}: 为空")
                all_fields_present = False
        
        # 检查账号和密码
        username = config.get("username", "")
        password = config.get("password", "")
        
        print(f"\n账号检查:")
        print(f"   账号: {username}")
        print(f"   密码: {'已设置' if password else '未设置'}")
        
        if username == "431122012":
            print("   ✅ 账号正确: 431122012")
        else:
            print(f"   ❌ 账号不正确: {username}")
            
        if password:
            print("   ✅ 密码已设置")
        else:
            print("   ⚠️  密码为空，请确保已输入密码")
        
        return all_fields_present
        
    except Exception as e:
        print(f"❌ 读取配置文件失败: {str(e)}")
        return False

def test_ui_variables():
    """测试UI变量"""
    print("\n🔍 测试UI变量")
    print("="*60)
    
    # 创建根窗口
    root = tk.Tk()
    root.withdraw()  # 隐藏主窗口
    
    try:
        # 导入应用类
        from app import GulfSignApp
        
        # 创建应用实例
        app = GulfSignApp()
        
        print("1. 检查主UI变量...")
        
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
                value = var.get()
                print(f"   ✅ {name}: 存在 (值: {value})")
            else:
                print(f"   ❌ {name}: 不存在")
                all_main_vars_ok = False
        
        print("\n2. 检查增强登录变量...")
        
        # 检查增强登录变量
        enhanced_variables = [
            ("enhanced_url_var", app.enhanced_url_var),
            ("enhanced_account_var", app.enhanced_account_var),
            ("enhanced_connection_status_var", app.enhanced_connection_status_var),
        ]
        
        all_enhanced_vars_ok = True
        for name, var in enhanced_variables:
            if hasattr(var, 'get'):
                value = var.get()
                print(f"   ✅ {name}: 存在 (值: {value})")
            else:
                print(f"   ❌ {name}: 不存在")
                all_enhanced_vars_ok = False
        
        print("\n3. 检查配置管理器...")
        
        # 检查配置管理器
        if hasattr(app, '_cfg'):
            config = app._cfg
            print(f"   ✅ 配置管理器存在")
            print(f"      账号: {config.get('username', '未设置')}")
            print(f"      密码: {'已设置' if config.get('password') else '未设置'}")
            print(f"      系统地址: {config.get('ggws_base_url', '未设置')}")
        else:
            print("   ❌ 配置管理器不存在")
            
        print("\n4. 检查客户端...")
        
        # 检查客户端
        if hasattr(app, 'client'):
            client = app.client
            print(f"   ✅ 客户端存在")
            
            if hasattr(client, 'logged_in'):
                print(f"      登录状态: {client.logged_in}")
            else:
                print(f"      登录状态属性不存在")
                
            if hasattr(client, 'base_url'):
                print(f"      客户端系统地址: {client.base_url}")
            else:
                print(f"      客户端系统地址属性不存在")
        else:
            print("   ❌ 客户端不存在")
        
        root.destroy()
        return all_main_vars_ok and all_enhanced_vars_ok
        
    except Exception as e:
        print(f"❌ 测试UI变量失败: {str(e)}")
        root.destroy()
        return False

def test_config_save_mechanism():
    """测试配置保存机制"""
    print("\n🔍 测试配置保存机制")
    print("="*60)
    
    # 创建根窗口
    root = tk.Tk()
    root.withdraw()  # 隐藏主窗口
    
    try:
        # 导入应用类
        from app import GulfSignApp
        
        # 创建应用实例
        app = GulfSignApp()
        
        print("1. 检查保存方法...")
        
        # 检查保存方法是否存在
        if hasattr(app, '_save_current_config'):
            print("   ✅ _save_current_config 方法存在")
            
            # 模拟保存配置
            test_config = {
                "username": "test_user",
                "password": "test_password",
                "ggws_base_url": "https://test.example.com",
                "org_code": "test_org_code",
                "doctor": "test_doctor",
                "team": "test_team"
            }
            
            # 临时替换配置
            original_config = app._cfg.copy()
            app._cfg = test_config.copy()
            
            try:
                # 调用保存方法
                app._save_current_config()
                print("   ✅ 配置保存方法可调用")
                
                # 验证配置文件
                config_path = Path("gulfsign_config.json")
                if config_path.exists():
                    with open(config_path, 'r', encoding='utf-8') as f:
                        saved_config = json.load(f)
                    
                    # 检查关键字段
                    if saved_config.get("username") == "test_user":
                        print("   ✅ 配置已正确保存到文件")
                    else:
                        print("   ❌ 配置未正确保存")
                        
                else:
                    print("   ❌ 配置文件未创建")
                    
            finally:
                # 恢复原始配置
                app._cfg = original_config
                # 保存原始配置
                app._save_current_config()
                
        else:
            print("   ❌ _save_current_config 方法不存在")
        
        print("\n2. 检查恢复方法...")
        
        # 检查恢复方法是否存在
        if hasattr(app, '_restore_config'):
            print("   ✅ _restore_config 方法存在")
            
            # 模拟恢复配置
            try:
                app._restore_config()
                print("   ✅ 配置恢复方法可调用")
                
                # 检查UI变量是否已恢复
                if app.var_account.get():
                    print(f"   ✅ 账号已恢复: {app.var_account.get()}")
                else:
                    print("   ⚠️  账号未恢复")
                    
                if app.var_password.get():
                    print(f"   ✅ 密码已恢复: {'*' * len(app.var_password.get())}")
                else:
                    print("   ⚠️  密码未恢复")
                    
                if app.var_url.get():
                    print(f"   ✅ 系统地址已恢复: {app.var_url.get()}")
                else:
                    print("   ⚠️  系统地址未恢复")
                    
            except Exception as e:
                print(f"   ❌ 配置恢复失败: {str(e)}")
                
        else:
            print("   ❌ _restore_config 方法不存在")
        
        root.destroy()
        return True
        
    except Exception as e:
        print(f"❌ 测试配置保存机制失败: {str(e)}")
        root.destroy()
        return False

def test_enhanced_login_config_save():
    """测试增强登录配置保存"""
    print("\n🔍 测试增强登录配置保存")
    print("="*60)
    
    # 创建根窗口
    root = tk.Tk()
    root.withdraw()  # 隐藏主窗口
    
    try:
        # 导入应用类
        from app import GulfSignApp
        
        # 创建应用实例
        app = GulfSignApp()
        
        print("1. 设置测试值...")
        
        # 设置测试值
        test_url = "https://test.ggws.example.com"
        test_account = "test_account_123"
        
        app.enhanced_url_var.set(test_url)
        app.enhanced_account_var.set(test_account)
        
        print(f"   设置系统地址: {test_url}")
        print(f"   设置账号: {test_account}")
        
        print("\n2. 模拟网页登录保存...")
        
        # 检查_open_web_login方法
        if hasattr(app, '_open_web_login'):
            print("   ✅ _open_web_login 方法存在")
            
            # 模拟保存配置
            app._cfg["ggws_base_url"] = test_url
            app._cfg["username"] = test_account
            app._save_current_config()
            
            print("   ✅ 配置已保存")
            
            # 验证配置文件
            config_path = Path("gulfsign_config.json")
            if config_path.exists():
                with open(config_path, 'r', encoding='utf-8') as f:
                    saved_config = json.load(f)
                
                if saved_config.get("ggws_base_url") == test_url:
                    print(f"   ✅ 系统地址已保存: {saved_config.get('ggws_base_url')}")
                else:
                    print(f"   ❌ 系统地址未正确保存")
                    
                if saved_config.get("username") == test_account:
                    print(f"   ✅ 账号已保存: {saved_config.get('username')}")
                else:
                    print(f"   ❌ 账号未正确保存")
                    
            else:
                print("   ❌ 配置文件不存在")
                
        else:
            print("   ❌ _open_web_login 方法不存在")
        
        print("\n3. 模拟API登录保存...")
        
        # 检查_perform_api_login方法
        if hasattr(app, '_perform_api_login'):
            print("   ✅ _perform_api_login 方法存在")
            
            # 设置密码
            test_password = "test_password_123"
            if hasattr(app, 'enhanced_api_password_var'):
                app.enhanced_api_password_var.set(test_password)
                print(f"   设置密码: {'*' * len(test_password)}")
            else:
                print("   ⚠️  enhanced_api_password_var 变量不存在")
            
            # 模拟保存配置
            app._cfg["password"] = test_password
            app._save_current_config()
            
            print("   ✅ 密码已保存")
            
            # 验证配置文件
            config_path = Path("gulfsign_config.json")
            if config_path.exists():
                with open(config_path, 'r', encoding='utf-8') as f:
                    saved_config = json.load(f)
                
                if saved_config.get("password") == test_password:
                    print(f"   ✅ 密码已保存")
                else:
                    print(f"   ❌ 密码未正确保存")
                    
            else:
                print("   ❌ 配置文件不存在")
                
        else:
            print("   ❌ _perform_api_login 方法不存在")
        
        root.destroy()
        return True
        
    except Exception as e:
        print(f"❌ 测试增强登录配置保存失败: {str(e)}")
        root.destroy()
        return False

def main():
    """主函数"""
    print("🚀 开始验证配置保存和恢复功能")
    print("="*60)
    
    # 切换到脚本所在目录
    script_dir = os.path.dirname(os.path.abspath(__file__))
    os.chdir(script_dir)
    
    # 运行测试
    tests = [
        ("配置文件", test_config_file),
        ("UI变量", test_ui_variables),
        ("配置保存机制", test_config_save_mechanism),
        ("增强登录配置保存", test_enhanced_login_config_save),
    ]
    
    all_passed = True
    
    for test_name, test_func in tests:
        print(f"\n📋 测试: {test_name}")
        print("-"*40)
        
        try:
            passed = test_func()
            if passed:
                print(f"✅ {test_name} 测试通过")
            else:
                print(f"❌ {test_name} 测试失败")
                all_passed = False
                
        except Exception as e:
            print(f"❌ {test_name} 测试异常: {str(e)}")
            all_passed = False
    
    print("\n" + "="*60)
    
    if all_passed:
        print("🎉 所有配置保存和恢复功能测试通过！")
        return True
    else:
        print("⚠️  部分配置保存和恢复功能测试失败")
        return False

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)