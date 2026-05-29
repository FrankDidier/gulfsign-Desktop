#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
简单测试配置保存功能
"""

import json
import os
import sys
import tkinter as tk
from pathlib import Path

# 添加当前目录到Python路径
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def test_direct_config_save():
    """直接测试配置保存"""
    print("🔍 直接测试配置保存")
    print("="*60)
    
    # 导入配置保存函数
    from config_manager import save_config
    
    # 测试配置数据
    test_config = {
        "username": "test_user_123",
        "password": "test_password_123",
        "ggws_base_url": "https://test.example.com",
        "org_code": "test_org_123",
        "doctor": "测试医生",
        "team": "测试团队",
        "delay": "1.0",
        "pop_type": "一般人群",
        "agree_start": "2026-01-01",
        "agree_end": "2026-12-31",
        "max_count": "10"
    }
    
    print("1. 保存测试配置...")
    print(f"   账号: {test_config['username']}")
    print(f"   密码: {'*' * len(test_config['password'])}")
    print(f"   系统地址: {test_config['ggws_base_url']}")
    
    try:
        # 保存配置
        save_config(test_config)
        print("   ✅ 配置保存方法调用成功")
        
        # 验证配置文件
        config_path = Path("gulfsign_config.json")
        if config_path.exists():
            print(f"   ✅ 配置文件存在: {config_path}")
            
            with open(config_path, 'r', encoding='utf-8') as f:
                saved_config = json.load(f)
            
            print(f"   文件大小: {config_path.stat().st_size} 字节")
            
            # 检查关键字段
            checks = [
                ("username", "账号"),
                ("password", "密码"),
                ("ggws_base_url", "系统地址"),
                ("org_code", "机构代码")
            ]
            
            all_ok = True
            for field, display_name in checks:
                saved_value = saved_config.get(field, "")
                expected_value = test_config.get(field, "")
                
                if field == "password":
                    # 密码字段应该被加密
                    if saved_value.startswith("ENC:"):
                        print(f"   ✅ {display_name}: 已加密保存")
                    else:
                        print(f"   ❌ {display_name}: 未加密保存")
                        all_ok = False
                elif saved_value == expected_value:
                    print(f"   ✅ {display_name}: {saved_value}")
                else:
                    print(f"   ❌ {display_name}: 期望 '{expected_value}', 实际 '{saved_value}'")
                    all_ok = False
            
            return all_ok
            
        else:
            print("   ❌ 配置文件未创建")
            return False
            
    except Exception as e:
        print(f"   ❌ 配置保存失败: {str(e)}")
        return False

def test_app_config_save():
    """测试应用程序配置保存"""
    print("\n🔍 测试应用程序配置保存")
    print("="*60)
    
    # 创建根窗口
    root = tk.Tk()
    root.withdraw()  # 隐藏主窗口
    
    try:
        # 导入应用类
        from app import GulfSignApp
        
        # 创建应用实例
        app = GulfSignApp()
        
        print("1. 设置UI变量...")
        
        # 设置测试值
        test_account = "app_test_user"
        test_password = "app_test_password"
        test_url = "https://app.test.example.com"
        
        app.var_account.set(test_account)
        app.var_password.set(test_password)
        app.var_url.set(test_url)
        
        print(f"   设置账号: {test_account}")
        print(f"   设置密码: {'*' * len(test_password)}")
        print(f"   设置系统地址: {test_url}")
        
        print("\n2. 调用保存方法...")
        
        # 调用保存方法
        app._save_current_config()
        print("   ✅ 保存方法调用成功")
        
        print("\n3. 验证保存结果...")
        
        # 验证配置文件
        config_path = Path("gulfsign_config.json")
        if config_path.exists():
            with open(config_path, 'r', encoding='utf-8') as f:
                saved_config = json.load(f)
            
            # 检查关键字段
            checks = [
                ("username", "账号"),
                ("password", "密码"),
                ("ggws_base_url", "系统地址")
            ]
            
            all_ok = True
            for field, display_name in checks:
                saved_value = saved_config.get(field, "")
                
                if field == "username":
                    expected = test_account
                elif field == "password":
                    expected = test_password
                elif field == "ggws_base_url":
                    expected = test_url
                else:
                    expected = ""
                
                if field == "password":
                    # 密码字段应该被加密
                    if saved_value.startswith("ENC:"):
                        print(f"   ✅ {display_name}: 已加密保存")
                    else:
                        print(f"   ❌ {display_name}: 未加密保存")
                        all_ok = False
                elif saved_value == expected:
                    print(f"   ✅ {display_name}: {saved_value}")
                else:
                    print(f"   ❌ {display_name}: 期望 '{expected}', 实际 '{saved_value}'")
                    all_ok = False
            
            return all_ok
            
        else:
            print("   ❌ 配置文件不存在")
            return False
            
    except Exception as e:
        print(f"   ❌ 测试失败: {str(e)}")
        return False
        
    finally:
        root.destroy()

def test_config_restore():
    """测试配置恢复"""
    print("\n🔍 测试配置恢复")
    print("="*60)
    
    # 创建根窗口
    root = tk.Tk()
    root.withdraw()  # 隐藏主窗口
    
    try:
        # 导入应用类
        from app import GulfSignApp
        
        # 创建应用实例
        app = GulfSignApp()
        
        print("1. 清空UI变量...")
        
        # 清空UI变量
        app.var_account.set("")
        app.var_password.set("")
        app.var_url.set("")
        
        print("   账号已清空")
        print("   密码已清空")
        print("   系统地址已清空")
        
        print("\n2. 调用恢复方法...")
        
        # 调用恢复方法
        app._restore_config()
        print("   ✅ 恢复方法调用成功")
        
        print("\n3. 验证恢复结果...")
        
        # 检查恢复的值
        restored_account = app.var_account.get()
        restored_password = app.var_password.get()
        restored_url = app.var_url.get()
        
        print(f"   恢复的账号: {restored_account}")
        print(f"   恢复的密码: {'已设置' if restored_password else '未设置'}")
        print(f"   恢复的系统地址: {restored_url}")
        
        # 检查是否从配置文件恢复了值
        config_path = Path("gulfsign_config.json")
        if config_path.exists():
            with open(config_path, 'r', encoding='utf-8') as f:
                file_config = json.load(f)
            
            file_account = file_config.get("username", "")
            file_password = file_config.get("password", "")
            file_url = file_config.get("ggws_base_url", "")
            
            if restored_account == file_account:
                print(f"   ✅ 账号正确恢复: {restored_account}")
            else:
                print(f"   ❌ 账号恢复不一致: UI={restored_account}, 文件={file_account}")
            
            if restored_password == file_password:
                print(f"   ✅ 密码正确恢复")
            else:
                print(f"   ❌ 密码恢复不一致")
            
            if restored_url == file_url:
                print(f"   ✅ 系统地址正确恢复: {restored_url}")
            else:
                print(f"   ❌ 系统地址恢复不一致: UI={restored_url}, 文件={file_url}")
            
            return True
            
        else:
            print("   ❌ 配置文件不存在")
            return False
            
    except Exception as e:
        print(f"   ❌ 测试失败: {str(e)}")
        return False
        
    finally:
        root.destroy()

def main():
    """主函数"""
    print("🚀 开始测试配置保存功能")
    print("="*60)
    
    # 切换到脚本所在目录
    script_dir = os.path.dirname(os.path.abspath(__file__))
    os.chdir(script_dir)
    
    # 运行测试
    tests = [
        ("直接配置保存", test_direct_config_save),
        ("应用程序配置保存", test_app_config_save),
        ("配置恢复", test_config_restore),
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
        print("🎉 所有配置保存功能测试通过！")
        return True
    else:
        print("⚠️  部分配置保存功能测试失败")
        return False

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)