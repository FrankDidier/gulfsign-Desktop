#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
诊断配置保存问题
分析为什么账号和base URL没有正确保存
"""
import os
import sys
import json
import tkinter as tk

# 添加当前目录到路径
sys.path.append('.')

def diagnose_config_issue():
    """诊断配置问题"""
    print("=" * 70)
    print("配置问题诊断")
    print("=" * 70)
    
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
        print(f"   - doctor: {config.get('doctor', '未设置')}")
        print(f"   - team: {config.get('team', '未设置')}")
        
        # 检查必需字段
        required_fields = ['username', 'ggws_base_url']
        missing_fields = []
        
        for field in required_fields:
            if field not in config or not config[field]:
                missing_fields.append(field)
        
        if missing_fields:
            print(f"   ❌ 缺少必需字段: {missing_fields}")
        else:
            print(f"   ✅ 所有必需字段都存在")
            
    else:
        print(f"   ❌ 配置文件不存在: {config_path}")
    
    print("\n2. 检查应用程序配置恢复...")
    try:
        root = tk.Tk()
        root.withdraw()
        
        from app import GulfSignApp
        app = GulfSignApp()
        
        print(f"   ✅ 应用程序启动成功")
        
        print(f"\n   当前UI变量值:")
        print(f"   - var_account: {app.var_account.get()}")
        print(f"   - var_password: {'已设置' if app.var_password.get() else '未设置'}")
        print(f"   - var_url: {app.var_url.get()}")
        print(f"   - var_doctor: {app.var_doctor.get()}")
        print(f"   - var_team: {app.var_team.get()}")
        
        # 检查配置恢复是否正确
        print(f"\n   配置恢复验证:")
        
        # 账号恢复
        config_username = config.get('username', '')
        ui_username = app.var_account.get()
        if config_username == ui_username:
            print(f"   ✅ 账号恢复正确: {ui_username}")
        else:
            print(f"   ❌ 账号恢复不一致 - 配置: {config_username}, UI: {ui_username}")
        
        # base URL恢复
        config_url = config.get('ggws_base_url', '')
        ui_url = app.var_url.get()
        if config_url == ui_url:
            print(f"   ✅ base URL恢复正确: {ui_url}")
        else:
            print(f"   ❌ base URL恢复不一致 - 配置: {config_url}, UI: {ui_url}")
        
        app.destroy()
        root.destroy()
        
    except Exception as e:
        print(f"   ❌ 应用程序检查失败: {e}")
        import traceback
        traceback.print_exc()
    
    print("\n3. 检查_save_current_config()方法...")
    try:
        # 重新加载应用程序来检查方法
        root = tk.Tk()
        root.withdraw()
        
        from app import GulfSignApp
        app = GulfSignApp()
        
        # 设置测试值
        test_account = "test_diagnose_account"
        test_password = "test_diagnose_password"
        test_url = "https://test.diagnose.example.com"
        
        app.var_account.set(test_account)
        app.var_password.set(test_password)
        app.var_url.set(test_url)
        
        print(f"   设置测试值:")
        print(f"   - 账号: {test_account}")
        print(f"   - 密码: {test_password}")
        print(f"   - URL: {test_url}")
        
        # 调用保存方法
        app._save_current_config()
        print(f"   ✅ 调用_save_current_config()成功")
        
        # 检查保存结果
        from config_manager import ConfigManager
        config_manager = ConfigManager()
        saved_config = config_manager.load()
        
        print(f"\n   保存后的配置:")
        print(f"   - username: {saved_config.get('username', '未设置')}")
        print(f"   - password: {'已设置' if saved_config.get('password') else '未设置'}")
        print(f"   - ggws_base_url: {saved_config.get('ggws_base_url', '未设置')}")
        
        # 验证保存是否正确
        if saved_config.get('username') == test_account:
            print(f"   ✅ 账号保存正确")
        else:
            print(f"   ❌ 账号保存错误 - 期望: {test_account}, 实际: {saved_config.get('username')}")
            
        if saved_config.get('password') == test_password:
            print(f"   ✅ 密码保存正确")
        else:
            print(f"   ❌ 密码保存错误 - 期望: {test_password}, 实际: {saved_config.get('password', '未设置')}")
            
        if saved_config.get('ggws_base_url') == test_url:
            print(f"   ✅ base URL保存正确")
        else:
            print(f"   ❌ base URL保存错误 - 期望: {test_url}, 实际: {saved_config.get('ggws_base_url', '未设置')}")
        
        # 恢复原始配置
        original_config = {
            'username': '431122012',
            'password': 'wei1147609775@',
            'ggws_base_url': 'https://ggws.hnhfpc.gov.cn',
            'doctor': '家庭医生',
            'team': '家庭团队',
            'delay': '0.5',
            'pop_type': '一般人群',
            'agree_start': '2026-05-29',
            'agree_end': '2027-05-28',
            'max_count': '2',
            'hc_openid': '',
            'hc_orgcode': '',
            'hc_team': '',
            'hc_doctor': '',
            'hc_start': '',
            'hc_end': '',
            'license_server_url': 'http://43.137.41.187:5004',
            'max_workers': 20,
            'batch_size': 2
        }
        
        config_manager.save(original_config)
        
        app.destroy()
        root.destroy()
        
    except Exception as e:
        print(f"   ❌ 检查_save_current_config()失败: {e}")
        import traceback
        traceback.print_exc()
    
    print("\n4. 检查ConfigManager...")
    try:
        from config_manager import ConfigManager
        config_manager = ConfigManager()
        
        # 测试保存和加载
        test_config = {
            'username': 'config_test_user',
            'password': 'config_test_pass',
            'ggws_base_url': 'https://config.test.example.com'
        }
        
        print(f"   测试ConfigManager:")
        print(f"   - 保存测试配置...")
        config_manager.save(test_config)
        
        print(f"   - 重新加载配置...")
        loaded_config = config_manager.load()
        
        print(f"\n   加载的配置:")
        print(f"   - username: {loaded_config.get('username', '未设置')}")
        print(f"   - password: {'已设置' if loaded_config.get('password') else '未设置'}")
        print(f"   - ggws_base_url: {loaded_config.get('ggws_base_url', '未设置')}")
        
        # 验证
        if loaded_config.get('username') == test_config['username']:
            print(f"   ✅ ConfigManager保存/加载正确")
        else:
            print(f"   ❌ ConfigManager保存/加载错误")
            
        # 恢复原始配置
        config_manager.save(original_config)
        
    except Exception as e:
        print(f"   ❌ 检查ConfigManager失败: {e}")
        import traceback
        traceback.print_exc()
    
    print("\n" + "=" * 70)
    print("诊断完成")
    print("=" * 70)

if __name__ == "__main__":
    diagnose_config_issue()