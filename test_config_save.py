#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
测试配置保存和加载功能
"""
import os
import sys
import json

# 添加模块路径
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "GulfSign_Client_Package/core_modules"))

from config_manager import ConfigManager

def test_config_save_load():
    """测试配置保存和加载"""
    print("=== 测试配置保存和加载功能 ===")
    
    # 创建配置管理器
    config_manager = ConfigManager()
    
    # 测试数据
    test_config = {
        "username": "431122012",
        "password": "test_password_123",
        "ggws_base_url": "https://ggws.hnhfpc.gov.cn",
        "org_code": "431122000000000",
        "doctor": "测试医生",
        "team": "测试团队",
        "delay": "0.5",
        "pop_type": "一般人群",
        "agree_start": "2026-01-01",
        "agree_end": "2026-12-31",
        "max_count": "100",
        "hc_openid": "test_openid",
        "hc_orgcode": "431122000000000",
        "hc_team": "测试团队",
        "hc_doctor": "测试医生",
        "hc_start": "2026-01-01",
        "hc_end": "2026-12-31"
    }
    
    print(f"1. 保存测试配置:")
    print(f"   - username: {test_config['username']}")
    print(f"   - ggws_base_url: {test_config['ggws_base_url']}")
    print(f"   - org_code: {test_config['org_code']}")
    
    # 保存配置
    config_manager.save(test_config)
    print("   ✓ 配置保存完成")
    
    # 加载配置
    print(f"\n2. 加载配置:")
    loaded_config = config_manager.load()
    
    # 检查关键字段
    print(f"   - username: {loaded_config.get('username', '未找到')}")
    print(f"   - ggws_base_url: {loaded_config.get('ggws_base_url', '未找到')}")
    print(f"   - org_code: {loaded_config.get('org_code', '未找到')}")
    
    # 验证字段
    if loaded_config.get('username') == test_config['username']:
        print("   ✓ username 字段正确")
    else:
        print("   ✗ username 字段不匹配")
        
    if loaded_config.get('ggws_base_url') == test_config['ggws_base_url']:
        print("   ✓ ggws_base_url 字段正确")
    else:
        print("   ✗ ggws_base_url 字段不匹配")
    
    print(f"\n3. 测试字段映射:")
    print(f"   - 检查 'account' 到 'username' 的映射:")
    
    # 测试旧格式配置
    old_format_config = {
        "account": "old_account_123",
        "url": "https://old.example.com",
        "org_code": "old_org_123"
    }
    
    print(f"   旧格式配置: account={old_format_config['account']}, url={old_format_config['url']}")
    
    # 使用配置管理器迁移
    migrated_config = config_manager._migrate_old_gulfsign_config(old_format_config)
    
    print(f"   迁移后配置: username={migrated_config.get('username', '未找到')}, ggws_base_url={migrated_config.get('ggws_base_url', '未找到')}")
    
    if migrated_config.get('username') == old_format_config['account']:
        print("   ✓ account 成功映射到 username")
    else:
        print("   ✗ account 映射失败")
        
    if migrated_config.get('ggws_base_url') == old_format_config['url']:
        print("   ✓ url 成功映射到 ggws_base_url")
    else:
        print("   ✗ url 映射失败")
    
    print(f"\n4. 检查配置文件:")
    config_dir = config_manager.config_dir
    config_file = os.path.join(config_dir, "gulfsign_config.json")
    if os.path.exists(config_file):
        print(f"   配置文件路径: {config_file}")
        
        # 读取原始文件内容
        with open(config_file, 'r', encoding='utf-8') as f:
            raw_content = json.load(f)
            
        print(f"   文件中的 username 字段: {raw_content.get('username', '未找到')}")
        print(f"   文件中的 ggws_base_url 字段: {raw_content.get('ggws_base_url', '未找到')}")
    else:
        print(f"   ✗ 配置文件不存在: {config_file}")
    
    print(f"\n=== 测试完成 ===")

def test_app_config_logic():
    """测试应用程序的配置逻辑"""
    print("\n=== 测试应用程序配置逻辑 ===")
    
    # 模拟应用程序的配置恢复逻辑
    print("1. 模拟 _restore_config 方法:")
    
    # 创建一个测试配置
    test_cfg = {
        "username": "431122012",
        "ggws_base_url": "https://ggws.hnhfpc.gov.cn",
        "org_code": "431122000000000",
        "doctor": "测试医生",
        "team": "测试团队"
    }
    
    print(f"   测试配置: {test_cfg}")
    
    # 模拟 _restore_config 逻辑
    var_account = ""
    var_url = ""
    
    # 兼容新旧配置格式
    if test_cfg.get("username"):
        var_account = test_cfg["username"]
        print(f"   ✓ 从 username 字段获取账号: {var_account}")
    elif test_cfg.get("account"):
        var_account = test_cfg["account"]
        print(f"   ✓ 从 account 字段获取账号: {var_account}")
    
    # 新格式使用 "ggws_base_url"，旧格式使用 "url"
    base_url = ""
    if test_cfg.get("ggws_base_url"):
        base_url = test_cfg["ggws_base_url"]
        var_url = base_url
        print(f"   ✓ 从 ggws_base_url 字段获取URL: {base_url}")
    elif test_cfg.get("url"):
        base_url = test_cfg["url"]
        var_url = base_url
        print(f"   ✓ 从 url 字段获取URL: {base_url}")
    
    # 设置PH3Client的base_url
    if base_url:
        client_base_url = base_url.rstrip("/")
        print(f"   ✓ 设置PH3Client base_url: {client_base_url}")
    else:
        print("   ✗ base_url 为空，PH3Client 将无法工作")
    
    print(f"\n2. 测试空配置情况:")
    empty_cfg = {}
    
    var_account2 = ""
    var_url2 = ""
    base_url2 = ""
    
    if empty_cfg.get("username"):
        var_account2 = empty_cfg["username"]
    elif empty_cfg.get("account"):
        var_account2 = empty_cfg["account"]
    
    if empty_cfg.get("ggws_base_url"):
        base_url2 = empty_cfg["ggws_base_url"]
        var_url2 = base_url2
    elif empty_cfg.get("url"):
        base_url2 = empty_cfg["url"]
        var_url2 = base_url2
    
    print(f"   空配置恢复结果:")
    print(f"   - var_account: '{var_account2}'")
    print(f"   - var_url: '{var_url2}'")
    print(f"   - base_url: '{base_url2}'")
    
    if not base_url2:
        print("   ⚠ 警告: base_url 为空，应用程序启动时可能会出错")
    
    print(f"\n=== 测试完成 ===")

if __name__ == "__main__":
    test_config_save_load()
    test_app_config_logic()