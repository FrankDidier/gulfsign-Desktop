#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
简单配置测试
"""
import os
import sys
import json

# 添加路径
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# 测试配置加载
config_file = "gulfsign_config.json"
print(f"检查配置文件: {config_file}")

if os.path.exists(config_file):
    with open(config_file, 'r', encoding='utf-8') as f:
        config = json.load(f)
    
    print("\n配置文件内容:")
    print(json.dumps(config, indent=2, ensure_ascii=False))
    
    print("\n关键字段检查:")
    
    # 检查所有可能的字段名
    fields_to_check = [
        ("username", "账号 (新格式)"),
        ("account", "账号 (旧格式)"),
        ("ggws_base_url", "3.0系统地址 (新格式)"),
        ("url", "3.0系统地址 (旧格式)"),
        ("org_code", "机构代码"),
        ("doctor", "医生"),
        ("team", "团队"),
    ]
    
    for field_name, field_desc in fields_to_check:
        if field_name in config:
            value = config[field_name]
            if value:
                print(f"  ✓ {field_desc}: {value}")
            else:
                print(f"  ⚠ {field_desc}: 存在但为空")
        else:
            print(f"  ✗ {field_desc}: 不存在")
    
    # 检查配置验证逻辑
    print("\n模拟配置验证逻辑:")
    missing = []
    
    # 检查账号字段（兼容新旧格式）
    has_username = "username" in config and config["username"]
    has_account = "account" in config and config["account"]
    if not has_username and not has_account:
        missing.append("账号")
    
    # 检查3.0系统地址字段（兼容新旧格式）
    has_ggws_base_url = "ggws_base_url" in config and config["ggws_base_url"]
    has_url = "url" in config and config["url"]
    if not has_ggws_base_url and not has_url:
        missing.append("3.0系统地址")
    
    # 检查机构代码字段
    has_org_code = "org_code" in config and config["org_code"]
    if not has_org_code:
        missing.append("机构代码")
    
    if missing:
        print(f"  ✗ 配置不完整，缺失字段: {', '.join(missing)}")
    else:
        print("  ✓ 配置完整")
    
    # 检查应用程序启动时的配置恢复
    print("\n模拟应用程序配置恢复:")
    
    # 模拟从配置恢复
    var_url_value = ""
    var_account_value = ""
    client_base_url = ""
    
    # 恢复URL（兼容新旧格式）
    if has_ggws_base_url:
        var_url_value = config["ggws_base_url"]
        client_base_url = config["ggws_base_url"].rstrip("/")
    elif has_url:
        var_url_value = config["url"]
        client_base_url = config["url"].rstrip("/")
    
    # 恢复账号（兼容新旧格式）
    if has_username:
        var_account_value = config["username"]
    elif has_account:
        var_account_value = config["account"]
    
    print(f"  URL 变量值: {var_url_value}")
    print(f"  账号变量值: {var_account_value}")
    print(f"  客户端 base_url: {client_base_url}")
    
    # 检查如果base_url为空会发生什么
    if not client_base_url:
        print("\n⚠ 警告: base_url 为空!")
        print("  如果此时尝试调用 _url('/FormMain.aspx')，会返回: '/FormMain.aspx'")
        print("  调用 requests.get('/FormMain.aspx') 可能会失败")
    
else:
    print(f"✗ 配置文件不存在: {config_file}")

print("\n" + "=" * 60)
print("建议:")
print("1. 确保配置文件包含必要的字段")
print("2. 如果字段缺失，用户需要先登录以保存配置")
print("3. 应用程序启动时应显示友好的错误提示")
print("=" * 60)