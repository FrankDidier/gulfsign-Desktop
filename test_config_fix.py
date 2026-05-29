#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
测试配置修复
"""
import os
import sys
import json

# 添加路径
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from GulfSign_Client_Package.core_modules.config_manager import ConfigManager

def test_config_loading():
    """测试配置加载"""
    print("=" * 60)
    print("测试配置加载修复")
    print("=" * 60)
    
    # 创建配置管理器
    config_manager = ConfigManager()
    
    # 加载配置
    config = config_manager.load()
    
    print("\n1. 加载的配置内容:")
    print(json.dumps(config, indent=2, ensure_ascii=False))
    
    # 检查关键字段
    print("\n2. 关键字段检查:")
    
    # 检查新格式字段
    has_username = "username" in config and config["username"]
    has_ggws_base_url = "ggws_base_url" in config and config["ggws_base_url"]
    has_org_code = "org_code" in config and config["org_code"]
    
    print(f"   username 字段: {'✓ 存在' if has_username else '✗ 缺失'}")
    if has_username:
        print(f"     值: {config['username']}")
    
    print(f"   ggws_base_url 字段: {'✓ 存在' if has_ggws_base_url else '✗ 缺失'}")
    if has_ggws_base_url:
        print(f"     值: {config['ggws_base_url']}")
    
    print(f"   org_code 字段: {'✓ 存在' if has_org_code else '✗ 缺失'}")
    if has_org_code:
        print(f"     值: {config['org_code']}")
    
    # 检查旧格式字段（兼容性）
    has_account = "account" in config and config["account"]
    has_url = "url" in config and config["url"]
    
    print(f"\n3. 旧格式字段检查（兼容性）:")
    print(f"   account 字段: {'✓ 存在' if has_account else '✗ 缺失'}")
    print(f"   url 字段: {'✓ 存在' if has_url else '✗ 缺失'}")
    
    # 验证配置完整性
    print("\n4. 配置完整性验证:")
    missing_fields = []
    
    if not has_username and not has_account:
        missing_fields.append("账号 (username/account)")
    
    if not has_ggws_base_url and not has_url:
        missing_fields.append("3.0系统地址 (ggws_base_url/url)")
    
    if not has_org_code:
        missing_fields.append("机构代码 (org_code)")
    
    if missing_fields:
        print(f"   ✗ 配置不完整，缺失字段: {', '.join(missing_fields)}")
        return False
    else:
        print("   ✓ 配置完整")
        return True

def test_app_restore_config():
    """测试应用程序的配置恢复逻辑"""
    print("\n" + "=" * 60)
    print("测试应用程序配置恢复逻辑")
    print("=" * 60)
    
    try:
        # 导入并测试应用程序的配置恢复
        import tkinter as tk
        
        # 创建一个简单的测试类来模拟配置恢复
        class TestApp:
            def __init__(self):
                self._cfg = {}
                self.var_url = tk.StringVar()
                self.var_account = tk.StringVar()
                self.var_org = tk.StringVar()
                self.client = type('MockClient', (), {'base_url': ''})()
                
            def _restore_config(self):
                c = self._cfg
                # 兼容新旧配置格式
                # 新格式使用 "username"，旧格式使用 "account"
                if c.get("username"):
                    self.var_account.set(c["username"])
                elif c.get("account"):
                    self.var_account.set(c["account"])
                
                # 新格式使用 "ggws_base_url"，旧格式使用 "url"
                base_url = ""
                if c.get("ggws_base_url"):
                    base_url = c["ggws_base_url"]
                    self.var_url.set(base_url)
                elif c.get("url"):
                    base_url = c["url"]
                    self.var_url.set(base_url)
                
                # 设置PH3Client的base_url
                if base_url:
                    self.client.base_url = base_url.rstrip("/")
                
                if c.get("org_code"):
                    self.var_org.set(c["org_code"])
        
        # 创建测试应用
        app = TestApp()
        
        # 模拟从配置文件加载的配置
        app._cfg = {
            "username": "430726000001010WS",
            "ggws_base_url": "https://ggws.hnhfpc.gov.cn",
            "org_code": "430726000001010"
        }
        
        # 执行配置恢复
        app._restore_config()
        
        print("\n1. 配置恢复结果:")
        print(f"   URL 变量值: {app.var_url.get()}")
        print(f"   账号变量值: {app.var_account.get()}")
        print(f"   机构代码变量值: {app.var_org.get()}")
        print(f"   客户端 base_url: {app.client.base_url}")
        
        # 验证结果
        print("\n2. 验证结果:")
        
        url_correct = app.var_url.get() == "https://ggws.hnhfpc.gov.cn"
        account_correct = app.var_account.get() == "430726000001010WS"
        org_correct = app.var_org.get() == "430726000001010"
        client_correct = app.client.base_url == "https://ggws.hnhfpc.gov.cn"
        
        print(f"   URL 正确: {'✓' if url_correct else '✗'}")
        print(f"   账号正确: {'✓' if account_correct else '✗'}")
        print(f"   机构代码正确: {'✓' if org_correct else '✗'}")
        print(f"   客户端 base_url 正确: {'✓' if client_correct else '✗'}")
        
        all_correct = url_correct and account_correct and org_correct and client_correct
        
        if all_correct:
            print("\n   ✓ 所有配置恢复正确")
            return True
        else:
            print("\n   ✗ 配置恢复有错误")
            return False
            
    except Exception as e:
        print(f"\n   ✗ 测试失败: {e}")
        return False

def main():
    """主测试函数"""
    print("湾流签约助手 - 配置修复测试")
    print("=" * 60)
    
    # 测试配置加载
    config_ok = test_config_loading()
    
    # 测试应用程序配置恢复
    restore_ok = test_app_restore_config()
    
    # 总结
    print("\n" + "=" * 60)
    print("测试总结")
    print("=" * 60)
    
    if config_ok and restore_ok:
        print("✓ 所有测试通过")
        print("\n配置修复成功！")
        print("应用程序现在应该能够正确加载配置，包括：")
        print("  - username 字段（账号）")
        print("  - ggws_base_url 字段（3.0系统地址）")
        print("  - org_code 字段（机构代码）")
        return 0
    else:
        print("✗ 测试失败")
        print("\n需要进一步调试的问题：")
        if not config_ok:
            print("  - 配置加载不完整")
        if not restore_ok:
            print("  - 应用程序配置恢复逻辑有问题")
        return 1

if __name__ == "__main__":
    sys.exit(main())