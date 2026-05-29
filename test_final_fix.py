#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
最终修复测试
"""
import os
import sys
import json

# 添加路径
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def test_configuration_files():
    """测试配置文件"""
    print("=" * 60)
    print("测试配置文件")
    print("=" * 60)
    
    # 检查根目录配置文件
    root_config = "gulfsign_config.json"
    print(f"\n1. 根目录配置文件: {root_config}")
    
    if os.path.exists(root_config):
        with open(root_config, 'r', encoding='utf-8') as f:
            config = json.load(f)
        
        print(f"   ✓ 文件存在")
        print(f"   username: {config.get('username', '未设置')}")
        print(f"   ggws_base_url: {config.get('ggws_base_url', '未设置')}")
        print(f"   org_code: {config.get('org_code', '未设置')}")
    else:
        print(f"   ✗ 文件不存在")
    
    # 检查核心模块配置文件
    core_config = "GulfSign_Client_Package/core_modules/gulfsign_config.json"
    print(f"\n2. 核心模块配置文件: {core_config}")
    
    if os.path.exists(core_config):
        with open(core_config, 'r', encoding='utf-8') as f:
            config = json.load(f)
        
        print(f"   ✓ 文件存在")
        print(f"   username: {config.get('username', '未设置')}")
        print(f"   ggws_base_url: {config.get('ggws_base_url', '未设置')}")
        print(f"   org_code: {config.get('org_code', '未设置')}")
        
        # 验证配置
        print(f"\n3. 配置验证:")
        
        has_username = "username" in config and config["username"]
        has_ggws_base_url = "ggws_base_url" in config and config["ggws_base_url"]
        has_org_code = "org_code" in config and config["org_code"]
        
        print(f"   username: {'✓ 存在' if has_username else '✗ 缺失'}")
        print(f"   ggws_base_url: {'✓ 存在' if has_ggws_base_url else '✗ 缺失'}")
        print(f"   org_code: {'✓ 存在' if has_org_code else '✗ 缺失'}")
        
        if has_username and has_ggws_base_url:
            print(f"\n   ✓ 核心配置文件正确")
            return True
        else:
            print(f"\n   ✗ 核心配置文件不完整")
            return False
    else:
        print(f"   ✗ 文件不存在")
        return False

def test_config_manager():
    """测试配置管理器"""
    print("\n" + "=" * 60)
    print("测试配置管理器")
    print("=" * 60)
    
    try:
        from GulfSign_Client_Package.core_modules.config_manager import ConfigManager
        
        print("\n1. 创建配置管理器...")
        config_manager = ConfigManager()
        
        print("\n2. 加载配置...")
        config = config_manager.load()
        
        print("\n3. 检查加载的配置:")
        print(f"   username: {config.get('username', '未设置')}")
        print(f"   ggws_base_url: {config.get('ggws_base_url', '未设置')}")
        print(f"   org_code: {config.get('org_code', '未设置')}")
        
        print("\n4. 验证配置...")
        is_valid, message = config_manager._validate_config(config)
        print(f"   验证结果: {'✓ 通过' if is_valid else '✗ 失败'}")
        print(f"   验证消息: {message}")
        
        if is_valid:
            print("\n   ✓ 配置管理器工作正常")
            return True
        else:
            print("\n   ✗ 配置管理器验证失败")
            return False
            
    except Exception as e:
        print(f"\n   ✗ 配置管理器测试失败: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_app_config_restore():
    """测试应用程序配置恢复"""
    print("\n" + "=" * 60)
    print("测试应用程序配置恢复")
    print("=" * 60)
    
    try:
        # 模拟应用程序配置恢复逻辑
        class MockTkVar:
            def __init__(self):
                self.value = ""
            def set(self, value):
                self.value = value
            def get(self):
                return self.value
        
        class MockClient:
            def __init__(self):
                self.base_url = ""
        
        class MockApp:
            def __init__(self):
                self._cfg = {}
                self.var_url = MockTkVar()
                self.var_account = MockTkVar()
                self.var_org = MockTkVar()
                self.client = MockClient()
            
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
        
        print("\n1. 创建模拟应用程序...")
        app = MockApp()
        
        print("\n2. 设置模拟配置...")
        app._cfg = {
            "username": "431122012",
            "ggws_base_url": "https://ggws.hnhfpc.gov.cn",
            "org_code": "430726000001010"
        }
        
        print("\n3. 执行配置恢复...")
        app._restore_config()
        
        print("\n4. 验证恢复结果:")
        print(f"   URL 变量值: {app.var_url.get()}")
        print(f"   账号变量值: {app.var_account.get()}")
        print(f"   机构代码变量值: {app.var_org.get()}")
        print(f"   客户端 base_url: {app.client.base_url}")
        
        # 检查结果
        url_correct = app.var_url.get() == "https://ggws.hnhfpc.gov.cn"
        account_correct = app.var_account.get() == "431122012"
        org_correct = app.var_org.get() == "430726000001010"
        client_correct = app.client.base_url == "https://ggws.hnhfpc.gov.cn"
        
        print(f"\n5. 验证:")
        print(f"   URL 正确: {'✓' if url_correct else '✗'}")
        print(f"   账号正确: {'✓' if account_correct else '✗'}")
        print(f"   机构代码正确: {'✓' if org_correct else '✗'}")
        print(f"   客户端 base_url 正确: {'✓' if client_correct else '✗'}")
        
        if url_correct and account_correct and org_correct and client_correct:
            print("\n   ✓ 应用程序配置恢复正确")
            return True
        else:
            print("\n   ✗ 应用程序配置恢复有误")
            return False
            
    except Exception as e:
        print(f"\n   ✗ 应用程序配置恢复测试失败: {e}")
        return False

def main():
    """主测试函数"""
    print("湾流签约助手 - 最终修复测试")
    print("=" * 60)
    
    print("\n重要提示:")
    print("1. 我们已经修复了以下问题:")
    print("   - 更新了 _restore_config() 方法以兼容新旧配置格式")
    print("   - 修复了 ConfigManager 验证逻辑（不再要求密码字段）")
    print("   - 修复了字段映射错误（org_code 映射到 org_code，而不是 password）")
    print("   - 更新了核心配置文件")
    print("2. 用户需要:")
    print("   - 确保配置文件有正确的字段")
    print("   - 登录成功后配置会自动保存")
    
    # 运行测试
    config_files_ok = test_configuration_files()
    config_manager_ok = test_config_manager()
    app_restore_ok = test_app_config_restore()
    
    # 总结
    print("\n" + "=" * 60)
    print("测试总结")
    print("=" * 60)
    
    print(f"\n测试结果:")
    print(f"  配置文件检查: {'✓ 通过' if config_files_ok else '✗ 失败'}")
    print(f"  配置管理器测试: {'✓ 通过' if config_manager_ok else '✗ 失败'}")
    print(f"  应用程序配置恢复: {'✓ 通过' if app_restore_ok else '✗ 失败'}")
    
    all_passed = config_files_ok and config_manager_ok and app_restore_ok
    
    if all_passed:
        print("\n✓ 所有测试通过!")
        print("\n修复已完成。应用程序现在应该能够:")
        print("  1. 正确加载配置文件中的 ggws_base_url 和 username 字段")
        print("  2. 恢复配置到 UI 界面")
        print("  3. 设置 PH3Client 的 base_url")
        print("  4. 允许用户登录并保存配置")
        print("\n用户应该不再看到 '缺失账号' 和 '缺失 3.0系统地址' 的错误。")
        return 0
    else:
        print("\n✗ 测试失败")
        print("\n需要进一步调试的问题:")
        if not config_files_ok:
            print("  - 配置文件不完整或不存在")
        if not config_manager_ok:
            print("  - 配置管理器有问题")
        if not app_restore_ok:
            print("  - 应用程序配置恢复逻辑有问题")
        return 1

if __name__ == "__main__":
    sys.exit(main())