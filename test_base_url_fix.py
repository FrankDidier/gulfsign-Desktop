#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
测试 PH3Client base_url 设置修复
验证应用程序启动时 base_url 是否正确设置
"""

import os
import sys
import json
from pathlib import Path

# 添加项目根目录到 Python 路径
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

# 模拟应用程序启动过程
def test_application_startup():
    print("=" * 60)
    print("测试应用程序启动和 base_url 设置")
    print("=" * 60)
    
    # 1. 检查配置文件
    print("\n1. 检查配置文件:")
    
    # 根目录配置文件
    root_config_path = project_root / "gulfsign_config.json"
    print(f"  根目录配置文件: {root_config_path}")
    if root_config_path.exists():
        with open(root_config_path, 'r', encoding='utf-8') as f:
            root_config = json.load(f)
        print(f"  username: {root_config.get('username', '未设置')}")
        print(f"  ggws_base_url: {root_config.get('ggws_base_url', '未设置')}")
        print(f"  org_code: {root_config.get('org_code', '未设置')}")
    else:
        print("  ✗ 根目录配置文件不存在")
    
    # 核心模块配置文件
    core_config_path = project_root / "GulfSign_Client_Package/core_modules/gulfsign_config.json"
    print(f"\n  核心模块配置文件: {core_config_path}")
    if core_config_path.exists():
        with open(core_config_path, 'r', encoding='utf-8') as f:
            core_config = json.load(f)
        print(f"  username: {core_config.get('username', '未设置')}")
        print(f"  ggws_base_url: {core_config.get('ggws_base_url', '未设置')}")
        print(f"  org_code: {core_config.get('org_code', '未设置')}")
    else:
        print("  ✗ 核心模块配置文件不存在")
    
    # 2. 模拟配置加载
    print("\n2. 模拟配置加载过程:")
    
    try:
        from GulfSign_Client_Package.core_modules.config_manager import ConfigManager
        
        config_manager = ConfigManager()
        config = config_manager.load()
        
        print(f"  加载的配置:")
        print(f"  username: {config.get('username', '未设置')}")
        print(f"  ggws_base_url: {config.get('ggws_base_url', '未设置')}")
        print(f"  org_code: {config.get('org_code', '未设置')}")
        
        # 验证配置
        is_valid, message = config_manager._validate_config(config)
        print(f"  配置验证: {'✓ 通过' if is_valid else '✗ 失败'} - {message}")
        
    except Exception as e:
        print(f"  ✗ 配置加载失败: {e}")
    
    # 3. 模拟应用程序配置恢复
    print("\n3. 模拟应用程序配置恢复:")
    
    try:
        # 创建模拟的应用程序类
        class MockApp:
            def __init__(self):
                self.client = MockPH3Client()
                self.var_account = MockVar()
                self.var_url = MockVar()
                self.var_org = MockVar()
                self._cfg = config if 'config' in locals() else {}
            
            def _restore_config(self):
                """模拟配置恢复逻辑"""
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
        
        class MockPH3Client:
            def __init__(self):
                self.base_url = ""
            
            def _url(self, path):
                """模拟 URL 构建方法"""
                if not self.base_url:
                    return path  # 如果 base_url 为空，返回路径本身
                return f"{self.base_url}{path}"
        
        class MockVar:
            def __init__(self):
                self._value = ""
            
            def set(self, value):
                self._value = value
            
            def get(self):
                return self._value
        
        # 创建模拟应用程序并恢复配置
        app = MockApp()
        app._restore_config()
        
        print(f"  账号变量值: {app.var_account.get()}")
        print(f"  URL 变量值: {app.var_url.get()}")
        print(f"  机构代码变量值: {app.var_org.get()}")
        print(f"  客户端 base_url: {app.client.base_url}")
        
        # 测试 URL 构建
        test_path = "/FormMain.aspx"
        test_url = app.client._url(test_path)
        print(f"  测试 URL 构建 ('{test_path}'): {test_url}")
        
        # 验证
        if app.client.base_url:
            print(f"  ✓ base_url 已正确设置: {app.client.base_url}")
            if test_url.startswith("http"):
                print(f"  ✓ URL 构建正确: {test_url}")
            else:
                print(f"  ✗ URL 构建不正确: {test_url}")
        else:
            print(f"  ✗ base_url 未设置!")
        
    except Exception as e:
        print(f"  ✗ 模拟应用程序失败: {e}")
    
    # 4. 检查实际配置文件问题
    print("\n4. 检查配置文件问题:")
    
    # 检查核心配置文件是否有正确的字段
    if core_config_path.exists():
        with open(core_config_path, 'r', encoding='utf-8') as f:
            core_config = json.load(f)
        
        issues = []
        
        # 检查必需字段
        if not core_config.get('username'):
            issues.append("username 字段为空")
        
        if not core_config.get('ggws_base_url'):
            issues.append("ggws_base_url 字段为空")
        
        if not core_config.get('org_code'):
            issues.append("org_code 字段为空 (但这不是必需字段)")
        
        if issues:
            print(f"  ✗ 配置文件问题:")
            for issue in issues:
                print(f"    - {issue}")
        else:
            print(f"  ✓ 配置文件字段完整")
    
    print("\n" + "=" * 60)
    print("测试完成")
    print("=" * 60)

if __name__ == "__main__":
    test_application_startup()