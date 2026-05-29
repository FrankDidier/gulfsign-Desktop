#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
测试应用程序启动
"""
import os
import sys
import logging

# 设置详细日志
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# 添加模块路径
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "GulfSign_Client_Package/core_modules"))

# 导入应用程序模块
import app

def test_app_initialization():
    """测试应用程序初始化"""
    print("=== 测试应用程序初始化 ===")
    
    print(f"1. 测试 load_config() 函数:")
    try:
        config = app.load_config()
        print(f"   - 加载成功")
        print(f"   - username: {repr(config.get('username'))}")
        print(f"   - ggws_base_url: {repr(config.get('ggws_base_url'))}")
        print(f"   - password: {repr(config.get('password'))}")
    except Exception as e:
        print(f"   - 加载失败: {e}")
        import traceback
        traceback.print_exc()
    
    print(f"\n2. 测试 GulfSignApp 初始化:")
    try:
        # 注意: 我们不实际运行Tkinter主循环，只测试初始化
        import tkinter as tk
        
        # 创建根窗口
        root = tk.Tk()
        root.withdraw()  # 隐藏窗口
        
        # 创建应用程序实例
        app_instance = app.GulfSignApp()
        
        print(f"   - 初始化成功")
        print(f"   - client.base_url: {repr(app_instance.client.base_url)}")
        print(f"   - client.logged_in: {app_instance.client.logged_in}")
        print(f"   - var_account: {repr(app_instance.var_account.get())}")
        print(f"   - var_url: {repr(app_instance.var_url.get())}")
        
        # 检查配置
        print(f"\n3. 检查配置状态:")
        print(f"   - _cfg username: {repr(app_instance._cfg.get('username'))}")
        print(f"   - _cfg ggws_base_url: {repr(app_instance._cfg.get('ggws_base_url'))}")
        
        # 测试登录按钮状态
        print(f"\n4. 测试登录相关:")
        print(f"   - 登录按钮状态: {app_instance.btn_login.cget('state')}")
        print(f"   - 登录状态文本: {repr(app_instance.var_login_status.get())}")
        
    except Exception as e:
        print(f"   - 初始化失败: {e}")
        import traceback
        traceback.print_exc()
    
    print(f"\n=== 测试完成 ===")

if __name__ == "__main__":
    test_app_initialization()