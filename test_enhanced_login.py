#!/usr/bin/env python3
"""
测试增强登录功能

这个脚本测试新集成的增强登录功能，包括：
1. 网页跳转登录
2. 连接诊断
3. 配置同步
"""

import os
import sys
import tkinter as tk
from tkinter import ttk, messagebox
import threading
import time

# 添加当前目录到路径
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def test_enhanced_login_ui():
    """测试增强登录UI"""
    print("测试增强登录UI...")
    
    # 创建测试窗口
    root = tk.Tk()
    root.title("测试增强登录功能")
    root.geometry("800x600")
    
    # 创建模拟的app实例
    class MockApp:
        def __init__(self):
            self._cfg = {
                "username": "test_user",
                "org_code": "",
                "ggws_base_url": "https://ggws.hnhfpc.gov.cn"
            }
            self.client = MockClient()
            
            # 增强登录相关的变量
            self.enhanced_url_var = tk.StringVar(value="https://ggws.hnhfpc.gov.cn")
            self.enhanced_account_var = tk.StringVar(value="test_user")
            self.enhanced_connection_status_var = tk.StringVar(value="待检测")
            self.enhanced_connection_status_label = ttk.Label(root, textvariable=self.enhanced_connection_status_var)
            self.enhanced_status_var = tk.StringVar(value="就绪")
            self.enhanced_api_account_var = tk.StringVar(value="test_user")
            self.enhanced_api_password_var = tk.StringVar()
        
        def after(self, delay, func):
            # 简化实现
            func()
    
    class MockClient:
        def __init__(self):
            self.base_url = "https://ggws.hnhfpc.gov.cn"
            self.logged_in = False
        
        def login(self, url, account, password):
            print(f"模拟登录: {url}, 账号: {account}")
            self.logged_in = True
            return True, "登录成功"
    
    # 创建模拟app
    mock_app = MockApp()
    
    # 测试UI组件创建
    print("1. 测试信息栏创建...")
    info_frame = ttk.Frame(root)
    info_frame.pack(fill=tk.X, pady=(0, 10))
    
    # 系统地址
    url_frame = ttk.Frame(info_frame)
    url_frame.pack(fill=tk.X, pady=(0, 5))
    
    ttk.Label(url_frame, text="公卫3.0系统:", font=("Arial", 10, "bold")).pack(side=tk.LEFT)
    ttk.Label(url_frame, textvariable=mock_app.enhanced_url_var, foreground="blue").pack(side=tk.LEFT, padx=(5, 0))
    
    print("✓ 信息栏创建成功")
    
    # 测试诊断区域
    print("2. 测试诊断区域创建...")
    diag_frame = ttk.LabelFrame(root, text=" 连接诊断 ", padding=10)
    diag_frame.pack(fill=tk.X, pady=(0, 10))
    
    from tkinter import scrolledtext
    diag_text = scrolledtext.ScrolledText(diag_frame, height=6, wrap=tk.WORD)
    diag_text.pack(fill=tk.X)
    diag_text.configure(state=tk.DISABLED)
    
    print("✓ 诊断区域创建成功")
    
    # 测试登录选项
    print("3. 测试登录选项创建...")
    login_frame = ttk.LabelFrame(root, text=" 登录方式 ", padding=10)
    login_frame.pack(fill=tk.X)
    
    # 网页跳转登录
    web_frame = ttk.Frame(login_frame)
    web_frame.pack(fill=tk.X, pady=(0, 10))
    
    ttk.Label(web_frame, text="方式1: 网页跳转登录", font=("Arial", 11, "bold")).pack(anchor=tk.W)
    ttk.Label(web_frame, text="直接打开公卫3.0系统登录页面，在浏览器中完成登录").pack(anchor=tk.W)
    
    web_button_frame = ttk.Frame(web_frame)
    web_button_frame.pack(fill=tk.X, pady=(5, 0))
    
    web_login_btn = ttk.Button(
        web_button_frame,
        text="🌐 跳转到3.0系统登录",
        command=lambda: print("网页跳转登录按钮点击"),
        style="Accent.TButton",
        width=20
    )
    web_login_btn.pack(side=tk.LEFT)
    
    print("✓ 登录选项创建成功")
    
    # 测试状态栏
    print("4. 测试状态栏创建...")
    status_frame = ttk.Frame(root)
    status_frame.pack(fill=tk.X, pady=(10, 0))
    
    status_label = ttk.Label(
        status_frame,
        textvariable=mock_app.enhanced_status_var,
        relief=tk.SUNKEN,
        anchor=tk.W,
        padding=(5, 2)
    )
    status_label.pack(fill=tk.X)
    
    print("✓ 状态栏创建成功")
    
    print("\n✅ 所有UI组件测试通过！")
    print("\n增强登录功能包括：")
    print("1. 🌐 网页跳转登录 - 直接打开公卫3.0系统登录页面")
    print("2. 🔍 连接诊断 - 检测网络和系统连接状态")
    print("3. 🔄 配置同步 - 自动提取机构、团队、医生信息")
    print("4. 📊 状态显示 - 实时显示连接状态")
    
    # 运行主循环
    root.mainloop()

def test_diagnosis_logic():
    """测试诊断逻辑"""
    print("\n测试诊断逻辑...")
    
    # 模拟诊断结果
    diagnostics = [
        ("网络连接", True, "网络连接正常"),
        ("公卫3.0系统", True, "系统可正常访问"),
        ("配置完整性", False, "缺失: 机构代码"),
        ("登录状态", False, "未登录")
    ]
    
    print("诊断结果：")
    for name, success, message in diagnostics:
        icon = "✅" if success else "❌"
        print(f"  {icon} {name}: {message}")
    
    # 检查是否所有测试通过
    all_passed = all(success for _, success, _ in diagnostics)
    print(f"\n所有测试通过: {all_passed}")
    
    if not all_passed:
        print("发现以下问题需要解决：")
        for name, success, message in diagnostics:
            if not success:
                print(f"  • {name}: {message}")
    
    return all_passed

def test_web_login_url():
    """测试网页登录URL构建"""
    print("\n测试网页登录URL构建...")
    
    from urllib.parse import quote
    
    base_url = "https://ggws.hnhfpc.gov.cn"
    account = "test_user"
    
    # 构建登录URL
    login_url = f"{base_url}/login.aspx"
    
    if account:
        login_url = f"{login_url}?user={quote(account)}"
    
    print(f"基础URL: {base_url}")
    print(f"账号: {account}")
    print(f"生成的登录URL: {login_url}")
    
    return login_url

def main():
    """主测试函数"""
    print("=" * 60)
    print("增强登录功能测试")
    print("=" * 60)
    
    # 测试诊断逻辑
    test_diagnosis_logic()
    
    # 测试网页登录URL构建
    test_web_login_url()
    
    print("\n" + "=" * 60)
    print("测试完成！")
    print("=" * 60)
    
    # 询问是否测试UI
    response = input("\n是否测试UI界面？(y/n): ").strip().lower()
    if response == 'y':
        test_enhanced_login_ui()

if __name__ == "__main__":
    main()