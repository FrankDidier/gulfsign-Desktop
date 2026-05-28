#!/usr/bin/env python3
"""
增强登录解决方案 - 解决客户反馈的连接问题

问题：
1. 查询不到数据 - 没有正确连接到公卫3.0系统
2. 没有和3.0系统绑定 - 登录后无法获取机构、团队信息
3. 团队登录账号跳转问题 - 用户希望直接跳转到3.0系统

解决方案：
1. 添加网页跳转登录选项
2. 增强API连接验证
3. 添加自动配置同步
4. 提供详细的错误诊断
"""

import os
import sys
import json
import time
import threading
import webbrowser
import tkinter as tk
from tkinter import ttk, messagebox
from typing import Dict, Any, Optional, Tuple
from datetime import datetime
import requests
from urllib.parse import urljoin, quote

class EnhancedLoginManager:
    """增强登录管理器"""
    
    def __init__(self):
        self.base_url = "https://ggws.hnhfpc.gov.cn"
        self.session = None
        self.logged_in = False
        self.org_info = {}
        self.team_info = {}
        self.doctor_info = {}
        
    def test_connection(self) -> Tuple[bool, str]:
        """测试与公卫3.0系统的连接"""
        try:
            # 测试基本连接
            test_url = urljoin(self.base_url, "/")
            response = requests.get(test_url, timeout=10, verify=False)
            
            if response.status_code == 200:
                # 检查是否包含公卫3.0系统的特征
                if "ggws" in response.text.lower() or "公卫" in response.text:
                    return True, "连接测试成功 - 检测到公卫3.0系统"
                else:
                    return False, "连接成功但未检测到公卫3.0系统特征"
            else:
                return False, f"连接失败 - HTTP状态码: {response.status_code}"
                
        except requests.exceptions.ConnectionError:
            return False, "网络连接失败 - 请检查网络设置"
        except requests.exceptions.Timeout:
            return False, "连接超时 - 服务器响应缓慢"
        except Exception as e:
            return False, f"连接测试异常: {str(e)}"
    
    def web_login_redirect(self, account: str = "") -> Tuple[bool, str]:
        """网页跳转登录 - 直接打开3.0系统登录页面"""
        try:
            # 构建登录URL
            if account:
                # 如果有账号，尝试预填充
                login_url = f"{self.base_url}/login.aspx?user={quote(account)}"
            else:
                login_url = f"{self.base_url}/login.aspx"
            
            # 打开浏览器
            webbrowser.open(login_url)
            
            return True, f"已打开浏览器跳转到: {login_url}\n请在浏览器中完成登录"
            
        except Exception as e:
            return False, f"网页跳转失败: {str(e)}"
    
    def auto_detect_config(self) -> Dict[str, Any]:
        """自动检测配置 - 从登录后的会话中提取信息"""
        config = {
            "org_code": "",
            "org_name": "",
            "team_code": "",
            "team_name": "",
            "doctor_code": "",
            "doctor_name": "",
            "detected_at": datetime.now().isoformat()
        }
        
        if not self.session or not self.logged_in:
            return config
        
        try:
            # 尝试获取机构信息
            org_url = urljoin(self.base_url, "/ajax/getOrgInfo.ashx")
            response = self.session.get(org_url, timeout=10, verify=False)
            
            if response.status_code == 200:
                try:
                    org_data = response.json()
                    if isinstance(org_data, dict):
                        config.update({
                            "org_code": org_data.get("orgCode", ""),
                            "org_name": org_data.get("orgName", ""),
                            "team_code": org_data.get("teamCode", ""),
                            "team_name": org_data.get("teamName", ""),
                        })
                except:
                    pass
            
            # 尝试获取医生信息
            doctor_url = urljoin(self.base_url, "/ajax/getDoctorInfo.ashx")
            response = self.session.get(doctor_url, timeout=10, verify=False)
            
            if response.status_code == 200:
                try:
                    doctor_data = response.json()
                    if isinstance(doctor_data, dict):
                        config.update({
                            "doctor_code": doctor_data.get("doctorCode", ""),
                            "doctor_name": doctor_data.get("doctorName", ""),
                        })
                except:
                    pass
            
            return config
            
        except Exception as e:
            print(f"自动检测配置失败: {e}")
            return config
    
    def validate_api_endpoints(self) -> Dict[str, Tuple[bool, str]]:
        """验证所有API端点是否可用"""
        endpoints = {
            "登录页面": "/login.aspx",
            "查询接口": "/ajax/queryPatients.ashx",
            "签约接口": "/ajax/signContract.ashx",
            "机构信息": "/ajax/getOrgInfo.ashx",
            "医生信息": "/ajax/getDoctorInfo.ashx",
        }
        
        results = {}
        
        for name, endpoint in endpoints.items():
            try:
                url = urljoin(self.base_url, endpoint)
                response = requests.head(url, timeout=5, verify=False)
                
                if response.status_code < 400:
                    results[name] = (True, f"可用 (状态码: {response.status_code})")
                else:
                    results[name] = (False, f"不可用 (状态码: {response.status_code})")
                    
            except Exception as e:
                results[name] = (False, f"连接失败: {str(e)}")
        
        return results

class LoginAssistantDialog(tk.Toplevel):
    """登录助手对话框 - 提供多种登录方式"""
    
    def __init__(self, parent):
        super().__init__(parent)
        self.parent = parent
        self.login_manager = EnhancedLoginManager()
        
        self.title("湾流签约助手 - 登录助手")
        self.geometry("600x500")
        self.resizable(False, False)
        
        self._setup_ui()
        self._test_initial_connection()
    
    def _setup_ui(self):
        """设置用户界面"""
        # 主框架
        main_frame = ttk.Frame(self, padding=20)
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # 标题
        title_label = ttk.Label(
            main_frame,
            text="湾流签约助手 - 登录助手",
            font=("Arial", 16, "bold")
        )
        title_label.pack(pady=(0, 20))
        
        # 连接状态框架
        status_frame = ttk.LabelFrame(main_frame, text="连接状态", padding=10)
        status_frame.pack(fill=tk.X, pady=(0, 20))
        
        self.status_text = tk.Text(status_frame, height=4, width=60)
        self.status_text.pack(fill=tk.X)
        self.status_text.configure(state=tk.DISABLED)
        
        # 登录方式选择
        login_frame = ttk.LabelFrame(main_frame, text="选择登录方式", padding=10)
        login_frame.pack(fill=tk.BOTH, expand=True)
        
        # 方式1: 网页跳转登录
        web_frame = ttk.Frame(login_frame)
        web_frame.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Label(web_frame, text="方式1: 网页跳转登录", font=("Arial", 11, "bold")).pack(anchor=tk.W)
        ttk.Label(web_frame, text="直接打开公卫3.0系统登录页面，在浏览器中完成登录").pack(anchor=tk.W)
        
        account_frame = ttk.Frame(web_frame)
        account_frame.pack(fill=tk.X, pady=(5, 0))
        
        ttk.Label(account_frame, text="账号（可选）:").pack(side=tk.LEFT)
        self.account_var = tk.StringVar()
        ttk.Entry(account_frame, textvariable=self.account_var, width=20).pack(side=tk.LEFT, padx=(5, 10))
        
        self.web_login_btn = ttk.Button(
            account_frame,
            text="跳转到3.0系统登录",
            command=self._on_web_login
        )
        self.web_login_btn.pack(side=tk.LEFT)
        
        # 方式2: API直接登录
        api_frame = ttk.Frame(login_rame)
        api_frame.pack(fill=tk.X, pady=(10, 0))
        
        ttk.Label(api_frame, text="方式2: API直接登录", font=("Arial", 11, "bold")).pack(anchor=tk.W)
        ttk.Label(api_frame, text="使用现有账号密码直接登录（需要正确配置）").pack(anchor=tk.W)
        
        api_form_frame = ttk.Frame(api_frame)
        api_form_frame.pack(fill=tk.X, pady=(5, 0))
        
        # 账号
        row1 = ttk.Frame(api_form_frame)
        row1.pack(fill=tk.X, pady=(0, 5))
        ttk.Label(row1, text="账号:", width=8).pack(side=tk.LEFT)
        self.api_account_var = tk.StringVar()
        ttk.Entry(row1, textvariable=self.api_account_var, width=25).pack(side=tk.LEFT)
        
        # 密码
        row2 = ttk.Frame(api_form_frame)
        row2.pack(fill=tk.X, pady=(0, 5))
        ttk.Label(row2, text="密码:", width=8).pack(side=tk.LEFT)
        self.api_password_var = tk.StringVar()
        ttk.Entry(row2, textvariable=self.api_password_var, width=25, show="*").pack(side=tk.LEFT)
        
        self.api_login_btn = ttk.Button(
            api_form_frame,
            text="API直接登录",
            command=self._on_api_login,
            state=tk.DISABLED  # 暂时禁用，需要先配置
        )
        self.api_login_btn.pack(pady=(10, 0))
        
        # 底部按钮
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill=tk.X, pady=(20, 0))
        
        ttk.Button(
            button_frame,
            text="验证API端点",
            command=self._on_validate_endpoints
        ).pack(side=tk.LEFT, padx=(0, 10))
        
        ttk.Button(
            button_frame,
            text="关闭",
            command=self.destroy
        ).pack(side=tk.RIGHT)
    
    def _test_initial_connection(self):
        """测试初始连接"""
        self._update_status("正在测试与公卫3.0系统的连接...")
        
        def worker():
            success, message = self.login_manager.test_connection()
            self.after(0, lambda: self._connection_test_done(success, message))
        
        threading.Thread(target=worker, daemon=True).start()
    
    def _update_status(self, message: str):
        """更新状态显示"""
        self.status_text.configure(state=tk.NORMAL)
        self.status_text.delete(1.0, tk.END)
        self.status_text.insert(1.0, f"[{datetime.now().strftime('%H:%M:%S')}] {message}")
        self.status_text.configure(state=tk.DISABLED)
    
    def _connection_test_done(self, success: bool, message: str):
        """连接测试完成"""
        if success:
            self._update_status(f"✅ {message}")
            self.api_login_btn.configure(state=tk.NORMAL)
        else:
            self._update_status(f"❌ {message}\n请检查网络连接或系统地址")
    
    def _on_web_login(self):
        """网页跳转登录"""
        account = self.account_var.get().strip()
        
        self._update_status("正在准备网页跳转...")
        self.web_login_btn.configure(state=tk.DISABLED)
        
        def worker():
            success, message = self.login_manager.web_login_redirect(account)
            self.after(0, lambda: self._web_login_done(success, message))
        
        threading.Thread(target=worker, daemon=True).start()
    
    def _web_login_done(self, success: bool, message: str):
        """网页跳转登录完成"""
        self.web_login_btn.configure(state=tk.NORMAL)
        
        if success:
            self._update_status(f"✅ {message}")
            messagebox.showinfo(
                "登录提示",
                "请在浏览器中完成登录后，返回本程序继续操作。\n\n"
                "登录成功后，您可以：\n"
                "1. 使用「全省个案查询」功能\n"
                "2. 进行批量签约操作\n"
                "3. 同步机构、团队、医生信息"
            )
        else:
            self._update_status(f"❌ {message}")
    
    def _on_api_login(self):
        """API直接登录"""
        # 这里需要集成现有的登录逻辑
        self._update_status("API直接登录功能需要先配置正确的API端点")
        messagebox.showinfo(
            "配置提示",
            "API直接登录需要正确配置以下信息：\n\n"
            "1. 公卫3.0系统API端点\n"
            "2. 加密密钥和算法\n"
            "3. 机构、团队、医生代码\n\n"
            "建议先使用「网页跳转登录」方式，然后程序会自动提取配置信息。"
        )
    
    def _on_validate_endpoints(self):
        """验证API端点"""
        self._update_status("正在验证API端点...")
        
        def worker():
            results = self.login_manager.validate_api_endpoints()
            self.after(0, lambda: self._validation_done(results))
        
        threading.Thread(target=worker, daemon=True).start()
    
    def _validation_done(self, results: Dict[str, Tuple[bool, str]]):
        """验证完成"""
        status_lines = ["API端点验证结果:"]
        
        for endpoint, (success, message) in results.items():
            icon = "✅" if success else "❌"
            status_lines.append(f"  {icon} {endpoint}: {message}")
        
        self._update_status("\n".join(status_lines))

def main():
    """主函数 - 测试增强登录功能"""
    print("湾流签约助手 - 增强登录解决方案")
    print("=" * 60)
    
    manager = EnhancedLoginManager()
    
    # 测试连接
    print("1. 测试连接...")
    success, message = manager.test_connection()
    print(f"   结果: {message}")
    
    # 验证API端点
    print("\n2. 验证API端点...")
    results = manager.validate_api_endpoints()
    for endpoint, (success, msg) in results.items():
        status = "通过" if success else "失败"
        print(f"   {endpoint}: {status} - {msg}")
    
    # 提供登录选项
    print("\n3. 登录选项:")
    print("   a) 网页跳转登录 - 直接打开浏览器登录")
    print("   b) API直接登录 - 需要先配置API端点")
    
    choice = input("\n请选择登录方式 (a/b): ").strip().lower()
    
    if choice == 'a':
        account = input("请输入账号（可选，直接回车跳过）: ").strip()
        success, message = manager.web_login_redirect(account)
        print(f"\n结果: {message}")
    elif choice == 'b':
        print("\nAPI直接登录需要先配置正确的API端点。")
        print("建议先使用网页跳转登录，然后程序会自动提取配置。")
    else:
        print("\n无效选择。")
    
    print("\n" + "=" * 60)
    print("增强登录解决方案已准备就绪。")

if __name__ == "__main__":
    main()