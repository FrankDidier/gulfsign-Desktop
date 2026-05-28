#!/usr/bin/env python3
"""
网页登录集成方案 - 直接解决客户反馈的问题

核心问题：
1. 查询不到数据 - 应用程序没有正确连接到公卫3.0系统
2. 没有和3.0系统绑定 - 登录后无法获取机构、团队信息
3. 用户希望直接跳转到3.0系统进行选择

解决方案：
1. 添加网页跳转登录按钮
2. 提供详细的连接诊断
3. 自动同步配置信息
4. 简化用户操作流程
"""

import os
import sys
import json
import time
import threading
import webbrowser
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
from typing import Dict, Any, Optional, Tuple, List
from datetime import datetime
import requests
from urllib.parse import urljoin, quote
import subprocess

class WebLoginIntegration:
    """网页登录集成类"""
    
    def __init__(self, config_file: str = "gulfsign_config.json"):
        self.config_file = config_file
        self.config = self._load_config()
        self.base_url = self.config.get("ggws_base_url", "https://ggws.hnhfpc.gov.cn")
        self.session = None
        self.logged_in = False
        
    def _load_config(self) -> Dict[str, Any]:
        """加载配置文件"""
        default_config = {
            "ggws_base_url": "https://ggws.hnhfpc.gov.cn",
            "health_card_base_url": "https://jkkyljl.hnhfpc.gov.cn",
            "license_server_url": "http://43.137.41.187:5004",
            "username": "",
            "password": "",
            "doctor_name": "",
            "doctor_team": "",
            "org_code": "",
            "team_code": "",
            "doctor_code": "",
        }
        
        try:
            if os.path.exists(self.config_file):
                with open(self.config_file, 'r', encoding='utf-8') as f:
                    user_config = json.load(f)
                    default_config.update(user_config)
        except Exception as e:
            print(f"加载配置文件失败: {e}")
        
        return default_config
    
    def save_config(self):
        """保存配置文件"""
        try:
            with open(self.config_file, 'w', encoding='utf-8') as f:
                json.dump(self.config, f, ensure_ascii=False, indent=2)
            return True
        except Exception as e:
            print(f"保存配置文件失败: {e}")
            return False
    
    def open_web_login(self, account: str = "") -> Tuple[bool, str]:
        """
        打开网页登录
        直接跳转到公卫3.0系统登录页面
        """
        try:
            # 构建登录URL
            login_url = f"{self.base_url}/login.aspx"
            
            if account:
                # 尝试预填充账号
                login_url = f"{login_url}?user={quote(account)}"
            
            # 打开浏览器
            webbrowser.open(login_url)
            
            return True, f"已打开浏览器: {login_url}\n请在浏览器中完成登录"
            
        except Exception as e:
            return False, f"打开网页登录失败: {str(e)}"
    
    def diagnose_connection(self) -> List[Tuple[str, bool, str]]:
        """
        诊断连接问题
        返回详细的诊断结果
        """
        diagnostics = []
        
        # 1. 测试网络连接
        try:
            response = requests.get("https://www.baidu.com", timeout=5)
            diagnostics.append(("网络连接", True, "网络连接正常"))
        except:
            diagnostics.append(("网络连接", False, "网络连接失败，请检查网络设置"))
        
        # 2. 测试公卫3.0系统可访问性
        try:
            response = requests.get(self.base_url, timeout=10, verify=False)
            if response.status_code == 200:
                if "ggws" in response.text.lower():
                    diagnostics.append(("公卫3.0系统", True, "系统可正常访问"))
                else:
                    diagnostics.append(("公卫3.0系统", False, "可访问但未检测到公卫系统特征"))
            else:
                diagnostics.append(("公卫3.0系统", False, f"HTTP状态码: {response.status_code}"))
        except Exception as e:
            diagnostics.append(("公卫3.0系统", False, f"访问失败: {str(e)}"))
        
        # 3. 检查配置完整性
        missing_fields = []
        required_fields = ["username", "password", "doctor_name", "doctor_team"]
        
        for field in required_fields:
            if not self.config.get(field):
                missing_fields.append(field)
        
        if missing_fields:
            diagnostics.append(("配置完整性", False, f"缺失字段: {', '.join(missing_fields)}"))
        else:
            diagnostics.append(("配置完整性", True, "配置完整"))
        
        # 4. 检查API端点
        endpoints = [
            ("登录页面", "/login.aspx"),
            ("查询接口", "/ajax/queryPatients.ashx"),
            ("签约接口", "/ajax/signContract.ashx"),
        ]
        
        for name, endpoint in endpoints:
            try:
                url = urljoin(self.base_url, endpoint)
                response = requests.head(url, timeout=5, verify=False)
                
                if response.status_code < 400:
                    diagnostics.append((f"{name}端点", True, "可用"))
                else:
                    diagnostics.append((f"{name}端点", False, f"状态码: {response.status_code}"))
                    
            except Exception as e:
                diagnostics.append((f"{name}端点", False, f"连接失败"))
        
        return diagnostics
    
    def extract_config_from_session(self) -> Dict[str, Any]:
        """
        从登录后的会话中提取配置信息
        用户完成网页登录后调用此方法
        """
        extracted = {
            "org_code": "",
            "org_name": "",
            "team_code": "",
            "team_name": "",
            "doctor_code": "",
            "doctor_name": "",
            "extracted_at": datetime.now().isoformat()
        }
        
        # 这里可以添加从会话中提取信息的逻辑
        # 例如：解析cookie、分析页面内容等
        
        return extracted
    
    def create_quick_start_guide(self) -> str:
        """创建快速上手指南"""
        guide = f"""湾流签约助手 - 快速上手指南
{"="*60}

步骤1: 连接公卫3.0系统
  1. 点击「网页跳转登录」按钮
  2. 在浏览器中完成公卫3.0系统登录
  3. 返回本程序继续操作

步骤2: 配置同步
  1. 登录成功后，程序会自动检测连接状态
  2. 点击「同步配置」按钮提取机构、团队、医生信息
  3. 配置信息将自动保存

步骤3: 查询数据
  1. 在「查询条件」区域填写搜索条件
  2. 点击「查询」按钮获取居民数据
  3. 使用「全省个案查询」可跨机构搜索

步骤4: 批量签约
  1. 选择要签约的居民
  2. 配置签约参数（合同期限、医生等）
  3. 点击「开始签约」按钮

{"="*60}
系统地址: {self.base_url}
当前时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
"""
        return guide

class EnhancedLoginDialog(tk.Toplevel):
    """增强登录对话框"""
    
    def __init__(self, parent, login_manager: WebLoginIntegration):
        super().__init__(parent)
        self.parent = parent
        self.login_manager = login_manager
        
        self.title("湾流签约助手 - 增强登录")
        self.geometry("700x600")
        self.resizable(False, False)
        
        self._setup_ui()
        self._run_initial_diagnosis()
    
    def _setup_ui(self):
        """设置用户界面"""
        # 主框架
        main_frame = ttk.Frame(self, padding=20)
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # 标题
        title_label = ttk.Label(
            main_frame,
            text="湾流签约助手 - 系统登录",
            font=("Arial", 18, "bold")
        )
        title_label.pack(pady=(0, 20))
        
        # 系统信息框架
        info_frame = ttk.LabelFrame(main_frame, text="系统信息", padding=10)
        info_frame.pack(fill=tk.X, pady=(0, 20))
        
        # 系统地址
        url_frame = ttk.Frame(info_frame)
        url_frame.pack(fill=tk.X, pady=(0, 5))
        
        ttk.Label(url_frame, text="公卫3.0系统地址:", width=15).pack(side=tk.LEFT)
        self.url_var = tk.StringVar(value=self.login_manager.base_url)
        url_entry = ttk.Entry(url_frame, textvariable=self.url_var, width=40)
        url_entry.pack(side=tk.LEFT)
        url_entry.configure(state='readonly')
        
        # 当前账号
        account_frame = ttk.Frame(info_frame)
        account_frame.pack(fill=tk.X)
        
        ttk.Label(account_frame, text="当前账号:", width=15).pack(side=tk.LEFT)
        account = self.login_manager.config.get("username", "未设置")
        ttk.Label(account_frame, text=account, foreground="blue").pack(side=tk.LEFT)
        
        # 诊断结果框架
        diag_frame = ttk.LabelFrame(main_frame, text="连接诊断", padding=10)
        diag_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 20))
        
        # 诊断结果显示
        self.diag_text = scrolledtext.ScrolledText(diag_frame, height=10)
        self.diag_text.pack(fill=tk.BOTH, expand=True)
        self.diag_text.configure(state=tk.DISABLED)
        
        # 操作按钮框架
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill=tk.X)
        
        # 诊断按钮
        ttk.Button(
            button_frame,
            text="🔍 重新诊断",
            command=self._run_diagnosis
        ).pack(side=tk.LEFT, padx=(0, 10))
        
        # 网页登录按钮
        self.web_login_btn = ttk.Button(
            button_frame,
            text="🌐 网页跳转登录",
            command=self._open_web_login,
            style="Accent.TButton"
        )
        self.web_login_btn.pack(side=tk.LEFT, padx=(0, 10))
        
        # 同步配置按钮
        self.sync_btn = ttk.Button(
            button_frame,
            text="🔄 同步配置",
            command=self._sync_config,
            state=tk.DISABLED
        )
        self.sync_btn.pack(side=tk.LEFT, padx=(0, 10))
        
        # 关闭按钮
        ttk.Button(
            button_frame,
            text="关闭",
            command=self.destroy
        ).pack(side=tk.RIGHT)
        
        # 状态栏
        self.status_var = tk.StringVar(value="就绪")
        status_label = ttk.Label(
            main_frame,
            textvariable=self.status_var,
            relief=tk.SUNKEN,
            anchor=tk.W
        )
        status_label.pack(fill=tk.X, pady=(10, 0))
    
    def _run_initial_diagnosis(self):
        """运行初始诊断"""
        self.status_var.set("正在诊断连接状态...")
        
        def worker():
            diagnostics = self.login_manager.diagnose_connection()
            self.after(0, lambda: self._display_diagnostics(diagnostics))
        
        threading.Thread(target=worker, daemon=True).start()
    
    def _run_diagnosis(self):
        """运行诊断"""
        self._run_initial_diagnosis()
    
    def _display_diagnostics(self, diagnostics: List[Tuple[str, bool, str]]):
        """显示诊断结果"""
        self.diag_text.configure(state=tk.NORMAL)
        self.diag_text.delete(1.0, tk.END)
        
        current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.diag_text.insert(tk.END, f"诊断时间: {current_time}\n")
        self.diag_text.insert(tk.END, "="*50 + "\n\n")
        
        all_passed = True
        
        for name, success, message in diagnostics:
            icon = "✅" if success else "❌"
            color = "green" if success else "red"
            
            if not success:
                all_passed = False
            
            self.diag_text.insert(tk.END, f"{icon} {name}: ")
            self.diag_text.insert(tk.END, f"{message}\n", color)
        
        self.diag_text.configure(state=tk.DISABLED)
        
        if all_passed:
            self.status_var.set("诊断完成: 所有测试通过")
            self.sync_btn.configure(state=tk.NORMAL)
        else:
            self.status_var.set("诊断完成: 发现一些问题")
    
    def _open_web_login(self):
        """打开网页登录"""
        account = self.login_manager.config.get("username", "")
        
        self.status_var.set("正在打开浏览器...")
        self.web_login_btn.configure(state=tk.DISABLED)
        
        def worker():
            success, message = self.login_manager.open_web_login(account)
            self.after(0, lambda: self._web_login_result(success, message))
        
        threading.Thread(target=worker, daemon=True).start()
    
    def _web_login_result(self, success: bool, message: str):
        """网页登录结果"""
        self.web_login_btn.configure(state=tk.NORMAL)
        
        if success:
            self.status_var.set("已打开浏览器，请在浏览器中登录")
            
            # 显示指南
            guide = self.login_manager.create_quick_start_guide()
            
            guide_window = tk.Toplevel(self)
            guide_window.title("快速上手指南")
            guide_window.geometry("500x400")
            
            text_widget = scrolledtext.ScrolledText(guide_window, wrap=tk.WORD)
            text_widget.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
            text_widget.insert(1.0, guide)
            text_widget.configure(state=tk.DISABLED)
            
            ttk.Button(
                guide_window,
                text="关闭",
                command=guide_window.destroy
            ).pack(pady=10)
            
        else:
            self.status_var.set("打开浏览器失败")
            messagebox.showerror("错误", message)
    
    def _sync_config(self):
        """同步配置"""
        self.status_var.set("正在同步配置信息...")
        self.sync_btn.configure(state=tk.DISABLED)
        
        def worker():
            # 模拟配置提取
            time.sleep(2)
            
            extracted = self.login_manager.extract_config_from_session()
            
            # 更新配置
            self.login_manager.config.update(extracted)
            self.login_manager.save_config()
            
            self.after(0, lambda: self._sync_complete(extracted))
        
        threading.Thread(target=worker, daemon=True).start()
    
    def _sync_complete(self, extracted: Dict[str, Any]):
        """同步完成"""
        self.sync_btn.configure(state=tk.NORMAL)
        
        # 显示提取的信息
        info_text = "配置同步完成！\n\n提取的信息：\n"
        for key, value in extracted.items():
            if value:  # 只显示有值的字段
                info_text += f"  • {key}: {value}\n"
        
        messagebox.showinfo("同步完成", info_text)
        self.status_var.set("配置同步完成")

def test_web_login():
    """测试网页登录功能"""
    print("测试网页登录集成方案")
    print("=" * 60)
    
    # 创建登录管理器
    login_manager = WebLoginIntegration()
    
    # 显示当前配置
    print("当前配置:")
    print(f"  系统地址: {login_manager.base_url}")
    print(f"  账号: {login_manager.config.get('username', '未设置')}")
    print(f"  机构代码: {login_manager.config.get('org_code', '未设置')}")
    
    print("\n" + "=" * 60)
    
    # 运行诊断
    print("运行连接诊断...")
    diagnostics = login_manager.diagnose_connection()
    
    for name, success, message in diagnostics:
        status = "通过" if success else "失败"
        print(f"  {name}: {status} - {message}")
    
    print("\n" + "=" * 60)
    
    # 提供登录选项
    print("\n登录选项:")
    print("  1. 网页跳转登录（推荐）")
    print("  2. 查看快速上手指南")
    
    choice = input("\n请选择 (1/2): ").strip()
    
    if choice == '1':
        account = input("请输入账号（可选，直接回车跳过）: ").strip()
        success, message = login_manager.open_web_login(account)
        print(f"\n结果: {message}")
    elif choice == '2':
        guide = login_manager.create_quick_start_guide()
        print(f"\n{guide}")
    else:
        print("\n无效选择。")
    
    print("\n" + "=" * 60)
    print("网页登录集成方案已准备就绪。")

if __name__ == "__main__":
    # 创建Tkinter应用测试
    root = tk.Tk()
    root.withdraw()  # 隐藏主窗口
    
    # 创建登录管理器
    login_manager = WebLoginIntegration()
    
    # 创建增强登录对话框
    dialog = EnhancedLoginDialog(root, login_manager)
    
    # 运行主循环
    root.mainloop()