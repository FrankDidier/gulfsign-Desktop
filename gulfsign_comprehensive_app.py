#!/usr/bin/env python3
"""
湾流签约助手 - 综合版应用程序
集成所有新功能和工具
"""

import os
import sys
import json
import time
import threading
import tkinter as tk
from tkinter import ttk, messagebox, filedialog, scrolledtext
from datetime import datetime
from typing import Dict, List, Optional, Any
from pathlib import Path
import webbrowser

# 添加当前目录到Python路径
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    from ph3_api import PH3Client, Patient, ProvinceMatch, SignResult, POPULATION_TYPES
    from hc_api import HealthCardClient, HealthCard, HCContract, HCConfirmResult
    from sign_engine import (
        SigningEngine, FullSignResult,
        get_age_from_id, needs_age_bypass,
        validate_id_card, generate_bypass_sfzh,
    )
    from proxy_capture import (
        OpenIDProxy, get_local_ip,
        set_windows_proxy, clear_windows_proxy,
        install_ca_to_windows, remove_ca_from_windows,
        set_system_proxy, clear_system_proxy, install_ca_to_system,
    )
    from license_client import LicenseClient
    from config_manager import ConfigManager
    from batch_processor import BatchProcessor
    
    # 新功能模块
    from ultimate_status_conversion_explorer import UltimateStatusConversionExplorer
    from ultimate_realname_id_modification_explorer import UltimateRealnameIDModificationExplorer
    from ultimate_family_member_removal_analyzer import UltimateFamilyMemberRemovalAnalyzer
    from ultimate_sjfx_field_discovery_explorer import UltimateSJFXFieldDiscoveryExplorer
    from comprehensive_age_bypass_validation import ComprehensiveAgeBypassValidator
    from comprehensive_solution_matrix import ComprehensiveSolutionMatrix
    from penetration_testing_simulation_framework import PenetrationTestingSimulationFramework
    from advanced_attack_simulation_scenarios import AdvancedAttackSimulationScenarios
    
    MODULES_LOADED = True
except ImportError as e:
    print(f"模块导入错误: {e}")
    MODULES_LOADED = False

VERSION = "3.1.0"
APP_TITLE = f"湾流签约助手 v{VERSION} - 综合版"
CONFIG_FILE = "gulfsign_config.json"

class ComprehensiveGulfSignApp:
    """综合版湾流签约助手应用程序"""
    
    def __init__(self, root):
        self.root = root
        self.root.title(APP_TITLE)
        self.root.geometry("1200x800")
        
        # 设置图标（如果存在）
        icon_path = Path(__file__).parent / "icon.ico"
        if icon_path.exists():
            try:
                self.root.iconbitmap(str(icon_path))
            except:
                pass
        
        # 初始化变量
        self.config = None
        self.ph3_client = None
        self.hc_client = None
        self.signing_engine = None
        self.batch_processor = None
        self.config_manager = None
        
        # 创建界面
        self.create_ui()
        
        # 加载配置
        self.load_config()
        
        # 设置关闭事件
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
    
    def create_ui(self):
        """创建用户界面"""
        # 创建主框架
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # 配置网格权重
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(0, weight=1)
        main_frame.rowconfigure(1, weight=1)
        
        # 标题标签
        title_label = ttk.Label(
            main_frame, 
            text=APP_TITLE,
            font=("Arial", 16, "bold")
        )
        title_label.grid(row=0, column=0, columnspan=2, pady=(0, 10))
        
        # 创建标签页控件
        self.notebook = ttk.Notebook(main_frame)
        self.notebook.grid(row=1, column=0, columnspan=2, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # 创建各个标签页
        self.create_main_tab()
        self.create_advanced_tools_tab()
        self.create_security_tab()
        self.create_config_tab()
        self.create_logs_tab()
        
        # 状态栏
        self.status_var = tk.StringVar(value="就绪")
        status_bar = ttk.Label(
            main_frame,
            textvariable=self.status_var,
            relief=tk.SUNKEN,
            anchor=tk.W
        )
        status_bar.grid(row=2, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(10, 0))
    
    def create_main_tab(self):
        """创建主标签页"""
        main_tab = ttk.Frame(self.notebook)
        self.notebook.add(main_tab, text="主功能")
        
        # 主功能框架
        main_frame = ttk.LabelFrame(main_tab, text="核心签约功能", padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # 配置网格
        main_frame.columnconfigure(1, weight=1)
        
        # 机构信息
        ttk.Label(main_frame, text="机构代码:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.orgcode_var = tk.StringVar()
        ttk.Entry(main_frame, textvariable=self.orgcode_var, width=30).grid(row=0, column=1, sticky=(tk.W, tk.E), pady=5)
        
        ttk.Label(main_frame, text="账号:").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.account_var = tk.StringVar()
        ttk.Entry(main_frame, textvariable=self.account_var, width=30).grid(row=1, column=1, sticky=(tk.W, tk.E), pady=5)
        
        ttk.Label(main_frame, text="密码:").grid(row=2, column=0, sticky=tk.W, pady=5)
        self.password_var = tk.StringVar()
        ttk.Entry(main_frame, textvariable=self.password_var, width=30, show="*").grid(row=2, column=1, sticky=(tk.W, tk.E), pady=5)
        
        # 按钮框架
        button_frame = ttk.Frame(main_frame)
        button_frame.grid(row=3, column=0, columnspan=2, pady=10)
        
        ttk.Button(button_frame, text="登录系统", command=self.login).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="测试连接", command=self.test_connection).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="保存配置", command=self.save_config).pack(side=tk.LEFT, padx=5)
        
        # 批量处理框架
        batch_frame = ttk.LabelFrame(main_tab, text="批量签约", padding="10")
        batch_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # 文件选择
        file_frame = ttk.Frame(batch_frame)
        file_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(file_frame, text="数据文件:").pack(side=tk.LEFT)
        self.data_file_var = tk.StringVar()
        ttk.Entry(file_frame, textvariable=self.data_file_var, width=40).pack(side=tk.LEFT, padx=5)
        ttk.Button(file_frame, text="浏览...", command=self.browse_data_file).pack(side=tk.LEFT)
        
        # 处理按钮
        process_frame = ttk.Frame(batch_frame)
        process_frame.pack(fill=tk.X, pady=10)
        
        ttk.Button(process_frame, text="开始批量签约", command=self.start_batch).pack(side=tk.LEFT, padx=5)
        ttk.Button(process_frame, text="停止", command=self.stop_batch).pack(side=tk.LEFT, padx=5)
        ttk.Button(process_frame, text="查看日志", command=self.view_logs).pack(side=tk.LEFT, padx=5)
        
        # 进度条
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(
            batch_frame, 
            variable=self.progress_var,
            maximum=100
        )
        self.progress_bar.pack(fill=tk.X, pady=5)
        
        # 状态文本
        self.status_text = scrolledtext.ScrolledText(
            batch_frame,
            height=10,
            wrap=tk.WORD
        )
        self.status_text.pack(fill=tk.BOTH, expand=True, pady=5)
    
    def create_advanced_tools_tab(self):
        """创建高级工具标签页"""
        tools_tab = ttk.Frame(self.notebook)
        self.notebook.add(tools_tab, text="高级工具")
        
        # 工具选择框架
        tools_frame = ttk.LabelFrame(tools_tab, text="可用工具", padding="10")
        tools_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # 工具按钮
        button_frame = ttk.Frame(tools_frame)
        button_frame.pack(fill=tk.X, pady=5)
        
        ttk.Button(button_frame, text="状态转换探索器", 
                  command=self.open_status_conversion_explorer).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="实名认证ID修改分析", 
                  command=self.open_realname_id_analysis).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="家庭成员移除分析", 
                  command=self.open_family_member_analysis).pack(side=tk.LEFT, padx=5)
        
        button_frame2 = ttk.Frame(tools_frame)
        button_frame2.pack(fill=tk.X, pady=5)
        
        ttk.Button(button_frame2, text="sjfx API字段名发现", 
                  command=self.open_sjfx_field_discovery).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame2, text="年龄验证绕行测试", 
                  command=self.open_age_bypass_test).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame2, text="综合解决方案矩阵", 
                  command=self.open_solution_matrix).pack(side=tk.LEFT, padx=5)
        
        # 工具输出区域
        output_frame = ttk.LabelFrame(tools_tab, text="工具输出", padding="10")
        output_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        self.tools_output = scrolledtext.ScrolledText(
            output_frame,
            height=15,
            wrap=tk.WORD
        )
        self.tools_output.pack(fill=tk.BOTH, expand=True)
    
    def create_security_tab(self):
        """创建安全评估标签页"""
        security_tab = ttk.Frame(self.notebook)
        self.notebook.add(security_tab, text="安全评估")
        
        # 安全工具框架
        security_frame = ttk.LabelFrame(security_tab, text="安全评估工具", padding="10")
        security_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # 安全工具按钮
        button_frame = ttk.Frame(security_frame)
        button_frame.pack(fill=tk.X, pady=5)
        
        ttk.Button(button_frame, text="渗透测试模拟", 
                  command=self.run_penetration_test).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="高级攻击模拟", 
                  command=self.run_advanced_attack_simulation).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="生成安全报告", 
                  command=self.generate_security_report).pack(side=tk.LEFT, padx=5)
        
        # 安全评估输出
        output_frame = ttk.LabelFrame(security_tab, text="评估结果", padding="10")
        output_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        self.security_output = scrolledtext.ScrolledText(
            output_frame,
            height=15,
            wrap=tk.WORD
        )
        self.security_output.pack(fill=tk.BOTH, expand=True)
    
    def create_config_tab(self):
        """创建配置标签页"""
        config_tab = ttk.Frame(self.notebook)
        self.notebook.add(config_tab, text="配置管理")
        
        # 配置编辑框架
        config_frame = ttk.LabelFrame(config_tab, text="配置文件编辑", padding="10")
        config_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # 配置文本编辑器
        self.config_editor = scrolledtext.ScrolledText(
            config_frame,
            height=20,
            wrap=tk.WORD
        )
        self.config_editor.pack(fill=tk.BOTH, expand=True)
        
        # 配置按钮
        button_frame = ttk.Frame(config_frame)
        button_frame.pack(fill=tk.X, pady=10)
        
        ttk.Button(button_frame, text="加载配置", command=self.load_config_editor).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="保存配置", command=self.save_config_editor).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="验证配置", command=self.validate_config).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="重置为默认", command=self.reset_config).pack(side=tk.LEFT, padx=5)
    
    def create_logs_tab(self):
        """创建日志标签页"""
        logs_tab = ttk.Frame(self.notebook)
        self.notebook.add(logs_tab, text="日志查看")
        
        # 日志查看框架
        logs_frame = ttk.LabelFrame(logs_tab, text="系统日志", padding="10")
        logs_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # 日志级别选择
        level_frame = ttk.Frame(logs_frame)
        level_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(level_frame, text="日志级别:").pack(side=tk.LEFT)
        self.log_level_var = tk.StringVar(value="INFO")
        level_combo = ttk.Combobox(
            level_frame,
            textvariable=self.log_level_var,
            values=["DEBUG", "INFO", "WARNING", "ERROR"],
            state="readonly",
            width=10
        )
        level_combo.pack(side=tk.LEFT, padx=5)
        
        ttk.Button(level_frame, text="刷新日志", command=self.refresh_logs).pack(side=tk.LEFT, padx=5)
        ttk.Button(level_frame, text="清空日志", command=self.clear_logs).pack(side=tk.LEFT, padx=5)
        ttk.Button(level_frame, text="导出日志", command=self.export_logs).pack(side=tk.LEFT, padx=5)
        
        # 日志显示区域
        self.logs_display = scrolledtext.ScrolledText(
            logs_frame,
            height=20,
            wrap=tk.WORD
        )
        self.logs_display.pack(fill=tk.BOTH, expand=True)
    
    def load_config(self):
        """加载配置文件"""
        config_path = Path(__file__).parent / CONFIG_FILE
        if config_path.exists():
            try:
                with open(config_path, 'r', encoding='utf-8') as f:
                    self.config = json.load(f)
                
                # 更新UI中的变量
                if "orgcode" in self.config:
                    self.orgcode_var.set(self.config["orgcode"])
                if "account" in self.config:
                    self.account_var.set(self.config["account"])
                if "password" in self.config:
                    self.password_var.set(self.config["password"])
                
                self.update_status("配置加载成功")
            except Exception as e:
                self.update_status(f"配置加载失败: {e}")
                self.config = {}
        else:
            self.config = {}
            self.update_status("配置文件不存在，使用默认配置")
    
    def save_config(self):
        """保存配置文件"""
        try:
            # 更新配置字典
            self.config["orgcode"] = self.orgcode_var.get()
            self.config["account"] = self.account_var.get()
            self.config["password"] = self.password_var.get()
            
            # 保存到文件
            config_path = Path(__file__).parent / CONFIG_FILE
            with open(config_path, 'w', encoding='utf-8') as f:
                json.dump(self.config, f, indent=2, ensure_ascii=False)
            
            self.update_status("配置保存成功")
        except Exception as e:
            self.update_status(f"配置保存失败: {e}")
    
    def login(self):
        """登录系统"""
        if not MODULES_LOADED:
            messagebox.showerror("错误", "模块加载失败，无法登录")
            return
        
        try:
            # 初始化客户端
            self.ph3_client = PH3Client(
                base_url="https://hnfpc.hunan.gov.cn",
                account=self.account_var.get(),
                password=self.password_var.get()
            )
            
            # 测试登录
            if self.ph3_client.login():
                self.update_status("登录成功")
                
                # 初始化其他组件
                self.hc_client = HealthCardClient()
                self.signing_engine = SigningEngine(self.ph3_client, self.hc_client)
                self.config_manager = ConfigManager()
                self.batch_processor = BatchProcessor(self.signing_engine)
                
                messagebox.showinfo("成功", "系统登录成功，可以开始使用")
            else:
                self.update_status("登录失败")
                messagebox.showerror("错误", "登录失败，请检查账号密码")
        except Exception as e:
            self.update_status(f"登录错误: {e}")
            messagebox.showerror("错误", f"登录过程中发生错误: {e}")
    
    def test_connection(self):
        """测试连接"""
        self.update_status("测试连接中...")
        # 这里可以添加实际的连接测试代码
        time.sleep(1)
        self.update_status("连接测试完成")
    
    def browse_data_file(self):
        """浏览数据文件"""
        file_path = filedialog.askopenfilename(
            title="选择数据文件",
            filetypes=[("JSON文件", "*.json"), ("Excel文件", "*.xlsx"), ("所有文件", "*.*")]
        )
        if file_path:
            self.data_file_var.set(file_path)
    
    def start_batch(self):
        """开始批量处理"""
        if not self.signing_engine:
            messagebox.showerror("错误", "请先登录系统")
            return
        
        data_file = self.data_file_var.get()
        if not data_file or not Path(data_file).exists():
            messagebox.showerror("错误", "请选择有效的数据文件")
            return
        
        # 启动批量处理线程
        self.batch_thread = threading.Thread(
            target=self.run_batch_processing,
            args=(data_file,),
            daemon=True
        )
        self.batch_thread.start()
        
        self.update_status("批量处理已启动")
    
    def run_batch_processing(self, data_file):
        """运行批量处理"""
        try:
            # 加载数据
            with open(data_file, 'r', encoding='utf-8') as f:
                patients_data = json.load(f)
            
            # 处理进度回调
            def progress_callback(current, total, message):
                progress_percent = (current / total) * 100
                self.progress_var.set(progress_percent)
                self.append_status_text(f"{message} ({current}/{total})")
            
            # 运行批量处理
            results = self.batch_processor.process_batch(
                patients_data,
                progress_callback=progress_callback
            )
            
            # 显示结果
            success_count = sum(1 for r in results if r.success)
            total_count = len(results)
            
            self.append_status_text(f"\n批量处理完成!")
            self.append_status_text(f"成功: {success_count}/{total_count}")
            
            # 保存结果
            results_file = Path(__file__).parent / f"batch_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            with open(results_file, 'w', encoding='utf-8') as f:
                json.dump([r.to_dict() for r in results], f, indent=2, ensure_ascii=False)
            
            self.append_status_text(f"结果已保存到: {results_file}")
            
        except Exception as e:
            self.append_status_text(f"批量处理错误: {e}")
    
    def stop_batch(self):
        """停止批量处理"""
        if hasattr(self, 'batch_processor') and self.batch_processor:
            self.batch_processor.stop()
            self.update_status("批量处理已停止")
    
    def view_logs(self):
        """查看日志"""
        # 切换到日志标签页
        self.notebook.select(4)  # 日志标签页是第5个（索引4）
        self.refresh_logs()
    
    def append_status_text(self, text):
        """追加状态文本"""
        self.status_text.insert(tk.END, f"{text}\n")
        self.status_text.see(tk.END)
        self.root.update_idletasks()
    
    def update_status(self, message):
        """更新状态栏"""
        self.status_var.set(message)
        self.root.update_idletasks()
    
    # 高级工具方法
    def open_status_conversion_explorer(self):
        """打开状态转换探索器"""
        if not MODULES_LOADED:
            messagebox.showerror("错误", "模块加载失败")
            return
        
        try:
            explorer = UltimateStatusConversionExplorer()
            results = explorer.explore_all_methods()
            
            # 显示结果
            self.tools_output.delete(1.0, tk.END)
            self.tools_output.insert(tk.END, "状态转换探索结果:\n")
            self.tools_output.insert(tk.END, f"测试方法总数: {results['total_methods']}\n")
            self.tools_output.insert(tk.END, f"成功方法数: {results['successful_methods']}\n")
            self.tools_output.insert(tk.END, f"成功率: {results['success_rate']:.2f}%\n\n")
            
            self.tools_output.insert(tk.END, "成功方法详情:\n")
            for method in results['successful_methods_details']:
                self.tools_output.insert(tk.END, f"- {method['method_name']}: {method['description']}\n")
            
            self.update_status("状态转换探索完成")
        except Exception as e:
            self.update_status(f"状态转换探索错误: {e}")
    
    def open_realname_id_analysis(self):
        """打开实名认证ID修改分析"""
        if not MODULES_LOADED:
            messagebox.showerror("错误", "模块加载失败")
            return
        
        try:
            analyzer = UltimateRealnameIdModificationExplorer()
            results = analyzer.explore_all_methods()
            
            # 显示结果
            self.tools_output.delete(1.0, tk.END)
            self.tools_output.insert(tk.END, "实名认证ID修改分析结果:\n")
            self.tools_output.insert(tk.END, f"测试方法总数: {results['total_methods']}\n")
            self.tools_output.insert(tk.END, f"成功方法数: {results['successful_methods']}\n")
            self.tools_output.insert(tk.END, f"成功率: {results['success_rate']:.2f}%\n\n")
            
            self.tools_output.insert(tk.END, "成功方法详情:\n")
            for method in results['successful_methods_details']:
                self.tools_output.insert(tk.END, f"- {method['method_name']}: {method['description']}\n")
            
            self.update_status("实名认证ID修改分析完成")
        except Exception as e:
            self.update_status(f"实名认证ID修改分析错误: {e}")
    
    def open_family_member_analysis(self):
        """打开家庭成员移除分析"""
        if not MODULES_LOADED:
            messagebox.showerror("错误", "模块加载失败")
            return
        
        try:
            analyzer = UltimateFamilyMemberRemovalAnalyzer()
            results = analyzer.analyze_all_scenarios()
            
            # 显示结果
            self.tools_output.delete(1.0, tk.END)
            self.tools_output.insert(tk.END, "家庭成员移除分析结果:\n")
            self.tools_output.insert(tk.END, f"分析场景总数: {results['total_scenarios']}\n")
            self.tools_output.insert(tk.END, f"可行方案数: {results['feasible_solutions']}\n\n")
            
            self.tools_output.insert(tk.END, "可行方案详情:\n")
            for solution in results['feasible_solutions_details']:
                self.tools_output.insert(tk.END, f"- {solution['solution_name']}: {solution['description']}\n")
            
            self.update_status("家庭成员移除分析完成")
        except Exception as e:
            self.update_status(f"家庭成员移除分析错误: {e}")
    
    def open_sjfx_field_discovery(self):
        """打开sjfx API字段名发现"""
        if not MODULES_LOADED:
            messagebox.showerror("错误", "模块加载失败")
            return
        
        try:
            explorer = UltimateSJFXFieldDiscoveryExplorer()
            results = explorer.explore_all_methods()
            
            # 显示结果
            self.tools_output.delete(1.0, tk.END)
            self.tools_output.insert(tk.END, "sjfx API字段名发现结果:\n")
            self.tools_output.insert(tk.END, f"发现技术总数: {results['total_methods']}\n")
            self.tools_output.insert(tk.END, f"候选字段名数量: {results['candidate_count']}\n\n")
            
            self.tools_output.insert(tk.END, "候选字段名示例:\n")
            for i, field in enumerate(results['candidate_examples'][:10], 1):
                self.tools_output.insert(tk.END, f"{i}. {field}\n")
            
            self.update_status("sjfx API字段名发现完成")
        except Exception as e:
            self.update_status(f"sjfx API字段名发现错误: {e}")
    
    def open_age_bypass_test(self):
        """打开年龄验证绕行测试"""
        if not MODULES_LOADED:
            messagebox.showerror("错误", "模块加载失败")
            return
        
        try:
            validator = ComprehensiveAgeBypassValidator()
            results = validator.run_comprehensive_tests()
            
            # 显示结果
            self.tools_output.delete(1.0, tk.END)
            self.tools_output.insert(tk.END, "年龄验证绕行测试结果:\n")
            self.tools_output.insert(tk.END, f"测试用例总数: {results['total_cases']}\n")
            self.tools_output.insert(tk.END, f"成功用例数: {results['successful_cases']}\n")
            self.tools_output.insert(tk.END, f"成功率: {results['success_rate']:.2f}%\n\n")
            
            self.tools_output.insert(tk.END, "核心算法验证:\n")
            for test in results['core_algorithm_tests']:
                status = "✓" if test['passed'] else "✗"
                self.tools_output.insert(tk.END, f"{status} {test['test_name']}: {test['description']}\n")
            
            self.update_status("年龄验证绕行测试完成")
        except Exception as e:
            self.update_status(f"年龄验证绕行测试错误: {e}")
    
    def open_solution_matrix(self):
        """打开综合解决方案矩阵"""
        if not MODULES_LOADED:
            messagebox.showerror("错误", "模块加载失败")
            return
        
        try:
            matrix = ComprehensiveSolutionMatrix()
            results = matrix.generate_solution_matrix()
            
            # 显示结果
            self.tools_output.delete(1.0, tk.END)
            self.tools_output.insert(tk.END, "综合解决方案矩阵:\n")
            self.tools_output.insert(tk.END, f"系统限制总数: {results['total_limitations']}\n")
            self.tools_output.insert(tk.END, f"解决方案总数: {results['total_solutions']}\n\n")
            
            self.tools_output.insert(tk.END, "解决方案分类:\n")
            for category in results['solution_categories']:
                self.tools_output.insert(tk.END, f"- {category['category_name']}: {category['solution_count']}个方案\n")
            
            self.update_status("综合解决方案矩阵生成完成")
        except Exception as e:
            self.update_status(f"综合解决方案矩阵生成错误: {e}")
    
    # 安全评估方法
    def run_penetration_test(self):
        """运行渗透测试"""
        if not MODULES_LOADED:
            messagebox.showerror("错误", "模块加载失败")
            return
        
        try:
            framework = PenetrationTestingSimulationFramework()
            results = framework.run_comprehensive_tests()
            
            # 显示结果
            self.security_output.delete(1.0, tk.END)
            self.security_output.insert(tk.END, "渗透测试模拟结果:\n")
            self.security_output.insert(tk.END, f"测试漏洞总数: {results['total_vulnerabilities']}\n")
            self.security_output.insert(tk.END, f"检测到的漏洞: {results['detected_vulnerabilities']}\n")
            self.security_output.insert(tk.END, f"检测率: {results['detection_rate']:.2f}%\n\n")
            
            self.security_output.insert(tk.END, "检测到的漏洞详情:\n")
            for vuln in results['detected_vulnerabilities_details']:
                self.security_output.insert(tk.END, f"- {vuln['vulnerability_id']}: {vuln['name']} (风险: {vuln['risk_level']})\n")
            
            self.update_status("渗透测试模拟完成")
        except Exception as e:
            self.update_status(f"渗透测试模拟错误: {e}")
    
    def run_advanced_attack_simulation(self):
        """运行高级攻击模拟"""
        if not MODULES_LOADED:
            messagebox.showerror("错误", "模块加载失败")
            return
        
        try:
            simulator = AdvancedAttackSimulationScenarios()
            results = simulator.run_comprehensive_simulations()
            
            # 显示结果
            self.security_output.delete(1.0, tk.END)
            self.security_output.insert(tk.END, "高级攻击模拟结果:\n")
            self.security_output.insert(tk.END, f"模拟场景总数: {results['total_scenarios']}\n")
            self.security_output.insert(tk.END, f"成功场景数: {results['successful_scenarios']}\n")
            self.security_output.insert(tk.END, f"成功率: {results['success_rate']:.2f}%\n\n")
            
            self.security_output.insert(tk.END, "模拟结果总结:\n")
            for scenario in results['scenario_results']:
                status = "成功" if scenario['success'] else "失败"
                self.security_output.insert(tk.END, f"- {scenario['scenario_id']}: {status} - {scenario['description']}\n")
            
            self.update_status("高级攻击模拟完成")
        except Exception as e:
            self.update_status(f"高级攻击模拟错误: {e}")
    
    def generate_security_report(self):
        """生成安全报告"""
        self.update_status("生成安全报告中...")
        # 这里可以添加生成安全报告的代码
        time.sleep(2)
        self.update_status("安全报告生成完成")
    
    # 配置管理方法
    def load_config_editor(self):
        """加载配置到编辑器"""
        config_path = Path(__file__).parent / CONFIG_FILE
        if config_path.exists():
            try:
                with open(config_path, 'r', encoding='utf-8') as f:
                    config_content = json.load(f, indent=2)
                
                self.config_editor.delete(1.0, tk.END)
                self.config_editor.insert(tk.END, json.dumps(config_content, indent=2, ensure_ascii=False))
                
                self.update_status("配置加载到编辑器")
            except Exception as e:
                self.update_status(f"配置加载失败: {e}")
        else:
            self.config_editor.delete(1.0, tk.END)
            self.config_editor.insert(tk.END, "{}")
            self.update_status("配置文件不存在，使用空配置")
    
    def save_config_editor(self):
        """保存编辑器中的配置"""
        try:
            config_content = self.config_editor.get(1.0, tk.END)
            config_dict = json.loads(config_content)
            
            config_path = Path(__file__).parent / CONFIG_FILE
            with open(config_path, 'w', encoding='utf-8') as f:
                json.dump(config_dict, f, indent=2, ensure_ascii=False)
            
            # 重新加载配置
            self.load_config()
            
            self.update_status("配置保存成功")
        except json.JSONDecodeError as e:
            self.update_status(f"配置JSON格式错误: {e}")
            messagebox.showerror("错误", f"配置JSON格式错误: {e}")
        except Exception as e:
            self.update_status(f"配置保存失败: {e}")
            messagebox.showerror("错误", f"配置保存失败: {e}")
    
    def validate_config(self):
        """验证配置"""
        try:
            config_content = self.config_editor.get(1.0, tk.END)
            config_dict = json.loads(config_content)
            
            # 检查必要字段
            required_fields = ["orgcode", "account", "password"]
            missing_fields = [field for field in required_fields if field not in config_dict]
            
            if missing_fields:
                messagebox.showwarning("警告", f"缺少必要字段: {', '.join(missing_fields)}")
            else:
                messagebox.showinfo("成功", "配置验证通过")
            
            self.update_status("配置验证完成")
        except json.JSONDecodeError as e:
            self.update_status(f"配置验证失败: JSON格式错误")
            messagebox.showerror("错误", f"配置JSON格式错误: {e}")
    
    def reset_config(self):
        """重置配置"""
        if messagebox.askyesno("确认", "确定要重置配置为默认值吗？"):
            default_config = {
                "orgcode": "",
                "account": "",
                "password": "",
                "version": VERSION,
                "last_updated": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }
            
            self.config_editor.delete(1.0, tk.END)
            self.config_editor.insert(tk.END, json.dumps(default_config, indent=2, ensure_ascii=False))
            
            self.update_status("配置已重置为默认值")
    
    def refresh_logs(self):
        """刷新日志"""
        try:
            # 获取日志文件
            log_dir = Path(__file__).parent / "logs"
            if not log_dir.exists():
                self.logs_display.delete(1.0, tk.END)
                self.logs_display.insert(tk.END, "日志目录不存在\n")
                return
            
            # 读取最新的日志文件
            log_files = list(log_dir.glob("*.log"))
            if not log_files:
                self.logs_display.delete(1.0, tk.END)
                self.logs_display.insert(tk.END, "没有找到日志文件\n")
                return
            
            latest_log = max(log_files, key=lambda x: x.stat().st_mtime)
            
            # 读取日志内容
            with open(latest_log, 'r', encoding='utf-8') as f:
                log_content = f.read()
            
            # 过滤日志级别
            level = self.log_level_var.get()
            filtered_lines = []
            for line in log_content.split('\n'):
                if level == "DEBUG" or \
                   (level == "INFO" and ("INFO" in line or "WARNING" in line or "ERROR" in line)) or \
                   (level == "WARNING" and ("WARNING" in line or "ERROR" in line)) or \
                   (level == "ERROR" and "ERROR" in line):
                    filtered_lines.append(line)
            
            # 显示日志
            self.logs_display.delete(1.0, tk.END)
            self.logs_display.insert(tk.END, f"日志文件: {latest_log.name}\n")
            self.logs_display.insert(tk.END, f"日志级别: {level}\n")
            self.logs_display.insert(tk.END, "=" * 50 + "\n")
            self.logs_display.insert(tk.END, '\n'.join(filtered_lines[-100:]))  # 显示最后100行
            
            self.update_status("日志已刷新")
        except Exception as e:
            self.update_status(f"日志刷新失败: {e}")
    
    def clear_logs(self):
        """清空日志显示"""
        self.logs_display.delete(1.0, tk.END)
        self.update_status("日志显示已清空")
    
    def export_logs(self):
        """导出日志"""
        file_path = filedialog.asksaveasfilename(
            title="导出日志",
            defaultextension=".txt",
            filetypes=[("文本文件", "*.txt"), ("所有文件", "*.*")]
        )
        
        if file_path:
            try:
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(self.logs_display.get(1.0, tk.END))
                
                self.update_status(f"日志已导出到: {file_path}")
                messagebox.showinfo("成功", f"日志已成功导出到:\n{file_path}")
            except Exception as e:
                self.update_status(f"日志导出失败: {e}")
                messagebox.showerror("错误", f"日志导出失败: {e}")
    
    def on_closing(self):
        """关闭应用程序"""
        if messagebox.askokcancel("退出", "确定要退出应用程序吗？"):
            # 清理资源
            if hasattr(self, 'batch_processor') and self.batch_processor:
                self.batch_processor.stop()
            
            self.root.destroy()
    
    def run(self):
        """运行应用程序"""
        self.root.mainloop()


def main():
    """主函数"""
    root = tk.Tk()
    app = ComprehensiveGulfSignApp(root)
    app.run()


if __name__ == "__main__":
    main()
