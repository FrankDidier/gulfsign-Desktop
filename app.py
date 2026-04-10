# -*- coding: utf-8 -*-
"""
湾流签约助手 — 桌面版
公卫3.0 批量签约 + 健康卡自动确认
"""
import os
import sys
import json
import time
import threading
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from datetime import datetime
from typing import List, Optional

if getattr(sys, "frozen", False):
    _bundle_dir = getattr(sys, "_MEIPASS", os.path.dirname(sys.executable))
    if _bundle_dir not in sys.path:
        sys.path.insert(0, _bundle_dir)

from ph3_api import PH3Client, Patient, SignResult, POPULATION_TYPES
from hc_api import HealthCardClient, HealthCard, HCContract, HCConfirmResult
from proxy_capture import (
    OpenIDProxy, get_local_ip,
    set_windows_proxy, clear_windows_proxy,
    install_ca_to_windows, remove_ca_from_windows,
    set_system_proxy, clear_system_proxy, install_ca_to_system,
)

VERSION = "2.1.0"
APP_TITLE = "湾流签约助手 v%s" % VERSION
CONFIG_FILE = "gulfsign_config.json"


def _config_path() -> str:
    if getattr(sys, "frozen", False):
        base = os.path.dirname(sys.executable)
    else:
        base = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(base, CONFIG_FILE)


def load_config() -> dict:
    try:
        with open(_config_path(), "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def save_config(cfg: dict):
    try:
        with open(_config_path(), "w", encoding="utf-8") as f:
            json.dump(cfg, f, ensure_ascii=False, indent=2)
    except Exception:
        pass


class GulfSignApp(tk.Tk):

    def __init__(self):
        super().__init__()

        self.title(APP_TITLE)
        self.geometry("980x800")
        self.minsize(860, 700)

        self.client = PH3Client()
        self.hc_client = HealthCardClient()
        self.patients: List[Patient] = []
        self.selected_ids: set = set()

        self._signing = False
        self._paused = False
        self._stop_event = threading.Event()
        self._sign_success = 0
        self._sign_fail = 0
        self._sign_total = 0
        self._sign_start_time = 0.0

        self._hc_confirming = False
        self._hc_stop = threading.Event()
        self._hc_cards: List[HealthCard] = []
        self._hc_selected: set = set()

        self._proxy: Optional[OpenIDProxy] = None
        self._proxy_running = False

        self._cap_proxy: Optional[OpenIDProxy] = None
        self._cap_running = False
        self._cap_request_count = 0

        self._cfg = load_config()

        self._build_ui()
        self._restore_config()

        self.protocol("WM_DELETE_WINDOW", self._on_close)

    # ================================================================
    # UI
    # ================================================================

    def _build_ui(self):
        style = ttk.Style(self)
        available = style.theme_names()
        if sys.platform == "darwin":
            preferred = ("clam", "alt", "default")
        else:
            preferred = ("vista", "winnative", "clam", "aqua")
        for theme in preferred:
            if theme in available:
                style.theme_use(theme)
                break

        style.configure("Success.TLabel", foreground="#16a34a")
        style.configure("Error.TLabel", foreground="#dc2626")
        style.configure("Info.TLabel", foreground="#2563eb")
        style.configure("Header.TLabel", font=("", 11, "bold"))

        main = ttk.Frame(self, padding=8)
        main.pack(fill=tk.BOTH, expand=True)

        self.notebook = ttk.Notebook(main)
        self.notebook.pack(fill=tk.BOTH, expand=True)

        tab1 = ttk.Frame(self.notebook, padding=4)
        tab2 = ttk.Frame(self.notebook, padding=4)
        tab3 = ttk.Frame(self.notebook, padding=4)
        tab4 = ttk.Frame(self.notebook, padding=4)

        self.notebook.add(tab1, text=" 3.0系统签约 ")
        self.notebook.add(tab2, text=" 健康卡确认 ")
        self.notebook.add(tab3, text=" 获取OpenID ")
        self.notebook.add(tab4, text=" 流量抓包 ")

        self._build_ph3_tab(tab1)
        self._build_hc_tab(tab2)
        self._build_openid_tab(tab3)
        self._build_capture_tab(tab4)

    # ================================================================
    # Tab 1: 3.0系统签约
    # ================================================================

    def _build_ph3_tab(self, parent):
        self._build_login_section(parent)
        self._build_query_section(parent)
        self._build_table_section(parent)
        self._build_signing_section(parent)
        self._build_log_section(parent)

    def _build_login_section(self, parent):
        frame = ttk.LabelFrame(parent, text=" 系统登录 ", padding=6)
        frame.pack(fill=tk.X, pady=(0, 4))

        r0 = ttk.Frame(frame)
        r0.pack(fill=tk.X)
        ttk.Label(r0, text="系统地址:").pack(side=tk.LEFT)
        self.var_url = tk.StringVar(value="https://ggws.hnhfpc.gov.cn")
        ttk.Entry(r0, textvariable=self.var_url, width=48).pack(
            side=tk.LEFT, padx=(4, 16)
        )

        ttk.Label(r0, text="账号:").pack(side=tk.LEFT)
        self.var_account = tk.StringVar()
        ttk.Entry(r0, textvariable=self.var_account, width=24).pack(
            side=tk.LEFT, padx=(4, 16)
        )

        ttk.Label(r0, text="密码:").pack(side=tk.LEFT)
        self.var_password = tk.StringVar()
        ttk.Entry(r0, textvariable=self.var_password, width=16, show="*").pack(
            side=tk.LEFT, padx=(4, 16)
        )

        self.btn_login = ttk.Button(r0, text="登 录", command=self._on_login)
        self.btn_login.pack(side=tk.LEFT, padx=(8, 0))

        r1 = ttk.Frame(frame)
        r1.pack(fill=tk.X, pady=(4, 0))
        self.var_login_status = tk.StringVar(value="未登录")
        self.lbl_login_status = ttk.Label(
            r1, textvariable=self.var_login_status, style="Info.TLabel"
        )
        self.lbl_login_status.pack(side=tk.LEFT)

    def _build_query_section(self, parent):
        frame = ttk.LabelFrame(parent, text=" 查询条件 ", padding=6)
        frame.pack(fill=tk.X, pady=(0, 4))

        r0 = ttk.Frame(frame)
        r0.pack(fill=tk.X)

        ttk.Label(r0, text="签约状态:").pack(side=tk.LEFT)
        self.var_status = tk.StringVar(value="未签约")
        ttk.Combobox(
            r0, textvariable=self.var_status, width=12, state="readonly",
            values=["未签约", "已签约", "医生申请", "居民申请", "拒绝签约", "全部"],
        ).pack(side=tk.LEFT, padx=(4, 16))

        ttk.Label(r0, text="机构代码:").pack(side=tk.LEFT)
        self.var_org = tk.StringVar()
        ttk.Entry(r0, textvariable=self.var_org, width=20).pack(
            side=tk.LEFT, padx=(4, 16)
        )

        self.btn_query = ttk.Button(r0, text="查询(首页)", command=self._on_query)
        self.btn_query.pack(side=tk.LEFT, padx=(8, 4))

        self.btn_query_all = ttk.Button(
            r0, text="查询全部", command=self._on_query_all
        )
        self.btn_query_all.pack(side=tk.LEFT, padx=(0, 16))

        self.var_query_info = tk.StringVar(value="")
        ttk.Label(r0, textvariable=self.var_query_info, style="Info.TLabel").pack(
            side=tk.LEFT
        )

        r1 = ttk.Frame(frame)
        r1.pack(fill=tk.X, pady=(4, 0))

        ttk.Label(r1, text="协议结束日期:").pack(side=tk.LEFT)
        self.var_expire_start = tk.StringVar()
        ttk.Entry(r1, textvariable=self.var_expire_start, width=10).pack(
            side=tk.LEFT, padx=(4, 0)
        )
        ttk.Label(r1, text="~").pack(side=tk.LEFT)
        self.var_expire_end = tk.StringVar()
        ttk.Entry(r1, textvariable=self.var_expire_end, width=10).pack(
            side=tk.LEFT, padx=(0, 8)
        )
        ttk.Label(r1, text="(如20250101~20261231)").pack(side=tk.LEFT)
        ttk.Label(r1, text="  姓名:").pack(side=tk.LEFT)
        self.var_name_filter = tk.StringVar()
        ttk.Entry(r1, textvariable=self.var_name_filter, width=10).pack(
            side=tk.LEFT, padx=(4, 8)
        )
        ttk.Label(r1, text="身份证:").pack(side=tk.LEFT)
        self.var_idcard_filter = tk.StringVar()
        ttk.Entry(r1, textvariable=self.var_idcard_filter, width=18).pack(
            side=tk.LEFT, padx=(4, 0)
        )

    def _build_table_section(self, parent):
        frame = ttk.LabelFrame(parent, text=" 居民列表 ", padding=4)
        frame.pack(fill=tk.BOTH, expand=True, pady=(0, 4))

        toolbar = ttk.Frame(frame)
        toolbar.pack(fill=tk.X, pady=(0, 4))

        self.var_check_all = tk.BooleanVar(value=False)
        ttk.Checkbutton(
            toolbar, text="全选", variable=self.var_check_all,
            command=self._on_toggle_all,
        ).pack(side=tk.LEFT)

        self.var_select_info = tk.StringVar(value="已选: 0")
        ttk.Label(toolbar, textvariable=self.var_select_info).pack(
            side=tk.LEFT, padx=(16, 0)
        )

        ttk.Button(
            toolbar, text="导出列表", command=self._on_export,
        ).pack(side=tk.RIGHT)

        cols = (
            "seq", "name", "id_card", "status", "team",
            "doctor", "sign_date", "expire_date", "pid",
        )
        col_names = {
            "seq": "#", "name": "姓名", "id_card": "身份证号",
            "status": "签约状态", "team": "签约团队",
            "doctor": "签约医生", "sign_date": "签约日期",
            "expire_date": "协议到期", "pid": "PERSONID",
        }
        col_widths = {
            "seq": 40, "name": 80, "id_card": 155, "status": 75,
            "team": 170, "doctor": 80, "sign_date": 85,
            "expire_date": 85, "pid": 100,
        }
        col_anchors = {
            "seq": "center", "name": "center", "status": "center",
            "doctor": "center", "sign_date": "center",
            "expire_date": "center",
        }

        tree_frame = ttk.Frame(frame)
        tree_frame.pack(fill=tk.BOTH, expand=True)

        self.tree = ttk.Treeview(
            tree_frame, columns=cols, show="headings", selectmode="extended",
        )
        for c in cols:
            self.tree.heading(c, text=col_names[c])
            anchor = col_anchors.get(c, "w")
            self.tree.column(
                c, width=col_widths.get(c, 80), minwidth=40, anchor=anchor,
            )

        vsb = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL, command=self.tree.yview)
        hsb = ttk.Scrollbar(tree_frame, orient=tk.HORIZONTAL, command=self.tree.xview)
        self.tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)

        self.tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")
        tree_frame.grid_rowconfigure(0, weight=1)
        tree_frame.grid_columnconfigure(0, weight=1)

        self.tree.bind("<Button-1>", self._on_tree_click)

        self.tree.tag_configure("selected", background="#dbeafe")
        self.tree.tag_configure("signed_ok", background="#dcfce7")
        self.tree.tag_configure("signed_fail", background="#fee2e2")

    def _build_signing_section(self, parent):
        frame = ttk.LabelFrame(parent, text=" 批量签约 ", padding=6)
        frame.pack(fill=tk.X, pady=(0, 4))

        r0 = ttk.Frame(frame)
        r0.pack(fill=tk.X)

        self.btn_start = ttk.Button(
            r0, text="▶ 开始签约", command=self._on_start_signing,
        )
        self.btn_start.pack(side=tk.LEFT, padx=(0, 4))

        self.btn_pause = ttk.Button(
            r0, text="⏸ 暂停", command=self._on_pause, state=tk.DISABLED,
        )
        self.btn_pause.pack(side=tk.LEFT, padx=(0, 4))

        self.btn_stop = ttk.Button(
            r0, text="⏹ 停止", command=self._on_stop, state=tk.DISABLED,
        )
        self.btn_stop.pack(side=tk.LEFT, padx=(0, 12))

        ttk.Label(r0, text="间隔(秒):").pack(side=tk.LEFT)
        self.var_delay = tk.StringVar(value="0.5")
        ttk.Entry(r0, textvariable=self.var_delay, width=4).pack(
            side=tk.LEFT, padx=(4, 8)
        )

        ttk.Label(r0, text="签约人数:").pack(side=tk.LEFT)
        self.var_max_count = tk.StringVar(value="")
        ttk.Entry(r0, textvariable=self.var_max_count, width=5).pack(
            side=tk.LEFT, padx=(4, 8)
        )

        ttk.Label(r0, text="签约医生:").pack(side=tk.LEFT)
        self.var_doctor = tk.StringVar()
        ttk.Entry(r0, textvariable=self.var_doctor, width=8).pack(
            side=tk.LEFT, padx=(4, 8)
        )

        ttk.Label(r0, text="签约团队:").pack(side=tk.LEFT)
        self.var_team = tk.StringVar()
        ttk.Entry(r0, textvariable=self.var_team, width=16).pack(
            side=tk.LEFT, padx=(4, 0)
        )

        r1 = ttk.Frame(frame)
        r1.pack(fill=tk.X, pady=(4, 0))

        ttk.Label(r1, text="人群类型:").pack(side=tk.LEFT)
        pop_values = [POPULATION_TYPES[k] for k in sorted(POPULATION_TYPES, key=int)]
        self.var_pop_type = tk.StringVar(value="一般人群")
        ttk.Combobox(
            r1, textvariable=self.var_pop_type, width=14, state="readonly",
            values=pop_values,
        ).pack(side=tk.LEFT, padx=(4, 12))

        ttk.Label(r1, text="协议开始:").pack(side=tk.LEFT)
        self.var_agree_start = tk.StringVar()
        ttk.Entry(r1, textvariable=self.var_agree_start, width=10).pack(
            side=tk.LEFT, padx=(4, 8)
        )
        ttk.Label(r1, text="协议结束:").pack(side=tk.LEFT)
        self.var_agree_end = tk.StringVar()
        ttk.Entry(r1, textvariable=self.var_agree_end, width=10).pack(
            side=tk.LEFT, padx=(4, 8)
        )
        ttk.Label(r1, text="(留空=自动,如20260101~20291231)").pack(side=tk.LEFT)

        r2 = ttk.Frame(frame)
        r2.pack(fill=tk.X, pady=(4, 0))

        self.var_auto_void = tk.BooleanVar(value=True)
        ttk.Checkbutton(
            r2, text="自动作废(已签约重签)", variable=self.var_auto_void,
        ).pack(side=tk.LEFT, padx=(0, 12))

        self.var_del_doctor = tk.BooleanVar(value=True)
        ttk.Checkbutton(
            r2, text="删除医生申请", variable=self.var_del_doctor,
        ).pack(side=tk.LEFT, padx=(0, 12))

        self.var_del_resident = tk.BooleanVar(value=False)
        ttk.Checkbutton(
            r2, text="删除居民申请", variable=self.var_del_resident,
        ).pack(side=tk.LEFT, padx=(0, 12))

        r3 = ttk.Frame(frame)
        r3.pack(fill=tk.X, pady=(4, 0))

        self.progress = ttk.Progressbar(r3, mode="determinate", length=400)
        self.progress.pack(side=tk.LEFT, padx=(0, 12))

        self.var_progress_text = tk.StringVar(value="就绪")
        ttk.Label(r3, textvariable=self.var_progress_text).pack(side=tk.LEFT)

        self.var_stats = tk.StringVar(value="")
        ttk.Label(
            r3, textvariable=self.var_stats, style="Info.TLabel"
        ).pack(side=tk.RIGHT)

    def _build_log_section(self, parent):
        frame = ttk.LabelFrame(parent, text=" 运行日志 ", padding=4)
        frame.pack(fill=tk.BOTH, expand=False, pady=(0, 0))
        frame.configure(height=120)

        log_frame = ttk.Frame(frame)
        log_frame.pack(fill=tk.BOTH, expand=True)

        self.log_text = tk.Text(
            log_frame, height=6, wrap=tk.WORD, state=tk.DISABLED,
            font=("Consolas", 9) if sys.platform == "win32" else ("Menlo", 10),
        )
        log_sb = ttk.Scrollbar(log_frame, command=self.log_text.yview)
        self.log_text.configure(yscrollcommand=log_sb.set)
        self.log_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        log_sb.pack(side=tk.RIGHT, fill=tk.Y)

        self.log_text.tag_configure("ok", foreground="#16a34a")
        self.log_text.tag_configure("err", foreground="#dc2626")
        self.log_text.tag_configure("info", foreground="#2563eb")
        self.log_text.tag_configure("warn", foreground="#d97706")

        btn_frame = ttk.Frame(frame)
        btn_frame.pack(fill=tk.X, pady=(2, 0))
        ttk.Button(btn_frame, text="清空日志", command=self._clear_log).pack(
            side=tk.RIGHT
        )

    # ================================================================
    # Tab 2: 健康卡确认
    # ================================================================

    def _build_hc_tab(self, parent):
        self._build_hc_workflow_guide(parent)
        self._build_hc_connect(parent)
        self._build_hc_card_table(parent)
        self._build_hc_control(parent)
        self._build_hc_log(parent)

    def _build_hc_workflow_guide(self, parent):
        frame = ttk.LabelFrame(parent, text=" 操作流程（每批最多9人）", padding=6)
        frame.pack(fill=tk.X, pady=(0, 4))

        guide = (
            "① 微信小程序\"我的健康卡\" → 添加家庭成员 → 绑定签约对象（输入姓名+身份证号）\n"
            "② 本软件点击「刷新卡列表」→ 看到绑定的卡 → 点击「一键确认签约」\n"
            "③ 确认完成后 → 微信小程序\"我的健康卡\" → 解绑已确认的卡\n"
            "④ 继续绑定下一批 → 重复以上步骤（每个OpenID最多同时绑9张卡）"
        )

        try:
            bg = self.cget("background")
        except Exception:
            bg = "#f0f0f0"
        text_w = tk.Text(
            frame, height=4, wrap=tk.WORD, state=tk.NORMAL,
            font=("", 10), relief=tk.FLAT, background=bg,
        )
        text_w.insert("1.0", guide)
        text_w.configure(state=tk.DISABLED)
        text_w.pack(fill=tk.X)

    def _build_hc_connect(self, parent):
        frame = ttk.LabelFrame(parent, text=" 健康卡连接 ", padding=6)
        frame.pack(fill=tk.X, pady=(0, 4))

        r0 = ttk.Frame(frame)
        r0.pack(fill=tk.X)
        ttk.Label(r0, text="微信OpenID:").pack(side=tk.LEFT)
        self.var_hc_openid = tk.StringVar()
        ttk.Entry(r0, textvariable=self.var_hc_openid, width=40).pack(
            side=tk.LEFT, padx=(4, 12)
        )

        self.btn_hc_connect = ttk.Button(
            r0, text="连接", command=self._on_hc_connect
        )
        self.btn_hc_connect.pack(side=tk.LEFT, padx=(0, 8))

        self.btn_hc_refresh = ttk.Button(
            r0, text="刷新卡列表", command=self._on_hc_refresh, state=tk.DISABLED
        )
        self.btn_hc_refresh.pack(side=tk.LEFT, padx=(0, 8))

        r1 = ttk.Frame(frame)
        r1.pack(fill=tk.X, pady=(4, 0))
        self.var_hc_status = tk.StringVar(value="未连接")
        self.lbl_hc_status = ttk.Label(
            r1, textvariable=self.var_hc_status, style="Info.TLabel"
        )
        self.lbl_hc_status.pack(side=tk.LEFT)

        ttk.Label(
            r1,
            text="(OpenID通过\"获取OpenID\"标签页抓包获取，每个OpenID最多绑定9张健康卡)",
            foreground="gray",
        ).pack(side=tk.RIGHT)

    def _build_hc_card_table(self, parent):
        frame = ttk.LabelFrame(parent, text=" 健康卡列表 ", padding=4)
        frame.pack(fill=tk.BOTH, expand=True, pady=(0, 4))

        toolbar = ttk.Frame(frame)
        toolbar.pack(fill=tk.X, pady=(0, 4))

        self.var_hc_check_all = tk.BooleanVar(value=True)
        ttk.Checkbutton(
            toolbar, text="全选", variable=self.var_hc_check_all,
            command=self._on_hc_toggle_all,
        ).pack(side=tk.LEFT)

        self.var_hc_select_info = tk.StringVar(value="已选: 0")
        ttk.Label(toolbar, textvariable=self.var_hc_select_info).pack(
            side=tk.LEFT, padx=(16, 0)
        )

        self.var_hc_summary = tk.StringVar(value="")
        ttk.Label(
            toolbar, textvariable=self.var_hc_summary, style="Info.TLabel"
        ).pack(side=tk.RIGHT)

        cols = (
            "seq", "name", "id_card", "age", "category",
            "gender", "rpc_status", "relation",
        )
        col_names = {
            "seq": "#", "name": "姓名", "id_card": "身份证号",
            "age": "年龄", "category": "人群分类",
            "gender": "性别", "rpc_status": "人脸认证",
            "relation": "关系",
        }
        col_widths = {
            "seq": 35, "name": 80, "id_card": 170, "age": 45,
            "category": 70, "gender": 45, "rpc_status": 80,
            "relation": 50,
        }
        col_anchors = {
            "seq": "center", "name": "center", "age": "center",
            "category": "center", "gender": "center",
            "rpc_status": "center", "relation": "center",
        }

        tree_frame = ttk.Frame(frame)
        tree_frame.pack(fill=tk.BOTH, expand=True)

        self.hc_tree = ttk.Treeview(
            tree_frame, columns=cols, show="headings", selectmode="extended",
        )
        for c in cols:
            self.hc_tree.heading(c, text=col_names[c])
            anchor = col_anchors.get(c, "w")
            self.hc_tree.column(
                c, width=col_widths.get(c, 80), minwidth=35, anchor=anchor,
            )

        vsb = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL, command=self.hc_tree.yview)
        self.hc_tree.configure(yscrollcommand=vsb.set)

        self.hc_tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        tree_frame.grid_rowconfigure(0, weight=1)
        tree_frame.grid_columnconfigure(0, weight=1)

        self.hc_tree.bind("<Button-1>", self._on_hc_tree_click)

        self.hc_tree.tag_configure("selected", background="#dbeafe")
        self.hc_tree.tag_configure("confirm_ok", background="#dcfce7")
        self.hc_tree.tag_configure("confirm_fail", background="#fee2e2")
        self.hc_tree.tag_configure("skipped", background="#fef9c3")

    def _build_hc_control(self, parent):
        frame = ttk.LabelFrame(parent, text=" 批量确认 ", padding=6)
        frame.pack(fill=tk.X, pady=(0, 4))

        r0 = ttk.Frame(frame)
        r0.pack(fill=tk.X)

        self.btn_hc_confirm = ttk.Button(
            r0, text="▶ 一键确认签约", command=self._on_hc_start_confirm,
        )
        self.btn_hc_confirm.pack(side=tk.LEFT, padx=(0, 8))

        self.btn_hc_stop = ttk.Button(
            r0, text="⏹ 停止", command=self._on_hc_stop, state=tk.DISABLED,
        )
        self.btn_hc_stop.pack(side=tk.LEFT, padx=(0, 12))

        self.hc_progress = ttk.Progressbar(r0, mode="determinate", length=300)
        self.hc_progress.pack(side=tk.LEFT, padx=(0, 12))

        self.var_hc_progress_text = tk.StringVar(value="就绪")
        ttk.Label(r0, textvariable=self.var_hc_progress_text).pack(side=tk.LEFT)

        self.var_hc_stats = tk.StringVar(value="")
        ttk.Label(
            r0, textvariable=self.var_hc_stats, style="Info.TLabel"
        ).pack(side=tk.RIGHT)

        r1 = ttk.Frame(frame)
        r1.pack(fill=tk.X, pady=(4, 0))
        ttk.Label(
            r1,
            text="自动流程: 设置人脸认证 → 查询签约状态 → 确认待确认合同  |  只处理3.0系统\"医生申请\"(状态5)的签约",
            foreground="gray",
        ).pack(side=tk.LEFT)

    def _build_hc_log(self, parent):
        frame = ttk.LabelFrame(parent, text=" 运行日志 ", padding=4)
        frame.pack(fill=tk.BOTH, expand=False, pady=(0, 0))
        frame.configure(height=140)

        log_frame = ttk.Frame(frame)
        log_frame.pack(fill=tk.BOTH, expand=True)

        self.hc_log_text = tk.Text(
            log_frame, height=7, wrap=tk.WORD, state=tk.DISABLED,
            font=("Consolas", 9) if sys.platform == "win32" else ("Menlo", 10),
        )
        log_sb = ttk.Scrollbar(log_frame, command=self.hc_log_text.yview)
        self.hc_log_text.configure(yscrollcommand=log_sb.set)
        self.hc_log_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        log_sb.pack(side=tk.RIGHT, fill=tk.Y)

        self.hc_log_text.tag_configure("ok", foreground="#16a34a")
        self.hc_log_text.tag_configure("err", foreground="#dc2626")
        self.hc_log_text.tag_configure("info", foreground="#2563eb")
        self.hc_log_text.tag_configure("warn", foreground="#d97706")

        btn_frame = ttk.Frame(frame)
        btn_frame.pack(fill=tk.X, pady=(2, 0))
        ttk.Button(
            btn_frame, text="清空日志", command=self._clear_hc_log
        ).pack(side=tk.RIGHT)

    # ================================================================
    # Tab 3: 获取OpenID
    # ================================================================

    def _build_openid_tab(self, parent):
        self._build_openid_guide(parent)
        self._build_openid_proxy(parent)
        self._build_openid_results(parent)
        self._build_openid_log(parent)

    def _build_openid_guide(self, parent):
        frame = ttk.LabelFrame(parent, text=" 使用说明 ", padding=8)
        frame.pack(fill=tk.X, pady=(0, 4))

        guide_text = (
            "OpenID 是微信用户在健康卡小程序中的唯一标识，用于健康卡确认功能。\n"
            "\n"
            "【电脑版微信一键抓取（推荐，最简单）】\n"
            "  ① 点击「启动代理」→ 系统自动安装证书并设置代理\n"
            "  ② 打开电脑版微信 → 搜索小程序\"我的健康卡\" → 进入\n"
            "  ③ OpenID自动抓取到下方列表 → 点击「使用此OpenID」\n"
            "  ④ 完成后点击「停止代理」→ 系统自动清除代理设置\n"
            "\n"
            "【手机抓取（备用）】\n"
            "  启动代理 → 手机WiFi设置代理(IP+端口) → 浏览器下载证书 → 安装并信任\n"
            "  → 打开微信\"我的健康卡\" → 自动抓取 → 完成后停止代理\n"
            "\n"
            "【手动输入】\n"
            "  如已通过其他方式获取OpenID，可直接在下方手动输入框中粘贴"
        )

        try:
            bg = self.cget("background")
        except Exception:
            bg = "#f0f0f0"
        text_widget = tk.Text(
            frame, height=10, wrap=tk.WORD, state=tk.NORMAL,
            font=("", 10), relief=tk.FLAT, background=bg,
        )
        text_widget.insert("1.0", guide_text)
        text_widget.configure(state=tk.DISABLED)
        text_widget.pack(fill=tk.X)

    def _build_openid_proxy(self, parent):
        frame = ttk.LabelFrame(parent, text=" 代理设置 ", padding=6)
        frame.pack(fill=tk.X, pady=(0, 4))

        r0 = ttk.Frame(frame)
        r0.pack(fill=tk.X)

        self.btn_proxy_start = ttk.Button(
            r0, text="▶ 启动代理", command=self._on_proxy_start
        )
        self.btn_proxy_start.pack(side=tk.LEFT, padx=(0, 4))

        self.btn_proxy_stop = ttk.Button(
            r0, text="⏹ 停止代理", command=self._on_proxy_stop, state=tk.DISABLED
        )
        self.btn_proxy_stop.pack(side=tk.LEFT, padx=(0, 12))

        ttk.Label(r0, text="端口:").pack(side=tk.LEFT)
        self.var_proxy_port = tk.StringVar(value="8888")
        ttk.Entry(r0, textvariable=self.var_proxy_port, width=6).pack(
            side=tk.LEFT, padx=(4, 12)
        )

        self.var_proxy_status = tk.StringVar(value="代理未启动")
        self.lbl_proxy_status = ttk.Label(
            r0, textvariable=self.var_proxy_status, style="Info.TLabel"
        )
        self.lbl_proxy_status.pack(side=tk.LEFT)

        r1 = ttk.Frame(frame)
        r1.pack(fill=tk.X, pady=(6, 0))

        local_ip = get_local_ip()
        ttk.Label(r1, text="手机代理设置:", font=("", 10, "bold")).pack(side=tk.LEFT)

        self.var_proxy_ip = tk.StringVar(value=local_ip)
        ttk.Label(r1, text="  IP地址:").pack(side=tk.LEFT)
        ip_entry = ttk.Entry(r1, textvariable=self.var_proxy_ip, width=16, state="readonly")
        ip_entry.pack(side=tk.LEFT, padx=(4, 8))

        ttk.Label(r1, text="端口:").pack(side=tk.LEFT)
        port_lbl = ttk.Entry(r1, textvariable=self.var_proxy_port, width=6, state="readonly")
        port_lbl.pack(side=tk.LEFT, padx=(4, 8))

        btn_copy_ip = ttk.Button(
            r1, text="复制代理信息",
            command=lambda: self._copy_to_clipboard(
                "%s:%s" % (self.var_proxy_ip.get(), self.var_proxy_port.get())
            ),
        )
        btn_copy_ip.pack(side=tk.LEFT, padx=(8, 0))

        r2 = ttk.Frame(frame)
        r2.pack(fill=tk.X, pady=(4, 0))

        ttk.Label(r2, text="证书地址:").pack(side=tk.LEFT)
        self.var_cert_url = tk.StringVar(value="(启动代理后显示)")
        ttk.Entry(r2, textvariable=self.var_cert_url, width=48, state="readonly").pack(
            side=tk.LEFT, padx=(4, 8)
        )
        self.btn_copy_cert = ttk.Button(
            r2, text="复制证书地址",
            command=lambda: self._copy_to_clipboard(self.var_cert_url.get()),
        )
        self.btn_copy_cert.pack(side=tk.LEFT, padx=(0, 8))

        self.btn_open_cert_dir = ttk.Button(
            r2, text="打开证书目录", command=self._open_cert_dir,
        )
        self.btn_open_cert_dir.pack(side=tk.LEFT)

        r3 = ttk.Frame(frame)
        r3.pack(fill=tk.X, pady=(6, 0))

        ttk.Label(r3, text="电脑版微信:", font=("", 10, "bold")).pack(side=tk.LEFT)

        self.btn_pc_setup = ttk.Button(
            r3, text="一键设置电脑代理+证书", command=self._on_pc_setup,
        )
        self.btn_pc_setup.pack(side=tk.LEFT, padx=(8, 4))

        self.btn_pc_clear = ttk.Button(
            r3, text="一键清除电脑代理", command=self._on_pc_clear,
        )
        self.btn_pc_clear.pack(side=tk.LEFT, padx=(0, 8))

        self.var_pc_status = tk.StringVar(value="")
        ttk.Label(r3, textvariable=self.var_pc_status, foreground="gray").pack(
            side=tk.LEFT
        )

    def _build_openid_results(self, parent):
        frame = ttk.LabelFrame(parent, text=" 已抓取的OpenID ", padding=6)
        frame.pack(fill=tk.BOTH, expand=True, pady=(0, 4))

        self.openid_listbox = tk.Listbox(
            frame, height=5,
            font=("Consolas", 11) if sys.platform == "win32" else ("Menlo", 11),
            selectmode=tk.SINGLE,
        )
        self.openid_listbox.pack(fill=tk.BOTH, expand=True, side=tk.LEFT)

        sb = ttk.Scrollbar(frame, orient=tk.VERTICAL, command=self.openid_listbox.yview)
        self.openid_listbox.configure(yscrollcommand=sb.set)
        sb.pack(side=tk.RIGHT, fill=tk.Y)

        btn_frame = ttk.Frame(parent)
        btn_frame.pack(fill=tk.X, pady=(0, 4))

        self.btn_use_openid = ttk.Button(
            btn_frame, text="★ 使用选中的OpenID（自动填入健康卡确认页）",
            command=self._on_use_openid,
        )
        self.btn_use_openid.pack(side=tk.LEFT, padx=(0, 8))

        ttk.Button(
            btn_frame, text="复制选中OpenID",
            command=self._on_copy_openid,
        ).pack(side=tk.LEFT, padx=(0, 8))

        ttk.Label(
            btn_frame,
            text="提示: 可手动输入OpenID到下方输入框",
            foreground="gray",
        ).pack(side=tk.LEFT)

        manual_frame = ttk.Frame(parent)
        manual_frame.pack(fill=tk.X, pady=(0, 4))

        ttk.Label(manual_frame, text="手动输入OpenID:").pack(side=tk.LEFT)
        self.var_manual_openid = tk.StringVar()
        ttk.Entry(manual_frame, textvariable=self.var_manual_openid, width=40).pack(
            side=tk.LEFT, padx=(4, 8)
        )
        ttk.Button(
            manual_frame, text="使用此OpenID",
            command=self._on_use_manual_openid,
        ).pack(side=tk.LEFT)

    def _build_openid_log(self, parent):
        frame = ttk.LabelFrame(parent, text=" 代理日志 ", padding=4)
        frame.pack(fill=tk.BOTH, expand=False, pady=(0, 0))
        frame.configure(height=100)

        log_frame = ttk.Frame(frame)
        log_frame.pack(fill=tk.BOTH, expand=True)

        self.proxy_log_text = tk.Text(
            log_frame, height=5, wrap=tk.WORD, state=tk.DISABLED,
            font=("Consolas", 9) if sys.platform == "win32" else ("Menlo", 10),
        )
        log_sb = ttk.Scrollbar(log_frame, command=self.proxy_log_text.yview)
        self.proxy_log_text.configure(yscrollcommand=log_sb.set)
        self.proxy_log_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        log_sb.pack(side=tk.RIGHT, fill=tk.Y)

        self.proxy_log_text.tag_configure("ok", foreground="#16a34a")
        self.proxy_log_text.tag_configure("err", foreground="#dc2626")
        self.proxy_log_text.tag_configure("info", foreground="#2563eb")
        self.proxy_log_text.tag_configure("warn", foreground="#d97706")

        btn_frame = ttk.Frame(frame)
        btn_frame.pack(fill=tk.X, pady=(2, 0))
        ttk.Button(
            btn_frame, text="清空日志", command=self._clear_proxy_log
        ).pack(side=tk.RIGHT)

    # -- Tab 3: Proxy Logic --

    def _proxy_log(self, msg: str, tag: str = ""):
        ts = datetime.now().strftime("%H:%M:%S")
        line = "[%s] %s\n" % (ts, msg)

        def _do():
            self.proxy_log_text.configure(state=tk.NORMAL)
            self.proxy_log_text.insert(tk.END, line, tag)
            self.proxy_log_text.see(tk.END)
            self.proxy_log_text.configure(state=tk.DISABLED)

        if threading.current_thread() is threading.main_thread():
            _do()
        else:
            self.after(0, _do)

    def _clear_proxy_log(self):
        self.proxy_log_text.configure(state=tk.NORMAL)
        self.proxy_log_text.delete("1.0", tk.END)
        self.proxy_log_text.configure(state=tk.DISABLED)

    def _on_proxy_start(self):
        if self._proxy_running:
            return

        try:
            port = int(self.var_proxy_port.get())
        except ValueError:
            messagebox.showwarning("提示", "请输入有效的端口号")
            return

        self._proxy_log("正在启动代理服务器...", "info")

        def on_openid_found(openid):
            self.after(0, lambda oid=openid: self._on_openid_captured(oid))

        def on_proxy_log(msg, tag=""):
            self._proxy_log(msg, tag)

        self._proxy = OpenIDProxy(
            port=port,
            on_openid=on_openid_found,
            on_log=on_proxy_log,
        )

        if self._proxy.start():
            self._proxy_running = True
            self.btn_proxy_start.configure(state=tk.DISABLED)
            self.btn_proxy_stop.configure(state=tk.NORMAL)
            self.var_proxy_status.set("代理运行中")
            self.lbl_proxy_status.configure(style="Success.TLabel")

            ip = get_local_ip()
            self.var_proxy_ip.set(ip)
            cert_url = "http://%s:%d/cert" % (ip, port)
            self.var_cert_url.set(cert_url)

            self._proxy_log(
                "手机WiFi代理设置: 服务器=%s  端口=%d" % (ip, port), "info"
            )
            self._proxy_log(
                "请用手机浏览器访问 %s 下载CA证书" % cert_url, "info"
            )

            self._auto_setup_local_proxy(port)
        else:
            self.var_proxy_status.set("启动失败")
            self.lbl_proxy_status.configure(style="Error.TLabel")

    def _auto_setup_local_proxy(self, port: int):
        """Auto-install CA cert and set system proxy after proxy starts."""
        ca_path = self._proxy.ca_cert_path

        cert_ok = install_ca_to_system(ca_path)
        if cert_ok:
            self._proxy_log("CA证书已安装到系统信任存储", "ok")
        else:
            self._proxy_log("CA证书自动安装失败，请手动安装或点击「一键设置电脑代理+证书」", "warn")

        proxy_ok = set_system_proxy("127.0.0.1", port)
        if proxy_ok:
            self._proxy_log("系统代理已自动设置: 127.0.0.1:%d" % port, "ok")
            self.var_pc_status.set("代理已开启 — 现在打开微信小程序\"我的健康卡\"")
            self._proxy_log("请打开电脑版微信 → 搜索小程序\"我的健康卡\" → 进入即可抓取", "info")
        else:
            self._proxy_log("系统代理自动设置失败，请手动设置或点击「一键设置电脑代理+证书」", "warn")

    def _on_proxy_stop(self):
        ok = clear_system_proxy()
        if ok:
            self._proxy_log("系统代理已清除", "ok")
        self.var_pc_status.set("")
        if self._proxy:
            self._proxy.stop()
        self._proxy_running = False
        self.btn_proxy_start.configure(state=tk.NORMAL)
        self.btn_proxy_stop.configure(state=tk.DISABLED)
        self.var_proxy_status.set("代理已停止")
        self.lbl_proxy_status.configure(style="Info.TLabel")

    def _on_openid_captured(self, openid: str):
        items = self.openid_listbox.get(0, tk.END)
        if openid not in items:
            self.openid_listbox.insert(tk.END, openid)
            self._proxy_log("已捕获 OpenID: %s" % openid, "ok")

    def _on_use_openid(self):
        sel = self.openid_listbox.curselection()
        if not sel:
            messagebox.showinfo("提示", "请先在列表中选择一个OpenID")
            return
        openid = self.openid_listbox.get(sel[0])
        self._apply_openid(openid)

    def _on_copy_openid(self):
        sel = self.openid_listbox.curselection()
        if not sel:
            messagebox.showinfo("提示", "请先在列表中选择一个OpenID")
            return
        openid = self.openid_listbox.get(sel[0])
        self._copy_to_clipboard(openid)
        self._proxy_log("已复制 OpenID: %s" % openid, "ok")

    def _on_use_manual_openid(self):
        openid = self.var_manual_openid.get().strip()
        if not openid:
            messagebox.showwarning("提示", "请输入OpenID")
            return
        self._apply_openid(openid)

    def _apply_openid(self, openid: str):
        self.var_hc_openid.set(openid)
        self.notebook.select(1)
        self._proxy_log("已将 OpenID 填入健康卡确认页: %s" % openid, "ok")
        self._save_current_config()

    def _copy_to_clipboard(self, text: str):
        self.clipboard_clear()
        self.clipboard_append(text)
        self.update()

    def _open_cert_dir(self):
        if self._proxy:
            cert_dir = self._proxy.cert_mgr.cert_dir
        else:
            cert_dir = os.path.join(
                os.path.dirname(os.path.abspath(__file__)), "certs"
            )
        if os.path.exists(cert_dir):
            if sys.platform == "win32":
                os.startfile(cert_dir)
            elif sys.platform == "darwin":
                import subprocess
                subprocess.Popen(["open", cert_dir])
            else:
                import subprocess
                subprocess.Popen(["xdg-open", cert_dir])
        else:
            messagebox.showinfo("提示", "请先启动代理以生成CA证书")

    def _on_pc_setup(self):
        if not self._proxy_running:
            self._proxy_log("请先点击「启动代理」", "warn")
            messagebox.showwarning("提示", "请先启动代理服务器")
            return

        self._proxy_log("正在设置电脑代理和安装证书...", "info")
        self.var_pc_status.set("设置中...")

        ca_path = self._proxy.ca_cert_path

        cert_ok = install_ca_to_system(ca_path)
        if cert_ok:
            self._proxy_log("CA证书已安装到系统信任存储", "ok")
        else:
            self._proxy_log("CA证书安装失败（可能需要确认弹窗）", "warn")

        port = int(self.var_proxy_port.get())
        proxy_ok = set_system_proxy("127.0.0.1", port)
        if proxy_ok:
            self._proxy_log("系统代理已设置: 127.0.0.1:%d" % port, "ok")
        else:
            self._proxy_log("系统代理设置失败", "err")

        if proxy_ok:
            self.var_pc_status.set("电脑代理已开启 — 现在打开微信小程序\"我的健康卡\"")
            self._proxy_log("请打开电脑版微信 → 搜索小程序\"我的健康卡\" → 进入即可抓取", "info")
        else:
            self.var_pc_status.set("设置失败")

    def _on_pc_clear(self):
        ok = clear_system_proxy()
        if ok:
            self._proxy_log("系统代理已清除", "ok")
            self.var_pc_status.set("电脑代理已关闭")
        else:
            self._proxy_log("清除系统代理失败", "err")
            self.var_pc_status.set("")

    # ================================================================
    # Tab 4: 流量抓包
    # ================================================================

    def _build_capture_tab(self, parent):
        self._build_capture_guide(parent)
        self._build_capture_controls(parent)
        self._build_capture_stats(parent)
        self._build_capture_log(parent)

    def _build_capture_guide(self, parent):
        frame = ttk.LabelFrame(parent, text=" 使用说明 ", padding=8)
        frame.pack(fill=tk.X, pady=(0, 4))

        guide_text = (
            "流量抓包功能用于记录微信小程序与服务器之间的完整通信数据，\n"
            "便于分析绑卡、解绑、人脸验证等关键接口的调用流程。\n"
            "\n"
            "操作步骤：\n"
            "  ① 点击「开始抓包」→ 系统自动设置代理和证书\n"
            "  ② 打开电脑版微信，进入目标小程序（如\"湖南省居民健康卡\"、\"我的健康卡\"等）\n"
            "  ③ 在小程序中执行需要分析的操作（绑卡、解绑、查看家庭医生等）\n"
            "  ④ 操作完成后点击「停止抓包」→ 点击「导出日志」保存文件\n"
            "  ⑤ 将导出的日志文件发送给技术人员进行分析"
        )

        try:
            bg = self.cget("background")
        except Exception:
            bg = "#f0f0f0"
        tw = tk.Text(
            frame, height=8, wrap=tk.WORD, state=tk.NORMAL,
            font=("", 10), relief=tk.FLAT, background=bg,
        )
        tw.insert("1.0", guide_text)
        tw.configure(state=tk.DISABLED)
        tw.pack(fill=tk.X)

    def _build_capture_controls(self, parent):
        frame = ttk.LabelFrame(parent, text=" 抓包控制 ", padding=6)
        frame.pack(fill=tk.X, pady=(0, 4))

        r0 = ttk.Frame(frame)
        r0.pack(fill=tk.X)

        self.btn_cap_start = ttk.Button(
            r0, text="▶ 开始抓包", command=self._on_cap_start,
        )
        self.btn_cap_start.pack(side=tk.LEFT, padx=(0, 4))

        self.btn_cap_stop = ttk.Button(
            r0, text="⏹ 停止抓包", command=self._on_cap_stop, state=tk.DISABLED,
        )
        self.btn_cap_stop.pack(side=tk.LEFT, padx=(0, 12))

        self.btn_cap_export = ttk.Button(
            r0, text="导出日志", command=self._on_cap_export,
        )
        self.btn_cap_export.pack(side=tk.LEFT, padx=(0, 12))

        self.var_cap_status = tk.StringVar(value="未启动")
        self.lbl_cap_status = ttk.Label(
            r0, textvariable=self.var_cap_status, style="Info.TLabel",
        )
        self.lbl_cap_status.pack(side=tk.LEFT, padx=(8, 0))

    def _build_capture_stats(self, parent):
        frame = ttk.Frame(parent)
        frame.pack(fill=tk.X, pady=(0, 4))

        self.var_cap_stats = tk.StringVar(value="拦截请求: 0  |  日志大小: 0 KB")
        ttk.Label(frame, textvariable=self.var_cap_stats, font=("", 10)).pack(
            side=tk.LEFT,
        )

    def _build_capture_log(self, parent):
        frame = ttk.LabelFrame(parent, text=" 实时抓包日志 ", padding=4)
        frame.pack(fill=tk.BOTH, expand=True)

        log_frame = ttk.Frame(frame)
        log_frame.pack(fill=tk.BOTH, expand=True)

        self.cap_log_text = tk.Text(
            log_frame, wrap=tk.WORD, state=tk.DISABLED,
            font=("Consolas", 9) if sys.platform == "win32" else ("Menlo", 10),
        )
        sb = ttk.Scrollbar(log_frame, command=self.cap_log_text.yview)
        self.cap_log_text.configure(yscrollcommand=sb.set)
        self.cap_log_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        sb.pack(side=tk.RIGHT, fill=tk.Y)

        self.cap_log_text.tag_configure("ok", foreground="#16a34a")
        self.cap_log_text.tag_configure("err", foreground="#dc2626")
        self.cap_log_text.tag_configure("info", foreground="#2563eb")
        self.cap_log_text.tag_configure("warn", foreground="#d97706")
        self.cap_log_text.tag_configure("req", foreground="#7c3aed")
        self.cap_log_text.tag_configure("resp", foreground="#0891b2")

        btn_frame = ttk.Frame(frame)
        btn_frame.pack(fill=tk.X, pady=(2, 0))
        ttk.Button(
            btn_frame, text="清空日志", command=self._clear_cap_log,
        ).pack(side=tk.RIGHT)

    # -- Tab 4: Capture Logic --

    def _cap_log(self, msg: str, tag: str = ""):
        ts = datetime.now().strftime("%H:%M:%S")
        line = "[%s] %s\n" % (ts, msg)

        def _do():
            self.cap_log_text.configure(state=tk.NORMAL)
            self.cap_log_text.insert(tk.END, line, tag)
            self.cap_log_text.see(tk.END)
            self.cap_log_text.configure(state=tk.DISABLED)

        if threading.current_thread() is threading.main_thread():
            _do()
        else:
            self.after(0, _do)

    def _clear_cap_log(self):
        self.cap_log_text.configure(state=tk.NORMAL)
        self.cap_log_text.delete("1.0", tk.END)
        self.cap_log_text.configure(state=tk.DISABLED)

    def _update_cap_stats(self):
        if self._cap_proxy and os.path.exists(self._cap_proxy.traffic_log_path):
            sz = os.path.getsize(self._cap_proxy.traffic_log_path)
        else:
            sz = 0
        kb = sz / 1024
        self.var_cap_stats.set(
            "拦截请求: %d  |  日志大小: %.1f KB" % (self._cap_request_count, kb)
        )

    def _on_cap_start(self):
        if self._cap_running:
            return

        if self._proxy_running:
            messagebox.showwarning("提示", "请先停止「获取OpenID」页面的代理，再启动抓包")
            return

        self._cap_log("正在启动抓包...", "info")
        self._cap_request_count = 0

        def on_openid(openid):
            self.after(0, lambda oid=openid: self._cap_log(
                "发现 OpenID: %s" % oid, "ok"
            ))

        def on_log(msg, tag=""):
            if msg.startswith("拦截"):
                self._cap_request_count += 1
                self.after(0, self._update_cap_stats)
                self._cap_log(msg, "req")
            else:
                self._cap_log(msg, tag)

        self._cap_proxy = OpenIDProxy(
            port=8888,
            on_openid=on_openid,
            on_log=on_log,
        )

        if self._cap_proxy.start():
            self._cap_running = True
            self.btn_cap_start.configure(state=tk.DISABLED)
            self.btn_cap_stop.configure(state=tk.NORMAL)
            self.var_cap_status.set("抓包运行中")
            self.lbl_cap_status.configure(style="Success.TLabel")

            ca_path = self._cap_proxy.ca_cert_path
            cert_ok = install_ca_to_system(ca_path)
            if cert_ok:
                self._cap_log("CA证书已安装", "ok")
            else:
                self._cap_log("CA证书安装失败，可能需要确认弹窗", "warn")

            proxy_ok = set_system_proxy("127.0.0.1", 8888)
            if proxy_ok:
                self._cap_log("系统代理已设置: 127.0.0.1:8888", "ok")
            else:
                self._cap_log("系统代理设置失败", "err")

            self._cap_log("", "")
            self._cap_log("现在请打开电脑版微信，进入需要分析的小程序", "info")
            self._cap_log("所有目标域名的请求和响应将被完整记录", "info")
            self._cap_log("", "")
        else:
            self.var_cap_status.set("启动失败")
            self.lbl_cap_status.configure(style="Error.TLabel")

    def _on_cap_stop(self):
        clear_system_proxy()
        self._cap_log("系统代理已清除", "ok")

        if self._cap_proxy:
            self._cap_proxy.stop()

        self._cap_running = False
        self.btn_cap_start.configure(state=tk.NORMAL)
        self.btn_cap_stop.configure(state=tk.DISABLED)
        self.var_cap_status.set("抓包已停止")
        self.lbl_cap_status.configure(style="Info.TLabel")
        self._update_cap_stats()

        if self._cap_proxy and os.path.exists(self._cap_proxy.traffic_log_path):
            sz = os.path.getsize(self._cap_proxy.traffic_log_path)
            if sz > 0:
                self._cap_log("", "")
                self._cap_log(
                    "日志已保存 (%.1f KB)，请点击「导出日志」保存到指定位置" % (sz / 1024), "ok"
                )

    def _on_cap_export(self):
        if not self._cap_proxy:
            src = os.path.join(
                os.path.dirname(os.path.abspath(__file__)), "traffic_log.txt"
            )
        else:
            src = self._cap_proxy.traffic_log_path

        if not os.path.exists(src) or os.path.getsize(src) == 0:
            messagebox.showinfo("提示", "暂无抓包日志，请先执行抓包操作")
            return

        dest = filedialog.asksaveasfilename(
            title="导出抓包日志",
            defaultextension=".txt",
            filetypes=[("文本文件", "*.txt"), ("所有文件", "*.*")],
            initialfile="traffic_log_%s.txt" % datetime.now().strftime("%Y%m%d_%H%M%S"),
        )
        if not dest:
            return

        try:
            import shutil
            shutil.copy2(src, dest)
            self._cap_log("日志已导出: %s" % dest, "ok")
            messagebox.showinfo("导出成功", "抓包日志已保存到:\n%s" % dest)
        except Exception as e:
            self._cap_log("导出失败: %s" % e, "err")
            messagebox.showerror("导出失败", str(e))

    # ================================================================
    # Config
    # ================================================================

    def _restore_config(self):
        c = self._cfg
        if c.get("url"):
            self.var_url.set(c["url"])
        if c.get("account"):
            self.var_account.set(c["account"])
        if c.get("org_code"):
            self.var_org.set(c["org_code"])
        if c.get("doctor"):
            self.var_doctor.set(c["doctor"])
        if c.get("team"):
            self.var_team.set(c["team"])
        if c.get("delay"):
            self.var_delay.set(c["delay"])
        if c.get("pop_type"):
            self.var_pop_type.set(c["pop_type"])
        if c.get("agree_start"):
            self.var_agree_start.set(c["agree_start"])
        if c.get("agree_end"):
            self.var_agree_end.set(c["agree_end"])
        if c.get("max_count"):
            self.var_max_count.set(c["max_count"])
        if c.get("hc_openid"):
            self.var_hc_openid.set(c["hc_openid"])

    def _save_current_config(self):
        save_config({
            "url": self.var_url.get(),
            "account": self.var_account.get(),
            "org_code": self.var_org.get(),
            "doctor": self.var_doctor.get(),
            "team": self.var_team.get(),
            "delay": self.var_delay.get(),
            "pop_type": self.var_pop_type.get(),
            "agree_start": self.var_agree_start.get(),
            "agree_end": self.var_agree_end.get(),
            "max_count": self.var_max_count.get(),
            "hc_openid": self.var_hc_openid.get(),
        })

    # ================================================================
    # Logging (Tab 1)
    # ================================================================

    def _log(self, msg: str, tag: str = ""):
        ts = datetime.now().strftime("%H:%M:%S")
        line = "[%s] %s\n" % (ts, msg)

        def _do():
            self.log_text.configure(state=tk.NORMAL)
            self.log_text.insert(tk.END, line, tag)
            self.log_text.see(tk.END)
            self.log_text.configure(state=tk.DISABLED)

        if threading.current_thread() is threading.main_thread():
            _do()
        else:
            self.after(0, _do)

    def _clear_log(self):
        self.log_text.configure(state=tk.NORMAL)
        self.log_text.delete("1.0", tk.END)
        self.log_text.configure(state=tk.DISABLED)

    # ================================================================
    # Logging (Tab 2 - Health Card)
    # ================================================================

    def _hc_log(self, msg: str, tag: str = ""):
        ts = datetime.now().strftime("%H:%M:%S")
        line = "[%s] %s\n" % (ts, msg)

        def _do():
            self.hc_log_text.configure(state=tk.NORMAL)
            self.hc_log_text.insert(tk.END, line, tag)
            self.hc_log_text.see(tk.END)
            self.hc_log_text.configure(state=tk.DISABLED)

        if threading.current_thread() is threading.main_thread():
            _do()
        else:
            self.after(0, _do)

    def _clear_hc_log(self):
        self.hc_log_text.configure(state=tk.NORMAL)
        self.hc_log_text.delete("1.0", tk.END)
        self.hc_log_text.configure(state=tk.DISABLED)

    # ================================================================
    # Tab 1: Login
    # ================================================================

    def _on_login(self):
        url = self.var_url.get().strip()
        acct = self.var_account.get().strip()
        pwd = self.var_password.get().strip()

        if not url or not acct or not pwd:
            messagebox.showwarning("提示", "请填写完整的登录信息")
            return

        self.btn_login.configure(state=tk.DISABLED)
        self.var_login_status.set("正在登录...")
        self.lbl_login_status.configure(style="Info.TLabel")
        self._log("正在登录 %s ..." % url, "info")

        def worker():
            ok, msg = self.client.login(url, acct, pwd)
            self.after(0, lambda: self._login_done(ok, msg))

        threading.Thread(target=worker, daemon=True).start()

    def _login_done(self, ok: bool, msg: str):
        self.btn_login.configure(state=tk.NORMAL)
        self.var_login_status.set(msg)

        if ok:
            self.lbl_login_status.configure(style="Success.TLabel")
            self._log("✓ %s" % msg, "ok")

            if self.client.org_code and not self.var_org.get():
                self.var_org.set(self.client.org_code)
            if self.client.doctor_name and not self.var_doctor.get():
                self.var_doctor.set(self.client.doctor_name)
            if self.client.team_name and not self.var_team.get():
                self.var_team.set(self.client.team_name)

            self._save_current_config()
        else:
            self.lbl_login_status.configure(style="Error.TLabel")
            self._log("✗ %s" % msg, "err")

    # ================================================================
    # Tab 1: Query
    # ================================================================

    def _get_status_code(self) -> str:
        mapping = {
            "未签约": "1", "已签约": "0", "医生申请": "5",
            "居民申请": "6", "拒绝签约": "4", "全部": "",
        }
        return mapping.get(self.var_status.get(), "")

    def _get_extra_filters(self) -> dict:
        extra = {}
        exp_s = self.var_expire_start.get().strip()
        exp_e = self.var_expire_end.get().strip()
        if exp_s:
            extra["XYJSRQ_BEGIN"] = exp_s
        if exp_e:
            extra["XYJSRQ_END"] = exp_e
        nm = self.var_name_filter.get().strip()
        if nm:
            extra["XM"] = nm
        idc = self.var_idcard_filter.get().strip()
        if idc:
            extra["SFZH"] = idc
        return extra

    def _on_query(self):
        if not self.client.logged_in:
            messagebox.showwarning("提示", "请先登录")
            return

        self.btn_query.configure(state=tk.DISABLED)
        self.btn_query_all.configure(state=tk.DISABLED)
        self.var_query_info.set("正在查询...")
        self._log("查询居民列表 (首页)...", "info")

        sc = self._get_status_code()
        oc = self.var_org.get().strip()
        ef = self._get_extra_filters()

        def worker():
            pts, total = self.client.query_patients(
                status=sc, org_code=oc, page=1, extra_filters=ef,
            )
            self.after(0, lambda: self._query_done(pts, total))

        threading.Thread(target=worker, daemon=True).start()

    def _on_query_all(self):
        if not self.client.logged_in:
            messagebox.showwarning("提示", "请先登录")
            return

        self.btn_query.configure(state=tk.DISABLED)
        self.btn_query_all.configure(state=tk.DISABLED)
        self.var_query_info.set("正在查询全部页...")
        self._log("查询全部居民数据...", "info")

        sc = self._get_status_code()
        oc = self.var_org.get().strip()
        ef = self._get_extra_filters()

        def progress(loaded, total):
            self.after(
                0, lambda l=loaded, t=total:
                self.var_query_info.set("已加载 %d / %d ..." % (l, t))
            )

        def worker():
            pts = self.client.query_all_patients(
                status=sc, org_code=oc, extra_filters=ef,
                progress_cb=progress,
            )
            self.after(0, lambda: self._query_done(pts, len(pts)))

        threading.Thread(target=worker, daemon=True).start()

    def _query_done(self, patients: List[Patient], total: int):
        self.btn_query.configure(state=tk.NORMAL)
        self.btn_query_all.configure(state=tk.NORMAL)

        self.patients = patients
        self.selected_ids = set(p.person_id for p in patients)
        self.var_check_all.set(True)

        self._refresh_table()
        self.var_query_info.set("共 %d 条记录" % total)
        self._log("查询完成: %d 条记录" % len(patients), "ok")
        self._update_select_info()

    def _refresh_table(self):
        self.tree.delete(*self.tree.get_children())
        for i, p in enumerate(self.patients, 1):
            tags = ()
            if p.person_id in self.selected_ids:
                tags = ("selected",)
            self.tree.insert("", tk.END, iid=p.person_id, values=(
                i, p.name, p.id_card, p.status_text,
                p.signing_team, p.signing_doctor,
                p.signing_date, p.agreement_end, p.person_id,
            ), tags=tags)

    def _on_tree_click(self, event):
        region = self.tree.identify_region(event.x, event.y)
        if region == "heading":
            return
        item = self.tree.identify_row(event.y)
        if not item:
            return
        if item in self.selected_ids:
            self.selected_ids.discard(item)
            self.tree.item(item, tags=())
        else:
            self.selected_ids.add(item)
            self.tree.item(item, tags=("selected",))
        self._update_select_info()
        self.tree.selection_remove(self.tree.selection())
        return "break"

    def _on_toggle_all(self):
        if self.var_check_all.get():
            self.selected_ids = set(p.person_id for p in self.patients)
        else:
            self.selected_ids = set()
        self._refresh_table()
        self._update_select_info()

    def _update_select_info(self):
        self.var_select_info.set(
            "已选: %d / %d" % (len(self.selected_ids), len(self.patients))
        )

    def _on_export(self):
        if not self.patients:
            messagebox.showinfo("提示", "没有数据可导出")
            return

        path = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV 文件", "*.csv"), ("所有文件", "*.*")],
            initialfile="居民列表_%s.csv" % datetime.now().strftime("%Y%m%d_%H%M"),
        )
        if not path:
            return

        try:
            import csv
            with open(path, "w", encoding="utf-8-sig", newline="") as f:
                writer = csv.writer(f)
                writer.writerow(["序号", "姓名", "身份证号", "签约状态", "签约团队",
                                 "签约医生", "签约日期", "协议到期", "PERSONID", "合同编号"])
                for i, p in enumerate(self.patients, 1):
                    writer.writerow([
                        i, p.name, p.id_card, p.status_text,
                        p.signing_team, p.signing_doctor,
                        p.signing_date, p.agreement_end,
                        p.person_id, p.contract_code,
                    ])
            self._log("导出成功: %s (%d条)" % (path, len(self.patients)), "ok")
            messagebox.showinfo("导出成功", "已导出 %d 条记录" % len(self.patients))
        except Exception as e:
            self._log("导出失败: %s" % e, "err")
            messagebox.showerror("导出失败", str(e))

    # ================================================================
    # Tab 1: Batch Signing
    # ================================================================

    def _get_pop_type_code(self) -> str:
        name = self.var_pop_type.get()
        for code, label in POPULATION_TYPES.items():
            if label == name:
                return code
        return "0"

    def _on_start_signing(self):
        if self._signing:
            return

        if not self.client.logged_in:
            messagebox.showwarning("提示", "请先登录")
            return

        targets = [p for p in self.patients if p.person_id in self.selected_ids]
        if not targets:
            messagebox.showwarning("提示", "请选择要签约的居民")
            return

        max_count_str = self.var_max_count.get().strip()
        if max_count_str:
            try:
                max_count = int(max_count_str)
                if max_count > 0 and max_count < len(targets):
                    targets = targets[:max_count]
            except ValueError:
                pass

        msg = "即将对 %d 位居民执行自动签约，是否继续？" % len(targets)
        if not messagebox.askyesno("确认签约", msg):
            return

        self._signing = True
        self._paused = False
        self._stop_event.clear()
        self._sign_success = 0
        self._sign_fail = 0
        self._sign_total = len(targets)
        self._sign_start_time = time.time()

        self.btn_start.configure(state=tk.DISABLED)
        self.btn_pause.configure(state=tk.NORMAL)
        self.btn_stop.configure(state=tk.NORMAL)
        self.btn_login.configure(state=tk.DISABLED)
        self.btn_query.configure(state=tk.DISABLED)
        self.btn_query_all.configure(state=tk.DISABLED)

        self.progress.configure(maximum=len(targets), value=0)
        self.var_progress_text.set("0 / %d" % len(targets))
        self.var_stats.set("")

        self._log("=" * 50, "info")
        self._log("开始批量签约: %d 人" % len(targets), "info")

        try:
            delay = float(self.var_delay.get())
        except ValueError:
            delay = 0.5

        doctor = self.var_doctor.get().strip()
        team = self.var_team.get().strip()
        pop_code = self._get_pop_type_code()
        agree_start = self.var_agree_start.get().strip()
        agree_end = self.var_agree_end.get().strip()
        auto_void = self.var_auto_void.get()
        del_doctor = self.var_del_doctor.get()
        del_resident = self.var_del_resident.get()

        opts = []
        if auto_void:
            opts.append("自动作废")
        if del_doctor:
            opts.append("删除医生申请")
        if del_resident:
            opts.append("删除居民申请")
        if agree_start or agree_end:
            opts.append("协议期: %s~%s" % (agree_start or "自动", agree_end or "自动"))
        if pop_code != "0":
            opts.append("人群: %s" % self.var_pop_type.get())
        if opts:
            self._log("选项: %s" % ", ".join(opts), "info")

        self._save_current_config()

        sign_opts = {
            "pop_code": pop_code,
            "agree_start": agree_start,
            "agree_end": agree_end,
            "auto_void": auto_void,
            "del_doctor": del_doctor,
            "del_resident": del_resident,
        }

        def worker():
            self._batch_sign_worker(targets, delay, doctor, team, sign_opts)

        threading.Thread(target=worker, daemon=True).start()

    def _batch_sign_worker(self, targets, delay, doctor, team, sign_opts=None):
        opts = sign_opts or {}
        for i, patient in enumerate(targets):
            if self._stop_event.is_set():
                self.after(0, lambda: self._log("已手动停止", "warn"))
                break

            while self._paused and not self._stop_event.is_set():
                time.sleep(0.2)

            if self._stop_event.is_set():
                break

            self.after(
                0,
                lambda idx=i, p=patient: self._log(
                    "正在签约 [%d/%d] %s (%s)" % (idx + 1, self._sign_total, p.name, p.id_card),
                    "info",
                ),
            )

            result = self.client.sign_one(
                person_id=patient.person_id,
                name=patient.name,
                team_name=team,
                doctor_name=doctor,
                delay=delay,
                contract_status=patient.contract_status,
                contract_code=patient.contract_code,
                auto_void=opts.get("auto_void", False),
                auto_delete_doctor=opts.get("del_doctor", False),
                auto_delete_resident=opts.get("del_resident", False),
                service_type=opts.get("pop_code", "0"),
                agreement_start=opts.get("agree_start", ""),
                agreement_end=opts.get("agree_end", ""),
            )

            self.after(0, lambda r=result, idx=i: self._on_sign_result(r, idx))

            if delay > 0 and i < len(targets) - 1:
                time.sleep(delay)

        self.after(0, self._signing_finished)

    def _on_sign_result(self, result: SignResult, index: int):
        done = index + 1
        label = result.name or result.person_id
        children = self.tree.get_children()

        if result.success and result.step == "confirm":
            self._sign_success += 1
            self._log("  ✓ %s 已签约 (%.1f秒)" % (label, result.elapsed), "ok")
            tag = "signed_ok"
        elif result.success and result.step == "initiate":
            self._sign_success += 1
            self._log(
                "  ◎ %s 已发起签约 (%.1f秒) [待确认]" % (label, result.elapsed),
                "warn",
            )
            tag = "signed_ok"
        else:
            self._sign_fail += 1
            step_label = {
                "void": "作废", "delete": "删除",
                "initiate": "发起", "confirm": "确认",
            }.get(result.step, result.step)
            self._log(
                "  ✗ %s 失败 [%s]: %s" % (label, step_label, result.error),
                "err",
            )
            tag = "signed_fail"

        if result.person_id in children:
            self.tree.item(result.person_id, tags=(tag,))

        self.progress.configure(value=done)
        self.var_progress_text.set("%d / %d" % (done, self._sign_total))

        elapsed = time.time() - self._sign_start_time
        speed = elapsed / done if done > 0 else 0
        self.var_stats.set(
            "成功: %d  失败: %d  速度: %.1f秒/人" % (
                self._sign_success, self._sign_fail, speed
            )
        )

    def _signing_finished(self):
        self._signing = False
        self.btn_start.configure(state=tk.NORMAL)
        self.btn_pause.configure(state=tk.DISABLED)
        self.btn_stop.configure(state=tk.DISABLED)
        self.btn_login.configure(state=tk.NORMAL)
        self.btn_query.configure(state=tk.NORMAL)
        self.btn_query_all.configure(state=tk.NORMAL)

        elapsed = time.time() - self._sign_start_time
        self._log("=" * 50, "info")
        self._log(
            "签约完成! 成功: %d, 失败: %d, 总耗时: %.1f秒" % (
                self._sign_success, self._sign_fail, elapsed
            ),
            "ok" if self._sign_fail == 0 else "warn",
        )

    def _on_pause(self):
        if self._paused:
            self._paused = False
            self.btn_pause.configure(text="⏸ 暂停")
            self._log("继续签约...", "info")
        else:
            self._paused = True
            self.btn_pause.configure(text="▶ 继续")
            self._log("已暂停", "warn")

    def _on_stop(self):
        self._stop_event.set()
        self._paused = False

    # ================================================================
    # Tab 2: Health Card - Connect
    # ================================================================

    def _on_hc_connect(self):
        openid = self.var_hc_openid.get().strip()
        if not openid:
            messagebox.showwarning("提示", "请输入微信OpenID")
            return

        self.btn_hc_connect.configure(state=tk.DISABLED)
        self.var_hc_status.set("正在连接...")
        self.lbl_hc_status.configure(style="Info.TLabel")
        self._hc_log("连接健康卡平台 (OpenID: %s)..." % openid[:20], "info")

        def worker():
            ok, msg = self.hc_client.connect(openid)
            if ok:
                cards = self.hc_client.get_card_list()
                self.after(0, lambda: self._hc_connect_done(True, msg, cards))
            else:
                self.after(0, lambda: self._hc_connect_done(False, msg, []))

        threading.Thread(target=worker, daemon=True).start()

    def _hc_connect_done(self, ok: bool, msg: str, cards: List[HealthCard]):
        self.btn_hc_connect.configure(state=tk.NORMAL)
        self.var_hc_status.set(msg)

        if ok:
            self.lbl_hc_status.configure(style="Success.TLabel")
            self.btn_hc_refresh.configure(state=tk.NORMAL)
            self._hc_log("✓ %s" % msg, "ok")

            self._hc_cards = cards
            self._hc_selected = set(c.health_card_id for c in cards)
            self.var_hc_check_all.set(True)
            self._refresh_hc_table()
            self._hc_log("找到 %d 张健康卡" % len(cards), "info")
            self._save_current_config()
        else:
            self.lbl_hc_status.configure(style="Error.TLabel")
            self._hc_log("✗ %s" % msg, "err")

    def _on_hc_refresh(self):
        if not self.hc_client.connected:
            return

        self.btn_hc_refresh.configure(state=tk.DISABLED)
        self._hc_log("刷新卡列表...", "info")

        def worker():
            cards = self.hc_client.get_card_list()
            self.after(0, lambda: self._hc_refresh_done(cards))

        threading.Thread(target=worker, daemon=True).start()

    def _hc_refresh_done(self, cards: List[HealthCard]):
        self.btn_hc_refresh.configure(state=tk.NORMAL)
        self._hc_cards = cards
        self._hc_selected = set(c.health_card_id for c in cards)
        self.var_hc_check_all.set(True)
        self._refresh_hc_table()
        self._hc_log("卡列表已刷新: %d 张" % len(cards), "ok")

    # ================================================================
    # Tab 2: Health Card - Table
    # ================================================================

    def _refresh_hc_table(self):
        self.hc_tree.delete(*self.hc_tree.get_children())
        for i, c in enumerate(self._hc_cards, 1):
            tags = ()
            if c.health_card_id in self._hc_selected:
                tags = ("selected",)

            gender_map = {"1": "男", "2": "女"}
            rpc_text = "已认证" if c.is_verified else "未认证"

            self.hc_tree.insert("", tk.END, iid=c.health_card_id, values=(
                i, c.name, c.id_card, c.age, c.age_category,
                gender_map.get(c.gender, c.gender), rpc_text, c.relation,
            ), tags=tags)

        verified = sum(1 for c in self._hc_cards if c.is_verified)
        self.var_hc_summary.set(
            "共 %d 张卡, 已认证 %d, 未认证 %d" % (
                len(self._hc_cards), verified, len(self._hc_cards) - verified
            )
        )
        self._update_hc_select_info()

    def _on_hc_tree_click(self, event):
        region = self.hc_tree.identify_region(event.x, event.y)
        if region == "heading":
            return
        item = self.hc_tree.identify_row(event.y)
        if not item:
            return
        if item in self._hc_selected:
            self._hc_selected.discard(item)
            self.hc_tree.item(item, tags=())
        else:
            self._hc_selected.add(item)
            self.hc_tree.item(item, tags=("selected",))
        self._update_hc_select_info()
        self.hc_tree.selection_remove(self.hc_tree.selection())
        return "break"

    def _on_hc_toggle_all(self):
        if self.var_hc_check_all.get():
            self._hc_selected = set(c.health_card_id for c in self._hc_cards)
        else:
            self._hc_selected = set()
        self._refresh_hc_table()

    def _update_hc_select_info(self):
        self.var_hc_select_info.set(
            "已选: %d / %d" % (len(self._hc_selected), len(self._hc_cards))
        )

    # ================================================================
    # Tab 2: Health Card - Confirm
    # ================================================================

    def _on_hc_start_confirm(self):
        if self._hc_confirming:
            return

        if not self.hc_client.connected:
            messagebox.showwarning("提示", "请先连接健康卡平台")
            return

        targets = [c for c in self._hc_cards if c.health_card_id in self._hc_selected]
        if not targets:
            messagebox.showwarning("提示", "请选择要处理的健康卡")
            return

        msg = "即将对 %d 张健康卡执行自动确认签约：\n\n" % len(targets)
        msg += "流程: 设置人脸认证 → 查询签约 → 确认待确认合同\n\n"
        msg += "是否继续？"
        if not messagebox.askyesno("确认操作", msg):
            return

        self._hc_confirming = True
        self._hc_stop.clear()

        self.btn_hc_confirm.configure(state=tk.DISABLED)
        self.btn_hc_stop.configure(state=tk.NORMAL)
        self.btn_hc_connect.configure(state=tk.DISABLED)
        self.btn_hc_refresh.configure(state=tk.DISABLED)

        self.hc_progress.configure(maximum=len(targets), value=0)
        self.var_hc_progress_text.set("0 / %d" % len(targets))
        self.var_hc_stats.set("")

        self._hc_log("=" * 50, "info")
        self._hc_log("开始批量确认: %d 张卡" % len(targets), "info")

        def worker():
            self._hc_confirm_worker(targets)

        threading.Thread(target=worker, daemon=True).start()

    def _hc_confirm_worker(self, targets: List[HealthCard]):
        success = 0
        fail = 0
        skipped = 0
        t0 = time.time()

        for i, card in enumerate(targets):
            if self._hc_stop.is_set():
                self.after(0, lambda: self._hc_log("已手动停止", "warn"))
                break

            self.after(
                0,
                lambda idx=i, c=card: self._hc_log(
                    "处理 [%d/%d] %s (%s, %s)" % (
                        idx + 1, len(targets), c.name, c.age_category or "?", c.id_card
                    ),
                    "info",
                ),
            )

            result = self.hc_client.process_card(
                card,
                log_cb=lambda msg, tag="", _=None: self._hc_log(msg, tag),
            )

            if result is None:
                tag = "skipped"
                skipped += 1
            elif result.success:
                tag = "confirm_ok"
                success += 1
            else:
                tag = "confirm_fail"
                fail += 1

            def _update_row(idx=i, t=tag, s=success, f=fail, sk=skipped):
                hcid = targets[idx].health_card_id
                children = self.hc_tree.get_children()
                if hcid in children:
                    self.hc_tree.item(hcid, tags=(t,))
                self.hc_progress.configure(value=idx + 1)
                self.var_hc_progress_text.set("%d / %d" % (idx + 1, len(targets)))
                elapsed = time.time() - t0
                speed = elapsed / (idx + 1)
                self.var_hc_stats.set(
                    "确认: %d  失败: %d  跳过: %d  速度: %.1f秒/人" % (s, f, sk, speed)
                )

            self.after(0, _update_row)
            time.sleep(0.3)

        def _done(s=success, f=fail, sk=skipped):
            self._hc_confirming = False
            self.btn_hc_confirm.configure(state=tk.NORMAL)
            self.btn_hc_stop.configure(state=tk.DISABLED)
            self.btn_hc_connect.configure(state=tk.NORMAL)
            if self.hc_client.connected:
                self.btn_hc_refresh.configure(state=tk.NORMAL)

            elapsed = time.time() - t0
            self._hc_log("=" * 50, "info")
            self._hc_log(
                "确认完成! 成功: %d, 失败: %d, 跳过: %d, 耗时: %.1f秒" % (
                    s, f, sk, elapsed
                ),
                "ok" if f == 0 else "warn",
            )

        self.after(0, _done)

    def _on_hc_stop(self):
        self._hc_stop.set()

    # ================================================================
    # Close
    # ================================================================

    def _on_close(self):
        if self._signing or self._hc_confirming:
            if not messagebox.askyesno("确认退出", "正在执行操作，确定要退出吗？"):
                return
            self._stop_event.set()
            self._hc_stop.set()
            self._paused = False
        if self._proxy and self._proxy_running:
            clear_system_proxy()
            self._proxy.stop()
        if self._cap_proxy and self._cap_running:
            clear_system_proxy()
            self._cap_proxy.stop()
        self._save_current_config()
        self.destroy()


def main():
    try:
        from gmssl.sm4 import CryptSM4
    except ImportError:
        pass

    app = GulfSignApp()
    app.mainloop()


if __name__ == "__main__":
    main()
