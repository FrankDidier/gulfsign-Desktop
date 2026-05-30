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
from tkinter import ttk, messagebox, filedialog, scrolledtext
from datetime import datetime
from typing import Dict, List, Optional, Tuple, Any
import webbrowser
import requests
from urllib.parse import urljoin, quote

if getattr(sys, "frozen", False):
    _bundle_dir = getattr(sys, "_MEIPASS", os.path.dirname(sys.executable))
    if _bundle_dir not in sys.path:
        sys.path.insert(0, _bundle_dir)

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

VERSION = "3.0.0"
APP_TITLE = "湾流签约助手 v%s" % VERSION
CONFIG_FILE = "gulfsign_config.json"


def _config_path() -> str:
    if getattr(sys, "frozen", False):
        base = os.path.dirname(sys.executable)
    else:
        base = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(base, CONFIG_FILE)


def load_config() -> dict:
    """加载配置，使用新的ConfigManager"""
    config_manager = ConfigManager()
    return config_manager.load()


def save_config(cfg: dict):
    """保存配置，使用新的ConfigManager"""
    config_manager = ConfigManager()
    config_manager.save(cfg)


_HJDZ_PRESETS = [
    ("湖南省 (全省)", "430000000000"),
    ("长沙市", "430100000000"),
    ("株洲市", "430200000000"),
    ("湘潭市", "430300000000"),
    ("衡阳市", "430400000000"),
    ("邵阳市", "430500000000"),
    ("岳阳市", "430600000000"),
    ("常德市", "430700000000"),
    ("张家界市", "430800000000"),
    ("益阳市", "430900000000"),
    ("郴州市", "431000000000"),
    ("永州市", "431100000000"),
    ("怀化市", "431200000000"),
    ("娄底市", "431300000000"),
    ("湘西州", "433100000000"),
]


class ProvinceLookupDialog(tk.Toplevel):
    """全省个案查询 + 跨机构发起医生申请的对话框。"""

    def __init__(self, master: "GulfSignApp"):
        super().__init__(master)
        self.app = master
        self.client = master.client
        self.matches: List[ProvinceMatch] = []
        self._busy = False

        self.title("全省找人 / 跨机构发起签约")
        self.geometry("1000x620")
        self.transient(master)
        self.minsize(900, 560)

        cfg = master._cfg
        self.var_sfzh = tk.StringVar()
        self.var_xm = tk.StringVar()
        self.var_pwd = tk.StringVar(value=cfg.get("province_password", ""))
        self.var_remember_pwd = tk.BooleanVar(
            value=bool(cfg.get("province_password"))
        )
        self.var_hjdz = tk.StringVar(
            value=cfg.get("province_hjdz", _HJDZ_PRESETS[0][1])
        )
        self.var_exclude = tk.BooleanVar(value=False)
        self.var_status = tk.StringVar(value="提示：身份证号或姓名至少填一项")

        self._build_ui()
        self._update_action_buttons()

    # --- UI ---

    def _build_ui(self):
        pad = ttk.Frame(self, padding=10)
        pad.pack(fill=tk.BOTH, expand=True)

        guide = ttk.LabelFrame(pad, text=" 说明 ", padding=6)
        guide.pack(fill=tk.X, pady=(0, 6))
        guide_text = (
            "本工具调用 3.0 系统「全省个案查询」(ACTION=10)，"
            "可越过本机构边界定位任何湖南省内的居民档案。\n"
            "命中后可一键「跨机构发起医生申请」(STATUS=5)，"
            "供居民户籍地的责任医生确认；或先「填入查询条件」回主界面继续操作。\n"
            "注意：身份证号查询可全省 (430000000000)；姓名查询时户籍地必须细化到地市级。"
        )
        try:
            bg = self.cget("background")
        except Exception:
            bg = "#f0f0f0"
        tw = tk.Text(
            guide, height=4, wrap=tk.WORD, state=tk.NORMAL,
            font=("", 10), relief=tk.FLAT, background=bg,
        )
        tw.insert("1.0", guide_text)
        tw.configure(state=tk.DISABLED)
        tw.pack(fill=tk.X)

        form = ttk.LabelFrame(pad, text=" 查询条件 ", padding=6)
        form.pack(fill=tk.X, pady=(0, 6))

        r0 = ttk.Frame(form)
        r0.pack(fill=tk.X)
        ttk.Label(r0, text="身份证号:").pack(side=tk.LEFT)
        ttk.Entry(r0, textvariable=self.var_sfzh, width=22).pack(
            side=tk.LEFT, padx=(4, 12)
        )
        ttk.Label(r0, text="姓名:").pack(side=tk.LEFT)
        ttk.Entry(r0, textvariable=self.var_xm, width=10).pack(
            side=tk.LEFT, padx=(4, 12)
        )
        ttk.Label(r0, text="户籍地范围:").pack(side=tk.LEFT)
        cb = ttk.Combobox(
            r0, width=18, state="readonly",
            values=[label for label, _ in _HJDZ_PRESETS],
        )
        for label, code in _HJDZ_PRESETS:
            if code == self.var_hjdz.get():
                cb.set(label)
                break
        else:
            cb.set(_HJDZ_PRESETS[0][0])

        def _on_hjdz_change(_evt=None):
            for label, code in _HJDZ_PRESETS:
                if label == cb.get():
                    self.var_hjdz.set(code)
                    return
        cb.bind("<<ComboboxSelected>>", _on_hjdz_change)
        cb.pack(side=tk.LEFT, padx=(4, 12))
        ttk.Checkbutton(
            r0, text="排除注销人口", variable=self.var_exclude,
        ).pack(side=tk.LEFT, padx=(0, 12))

        r1 = ttk.Frame(form)
        r1.pack(fill=tk.X, pady=(6, 0))
        ttk.Label(r1, text="登录密码:").pack(side=tk.LEFT)
        ttk.Entry(
            r1, textvariable=self.var_pwd, width=18, show="*",
        ).pack(side=tk.LEFT, padx=(4, 8))
        ttk.Label(
            r1, text="(全省查档需要再输一次当前账号密码作为安全码)",
            foreground="gray",
        ).pack(side=tk.LEFT)
        ttk.Checkbutton(
            r1, text="记住密码", variable=self.var_remember_pwd,
        ).pack(side=tk.LEFT, padx=(8, 0))

        r2 = ttk.Frame(form)
        r2.pack(fill=tk.X, pady=(6, 0))
        self.btn_search = ttk.Button(
            r2, text="🔍 查询", command=self._on_search,
        )
        self.btn_search.pack(side=tk.LEFT, padx=(0, 8))
        ttk.Label(r2, textvariable=self.var_status, style="Info.TLabel").pack(
            side=tk.LEFT
        )

        # 结果表
        table_frame = ttk.LabelFrame(pad, text=" 命中结果 ", padding=4)
        table_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 6))

        cols = (
            "name", "id_card", "age", "gender", "address",
            "doctor", "archive_no", "realname",
        )
        col_names = {
            "name": "姓名", "id_card": "身份证号", "age": "年龄",
            "gender": "性别", "address": "户籍地",
            "doctor": "责任医生", "archive_no": "档案号",
            "realname": "实名/面访",
        }
        col_widths = {
            "name": 70, "id_card": 150, "age": 40,
            "gender": 50, "address": 220, "doctor": 80,
            "archive_no": 130, "realname": 80,
        }

        tree_wrap = ttk.Frame(table_frame)
        tree_wrap.pack(fill=tk.BOTH, expand=True)
        self.tree = ttk.Treeview(
            tree_wrap, columns=cols, show="headings", selectmode="browse",
        )
        for c in cols:
            self.tree.heading(c, text=col_names[c])
            self.tree.column(
                c, width=col_widths.get(c, 80), minwidth=40,
                anchor=("center" if c in ("age", "gender", "realname") else "w"),
            )
        vsb = ttk.Scrollbar(
            tree_wrap, orient=tk.VERTICAL, command=self.tree.yview,
        )
        self.tree.configure(yscrollcommand=vsb.set)
        self.tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        tree_wrap.grid_rowconfigure(0, weight=1)
        tree_wrap.grid_columnconfigure(0, weight=1)
        self.tree.bind("<<TreeviewSelect>>", self._on_tree_select)

        # 详情区
        detail_frame = ttk.LabelFrame(pad, text=" 已有家医签约（按选中居民） ", padding=4)
        detail_frame.pack(fill=tk.BOTH, expand=False, pady=(0, 6))

        d_cols = ("contract_code", "status", "agreement", "doctor")
        d_names = {
            "contract_code": "合同编号", "status": "状态",
            "agreement": "协议期", "doctor": "签约医生",
        }
        d_widths = {
            "contract_code": 280, "status": 80,
            "agreement": 200, "doctor": 100,
        }
        self.detail_tree = ttk.Treeview(
            detail_frame, columns=d_cols, show="headings",
            height=4, selectmode="none",
        )
        for c in d_cols:
            self.detail_tree.heading(c, text=d_names[c])
            self.detail_tree.column(
                c, width=d_widths.get(c, 100), minwidth=40,
                anchor=("center" if c == "status" else "w"),
            )
        self.detail_tree.pack(fill=tk.BOTH, expand=True)

        # 操作按钮
        btn_bar = ttk.Frame(pad)
        btn_bar.pack(fill=tk.X)

        self.btn_apply = ttk.Button(
            btn_bar, text="↑ 填入主界面查询条件",
            command=self._on_apply_to_main, state=tk.DISABLED,
        )
        self.btn_apply.pack(side=tk.LEFT, padx=(0, 8))

        self.btn_initiate = ttk.Button(
            btn_bar, text="✦ 跨机构发起医生申请 (STATUS=5)",
            command=self._on_initiate, state=tk.DISABLED,
        )
        self.btn_initiate.pack(side=tk.LEFT, padx=(0, 8))

        ttk.Button(btn_bar, text="关闭", command=self.destroy).pack(side=tk.RIGHT)

    # --- Logic ---

    def _set_busy(self, busy: bool):
        self._busy = busy
        state = tk.DISABLED if busy else tk.NORMAL
        self.btn_search.configure(state=state)
        if busy:
            self.btn_apply.configure(state=tk.DISABLED)
            self.btn_initiate.configure(state=tk.DISABLED)
        else:
            self._update_action_buttons()

    def _selected_match(self) -> Optional[ProvinceMatch]:
        sel = self.tree.selection()
        if not sel:
            return None
        try:
            idx = int(sel[0])
        except ValueError:
            return None
        if 0 <= idx < len(self.matches):
            return self.matches[idx]
        return None

    def _update_action_buttons(self):
        if self._busy:
            return
        m = self._selected_match()
        state = tk.NORMAL if m else tk.DISABLED
        self.btn_apply.configure(state=state)
        self.btn_initiate.configure(state=state)

    def _on_search(self):
        if not self.app._ensure_session_usable("查找"):
            return
        sfzh = self.var_sfzh.get().strip()
        xm = self.var_xm.get().strip()
        pwd = self.var_pwd.get().strip()
        if not sfzh and not xm:
            messagebox.showwarning("提示", "身份证号或姓名至少填一项")
            return
        if not pwd:
            messagebox.showwarning(
                "提示", "请填写当前账号的登录密码（全省查档安全码）"
            )
            return
        if not sfzh and self.var_hjdz.get() == "430000000000":
            if not messagebox.askyesno(
                "提示",
                "仅按姓名 + 全省范围查询通常会被拒绝。\n\n"
                "建议把户籍地范围缩到地市级。仍要继续吗？",
            ):
                return

        self._set_busy(True)
        self.var_status.set("正在查询...")
        if self.var_remember_pwd.get():
            self.app._cfg["province_password"] = pwd
        else:
            self.app._cfg.pop("province_password", None)
        self.app._cfg["province_hjdz"] = self.var_hjdz.get()
        save_config(self.app._cfg)

        def worker():
            matches, total, err = self.client.query_province_wide(
                sfzh=sfzh,
                name=xm,
                hjdz=self.var_hjdz.get() or "430000000000",
                password=pwd,
                exclude_cancelled=self.var_exclude.get(),
            )
            self.after(0, lambda: self._on_search_done(matches, total, err))

        threading.Thread(target=worker, daemon=True).start()

    def _on_search_done(
        self, matches: List[ProvinceMatch], total: int, err: str,
    ):
        self._set_busy(False)
        self.tree.delete(*self.tree.get_children())
        self.detail_tree.delete(*self.detail_tree.get_children())
        self.matches = matches

        if err:
            self.var_status.set("✗ %s" % err)
            messagebox.showerror("查询失败", err)
            return

        if not matches:
            self.var_status.set("查询成功，但没有命中记录")
            return

        for i, m in enumerate(matches):
            flags = []
            if m.is_realname:
                flags.append("实名")
            if m.is_visited:
                flags.append("面访")
            flags_text = "/".join(flags) if flags else "-"
            self.tree.insert("", tk.END, iid=str(i), values=(
                m.name, m.id_card, m.age, m.gender, m.address,
                m.doctor, m.archive_no, flags_text,
            ))
        self.var_status.set("命中 %d 人 (共 %d 条)" % (len(matches), total))
        self.tree.selection_set("0")
        self.tree.focus("0")
        self._on_load_contracts(matches[0])

    def _on_tree_select(self, _evt=None):
        m = self._selected_match()
        if m:
            self._on_load_contracts(m)
        self._update_action_buttons()

    def _on_load_contracts(self, m: ProvinceMatch):
        self.detail_tree.delete(*self.detail_tree.get_children())

        def worker():
            recs = self.client.list_personal_b0105(m.person_id)
            self.after(0, lambda: self._render_contracts(recs))

        threading.Thread(target=worker, daemon=True).start()

    def _render_contracts(self, recs: List[Dict]):
        self.detail_tree.delete(*self.detail_tree.get_children())
        if not recs:
            self.detail_tree.insert("", tk.END, values=(
                "(无家医签约记录)", "", "", "",
            ))
            return
        for r in recs:
            agreement = "%s ~ %s" % (
                r.get("agreement_start", "") or "?",
                r.get("agreement_end", "") or "?",
            )
            self.detail_tree.insert("", tk.END, values=(
                r.get("contract_code", ""),
                r.get("status_text", ""),
                agreement,
                r.get("doctor", ""),
            ))

    def _on_apply_to_main(self):
        m = self._selected_match()
        if not m:
            return
        self.app.var_idcard_filter.set(m.id_card or "")
        self.app.var_name_filter.set(m.name or "")
        self.app.var_status.set("全部")
        messagebox.showinfo(
            "已填入",
            "已把身份证号 / 姓名填入主界面查询条件。\n\n"
            "若该居民属于本机构，可点击「查询(首页)」加载并签约。\n"
            "若属于其他机构，请改用本对话框中的「跨机构发起」。",
        )
        self.lift()

    def _on_initiate(self):
        m = self._selected_match()
        if not m:
            return

        warn = (
            "即将以当前登录账号 (%s) 的名义，跨机构为以下居民"
            "发起一份医生申请 (STATUS=5)：\n\n"
            "  姓名: %s\n  身份证: %s\n  户籍地: %s\n  责任医生: %s\n\n"
            "说明：\n"
            "• 合同会先落到「医生申请」状态，需户籍地责任医生确认才生效；\n"
            "• 若失败 / 不需要，可在主界面「3.0系统签约」 → 状态选「医生申请」"
            "找到该合同并删除；\n"
            "• 当前账号若没有跨机构权限，发起会被服务端拒绝。\n\n"
            "确认继续？"
        ) % (
            self.client.org_code or self.client.account or "?",
            m.name, m.id_card, m.address, m.doctor or "(无)",
        )
        if not messagebox.askyesno("确认跨机构发起", warn):
            return

        self._set_busy(True)
        self.var_status.set("正在跨机构发起 %s ..." % m.name)

        agree_start = self.app.var_agree_start.get().strip()
        agree_end = self.app.var_agree_end.get().strip()
        team_name = self.app.var_team.get().strip()
        doctor = self.app.var_doctor.get().strip()
        pop_code = self.app._get_pop_type_code()

        def worker():
            res = self.client.initiate_signing(
                person_id=m.person_id,
                team_name=team_name,
                doctor_name=doctor,
                service_type=pop_code,
                agreement_start=agree_start,
                agreement_end=agree_end,
            )
            self.after(0, lambda: self._on_initiate_done(m, res))

        threading.Thread(target=worker, daemon=True).start()

    def _on_initiate_done(self, m: ProvinceMatch, res: SignResult):
        self._set_busy(False)
        if res.success:
            self.var_status.set(
                "✓ 跨机构发起成功 — 合同 %s（STATUS=5，待户籍地医生确认）"
                % res.contract_code
            )
            messagebox.showinfo(
                "发起成功",
                "已为 %s 创建医生申请。\n\n"
                "合同编号：%s\n"
                "状态：医生申请 (STATUS=5)\n\n"
                "下一步：请联系户籍地（%s）责任医生在他们端「确认」该合同，"
                "或参考《查证记录_曾桃英_v1.txt》6.A 方案换户籍地账号操作。"
                % (m.name, res.contract_code, m.address),
            )
            self._on_load_contracts(m)
        else:
            self.var_status.set("✗ 发起失败：%s" % res.error)
            messagebox.showerror("发起失败", res.error or "未知错误")


class GulfSignApp(tk.Tk):

    def __init__(self):
        super().__init__()

        self.title(APP_TITLE)
        self.geometry("980x800")
        self.minsize(860, 700)

        self.client = PH3Client()
        self.hc_client = HealthCardClient()
        self.sign_engine = SigningEngine(self.hc_client, self.client)
        
        # 新增组件
        self.license_client = LicenseClient()
        self.config_manager = ConfigManager()
        self.batch_processor = BatchProcessor()
        
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

        self.capability_profile = {
            "mode": "unknown",
            "reason": "未检测",
            "status0_total": 0,
            "status5_total": 0,
            "status6_total": 0,
        }
        self._pending_export_after_batch = False

        # 创建UI变量
        self.var_url = tk.StringVar()
        self.var_account = tk.StringVar()
        self.var_password = tk.StringVar()
        self.var_org = tk.StringVar()
        self.var_doctor = tk.StringVar()
        self.var_team = tk.StringVar()
        self.var_delay = tk.StringVar()
        self.var_pop_type = tk.StringVar()
        self.var_agree_start = tk.StringVar()
        self.var_agree_end = tk.StringVar()
        self.var_max_count = tk.StringVar()
        self.var_hc_openid = tk.StringVar()
        self.var_hc_orgcode = tk.StringVar()
        self.var_hc_team = tk.StringVar()
        self.var_hc_doctor = tk.StringVar()
        self.var_hc_start = tk.StringVar()
        self.var_hc_end = tk.StringVar()
        self.var_license_user = tk.StringVar()
        self.var_license_password = tk.StringVar()
        self.var_license_server = tk.StringVar()
        self.var_max_workers = tk.StringVar()
        self.var_batch_size = tk.StringVar()

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
        style.configure("RouteUnknown.TLabel", foreground="#6b7280")
        style.configure("RouteWarn.TLabel", foreground="#d97706")
        style.configure("RouteDirect.TLabel", foreground="#16a34a")
        style.configure("Header.TLabel", font=("", 11, "bold"))

        main = ttk.Frame(self, padding=8)
        main.pack(fill=tk.BOTH, expand=True)

        self.notebook = ttk.Notebook(main)
        self.notebook.pack(fill=tk.BOTH, expand=True)

        tab1 = ttk.Frame(self.notebook, padding=4)
        tab2 = ttk.Frame(self.notebook, padding=4)
        tab3 = ttk.Frame(self.notebook, padding=4)
        tab4 = ttk.Frame(self.notebook, padding=4)
        tab5 = ttk.Frame(self.notebook, padding=4)

        self.notebook.add(tab1, text=" 3.0系统签约 ")
        self.notebook.add(tab2, text=" 健康卡确认 ")
        self.notebook.add(tab3, text=" 获取OpenID ")
        self.notebook.add(tab4, text=" 流量抓包 ")
        self.notebook.add(tab5, text=" 许可证配置 ")

        self._build_ph3_tab(tab1)
        self._build_hc_tab(tab2)
        self._build_openid_tab(tab3)
        self._build_capture_tab(tab4)
        self._build_license_tab(tab5)

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
        """增强登录界面 - 解决客户反馈的连接问题"""
        frame = ttk.LabelFrame(parent, text=" 系统登录与连接诊断 ", padding=10)
        frame.pack(fill=tk.X, pady=(0, 10))
        
        # 创建UI组件
        self._create_login_info_bar(frame)
        self._create_login_diagnostic_area(frame)
        self._create_login_options(frame)
        self._create_login_status_bar(frame)
        
        # 初始诊断
        self._run_login_initial_diagnosis()
    
    def _create_login_info_bar(self, parent):
        """创建登录信息栏"""
        info_frame = ttk.Frame(parent)
        info_frame.pack(fill=tk.X, pady=(0, 10))
        
        # 系统地址
        url_frame = ttk.Frame(info_frame)
        url_frame.pack(fill=tk.X, pady=(0, 5))
        
        ttk.Label(url_frame, text="公卫3.0系统:", font=("Arial", 10, "bold")).pack(side=tk.LEFT)
        self.enhanced_url_var = tk.StringVar(value=self.client.base_url if hasattr(self.client, 'base_url') else "https://ggws.hnhfpc.gov.cn")
        ttk.Label(url_frame, textvariable=self.enhanced_url_var, foreground="blue").pack(side=tk.LEFT, padx=(5, 0))
        
        # 当前账号状态
        account_frame = ttk.Frame(info_frame)
        account_frame.pack(fill=tk.X)
        
        ttk.Label(account_frame, text="当前账号:", font=("Arial", 10, "bold")).pack(side=tk.LEFT)
        account = self._cfg.get("username", "未设置")
        self.enhanced_account_var = tk.StringVar(value=account)
        ttk.Label(account_frame, textvariable=self.enhanced_account_var, 
                 foreground="green" if account else "red").pack(side=tk.LEFT, padx=(5, 0))
        
        # 连接状态指示器
        status_frame = ttk.Frame(info_frame)
        status_frame.pack(fill=tk.X, pady=(5, 0))
        
        ttk.Label(status_frame, text="连接状态:").pack(side=tk.LEFT)
        self.enhanced_connection_status_var = tk.StringVar(value="待检测")
        self.enhanced_connection_status_label = ttk.Label(
            status_frame, 
            textvariable=self.enhanced_connection_status_var,
            font=("Arial", 10)
        )
        self.enhanced_connection_status_label.pack(side=tk.LEFT, padx=(5, 0))
    
    def _create_login_diagnostic_area(self, parent):
        """创建登录诊断区域"""
        diag_frame = ttk.LabelFrame(parent, text=" 连接诊断 ", padding=10)
        diag_frame.pack(fill=tk.X, pady=(0, 10))
        
        # 诊断结果显示
        self.enhanced_diag_text = scrolledtext.ScrolledText(diag_frame, height=8, wrap=tk.WORD)
        self.enhanced_diag_text.pack(fill=tk.X)
        self.enhanced_diag_text.configure(state=tk.DISABLED)
        
        # 诊断按钮区域
        button_frame = ttk.Frame(diag_frame)
        button_frame.pack(fill=tk.X, pady=(5, 0))
        
        # 基础诊断按钮
        self.enhanced_diagnose_btn = ttk.Button(
            button_frame,
            text="🔍 基础诊断",
            command=self._run_login_diagnosis,
            width=12
        )
        self.enhanced_diagnose_btn.pack(side=tk.LEFT)
        
        # 详细诊断按钮
        self.enhanced_detailed_diagnose_btn = ttk.Button(
            button_frame,
            text="🔬 详细诊断",
            command=self._run_detailed_diagnosis,
            width=12
        )
        self.enhanced_detailed_diagnose_btn.pack(side=tk.LEFT, padx=(10, 0))
        
        # 同步配置按钮
        self.enhanced_sync_btn = ttk.Button(
            button_frame,
            text="🔄 同步配置",
            command=self._sync_login_configuration,
            width=12,
            state=tk.DISABLED
        )
        self.enhanced_sync_btn.pack(side=tk.LEFT, padx=(10, 0))
    
    def _create_login_options(self, parent):
        """创建登录选项"""
        login_frame = ttk.LabelFrame(parent, text=" 登录方式 ", padding=10)
        login_frame.pack(fill=tk.X)
        
        # 方式1: 网页跳转登录（推荐）
        web_frame = ttk.Frame(login_frame)
        web_frame.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Label(web_frame, text="方式1: 网页跳转登录", font=("Arial", 11, "bold")).pack(anchor=tk.W)
        ttk.Label(web_frame, text="直接打开公卫3.0系统登录页面，在浏览器中完成登录").pack(anchor=tk.W)
        
        web_button_frame = ttk.Frame(web_frame)
        web_button_frame.pack(fill=tk.X, pady=(5, 0))
        
        self.enhanced_web_login_btn = ttk.Button(
            web_button_frame,
            text="🌐 跳转到3.0系统登录",
            command=self._open_web_login,
            style="Accent.TButton",
            width=20
        )
        self.enhanced_web_login_btn.pack(side=tk.LEFT)
        
        # 方式2: API直接登录
        api_frame = ttk.Frame(login_frame)
        api_frame.pack(fill=tk.X)
        
        ttk.Label(api_frame, text="方式2: API直接登录", font=("Arial", 11, "bold")).pack(anchor=tk.W)
        ttk.Label(api_frame, text="使用现有账号密码直接登录（需要正确配置）").pack(anchor=tk.W)
        
        api_form_frame = ttk.Frame(api_frame)
        api_form_frame.pack(fill=tk.X, pady=(5, 0))
        
        # 账号输入
        row1 = ttk.Frame(api_form_frame)
        row1.pack(fill=tk.X, pady=(0, 5))
        
        ttk.Label(row1, text="账号:", width=8).pack(side=tk.LEFT)
        self.enhanced_api_account_var = tk.StringVar(value=self._cfg.get("username", ""))
        ttk.Entry(row1, textvariable=self.enhanced_api_account_var, width=25).pack(side=tk.LEFT)
        
        # 密码输入
        row2 = ttk.Frame(api_form_frame)
        row2.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Label(row2, text="密码:", width=8).pack(side=tk.LEFT)
        self.enhanced_api_password_var = tk.StringVar()
        ttk.Entry(row2, textvariable=self.enhanced_api_password_var, width=25, show="*").pack(side=tk.LEFT)
        
        # API登录按钮
        self.enhanced_api_login_btn = ttk.Button(
            api_form_frame,
            text="API直接登录",
            command=self._perform_api_login,
            width=15
        )
        self.enhanced_api_login_btn.pack()
    
    def _create_login_status_bar(self, parent):
        """创建登录状态栏"""
        self.enhanced_status_var = tk.StringVar(value="就绪")
        status_frame = ttk.Frame(parent)
        status_frame.pack(fill=tk.X, pady=(10, 0))
        
        status_label = ttk.Label(
            status_frame,
            textvariable=self.enhanced_status_var,
            relief=tk.SUNKEN,
            anchor=tk.W,
            padding=(5, 2)
        )
        status_label.pack(fill=tk.X)

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
        self.btn_query_all.pack(side=tk.LEFT, padx=(0, 8))

        self.btn_province_query = ttk.Button(
            r0, text="🌐 全省找人 / 跨机构发起",
            command=self._on_open_province_dialog,
        )
        self.btn_province_query.pack(side=tk.LEFT, padx=(0, 16))

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

        r4 = ttk.Frame(frame)
        r4.pack(fill=tk.X, pady=(4, 0))

        self.var_route_mode = tk.StringVar(
            value="能力路由: 未检测（登录后自动检测）"
        )
        self.lbl_route_mode = ttk.Label(
            r4, textvariable=self.var_route_mode, style="RouteUnknown.TLabel",
        )
        self.lbl_route_mode.pack(side=tk.LEFT)

        self.btn_smart_start = ttk.Button(
            r4, text="⚡ 智能执行", command=self._on_start_smart_signing,
        )
        self.btn_smart_start.pack(side=tk.RIGHT, padx=(8, 0))

        self.btn_family_batch = ttk.Button(
            r4, text="🏠 家庭批量发起", command=self._on_family_batch_initiate,
        )
        self.btn_family_batch.pack(side=tk.RIGHT, padx=(8, 0))

        self.btn_export_relay = ttk.Button(
            r4, text="📦 导出接力包", command=self._on_export_relay_package,
        )
        self.btn_export_relay.pack(side=tk.RIGHT)

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
        self._build_hc_signing_config(parent)
        self._build_hc_card_table(parent)
        self._build_hc_control(parent)
        self._build_hc_log(parent)

    def _build_hc_workflow_guide(self, parent):
        frame = ttk.LabelFrame(parent, text=" 操作流程（每批最多9人）", padding=6)
        frame.pack(fill=tk.X, pady=(0, 4))

        guide = (
            "① 微信小程序\"我的健康卡\" → 添加家庭成员 → 绑定签约对象（输入姓名+身份证号）\n"
            "② 本软件点击「刷新卡列表」→ 看到绑定的卡 → 点击「一键全流程签约」\n"
            "③ 自动流程: 绕过人脸 → 查询状态 → 创建合同 → 确认签约 (全自动)\n"
            "④ 完成后解绑已签约的卡 → 继续绑定下一批 → 重复以上步骤"
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

    def _build_hc_signing_config(self, parent):
        frame = ttk.LabelFrame(parent, text=" 签约配置 ", padding=6)
        frame.pack(fill=tk.X, pady=(0, 4))

        r0 = ttk.Frame(frame)
        r0.pack(fill=tk.X)

        ttk.Label(r0, text="机构代码:").pack(side=tk.LEFT)
        self.var_hc_orgcode = tk.StringVar()
        ttk.Entry(r0, textvariable=self.var_hc_orgcode, width=20).pack(
            side=tk.LEFT, padx=(4, 12)
        )

        ttk.Label(r0, text="签约团队:").pack(side=tk.LEFT)
        self.var_hc_team = tk.StringVar()
        ttk.Entry(r0, textvariable=self.var_hc_team, width=16).pack(
            side=tk.LEFT, padx=(4, 12)
        )

        ttk.Label(r0, text="签约医生:").pack(side=tk.LEFT)
        self.var_hc_doctor = tk.StringVar()
        ttk.Entry(r0, textvariable=self.var_hc_doctor, width=10).pack(
            side=tk.LEFT, padx=(4, 0)
        )

        r1 = ttk.Frame(frame)
        r1.pack(fill=tk.X, pady=(4, 0))

        ttk.Label(r1, text="协议开始:").pack(side=tk.LEFT)
        self.var_hc_start = tk.StringVar()
        ttk.Entry(r1, textvariable=self.var_hc_start, width=10).pack(
            side=tk.LEFT, padx=(4, 8)
        )

        ttk.Label(r1, text="协议结束:").pack(side=tk.LEFT)
        self.var_hc_end = tk.StringVar()
        ttk.Entry(r1, textvariable=self.var_hc_end, width=10).pack(
            side=tk.LEFT, padx=(4, 8)
        )

        ttk.Label(r1, text="(如 20260101 ~ 20291231, 留空=自动3年)").pack(
            side=tk.LEFT, padx=(4, 0)
        )

        self.var_hc_auto_create = tk.BooleanVar(value=True)
        ttk.Checkbutton(
            r1, text="自动创建合同(未签约居民)",
            variable=self.var_hc_auto_create,
        ).pack(side=tk.RIGHT)

        r2 = ttk.Frame(frame)
        r2.pack(fill=tk.X, pady=(4, 0))

        self.btn_hc_sync_from_ph3 = ttk.Button(
            r2, text="从3.0系统同步配置",
            command=self._on_hc_sync_from_ph3,
        )
        self.btn_hc_sync_from_ph3.pack(side=tk.LEFT, padx=(0, 8))

        ttk.Label(
            r2,
            text="(登录3.0系统后可一键同步机构代码、医生、团队信息)",
            foreground="gray",
        ).pack(side=tk.LEFT)

    def _on_hc_sync_from_ph3(self):
        """Sync signing config from the logged-in 3.0 system."""
        if not self._ensure_session_usable("从3.0同步配置"):
            return

        self.btn_hc_sync_from_ph3.configure(state=tk.DISABLED)
        self._hc_log("正在从3.0系统同步配置...", "info")

        def worker():
            synced = []
            orgcode = self.client.org_code
            if orgcode:
                synced.append("机构代码(%s)" % orgcode)
            if self.client.doctor_name:
                synced.append("医生(%s)" % self.client.doctor_name)

            team_guid, team_name = "", ""
            try:
                teams = self.sign_engine._teams_from_ph3()
                if teams:
                    first = teams[0]
                    team_guid = first.get("id", first.get("guid", ""))
                    team_name = first.get("name", "")
                    synced.append("团队(%s)" % team_name)
                    self.after(0, lambda tn=team_name: self.var_hc_team.set(tn))
            except Exception as e:
                self.after(0, lambda: self._hc_log(
                    "团队查询失败: %s" % e, "warn"
                ))

            pkg_guids, pkg_names = "", ""
            try:
                pkg_guids, pkg_names = self.client._load_service_packs("0")
                if pkg_guids:
                    synced.append("服务包(%d个)" % len(pkg_guids.split(",")))
            except Exception as e:
                self.after(0, lambda: self._hc_log(
                    "服务包查询失败: %s" % e, "warn"
                ))

            def done():
                self.btn_hc_sync_from_ph3.configure(state=tk.NORMAL)
                if orgcode:
                    self.var_hc_orgcode.set(orgcode)
                if self.client.doctor_name:
                    self.var_hc_doctor.set(self.client.doctor_name)

                self.sign_engine._cached_teams[orgcode] = (
                    [{"id": team_guid, "name": team_name}] if team_guid else []
                )
                if pkg_guids:
                    self.sign_engine._cached_packages["%s|" % orgcode] = (
                        pkg_guids, pkg_names,
                    )

                if synced:
                    self._hc_log("已同步: %s" % ", ".join(synced), "ok")
                else:
                    self._hc_log("3.0系统无可同步信息", "warn")
                self._save_current_config()

            self.after(0, done)

        threading.Thread(target=worker, daemon=True).start()

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
            "gender", "rpc_status", "bypass", "relation",
        )
        col_names = {
            "seq": "#", "name": "姓名", "id_card": "身份证号",
            "age": "年龄", "category": "人群分类",
            "gender": "性别", "rpc_status": "人脸认证",
            "bypass": "需绕行", "relation": "关系",
        }
        col_widths = {
            "seq": 35, "name": 80, "id_card": 170, "age": 45,
            "category": 70, "gender": 45, "rpc_status": 80,
            "bypass": 55, "relation": 50,
        }
        col_anchors = {
            "seq": "center", "name": "center", "age": "center",
            "category": "center", "gender": "center",
            "rpc_status": "center", "bypass": "center",
            "relation": "center",
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
        frame = ttk.LabelFrame(parent, text=" 批量签约 ", padding=6)
        frame.pack(fill=tk.X, pady=(0, 4))

        r0 = ttk.Frame(frame)
        r0.pack(fill=tk.X)

        self.btn_hc_confirm = ttk.Button(
            r0, text="▶ 一键全流程签约", command=self._on_hc_start_confirm,
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
            text="全自动: 绕过人脸 → 查询状态 → 创建合同(可选) → 确认签约  |  支持状态5(医生申请) + 状态6(居民申请) + 未签约",
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
            "说明：日志里的「已记录」表示请求已被解密并写入日志，代理会照常转发，\n"
            "不会故意阻断小程序；若页面一直转圈，再检查证书是否信任、是否已重启微信。\n"
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
            frame, height=10, wrap=tk.WORD, state=tk.NORMAL,
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

        self.var_cap_stats = tk.StringVar(value="已记录请求: 0  |  日志大小: 0 KB")
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
            "已记录请求: %d  |  日志大小: %.1f KB" % (self._cap_request_count, kb)
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
            if msg.startswith("已记录"):
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
    # Tab 5: License Configuration
    # ================================================================

    def _build_license_tab(self, parent):
        """构建许可证配置标签页"""
        self._build_license_info_section(parent)
        self._build_license_verification_section(parent)
        self._build_license_config_section(parent)
        self._build_license_log_section(parent)

    def _build_license_info_section(self, parent):
        """构建许可证信息部分"""
        frame = ttk.LabelFrame(parent, text=" 许可证信息 ", padding=8)
        frame.pack(fill=tk.X, pady=(0, 4))

        info_text = (
            "本系统使用与原始client.exe相同的许可证验证机制。\n"
            "许可证服务器: http://43.137.41.187:5004\n"
            "验证端点: /yanzheng (验证许可证)\n"
            "消耗端点: /xiaohao (消耗许可证次数)\n"
            "\n"
            "加密方式:\n"
            "  • RSA-2048公钥加密AES密钥\n"
            "  • AES-CBC加密数据\n"
            "  • 使用原始client.exe相同的RSA公钥\n"
            "\n"
            "功能:\n"
            "  • 支持批量处理 (20个工作线程)\n"
            "  • 批量大小: 2 (与原始client.exe一致)\n"
            "  • 成功日志记录到Excel文件\n"
            "  • 兼容原始client.exe配置格式\n"
        )

        try:
            bg = self.cget("background")
        except Exception:
            bg = "#f0f0f0"
        tw = tk.Text(
            frame, height=12, wrap=tk.WORD, state=tk.NORMAL,
            font=("", 10), relief=tk.FLAT, background=bg,
        )
        tw.insert("1.0", info_text)
        tw.configure(state=tk.DISABLED)
        tw.pack(fill=tk.X)

    def _build_license_verification_section(self, parent):
        """构建许可证验证部分"""
        frame = ttk.LabelFrame(parent, text=" 许可证验证 ", padding=6)
        frame.pack(fill=tk.X, pady=(0, 4))

        # 用户名和密码输入
        r0 = ttk.Frame(frame)
        r0.pack(fill=tk.X, pady=(0, 6))
        
        ttk.Label(r0, text="用户名:").pack(side=tk.LEFT)
        self.var_license_user = tk.StringVar(value=self._cfg.get("auth", {}).get("user", ""))
        ttk.Entry(r0, textvariable=self.var_license_user, width=20).pack(side=tk.LEFT, padx=(4, 12))
        
        ttk.Label(r0, text="密码:").pack(side=tk.LEFT)
        self.var_license_password = tk.StringVar(value=self._cfg.get("auth", {}).get("password", ""))
        ttk.Entry(r0, textvariable=self.var_license_password, width=20, show="*").pack(side=tk.LEFT, padx=(4, 12))
        
        # 验证按钮
        self.btn_license_verify = ttk.Button(
            r0, text="验证许可证", command=self._on_license_verify
        )
        self.btn_license_verify.pack(side=tk.LEFT, padx=(0, 12))
        
        # 状态显示
        self.var_license_status = tk.StringVar(value="未验证")
        self.lbl_license_status = ttk.Label(
            r0, textvariable=self.var_license_status, style="Info.TLabel"
        )
        self.lbl_license_status.pack(side=tk.LEFT)

    def _build_license_config_section(self, parent):
        """构建许可证配置部分"""
        frame = ttk.LabelFrame(parent, text=" 高级配置 ", padding=6)
        frame.pack(fill=tk.X, pady=(0, 4))

        r0 = ttk.Frame(frame)
        r0.pack(fill=tk.X, pady=(0, 6))
        
        ttk.Label(r0, text="服务器地址:").pack(side=tk.LEFT)
        self.var_license_server = tk.StringVar(value=self._cfg.get("license_server_url", "http://43.137.41.187:5004"))
        ttk.Entry(r0, textvariable=self.var_license_server, width=40).pack(side=tk.LEFT, padx=(4, 12))
        
        ttk.Label(r0, text="工作线程:").pack(side=tk.LEFT)
        self.var_max_workers = tk.StringVar(value=str(self._cfg.get("max_workers", 20)))
        ttk.Entry(r0, textvariable=self.var_max_workers, width=8).pack(side=tk.LEFT, padx=(4, 12))
        
        ttk.Label(r0, text="批量大小:").pack(side=tk.LEFT)
        self.var_batch_size = tk.StringVar(value=str(self._cfg.get("batch_size", 2)))
        ttk.Entry(r0, textvariable=self.var_batch_size, width=8).pack(side=tk.LEFT, padx=(4, 12))
        
        # 保存配置按钮
        self.btn_save_license_config = ttk.Button(
            r0, text="保存配置", command=self._on_save_license_config
        )
        self.btn_save_license_config.pack(side=tk.RIGHT)

    def _build_license_log_section(self, parent):
        """构建许可证日志部分"""
        frame = ttk.LabelFrame(parent, text=" 许可证日志 ", padding=4)
        frame.pack(fill=tk.BOTH, expand=True)

        log_frame = ttk.Frame(frame)
        log_frame.pack(fill=tk.BOTH, expand=True)

        self.license_log_text = tk.Text(
            log_frame, wrap=tk.WORD, state=tk.DISABLED,
            font=("Consolas", 9) if sys.platform == "win32" else ("Menlo", 10),
        )
        sb = ttk.Scrollbar(log_frame, command=self.license_log_text.yview)
        self.license_log_text.configure(yscrollcommand=sb.set)
        self.license_log_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        sb.pack(side=tk.RIGHT, fill=tk.Y)

        self.license_log_text.tag_configure("ok", foreground="#16a34a")
        self.license_log_text.tag_configure("err", foreground="#dc2626")
        self.license_log_text.tag_configure("info", foreground="#2563eb")
        self.license_log_text.tag_configure("warn", foreground="#d97706")

    # -- Tab 5: License Logic --

    def _license_log(self, msg: str, tag: str = ""):
        """记录许可证日志"""
        ts = datetime.now().strftime("%H:%M:%S")
        line = "[%s] %s\n" % (ts, msg)

        def _do():
            self.license_log_text.configure(state=tk.NORMAL)
            self.license_log_text.insert(tk.END, line, tag)
            self.license_log_text.see(tk.END)
            self.license_log_text.configure(state=tk.DISABLED)

        if threading.current_thread() is threading.main_thread():
            _do()
        else:
            self.after(0, _do)

    def _on_license_verify(self):
        """验证许可证按钮点击事件"""
        username = self.var_license_user.get().strip()
        password = self.var_license_password.get().strip()
        
        if not username or not password:
            self._license_log("请输入用户名和密码", "err")
            self.var_license_status.set("验证失败")
            self.lbl_license_status.configure(style="Error.TLabel")
            return
        
        self._license_log(f"正在验证许可证: {username}", "info")
        self.var_license_status.set("验证中...")
        self.lbl_license_status.configure(style="Info.TLabel")
        self.btn_license_verify.configure(state=tk.DISABLED)
        
        def verify_thread():
            try:
                # 设置服务器地址
                server_url = self.var_license_server.get().strip()
                if server_url:
                    # 更新配置中的服务器地址
                    self.license_client.config.server_url = server_url
                
                # 验证许可证
                result = self.license_client.verify_license(username, password)
                
                if result["success"]:
                    self.after(0, lambda: self._license_log(f"许可证验证成功: {result.get('message', '')}", "ok"))
                    self.after(0, lambda: self.var_license_status.set("验证成功"))
                    self.after(0, lambda: self.lbl_license_status.configure(style="Success.TLabel"))
                    
                    # 更新配置
                    self._cfg["auth"] = {"user": username, "password": password}
                    self._cfg["license_server_url"] = server_url
                    save_config(self._cfg)
                else:
                    self.after(0, lambda: self._license_log(f"许可证验证失败: {result.get('message', '')}", "err"))
                    self.after(0, lambda: self.var_license_status.set("验证失败"))
                    self.after(0, lambda: self.lbl_license_status.configure(style="Error.TLabel"))
                    
            except Exception as e:
                self.after(0, lambda: self._license_log(f"验证过程中发生错误: {str(e)}", "err"))
                self.after(0, lambda: self.var_license_status.set("验证失败"))
                self.after(0, lambda: self.lbl_license_status.configure(style="Error.TLabel"))
                
            finally:
                self.after(0, lambda: self.btn_license_verify.configure(state=tk.NORMAL))
        
        # 在新线程中执行验证
        threading.Thread(target=verify_thread, daemon=True).start()

    def _on_save_license_config(self):
        """保存许可证配置按钮点击事件"""
        try:
            # 更新配置
            self._cfg["max_workers"] = int(self.var_max_workers.get())
            self._cfg["batch_size"] = int(self.var_batch_size.get())
            self._cfg["license_server_url"] = self.var_license_server.get().strip()
            
            # 保存到文件
            save_config(self._cfg)
            
            self._license_log("配置已保存", "ok")
            
        except ValueError:
            self._license_log("请输入有效的数字", "err")
        except Exception as e:
            self._license_log(f"保存配置失败: {str(e)}", "err")

    # ================================================================
    # Config
    # ================================================================

    def _restore_config(self):
        c = self._cfg
        # 兼容新旧配置格式
        # 新格式使用 "username"，旧格式使用 "account"
        username = ""
        if c.get("username"):
            username = c["username"]
            self.var_account.set(username)
        elif c.get("account"):
            username = c["account"]
            self.var_account.set(username)
        
        # 恢复密码字段
        password = ""
        if c.get("password"):
            password = c["password"]
            self.var_password.set(password)
        
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
        
        # 恢复增强登录界面的变量
        if hasattr(self, 'enhanced_url_var'):
            self.enhanced_url_var.set(base_url)
        
        if hasattr(self, 'enhanced_account_var'):
            self.enhanced_account_var.set(username)
        
        if hasattr(self, 'enhanced_api_account_var'):
            self.enhanced_api_account_var.set(username)
        
        # 恢复增强登录密码变量
        if hasattr(self, 'enhanced_api_password_var') and password:
            self.enhanced_api_password_var.set(password)
        
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
        if c.get("hc_orgcode"):
            self.var_hc_orgcode.set(c["hc_orgcode"])
        if c.get("hc_team"):
            self.var_hc_team.set(c["hc_team"])
        if c.get("hc_doctor"):
            self.var_hc_doctor.set(c["hc_doctor"])
        if c.get("hc_start"):
            self.var_hc_start.set(c["hc_start"])
        if c.get("hc_end"):
            self.var_hc_end.set(c["hc_end"])
        
        # 恢复许可证配置
        if c.get("auth"):
            auth_config = c["auth"]
            if auth_config.get("user"):
                self.var_license_user.set(auth_config["user"])
            if auth_config.get("password"):
                self.var_license_password.set(auth_config["password"])
        
        if c.get("license_server_url"):
            self.var_license_server.set(c["license_server_url"])
        
        if c.get("max_workers"):
            self.var_max_workers.set(str(c["max_workers"]))
        
        if c.get("batch_size"):
            self.var_batch_size.set(str(c["batch_size"]))

    def _save_current_config(self):
        """Persist the current GUI state to disk.

        Reading Tk variables (`StringVar.get()`) from a non-main thread is a
        Tcl threading violation. If a worker accidentally calls us, hop back
        to the main thread using ``after(0, ...)`` to do the actual read+save.
        """
        if threading.current_thread() is not threading.main_thread():
            self.after(0, self._save_current_config)
            return

        config_data = {
            # 使用新格式字段名
            "username": self.var_account.get(),
            "password": self.var_password.get(),
            "ggws_base_url": self.var_url.get(),
            # 其他字段
            "org_code": self.var_org.get(),
            "doctor": self.var_doctor.get(),
            "team": self.var_team.get(),
            "delay": self.var_delay.get(),
            "pop_type": self.var_pop_type.get(),
            "agree_start": self.var_agree_start.get(),
            "agree_end": self.var_agree_end.get(),
            "max_count": self.var_max_count.get(),
            "hc_openid": self.var_hc_openid.get(),
            "hc_orgcode": self.var_hc_orgcode.get(),
            "hc_team": self.var_hc_team.get(),
            "hc_doctor": self.var_hc_doctor.get(),
            "hc_start": self.var_hc_start.get(),
            "hc_end": self.var_hc_end.get(),
        }
        
        # 添加许可证配置
        license_user = self.var_license_user.get().strip()
        license_password = self.var_license_password.get().strip()
        if license_user or license_password:
            config_data["auth"] = {
                "user": license_user,
                "password": license_password
            }
        
        license_server = self.var_license_server.get().strip()
        if license_server:
            config_data["license_server_url"] = license_server
        
        try:
            max_workers = int(self.var_max_workers.get())
            if max_workers > 0:
                config_data["max_workers"] = max_workers
        except ValueError:
            pass
        
        try:
            batch_size = int(self.var_batch_size.get())
            if batch_size > 0:
                config_data["batch_size"] = batch_size
        except ValueError:
            pass
        
        save_config(config_data)

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
            self._start_capability_router_check()
        else:
            self.lbl_login_status.configure(style="Error.TLabel")
            self._log("✗ %s" % msg, "err")

    def _start_capability_router_check(self):
        self.var_route_mode.set("能力路由: 检测中...")
        self.lbl_route_mode.configure(style="RouteUnknown.TLabel")
        self._log("能力路由检测: 开始（使用临时测试合同）", "info")

        def worker():
            profile = {
                "mode": "blocked",
                "reason": "当前权限下未发现直生效通道",
                "status0_total": 0,
                "status5_total": 0,
                "status6_total": 0,
            }
            temp_cc = ""
            try:
                _, t0 = self.client.query_patients(status="0", page=1)
                _, t5 = self.client.query_patients(status="5", page=1)
                _, t6 = self.client.query_patients(status="6", page=1)
                profile["status0_total"] = t0
                profile["status5_total"] = t5
                profile["status6_total"] = t6

                if t6 > 0:
                    profile["mode"] = "doctor_only"
                    profile["reason"] = "可确认居民申请(6->0)，医生申请仍需外部通道"

                pool, _ = self.client.query_patients(status="", page=1)
                target = next((p for p in pool if not p.contract_code), None)
                if target:
                    r = self.client.initiate_signing(
                        person_id=target.person_id,
                        agreement_start="20260101",
                        agreement_end="20261231",
                        period="1",
                    )
                    if r.success and r.contract_code:
                        temp_cc = r.contract_code
                        r2 = self.client.confirm_signing(
                            person_id=target.person_id,
                            contract_code=r.contract_code,
                            name=target.name,
                        )
                        if r2.success:
                            profile["mode"] = "direct"
                            profile["reason"] = "检测到医生申请可直接生效"
                        else:
                            if profile["mode"] == "blocked":
                                profile["mode"] = "doctor_only"
                            profile["reason"] = "医生申请不可直生效，建议接力包/高权限通道"
            except Exception as e:
                profile["mode"] = "blocked"
                profile["reason"] = "检测异常: %s" % str(e)
            finally:
                if temp_cc:
                    try:
                        self.client.delete_signing(temp_cc)
                    except Exception:
                        pass
            self.after(0, lambda: self._finish_capability_router_check(profile))

        threading.Thread(target=worker, daemon=True).start()

    def _finish_capability_router_check(self, profile: dict):
        self.capability_profile = profile
        mode = profile.get("mode", "unknown")
        reason = profile.get("reason", "")
        self.var_route_mode.set(
            "能力路由: %s | 0:%s 5:%s 6:%s"
            % (
                mode,
                profile.get("status0_total", 0),
                profile.get("status5_total", 0),
                profile.get("status6_total", 0),
            )
        )
        if mode == "direct":
            self.lbl_route_mode.configure(style="RouteDirect.TLabel")
        elif mode in ("doctor_only", "blocked"):
            self.lbl_route_mode.configure(style="RouteWarn.TLabel")
        else:
            self.lbl_route_mode.configure(style="RouteUnknown.TLabel")
        self._log("能力路由检测完成: %s (%s)" % (mode, reason), "info")

    def _on_start_smart_signing(self):
        mode = self.capability_profile.get("mode", "unknown")
        if mode == "direct":
            self._log("智能执行: 检测到直生效能力，走自动签约流程", "ok")
            self._on_start_signing()
            return
        self._log(
            "智能执行: 当前账号不具备5->0直生效能力，使用最快合法路径——",
            "info",
        )
        self._log(
            "  1) 家庭批量发起『医生申请』(ACTION=10) → 2) 单人补齐 → 3) 提示导出接力包",
            "info",
        )
        self._pending_export_after_batch = True
        self._on_family_batch_initiate()

    def _on_family_batch_initiate(self):
        if self._signing:
            return
        if not self._ensure_session_usable("家庭批量发起"):
            return
        if not self.patients:
            messagebox.showwarning("提示", "请先查询并选择居民")
            return
        targets = [p for p in self.patients if p.person_id in self.selected_ids]
        if not targets:
            messagebox.showwarning("提示", "请勾选要批量发起的居民")
            return

        eligible = [p for p in targets if p.contract_status not in ("0", "5", "6")]
        skipped = len(targets) - len(eligible)
        if not eligible:
            messagebox.showwarning(
                "提示",
                "选中居民均已存在签约/申请记录，请先用『删除医生申请/作废已签约』清理或改用『智能执行』。",
            )
            return

        msg_parts = [
            "将先反查每位居民所属家庭档案，",
            "同家庭成员合并走批量接口（ACTION=10），",
            "未挂入家庭档案的对象自动回退为单人发起。",
            "本批共 %d 人。" % len(eligible),
        ]
        if skipped:
            msg_parts.append("跳过 %d 人（已存在签约/申请记录）。" % skipped)
        msg_parts.append("注意：所有路径均产生『医生申请(STATUS=5)』，不会直接生效到 STATUS=0。")
        msg_parts.append("是否继续？")
        if not messagebox.askyesno("家庭批量发起", "\n".join(msg_parts)):
            return

        doctor = self.var_doctor.get().strip()
        team = self.var_team.get().strip()
        pop_code = self._get_pop_type_code()
        agree_start = self.var_agree_start.get().strip()
        agree_end = self.var_agree_end.get().strip()
        try:
            delay = float(self.var_delay.get())
        except ValueError:
            delay = 0.5

        self._signing = True
        self._stop_event.clear()
        self._sign_success = 0
        self._sign_fail = 0
        self._sign_total = len(eligible)
        self._sign_start_time = time.time()
        self.btn_start.configure(state=tk.DISABLED)
        self.btn_pause.configure(state=tk.DISABLED)
        self.btn_stop.configure(state=tk.NORMAL)
        self.btn_login.configure(state=tk.DISABLED)
        self.btn_query.configure(state=tk.DISABLED)
        self.btn_query_all.configure(state=tk.DISABLED)
        self.progress.configure(maximum=len(eligible), value=0)
        self.var_progress_text.set("0 / %d" % len(eligible))
        self.var_stats.set("")
        self._log("=" * 50, "info")
        self._log("家庭批量发起: %d 人，先反查家庭归属..." % len(eligible), "info")

        def worker():
            family_groups: dict = {}
            singletons: list = []
            for p in eligible:
                if self._stop_event.is_set():
                    break
                fg, _head = self.client.find_family_guid(p.person_id, p.name)
                if fg:
                    family_groups.setdefault(fg, []).append(p)
                else:
                    singletons.append(p)

            self.after(
                0,
                lambda fg=len(family_groups), sg=len(singletons): self._log(
                    "  归属反查完成：%d 个家庭组，%d 人无家庭归属（将单人发起）"
                    % (fg, sg), "info",
                ),
            )

            done = 0
            chunk_size = 8

            for family_guid, members in family_groups.items():
                if self._stop_event.is_set():
                    break
                chunks = [
                    members[i:i + chunk_size]
                    for i in range(0, len(members), chunk_size)
                ]
                for batch in chunks:
                    if self._stop_event.is_set():
                        break
                    pids = [m.person_id for m in batch]
                    t_start = time.time()
                    ok, msg2, created = self.client.family_batch_initiate(
                        person_ids=pids,
                        family_guid=family_guid,
                        team_name=team,
                        doctor_name=doctor,
                        service_type=pop_code,
                        agreement_start=agree_start,
                        agreement_end=agree_end,
                        contact_phone="13800000000",
                    )
                    elapsed = time.time() - t_start
                    code_map = {c["person_id"]: c for c in created}
                    if ok:
                        self.after(
                            0,
                            lambda fg=family_guid, n=len(pids), e=elapsed, m=msg2: (
                                self._log(
                                    "  ✓ 家庭 %s: %d 人 (%.1fs) — %s"
                                    % (fg[:8], n, e, m), "ok",
                                )
                            ),
                        )
                        for p in batch:
                            done += 1
                            cc_info = code_map.get(p.person_id)
                            success = bool(cc_info)
                            if success:
                                self._sign_success += 1
                            else:
                                self._sign_fail += 1
                            self.after(
                                0,
                                lambda d=done, p=p, s=success, ci=cc_info: (
                                    self._update_family_batch_row(d, p, s, ci)
                                ),
                            )
                    else:
                        self.after(
                            0,
                            lambda fg=family_guid, m=msg2: self._log(
                                "  ! 家庭 %s 批量失败 (%s)，回退为单人"
                                % (fg[:8], m), "warn",
                            ),
                        )
                        singletons.extend(batch)
                    if delay > 0:
                        time.sleep(delay)

            for p in singletons:
                if self._stop_event.is_set():
                    break
                r = self.client.initiate_signing(
                    person_id=p.person_id,
                    team_name=team,
                    doctor_name=doctor,
                    service_type=pop_code,
                    agreement_start=agree_start,
                    agreement_end=agree_end,
                )
                done += 1
                success = r.success and bool(r.contract_code)
                if success:
                    self._sign_success += 1
                    cc_info = {
                        "person_id": p.person_id,
                        "contract_code": r.contract_code,
                        "status_text": "医生申请",
                    }
                else:
                    self._sign_fail += 1
                    cc_info = None
                self.after(
                    0,
                    lambda d=done, p=p, s=success, ci=cc_info: (
                        self._update_family_batch_row(d, p, s, ci)
                    ),
                )
                if delay > 0:
                    time.sleep(delay)

            self.after(0, self._signing_finished)

        threading.Thread(target=worker, daemon=True).start()

    def _update_family_batch_row(self, done, patient, success, cc_info):
        children = self.tree.get_children()
        if patient.person_id in children:
            self.tree.item(
                patient.person_id,
                tags=("signed_ok" if success else "signed_fail",),
            )
        if success and cc_info:
            patient.contract_code = cc_info.get("contract_code", "")
            patient.contract_status = "5"
            patient.status_text = cc_info.get("status_text", "医生申请")
        self.progress.configure(value=done)
        self.var_progress_text.set("%d / %d" % (done, self._sign_total))
        elapsed = time.time() - self._sign_start_time
        speed = elapsed / done if done > 0 else 0
        self.var_stats.set(
            "成功: %d  失败: %d  速度: %.2f秒/人"
            % (self._sign_success, self._sign_fail, speed)
        )

    def _on_export_relay_package(self):
        if not self.patients:
            messagebox.showwarning("提示", "请先查询并选择居民")
            return
        targets = [p for p in self.patients if p.person_id in self.selected_ids]
        if not targets:
            messagebox.showwarning("提示", "请选择要导出的居民")
            return

        path = filedialog.asksaveasfilename(
            defaultextension=".zip",
            filetypes=[("ZIP 文件", "*.zip"), ("所有文件", "*.*")],
            initialfile="签约接力包_%s.zip" % datetime.now().strftime("%Y%m%d_%H%M"),
        )
        if not path:
            return

        try:
            import csv
            import io
            import zipfile

            rows = []
            for i, p in enumerate(targets, 1):
                rows.append([
                    i, p.name, p.id_card, p.person_id,
                    p.contract_status, p.status_text, p.contract_code,
                    self.var_agree_start.get().strip() or "自动",
                    self.var_agree_end.get().strip() or "自动",
                    self.var_doctor.get().strip() or p.signing_doctor,
                    self.var_team.get().strip() or p.signing_team,
                    "目标: STATUS=0 已签约有效",
                ])

            csv_buf = io.StringIO()
            writer = csv.writer(csv_buf)
            writer.writerow([
                "序号", "姓名", "身份证号", "PERSONID",
                "当前状态码", "当前状态", "合同号",
                "协议开始", "协议结束", "签约医生", "签约团队", "处理目标",
            ])
            writer.writerows(rows)

            manifest = {
                "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "source_account": self.var_account.get().strip(),
                "source_org": self.var_org.get().strip() or self.client.org_code,
                "capability_profile": self.capability_profile,
                "target_count": len(targets),
                "goal": "将医生申请/未签约对象处理为 STATUS=0（已签约有效）",
            }
            readme = (
                "签约接力包说明\n"
                "====================\n"
                "用途：将本机已发起『医生申请(STATUS=5)』的对象交由有权限账号或外部团队\n"
                "      执行最终落库（STATUS=0）。\n\n"
                "包内文件：\n"
                "  - relay_queue.csv  待处理居民列表（含 PERSONID/合同号/协议期/医生/团队）\n"
                "  - manifest.json    来源账号、能力检测结果、生成时间等元数据\n"
                "  - 厂商升级包_技术证据_v2.md (如附带) 当前账号能力差异说明\n\n"
                "操作建议：\n"
                "  1) 处理方使用其授权账号登录公卫3.0；\n"
                "  2) 按 relay_queue.csv 的 PERSONID/合同号定位记录；\n"
                "  3) 在其权限范围内执行确认/审核或后台落库流程。\n\n"
                "注意：\n"
                "  - 本机账号已经历完整能力面探测，无 5->0 通道。\n"
                "  - 若处理方仅有同等权限账号，请先与厂商确认其授权差异。\n"
            )

            from collections import OrderedDict
            grouped = OrderedDict()
            for p in targets:
                key = (p.signing_team or "未指派团队", p.signing_doctor or "未指派医生")
                grouped.setdefault(key, []).append(p)

            family_csv = io.StringIO()
            fwriter = csv.writer(family_csv)
            fwriter.writerow(["签约团队", "签约医生", "人数", "PERSONID列表", "合同号列表"])
            for (tm, dr), group in grouped.items():
                fwriter.writerow([
                    tm, dr, len(group),
                    "|".join(p.person_id for p in group),
                    "|".join(p.contract_code for p in group if p.contract_code),
                ])

            evidence_path = os.path.join(
                os.path.dirname(os.path.abspath(__file__)),
                "厂商升级包_技术证据_v2.md",
            )
            evidence_bytes = None
            if os.path.isfile(evidence_path):
                try:
                    with open(evidence_path, "rb") as ef:
                        evidence_bytes = ef.read()
                except Exception:
                    evidence_bytes = None

            with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as zf:
                zf.writestr("relay_queue.csv", csv_buf.getvalue().encode("utf-8-sig"))
                zf.writestr("relay_by_team.csv", family_csv.getvalue().encode("utf-8-sig"))
                zf.writestr(
                    "manifest.json",
                    json.dumps(manifest, ensure_ascii=False, indent=2).encode("utf-8"),
                )
                zf.writestr("README.txt", readme.encode("utf-8"))
                if evidence_bytes:
                    zf.writestr("厂商升级包_技术证据_v2.md", evidence_bytes)

            attached = " + 厂商证据" if evidence_bytes else ""
            self._log(
                "接力包导出成功: %s (%d人, 团队%d个%s)"
                % (path, len(targets), len(grouped), attached),
                "ok",
            )
            messagebox.showinfo("导出成功", "已导出接力包：\n%s" % path)
        except Exception as e:
            self._log("导出接力包失败: %s" % e, "err")
            messagebox.showerror("导出失败", str(e))

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

    def _on_open_province_dialog(self):
        if not self._ensure_session_usable("打开全省查找"):
            return
        dlg = ProvinceLookupDialog(self)
        dlg.grab_set()

    def _ensure_session_usable(self, action: str = "操作") -> bool:
        """Pre-flight check: session must be fully authenticated (not just
        QR-pending). Pops a clear, actionable error and returns False
        otherwise. ``action`` is woven into the message (e.g. "查询" / "签约").
        """
        if not getattr(self.client, "logged_in", False):
            messagebox.showwarning("提示", f"请先登录公卫3.0系统再{action}")
            return False
        if getattr(self.client, "qr_pending", False):
            messagebox.showwarning(
                "需要二维码验证",
                f"API 登录已下发 Token，但服务器仍在等待二维码扫描，"
                f"无法{action}。\n\n"
                "请按以下步骤操作：\n"
                "  1. 点击 [跳转到3.0系统登录]，在浏览器中完成扫码\n"
                "  2. 浏览器登录成功后回到本程序，点击 [同步配置]\n"
                f"  3. 同步成功后再{action}",
            )
            return False
        return True

    def _ensure_can_query(self) -> bool:
        """Pre-flight for 查询(首页) / 查询全部 — adds org_code check."""
        if not self._ensure_session_usable("查询"):
            return False
        if not self.var_org.get().strip():
            messagebox.showwarning(
                "缺少机构代码",
                "查询需要机构代码 (org_code)，但当前为空。\n\n"
                "请先完成浏览器扫码登录后点 [同步配置] 自动获取，\n"
                "或在 [机构代码] 字段中手动填入您所属医院的代码。",
            )
            return False
        return True

    def _on_query(self):
        if not self._ensure_can_query():
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
        if not self._ensure_can_query():
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

        if not self._ensure_session_usable("批量签约"):
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

        if getattr(self, "_pending_export_after_batch", False):
            self._pending_export_after_batch = False
            if self._sign_success > 0 and messagebox.askyesno(
                "导出接力包",
                "已成功发起 %d 条医生申请。\n是否立即导出『接力包』交给有权限处理方？"
                % self._sign_success,
            ):
                self._on_export_relay_package()

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
            if "*" in (c.id_card or ""):
                try:
                    bypass_text = "是" if needs_age_bypass(int(c.age)) else ""
                except (ValueError, TypeError):
                    bypass_text = ""
            else:
                bypass_text = "是" if needs_age_bypass(c.id_card) else ""

            self.hc_tree.insert("", tk.END, iid=c.health_card_id, values=(
                i, c.name, c.id_card, c.age, c.age_category,
                gender_map.get(c.gender, c.gender), rpc_text,
                bypass_text, c.relation,
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

        orgcode = self.var_hc_orgcode.get().strip()
        auto_create = self.var_hc_auto_create.get()
        if auto_create and not orgcode:
            messagebox.showwarning(
                "提示",
                "自动创建合同需要填写「机构代码」。\n\n"
                "可在3.0系统登录后点击「从3.0系统同步配置」获取，\n"
                "或取消勾选「自动创建合同」仅确认已有的待确认合同。",
            )
            return

        flow_desc = "全流程签约" if auto_create else "确认已有合同"
        msg = "即将对 %d 张健康卡执行「%s」：\n\n" % (len(targets), flow_desc)
        msg += "流程: 绕过人脸 → 查询状态 → "
        if auto_create:
            msg += "创建合同 → "
        msg += "确认签约\n\n"
        if auto_create:
            msg += "机构: %s\n医生: %s\n团队: %s\n\n" % (
                orgcode or "(未设置)",
                self.var_hc_doctor.get().strip() or "(自动)",
                self.var_hc_team.get().strip() or "(自动)",
            )
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
        self._hc_log("开始批量签约: %d 张卡 (%s)" % (len(targets), flow_desc), "info")

        self._save_current_config()

        sign_config = {
            "orgcode": orgcode,
            "team_name": self.var_hc_team.get().strip(),
            "doctor_name": self.var_hc_doctor.get().strip(),
            "start_date": self.var_hc_start.get().strip(),
            "end_date": self.var_hc_end.get().strip(),
            "auto_create": auto_create,
        }

        def worker():
            self._hc_confirm_worker(targets, sign_config)

        threading.Thread(target=worker, daemon=True).start()

    def _hc_confirm_worker(self, targets: List[HealthCard], config: dict):
        success = 0
        fail = 0
        skipped = 0
        created = 0
        t0 = time.time()

        for i, card in enumerate(targets):
            if self._hc_stop.is_set():
                self.after(0, lambda: self._hc_log("已手动停止", "warn"))
                break

            self.after(
                0,
                lambda idx=i, c=card: self._hc_log(
                    "处理 [%d/%d] %s (%s, %s)" % (
                        idx + 1, len(targets), c.name,
                        c.age_category or "?", c.id_card,
                    ),
                    "info",
                ),
            )

            result = self.sign_engine.process_card_full(
                card,
                orgcode=config["orgcode"],
                team_name=config.get("team_name", ""),
                doctor_name=config.get("doctor_name", ""),
                start_date=config.get("start_date", ""),
                end_date=config.get("end_date", ""),
                auto_create=config.get("auto_create", True),
                log_cb=lambda msg, tag="", _=None: self._hc_log(msg, tag),
            )

            if result.step == "already_signed":
                tag = "skipped"
                skipped += 1
            elif result.success:
                tag = "confirm_ok"
                success += 1
                if result.contract_created:
                    created += 1
            else:
                tag = "confirm_fail"
                fail += 1

            def _update_row(
                idx=i, t=tag, s=success, f=fail, sk=skipped, cr=created,
            ):
                hcid = targets[idx].health_card_id
                children = self.hc_tree.get_children()
                if hcid in children:
                    self.hc_tree.item(hcid, tags=(t,))
                self.hc_progress.configure(value=idx + 1)
                self.var_hc_progress_text.set(
                    "%d / %d" % (idx + 1, len(targets))
                )
                elapsed = time.time() - t0
                speed = elapsed / (idx + 1)
                self.var_hc_stats.set(
                    "签约: %d  新建: %d  失败: %d  跳过: %d  %.1f秒/人" % (
                        s, cr, f, sk, speed,
                    )
                )

            self.after(0, _update_row)
            time.sleep(0.3)

        def _done(s=success, f=fail, sk=skipped, cr=created):
            self._hc_confirming = False
            self.btn_hc_confirm.configure(state=tk.NORMAL)
            self.btn_hc_stop.configure(state=tk.DISABLED)
            self.btn_hc_connect.configure(state=tk.NORMAL)
            if self.hc_client.connected:
                self.btn_hc_refresh.configure(state=tk.NORMAL)

            elapsed = time.time() - t0
            self._hc_log("=" * 50, "info")
            self._hc_log(
                "签约完成! 成功: %d (新建: %d), 失败: %d, 跳过: %d, 耗时: %.1f秒" % (
                    s, cr, f, sk, elapsed,
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
    
    # ================================================================
    # 增强登录功能方法
    # ================================================================
    
    def _run_login_initial_diagnosis(self):
        """运行初始诊断"""
        self.enhanced_status_var.set("正在诊断连接状态...")
        self.enhanced_diagnose_btn.configure(state=tk.DISABLED)
        
        # Capture Tk variables on main thread to avoid Tcl threading violations
        snapshot = {
            "base_url": self.enhanced_url_var.get(),
            "account": self.enhanced_account_var.get(),
        }

        def worker():
            diagnostics = self._perform_login_diagnosis(snapshot)
            self._safe_after(
                lambda: self._display_login_diagnostics(diagnostics)
            )
        
        threading.Thread(target=worker, daemon=True).start()
    
    def _run_login_diagnosis(self):
        """运行诊断"""
        self._run_login_initial_diagnosis()
    
    def _run_detailed_diagnosis(self):
        """运行详细诊断"""
        self.enhanced_status_var.set("正在执行详细诊断...")
        self.enhanced_diagnose_btn.configure(state=tk.DISABLED)
        self.enhanced_detailed_diagnose_btn.configure(state=tk.DISABLED)
        
        # Capture Tk variables on main thread to avoid Tcl threading violations
        snapshot = {
            "base_url": self.enhanced_url_var.get(),
            "account": self.enhanced_account_var.get(),
        }

        def worker():
            diagnostics = self._perform_detailed_diagnosis(snapshot)
            self._safe_after(
                lambda: self._display_detailed_diagnostics(diagnostics)
            )
        
        threading.Thread(target=worker, daemon=True).start()

    def _safe_after(self, callback):
        """Schedule a callback on the Tk thread, but tolerate a destroyed
        root window or a parent widget already torn down (this can happen
        when a worker thread completes after the user closed the app)."""
        try:
            self.after(0, callback)
        except (tk.TclError, RuntimeError):
            pass
    
    def _check_login_status(self) -> Tuple[bool, str, str]:
        """统一检查登录状态
        
        返回: (是否已登录(且可用), 状态消息, 详细信息)
        
        注意 "可用" 的语义: 仅当 PH3 会话完全通过 SSO + 二维码验证、
        且已拿到机构代码时才返回 True。仅持有 Token 但卡在二维码 2FA 上
        的会话在这里返回 False，避免误导用户去点 [查询]。
        """
        client = self.client
        # QR-pending: token 已下发但服务器仍在等扫码，查询/签约都会失败。
        if getattr(client, "qr_pending", False):
            return (
                False,
                "登录不完整: 需要二维码验证",
                "请使用 [跳转到3.0系统登录] 在浏览器扫码后回来点 [同步配置]",
            )

        # 完整登录 (logged_in 且 不是 qr_pending)
        if getattr(client, "logged_in", False):
            user_info = self._cfg.get("username", "未知用户")
            org_info = self._cfg.get("org_name", "") or getattr(client, "org_name", "")
            if org_info:
                user_info = f"{user_info} ({org_info})"
            # 即使 logged_in，如果 org_code 还没拿到也算 "登录但未同步"
            if not (self._cfg.get("org_code") or getattr(client, "org_code", "")):
                return (
                    True,
                    f"已登录但缺少机构信息: {user_info}",
                    "请点击 [同步配置] 获取机构代码",
                )
            return True, f"已登录: {user_info}", "客户端状态有效"

        # 仅检测到认证Cookie (例如手动浏览器登录后再打开App)
        if hasattr(client, "session") and client.session and client.session.cookies:
            auth_cookies = [
                name for name in client.session.cookies.keys()
                if any(k in name.lower()
                       for k in ("auth", "token", "session", "login"))
            ]
            if auth_cookies:
                return (
                    False,
                    "检测到认证Cookie但未确认登录",
                    f"Cookie: {', '.join(auth_cookies[:2])}; 请点 [API直接登录] 或 [同步配置]",
                )

        # 配置中有机构代码: 上一次登录留下的, 但当前未连
        if self._cfg.get("org_code"):
            return (
                False,
                "未登录 (上次配置中保留有机构代码)",
                "请点 [API直接登录] 或 [跳转到3.0系统登录]",
            )

        # 有账号但未点过登录按钮
        if (hasattr(self, "enhanced_account_var") and
                self.enhanced_account_var.get() and
                hasattr(self, "enhanced_url_var") and
                self.enhanced_url_var.get()):
            return False, "有账号信息但未执行登录", "请点击API登录或网页登录按钮"
        
        return False, "未登录或会话已过期", "请使用API登录或网页登录"
    
    def _perform_login_diagnosis(
        self, snapshot: Optional[Dict[str, str]] = None,
    ) -> List[Tuple[str, bool, str]]:
        """执行诊断 (snapshot 为主线程预先采集的 Tk 变量值，避免线程冲突)"""
        snapshot = snapshot or {}
        diagnostics = []
        
        # 1. 测试网络连接
        try:
            response = requests.get("https://www.baidu.com", timeout=5)
            diagnostics.append(("网络连接", True, "网络连接正常"))
        except Exception as e:
            diagnostics.append(("网络连接", False, f"网络连接失败: {str(e)}"))
        
        # 2. 测试公卫3.0系统 - 使用多种SSL/TLS配置和SSO重定向处理
        base_url = snapshot.get("base_url", "") or self._cfg.get("ggws_base_url", "")
        if not base_url:
            diagnostics.append(("公卫3.0系统", False, "系统地址为空"))
            diagnostics.append(("配置完整性", False, "缺失: 3.0系统地址"))
            diagnostics.append(("登录状态", False, "未登录"))
            return diagnostics
        
        # 尝试多种SSL/TLS配置
        connection_success = False
        connection_error = ""
        redirect_info = ""
        
        # 配置1: 使用自定义SSL适配器处理SSO重定向（访问FormMain.aspx）
        try:
            import ssl
            from requests.adapters import HTTPAdapter
            from urllib3.util.ssl_ import create_urllib3_context
            
            class CustomSSLAdapter(HTTPAdapter):
                """自定义SSL适配器，支持较旧的TLS版本和SSO重定向"""
                def init_poolmanager(self, *args, **kwargs):
                    ctx = create_urllib3_context()
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE
                    ctx.set_ciphers('DEFAULT:@SECLEVEL=1')
                    kwargs['ssl_context'] = ctx
                    return super().init_poolmanager(*args, **kwargs)
            
            session = requests.Session()
            session.mount("https://", CustomSSLAdapter())
            session.verify = False
            session.headers.update({
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
            })
            
            # 尝试访问FormMain.aspx（这会触发SSO重定向）
            test_url = f"{base_url.rstrip('/')}/FormMain.aspx"
            response = session.get(test_url, timeout=15, allow_redirects=True)
            
            if response.status_code == 200:
                # 检查是否成功访问系统
                is_ggws = "ggws" in response.text.lower() or "公卫" in response.text or "湖南省基层卫生信息系统" in response.text
                has_token = "Token" in response.url or "token" in response.url.lower()
                
                if is_ggws or has_token:
                    diagnostics.append(("公卫3.0系统", True, "系统可正常访问 (支持SSO重定向)"))
                    connection_success = True
                    
                    # 检查是否有Token（SSO认证成功）
                    if has_token:
                        diagnostics.append(("SSO认证", True, "检测到认证Token"))
                    else:
                        diagnostics.append(("SSO认证", False, "未检测到认证Token，可能需要登录"))
                else:
                    diagnostics.append(("公卫3.0系统", False, "未检测到公卫系统特征"))
            else:
                diagnostics.append(("公卫3.0系统", False, f"HTTP状态码: {response.status_code}"))
                
            # 检查重定向链
            if response.history:
                redirect_count = len(response.history)
                redirect_info = f"处理了 {redirect_count} 次重定向"
                diagnostics.append(("重定向处理", True, redirect_info))
                
                # 检查是否重定向到SSO服务器
                sso_redirect = any("sso.hnhfpc.gov.cn" in resp.url for resp in response.history)
                if sso_redirect:
                    diagnostics.append(("SSO重定向", True, "检测到SSO认证流程"))
                    
        except requests.exceptions.TooManyRedirects as e:
            connection_error = f"重定向过多: {str(e)}"
            diagnostics.append(("公卫3.0系统", False, f"访问失败: {connection_error}"))
        except Exception as e:
            connection_error = f"SSO重定向处理失败: {str(e)}"
        
        # 配置2: 标准HTTPS连接（备用）
        if not connection_success:
            try:
                response = requests.get(base_url, timeout=10, verify=True)
                if response.status_code == 200:
                    if "ggws" in response.text.lower() or "公卫" in response.text:
                        diagnostics.append(("公卫3.0系统", True, "系统可正常访问 (标准HTTPS)"))
                        connection_success = True
                    else:
                        diagnostics.append(("公卫3.0系统", False, "未检测到公卫系统特征"))
                else:
                    diagnostics.append(("公卫3.0系统", False, f"HTTP状态码: {response.status_code}"))
            except Exception as e:
                connection_error = f"标准HTTPS失败: {str(e)}"
        
        # 配置3: 跳过证书验证（备用）
        if not connection_success:
            try:
                response = requests.get(base_url, timeout=10, verify=False)
                if response.status_code == 200:
                    if "ggws" in response.text.lower() or "公卫" in response.text:
                        diagnostics.append(("公卫3.0系统", True, "系统可正常访问 (跳过证书验证)"))
                        connection_success = True
                    else:
                        diagnostics.append(("公卫3.0系统", False, "未检测到公卫系统特征"))
                else:
                    diagnostics.append(("公卫3.0系统", False, f"HTTP状态码: {response.status_code}"))
            except Exception as e:
                connection_error = f"跳过证书验证失败: {str(e)}"
        
        # 如果所有配置都失败
        if not connection_success and not connection_error.startswith("重定向过多"):
            diagnostics.append(("公卫3.0系统", False, f"访问失败: {connection_error}"))
        
        # 3. 检查配置
        missing = []
        
        # 检查账号
        account = self._cfg.get("username")
        if not account:
            missing.append("账号")
        
        # 检查系统地址
        base_url = self._cfg.get("ggws_base_url")
        if not base_url:
            missing.append("3.0系统地址")
        
        # 检查密码（如果账号存在但密码为空）
        password = self._cfg.get("password")
        if account and not password:
            # 密码可以为空，但需要提示用户
            diagnostics.append(("密码配置", False, "密码为空，请确保已输入密码"))
        
        # 检查机构代码（如果已登录但机构代码为空）
        org_code = self._cfg.get("org_code")
        if hasattr(self.client, 'logged_in') and self.client.logged_in and not org_code:
            # 尝试从客户端获取机构代码
            if hasattr(self.client, 'org_code') and self.client.org_code:
                self._cfg["org_code"] = self.client.org_code
                self._save_current_config()
                org_code = self.client.org_code
            
            if not org_code:
                diagnostics.append(("机构信息", False, "机构代码未提取，请尝试同步配置"))
        
        if missing:
            diagnostics.append(("配置完整性", False, f"缺失: {', '.join(missing)}"))
        else:
            # 如果有警告信息但主要配置完整，仍然显示配置完整
            diagnostics.append(("配置完整性", True, "配置完整"))
        
        # 4. 检查登录状态 - 使用统一的检测函数
        login_detected, login_message, login_details = self._check_login_status()
        diagnostics.append(("登录状态", login_detected, login_message))
        
        return diagnostics
    
    def _display_login_diagnostics(self, diagnostics: List[Tuple[str, bool, str]]):
        """显示诊断结果"""
        self.enhanced_diag_text.configure(state=tk.NORMAL)
        self.enhanced_diag_text.delete(1.0, tk.END)
        
        current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.enhanced_diag_text.insert(tk.END, f"诊断时间: {current_time}\n")
        self.enhanced_diag_text.insert(tk.END, "="*50 + "\n\n")
        
        all_passed = True
        
        for name, success, message in diagnostics:
            icon = "✅" if success else "❌"
            tag = "success" if success else "error"
            
            if not success:
                all_passed = False
            
            self.enhanced_diag_text.insert(tk.END, f"{icon} {name}: ")
            self.enhanced_diag_text.insert(tk.END, f"{message}\n", tag)
        
        # 配置标签样式
        self.enhanced_diag_text.tag_config("success", foreground="green")
        self.enhanced_diag_text.tag_config("error", foreground="red")
        
        self.enhanced_diag_text.configure(state=tk.DISABLED)
        self.enhanced_diagnose_btn.configure(state=tk.NORMAL)
        
        if all_passed:
            self.enhanced_status_var.set("诊断完成: 所有测试通过")
            self.enhanced_connection_status_var.set("已连接")
            self.enhanced_connection_status_label.configure(foreground="green")
            self.enhanced_sync_btn.configure(state=tk.NORMAL)
        else:
            self.enhanced_status_var.set("诊断完成: 发现一些问题")
            self.enhanced_connection_status_var.set("连接异常")
            self.enhanced_connection_status_label.configure(foreground="red")
    
    def _perform_detailed_diagnosis(
        self, snapshot: Optional[Dict[str, str]] = None,
    ) -> List[Tuple[str, bool, str, str]]:
        """执行详细诊断 (snapshot 为主线程预先采集的 Tk 变量值，避免线程冲突)"""
        snapshot = snapshot or {}
        diagnostics = []
        
        # 1. 测试网络连接
        try:
            import socket
            start_time = time.time()
            socket.create_connection(("www.baidu.com", 443), timeout=5)
            response_time = int((time.time() - start_time) * 1000)
            diagnostics.append(("网络连接", True, f"连接正常 (响应时间: {response_time}ms)", ""))
        except Exception as e:
            diagnostics.append(("网络连接", False, f"连接失败", str(e)))
        
        # 2. 测试DNS解析
        try:
            import socket
            start_time = time.time()
            socket.gethostbyname("ggws.hnhfpc.gov.cn")
            dns_time = int((time.time() - start_time) * 1000)
            diagnostics.append(("DNS解析", True, f"解析成功 (耗时: {dns_time}ms)", ""))
        except Exception as e:
            diagnostics.append(("DNS解析", False, f"解析失败", str(e)))
        
        # 3. 测试公卫3.0系统连接
        base_url = snapshot.get("base_url", "") or self._cfg.get("ggws_base_url", "")
        if not base_url:
            diagnostics.append(("系统连接", False, "系统地址为空", ""))
        else:
            # 测试多种SSL/TLS配置和SSO重定向处理
            connection_success = False
            best_config = ""
            error_details = ""
            redirect_info = ""
            
            # 配置1: 使用自定义SSL适配器处理SSO重定向
            try:
                import ssl
                from requests.adapters import HTTPAdapter
                from urllib3.util.ssl_ import create_urllib3_context
                
                class CustomSSLAdapter(HTTPAdapter):
                    """自定义SSL适配器，支持较旧的TLS版本和SSO重定向"""
                    def init_poolmanager(self, *args, **kwargs):
                        ctx = create_urllib3_context()
                        ctx.check_hostname = False
                        ctx.verify_mode = ssl.CERT_NONE
                        ctx.set_ciphers('DEFAULT:@SECLEVEL=1')
                        kwargs['ssl_context'] = ctx
                        return super().init_poolmanager(*args, **kwargs)
                
                session = requests.Session()
                session.mount("https://", CustomSSLAdapter())
                session.verify = False
                session.headers.update({
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
                })
                
                start_time = time.time()
                
                # 尝试访问FormMain.aspx（这会触发SSO重定向）
                test_url = f"{base_url.rstrip('/')}/FormMain.aspx"
                response = session.get(test_url, timeout=15, allow_redirects=True)
                response_time = int((time.time() - start_time) * 1000)
                
                if response.status_code == 200:
                    connection_success = True
                    best_config = "SSO重定向处理"
                    
                    # 检查重定向链
                    if response.history:
                        redirect_count = len(response.history)
                        redirect_info = f"处理了 {redirect_count} 次重定向"
                        
                        # 检查是否经过SSO服务器
                        sso_redirect = any("sso.hnhfpc.gov.cn" in resp.url for resp in response.history)
                        if sso_redirect:
                            redirect_info += " (包含SSO认证)"
                    
                    # 检查是否是公卫系统
                    is_ggws = "ggws" in response.text.lower() or "公卫" in response.text or "湖南省基层卫生信息系统" in response.text
                    system_type = "公卫3.0系统" if is_ggws else "未知系统"
                    
                    # 检查是否有Token
                    has_token = "Token" in response.url or "token" in response.url.lower()
                    token_info = "有认证Token" if has_token else "无Token（可能需要登录）"
                    
                    diagnostics.append(("系统连接", True, 
                                      f"{system_type}可访问 ({best_config}, 响应时间: {response_time}ms)",
                                      f"{redirect_info}; {token_info}"))
                else:
                    error_details = f"HTTP {response.status_code}"
                    
            except Exception as e:
                error_details = f"SSO重定向处理失败: {str(e)}"
            
            # 配置2: 标准HTTPS连接（备用）
            if not connection_success:
                try:
                    start_time = time.time()
                    response = requests.get(base_url, timeout=10, verify=True)
                    response_time = int((time.time() - start_time) * 1000)
                    
                    if response.status_code == 200:
                        connection_success = True
                        best_config = "标准HTTPS"
                        
                        # 检查是否是公卫系统
                        is_ggws = "ggws" in response.text.lower() or "公卫" in response.text
                        system_type = "公卫3.0系统" if is_ggws else "未知系统"
                        
                        diagnostics.append(("系统连接", True, 
                                          f"{system_type}可访问 ({best_config}, 响应时间: {response_time}ms)",
                                          ""))
                    else:
                        error_details = f"HTTP {response.status_code}"
                except Exception as e:
                    error_details = f"标准HTTPS失败: {str(e)}"
            
            # 配置3: 跳过证书验证（备用）
            if not connection_success:
                try:
                    start_time = time.time()
                    response = requests.get(base_url, timeout=10, verify=False)
                    response_time = int((time.time() - start_time) * 1000)
                    
                    if response.status_code == 200:
                        connection_success = True
                        best_config = "跳过证书验证"
                        
                        # 检查是否是公卫系统
                        is_ggws = "ggws" in response.text.lower() or "公卫" in response.text
                        system_type = "公卫3.0系统" if is_ggws else "未知系统"
                        
                        diagnostics.append(("系统连接", True, 
                                          f"{system_type}可访问 ({best_config}, 响应时间: {response_time}ms)",
                                          ""))
                    else:
                        error_details = f"HTTP {response.status_code}"
                except Exception as e:
                    error_details = f"跳过证书验证失败: {str(e)}"
            
            if not connection_success:
                diagnostics.append(("系统连接", False, 
                                  f"所有连接尝试均失败", 
                                  f"最后错误: {error_details}"))
        
        # 4. 检查配置完整性
        missing_fields = []
        config_details = []
        
        for field, display_name in [
            ("username", "账号"),
            ("ggws_base_url", "系统地址"),
            ("org_code", "机构代码"),
            ("doctor", "签约医生"),
            ("team", "签约团队")
        ]:
            value = self._cfg.get(field, "")
            if value:
                config_details.append(f"{display_name}: {value}")
            else:
                missing_fields.append(display_name)
        
        if missing_fields:
            diagnostics.append(("配置检查", False, 
                              f"缺失字段: {', '.join(missing_fields)}",
                              f"现有配置: {'; '.join(config_details) if config_details else '无'}"))
        else:
            diagnostics.append(("配置检查", True, 
                              "所有必需配置完整",
                              f"配置详情: {'; '.join(config_details)}"))
        
        # 5. 检查登录状态 - 使用统一的检测函数
        login_detected, login_message, login_details = self._check_login_status()
        diagnostics.append(("登录状态", login_detected, login_message, login_details))
        
        return diagnostics
    
    def _display_detailed_diagnostics(self, diagnostics: List[Tuple[str, bool, str, str]]):
        """显示详细诊断结果"""
        self.enhanced_diag_text.configure(state=tk.NORMAL)
        self.enhanced_diag_text.delete(1.0, tk.END)
        
        current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.enhanced_diag_text.insert(tk.END, f"详细诊断时间: {current_time}\n")
        self.enhanced_diag_text.insert(tk.END, "="*60 + "\n\n")
        
        all_passed = True
        
        for name, success, message, details in diagnostics:
            icon = "✅" if success else "❌"
            tag = "success" if success else "error"
            
            if not success:
                all_passed = False
            
            self.enhanced_diag_text.insert(tk.END, f"{icon} {name}: ")
            self.enhanced_diag_text.insert(tk.END, f"{message}\n", tag)
            
            if details:
                self.enhanced_diag_text.insert(tk.END, f"   └─ {details}\n", "details")
        
        # 配置标签样式
        self.enhanced_diag_text.tag_config("success", foreground="green")
        self.enhanced_diag_text.tag_config("error", foreground="red")
        self.enhanced_diag_text.tag_config("details", foreground="gray")
        
        self.enhanced_diag_text.configure(state=tk.DISABLED)
        self.enhanced_diagnose_btn.configure(state=tk.NORMAL)
        self.enhanced_detailed_diagnose_btn.configure(state=tk.NORMAL)
        
        if all_passed:
            self.enhanced_status_var.set("详细诊断完成: 所有测试通过")
            self.enhanced_connection_status_var.set("已连接")
            self.enhanced_connection_status_label.configure(foreground="green")
            self.enhanced_sync_btn.configure(state=tk.NORMAL)
        else:
            self.enhanced_status_var.set("详细诊断完成: 发现问题")
            self.enhanced_connection_status_var.set("连接异常")
            self.enhanced_connection_status_label.configure(foreground="red")
            
            # 提供修复建议
            self.enhanced_diag_text.configure(state=tk.NORMAL)
            self.enhanced_diag_text.insert(tk.END, "\n" + "="*60 + "\n")
            self.enhanced_diag_text.insert(tk.END, "🔧 修复建议:\n\n")
            
            for name, success, message, details in diagnostics:
                if not success:
                    if "SSL" in message or "握手" in message:
                        self.enhanced_diag_text.insert(tk.END, f"• {name}: 尝试使用网页登录方式\n", "advice")
                    elif "缺失" in message:
                        self.enhanced_diag_text.insert(tk.END, f"• {name}: 请填写完整配置信息\n", "advice")
                    elif "未登录" in message:
                        self.enhanced_diag_text.insert(tk.END, f"• {name}: 请先登录系统\n", "advice")
            
            self.enhanced_diag_text.tag_config("advice", foreground="blue")
            self.enhanced_diag_text.configure(state=tk.DISABLED)
    
    def _open_web_login(self):
        """打开网页登录 (方式1)"""
        account = self.enhanced_api_account_var.get().strip()
        base_url = self.enhanced_url_var.get().strip()
        
        if not base_url:
            messagebox.showwarning("提示", "请输入公卫3.0系统地址")
            return
        
        self.enhanced_status_var.set("正在打开浏览器...")
        self.enhanced_web_login_btn.configure(state=tk.DISABLED)

        # Pre-bind PH3 client base_url on main thread so subsequent
        # 同步配置 calls hit the right server.
        try:
            self.client.base_url = base_url.rstrip("/")
        except Exception:
            pass

        def worker():
            try:
                # 构建登录URL - 使用FormMain.aspx触发SSO重定向
                # 这是PH3Client使用的正确登录流程
                login_url = f"{base_url.rstrip('/')}/FormMain.aspx"
                webbrowser.open(login_url)
                success = True
                message = (f"已打开浏览器: {login_url}\n"
                           "请在浏览器中完成SSO登录")
            except Exception as e:
                success = False
                message = f"打开浏览器失败: {str(e)}"
            
            # All Tk-variable writes + config save happen on the main thread.
            self._safe_after(lambda: self._web_login_apply_and_finish(
                success, message, account, base_url
            ))

        threading.Thread(target=worker, daemon=True).start()

    def _web_login_apply_and_finish(self, success: bool, message: str,
                                    account: str, base_url: str):
        """Main-thread continuation for `_open_web_login`."""
        if success and (account or base_url):
            try:
                self.var_account.set(account)
                self.var_url.set(base_url)
                self._cfg["username"] = account
                self._cfg["ggws_base_url"] = base_url
                self._save_current_config()
            except Exception as e:
                # Don't crash the UI if config save fails for some reason.
                print(f"[web-login] config save warning: {e}")
        self._web_login_result(success, message)
    def _web_login_result(self, success: bool, message: str):
        """网页登录结果"""
        self.enhanced_web_login_btn.configure(state=tk.NORMAL)
        
        if success:
            self.enhanced_status_var.set("已打开浏览器，请在浏览器中登录")
            
            # 显示提示信息
            guide = """登录提示：
            
1. 请在浏览器中完成公卫3.0系统登录
2. 登录成功后，返回本程序
3. 点击「同步配置」按钮提取机构、团队、医生信息
4. 然后即可使用查询和签约功能
            
注意：请确保在浏览器中登录的是正确的账号和系统。"""
            
            messagebox.showinfo("登录提示", guide)
            
            # 启用同步按钮
            self.enhanced_sync_btn.configure(state=tk.NORMAL)
            
        else:
            self.enhanced_status_var.set("打开浏览器失败")
            messagebox.showerror("错误", message)
    
    def _sync_login_configuration(self):
        """同步配置 - 从PH3Client会话中提取机构信息"""
        self.enhanced_status_var.set("正在同步配置信息...")
        self.enhanced_sync_btn.configure(state=tk.DISABLED)
        
        def worker():
            try:
                # 获取当前页面HTML (网络IO在 worker 线程)
                current_page_html = self._get_current_page_html()
                
                if not current_page_html:
                    self._safe_after(lambda: self._sync_login_failed(
                        "无法获取当前页面，请确保已在浏览器中登录"
                    ))
                    return
                
                # 从HTML中提取机构信息
                extracted = self._extract_org_info_from_html(current_page_html)
                
                # 如果机构代码为空，回退到客户端已有的字段
                if not extracted.get("org_code"):
                    if getattr(self.client, "org_code", ""):
                        extracted["org_code"] = self.client.org_code
                    if getattr(self.client, "org_name", ""):
                        extracted["org_name"] = self.client.org_name
                    if getattr(self.client, "doctor_name", ""):
                        extracted["doctor_name"] = self.client.doctor_name
                    if getattr(self.client, "team_name", ""):
                        extracted["team_name"] = self.client.team_name
                
                extracted["synced_at"] = datetime.now().isoformat()
                extracted["extraction_method"] = "actual_session"
                
                # All UI writes + config save run on main thread
                self._safe_after(lambda: self._sync_apply_and_complete(extracted))
                
            except Exception as e:
                error_msg = f"同步配置失败: {str(e)}"
                print(f"❌ {error_msg}")
                self._safe_after(lambda: self._sync_login_failed(error_msg))
        
        threading.Thread(target=worker, daemon=True).start()

    def _sync_apply_and_complete(self, extracted: Dict[str, Any]):
        """Main-thread continuation for `_sync_login_configuration`."""
        try:
            self._cfg.update(extracted)
            self.enhanced_account_var.set(self._cfg.get("username", "未设置"))
            self._save_current_config()
        except Exception as e:
            print(f"[sync] apply warning: {e}")
        self._sync_login_complete(extracted)
    
    def _get_current_page_html(self) -> str:
        """获取当前页面HTML"""
        try:
            # 尝试访问主页面
            response = self.client.session.get(self.client._url("/FormMain.aspx"), timeout=30)
            if response.status_code == 200:
                return response.text
            
            # 如果失败，尝试其他页面
            response = self.client.session.get(self.client._url("/Index.aspx"), timeout=30)
            if response.status_code == 200:
                return response.text
                
        except Exception as e:
            print(f"❌ 获取当前页面失败: {e}")
        
        return ""
    
    def _extract_org_info_from_html(self, html: str) -> dict:
        """从HTML中提取机构信息"""
        import re
        
        result = {
            "org_code": "",
            "org_name": "",
            "team_code": "",
            "team_name": "",
            "doctor_code": "",
            "doctor_name": ""
        }
        
        if not html:
            return result
        
        # 尝试多种机构代码模式
        org_patterns = [
            r"""(?:ORGCODE|orgcode|OrgCode)\s*[=:]\s*['"](\d{10,})['"]""",
            r"""orgCode\s*:\s*['"](\d{10,})['"]""",
            r"""orgCode\s*=\s*['"](\d{10,})['"]""",
            r"""orgcode\s*:\s*['"](\d{10,})['"]""",
            r"""orgcode\s*=\s*['"](\d{10,})['"]""",
            r"""ORGCODE\s*:\s*['"](\d{10,})['"]""",
            r"""ORGCODE\s*=\s*['"](\d{10,})['"]""",
            r"""var\s+orgCode\s*=\s*['"](\d{10,})['"]""",
            r"""var\s+ORGCODE\s*=\s*['"](\d{10,})['"]""",
            r"""name\s*=\s*['"]orgcode['"]\s+value\s*=\s*['"](\d{10,})['"]""",
            r"""type\s*=\s*['"]hidden['"]\s+name\s*=\s*['"]orgcode['"]\s+value\s*=\s*['"](\d{10,})['"]""",
            r"""data-orgcode\s*=\s*['"](\d{10,})['"]""",
            r"""orgCode\s*=\s*['"](\d{10,})['"]""",
            r"""orgcode\s*=\s*['"](\d{10,})['"]""",
            r"""ORGCODE\s*=\s*['"](\d{10,})['"]""",
            r"""org[^>]*?['"](\d{10,})['"]""",
        ]
        
        # 提取机构代码
        for pattern in org_patterns:
            org_m = re.search(pattern, html, re.IGNORECASE)
            if org_m:
                result["org_code"] = org_m.group(1)
                break
        
        # 提取机构名称
        org_name_patterns = [
            r"""orgName\s*[=:]\s*['"]([^'"]+)['"]""",
            r"""ORGNAME\s*[=:]\s*['"]([^'"]+)['"]""",
            r"""机构名称[^>]*?['"]([^'"]+)['"]""",
        ]
        
        for pattern in org_name_patterns:
            name_m = re.search(pattern, html, re.IGNORECASE)
            if name_m:
                result["org_name"] = name_m.group(1)
                break
        
        # 提取医生信息
        doctor_patterns = [
            r"""doctorName\s*[=:]\s*['"]([^'"]+)['"]""",
            r"""DOCTORNAME\s*[=:]\s*['"]([^'"]+)['"]""",
            r"""医生姓名[^>]*?['"]([^'"]+)['"]""",
            r"""<span[^>]*?id="lblDoctor"[^>]*?>([^<]+)</span>""",
        ]
        
        for pattern in doctor_patterns:
            doctor_m = re.search(pattern, html, re.IGNORECASE)
            if doctor_m:
                result["doctor_name"] = doctor_m.group(1)
                break
        
        # 提取团队信息
        team_patterns = [
            r"""teamName\s*[=:]\s*['"]([^'"]+)['"]""",
            r"""TEAMNAME\s*[=:]\s*['"]([^'"]+)['"]""",
            r"""团队名称[^>]*?['"]([^'"]+)['"]""",
        ]
        
        for pattern in team_patterns:
            team_m = re.search(pattern, html, re.IGNORECASE)
            if team_m:
                result["team_name"] = team_m.group(1)
                break
        
        return result
    
    def _sync_login_failed(self, error_message: str):
        """同步配置失败"""
        self.enhanced_sync_btn.configure(state=tk.NORMAL)
        self.enhanced_status_var.set("同步失败")
        messagebox.showerror("同步失败", f"配置同步失败:\n\n{error_message}\n\n请确保：\n1. 已在浏览器中登录公卫3.0系统\n2. 登录的账号有权限访问当前机构\n3. 网络连接正常")
    
    def _sync_login_complete(self, extracted: Dict[str, Any]):
        """同步完成"""
        self.enhanced_sync_btn.configure(state=tk.NORMAL)
        
        # 显示提取的信息
        info_text = "✅ 配置同步完成！\n\n已提取的信息：\n"
        for key, value in extracted.items():
            if value and key not in ['synced_at']:
                info_text += f"  • {key}: {value}\n"
        
        messagebox.showinfo("同步完成", info_text)
        self.enhanced_status_var.set("配置同步完成")
        
        # 重新运行诊断
        self._run_login_diagnosis()
    
    def _perform_api_login(self):
        """执行API登录 (方式2)"""
        account = self.enhanced_api_account_var.get().strip()
        password = self.enhanced_api_password_var.get().strip()
        base_url = self.enhanced_url_var.get().strip()
        
        if not account or not password or not base_url:
            messagebox.showwarning("提示", "请输入完整的登录信息（账号、密码、系统地址）")
            return
        
        self.enhanced_status_var.set("正在登录...")
        self.enhanced_api_login_btn.configure(state=tk.DISABLED)
        
        def worker():
            try:
                # 调用现有的登录方法 (网络IO在 worker 线程)
                success, message = self.client.login(
                    base_url, account, password
                )
            except Exception as e:
                success, message = False, f"登录异常: {str(e)}"
            
            # All Tk-variable writes + config save happen on the main thread.
            self._safe_after(lambda: self._api_login_apply_and_finish(
                success, message, account, password, base_url
            ))
        
        threading.Thread(target=worker, daemon=True).start()

    def _api_login_apply_and_finish(self, success: bool, message: str,
                                    account: str, password: str,
                                    base_url: str):
        """Main-thread continuation for `_perform_api_login`."""
        if success:
            try:
                self.var_account.set(account)
                self.var_password.set(password)
                self.var_url.set(base_url)
                self._cfg["username"] = account
                self._cfg["password"] = password
                self._cfg["ggws_base_url"] = base_url
                self._save_current_config()
            except Exception as e:
                print(f"[api-login] config save warning: {e}")
        self._api_login_result(success, message)
    
    def _api_login_result(self, success: bool, message: str):
        """API登录结果"""
        self.enhanced_api_login_btn.configure(state=tk.NORMAL)
        
        if not success:
            self.enhanced_status_var.set("登录失败")
            messagebox.showerror("登录失败", message)
            return

        # success=True 也可能只是 "Token已下发但二维码未扫描"
        if getattr(self.client, "qr_pending", False):
            self.enhanced_status_var.set("登录不完整: 需要二维码验证")
            self.enhanced_sync_btn.configure(state=tk.NORMAL)
            messagebox.showwarning(
                "需要二维码验证",
                f"{message}\n\n"
                "服务器在 SSO 之外强制要求二维码扫码验证。\n\n"
                "下一步：\n"
                "  1. 点击 [跳转到3.0系统登录]，在浏览器中完成扫码\n"
                "  2. 浏览器登录成功后回到本程序，点击 [同步配置]\n"
                "  3. 同步成功后再使用 [查询(首页)] / [查询全部]"
            )
        else:
            self.enhanced_status_var.set("登录成功")
            self.enhanced_sync_btn.configure(state=tk.NORMAL)
            messagebox.showinfo("登录成功", message)

        # 不论是哪一种成功，都重新跑诊断
        self._run_login_diagnosis()


def main():
    try:
        from gmssl.sm4 import CryptSM4
    except ImportError:
        pass

    app = GulfSignApp()
    app.mainloop()


if __name__ == "__main__":
    main()
