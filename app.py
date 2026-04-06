# -*- coding: utf-8 -*-
"""
湾流签约助手 — 桌面版
公卫3.0 批量签约自动化工具
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

# PyInstaller frozen EXE: add bundled data dir to import path
if getattr(sys, "frozen", False):
    _bundle_dir = getattr(sys, "_MEIPASS", os.path.dirname(sys.executable))
    if _bundle_dir not in sys.path:
        sys.path.insert(0, _bundle_dir)

from ph3_api import PH3Client, Patient, SignResult, POPULATION_TYPES

VERSION = "1.1.0"
APP_TITLE = "湾流签约助手 v%s" % VERSION
CONFIG_FILE = "gulfsign_config.json"

# ---------------------------------------------------------------------------
# 配置持久化
# ---------------------------------------------------------------------------

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


# ---------------------------------------------------------------------------
# 主应用
# ---------------------------------------------------------------------------

class GulfSignApp(tk.Tk):

    def __init__(self):
        super().__init__()

        self.title(APP_TITLE)
        self.geometry("960x750")
        self.minsize(860, 680)

        self.client = PH3Client()
        self.patients: List[Patient] = []
        self.selected_ids: set = set()

        self._signing = False
        self._paused = False
        self._stop_event = threading.Event()

        self._sign_success = 0
        self._sign_fail = 0
        self._sign_total = 0
        self._sign_start_time = 0.0

        self._cfg = load_config()

        self._build_ui()
        self._restore_config()

        self.protocol("WM_DELETE_WINDOW", self._on_close)

    # ================================================================
    # UI 构建
    # ================================================================

    def _build_ui(self):
        style = ttk.Style(self)
        available = style.theme_names()
        for theme in ("vista", "winnative", "clam", "aqua"):
            if theme in available:
                style.theme_use(theme)
                break

        style.configure("Success.TLabel", foreground="#16a34a")
        style.configure("Error.TLabel", foreground="#dc2626")
        style.configure("Info.TLabel", foreground="#2563eb")
        style.configure(
            "Header.TLabel", font=("", 11, "bold"),
        )

        main = ttk.Frame(self, padding=8)
        main.pack(fill=tk.BOTH, expand=True)

        self._build_login_section(main)
        self._build_query_section(main)
        self._build_table_section(main)
        self._build_signing_section(main)
        self._build_log_section(main)

    # ---- 登录区 ----

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

    # ---- 查询区 ----

    def _build_query_section(self, parent):
        frame = ttk.LabelFrame(parent, text=" 查询条件 ", padding=6)
        frame.pack(fill=tk.X, pady=(0, 4))

        r0 = ttk.Frame(frame)
        r0.pack(fill=tk.X)

        ttk.Label(r0, text="签约状态:").pack(side=tk.LEFT)
        self.var_status = tk.StringVar(value="未签约")
        status_combo = ttk.Combobox(
            r0, textvariable=self.var_status, width=12, state="readonly",
            values=["未签约", "已签约", "医生申请", "居民申请", "拒绝签约", "全部"],
        )
        status_combo.pack(side=tk.LEFT, padx=(4, 16))

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

    # ---- 表格区 ----

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

    # ---- 签约控制区 ----

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

    # ---- 日志区 ----

    def _build_log_section(self, parent):
        frame = ttk.LabelFrame(parent, text=" 运行日志 ", padding=4)
        frame.pack(fill=tk.BOTH, expand=False, pady=(0, 0))
        frame.configure(height=140)

        log_frame = ttk.Frame(frame)
        log_frame.pack(fill=tk.BOTH, expand=True)

        self.log_text = tk.Text(
            log_frame, height=7, wrap=tk.WORD, state=tk.DISABLED,
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
    # 配置 保存/恢复
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
        })

    # ================================================================
    # 日志
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
    # 登录
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
    # 查询
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

    # ---- 表格交互 ----

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

    # ---- 导出 ----

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
    # 批量签约
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

    def _batch_sign_worker(
        self,
        targets: List[Patient],
        delay: float,
        doctor: str,
        team: str,
        sign_opts: dict = None,
    ):
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

    def _on_close(self):
        if self._signing:
            if not messagebox.askyesno("确认退出", "正在签约中，确定要退出吗？"):
                return
            self._stop_event.set()
            self._paused = False
        self._save_current_config()
        self.destroy()


# ---------------------------------------------------------------------------
# 入口
# ---------------------------------------------------------------------------

def main():
    try:
        from gmssl.sm4 import CryptSM4
    except ImportError:
        root = tk.Tk()
        root.withdraw()
        messagebox.showerror(
            "缺少依赖",
            "未安装 gmssl 加密库。\n\n"
            "请执行以下命令安装:\n"
            "  pip install gmssl\n\n"
            "安装后重新启动程序。"
        )
        sys.exit(1)

    app = GulfSignApp()
    app.mainloop()


if __name__ == "__main__":
    main()
