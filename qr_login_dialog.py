# -*- coding: utf-8 -*-
"""集成的二维码扫码登录对话框 (与原 client.exe show_qrcode_dialog 同功能)。

使用方式:
    dlg = QRLoginDialog(parent_app, ph3_client)
    result = dlg.show()  # 阻塞式; 返回 (success: bool, message: str)

如何工作:
    1. 调用 ``ph3_client.qr_login_generate()`` 拿 base64 PNG + catoken.
    2. 把 PNG 解码后用 PIL/ImageTk 显示在窗口里.
    3. 后台线程每 2 秒调 ``ph3_client.qr_login_query(catoken)``;
       在主线程更新状态文本.
    4. 用户在 PH3 公卫小程序里扫码并确认 → query 返回 code=0.
       自动调 ``ph3_client.qr_login_finalize()`` 拿 org_code / 用户信息.
    5. 关闭对话框, 返回 (True, 描述信息).

UX 点:
    * 倒计时显示 (二维码默认有效期 ~120s, 过期后弹刷新按钮).
    * 任何阶段都允许用户取消; 取消后调用方应继续保持 qr_pending=True.
    * 在主线程外不触碰任何 Tk 变量 (用 ``parent.after(0, ...)`` 调度回主线程).
"""
from __future__ import annotations

import base64
import io
import threading
import tkinter as tk
from tkinter import ttk, messagebox
from typing import Optional, Tuple, TYPE_CHECKING

if TYPE_CHECKING:
    from ph3_api import PH3Client

try:
    from PIL import Image, ImageTk  # type: ignore
    _PIL_OK = True
except ImportError:  # pragma: no cover - tested at runtime
    _PIL_OK = False


# 二维码图像在 PH3 portal 里默认 ~130x130 px; 我们放大 2x 以方便扫码.
_QR_DISPLAY_SIZE = (260, 260)

# 轮询间隔 (与原 client.exe / 网页 setInterval 一致, 都是 2 秒)
_POLL_INTERVAL_MS = 2000

# 二维码默认服务端有效期 (估算; 服务端给的精确值不一定可见, 我们走渐进式
# 提示: 60s 后给一个 "如果扫不进就刷新" 提示, 但不强制刷新)
_REFRESH_HINT_AFTER_S = 60


class QRLoginDialog(tk.Toplevel):
    """阻塞式 (transient + grab_set) 的二维码扫码窗口."""

    def __init__(self, parent: tk.Misc, client: "PH3Client",
                 title: str = "扫码完成 2FA 登录"):
        super().__init__(parent)
        self.title(title)
        self.resizable(False, False)
        self.transient(parent)
        self.protocol("WM_DELETE_WINDOW", self._on_cancel)

        self._client = client
        self._catoken: str = ""
        self._photo: Optional["ImageTk.PhotoImage"] = None
        self._poll_after_id: Optional[str] = None
        self._tick_after_id: Optional[str] = None
        self._elapsed_s = 0
        self._closed = False
        self._result: Tuple[bool, str] = (False, "用户取消")

        self._build_ui()
        # 居中到 parent
        try:
            parent.update_idletasks()
            px = parent.winfo_rootx()
            py = parent.winfo_rooty()
            pw = parent.winfo_width()
            ph = parent.winfo_height()
            self.update_idletasks()
            sw = self.winfo_width()
            sh = self.winfo_height()
            self.geometry("+%d+%d" % (
                px + (pw - sw) // 2,
                py + (ph - sh) // 2,
            ))
        except Exception:
            pass

        # 第一次生成二维码
        self.after(50, self._generate_qr)

    # ----- 公开 API -----

    def show(self) -> Tuple[bool, str]:
        """阻塞直到关闭. 返回 (success, message)."""
        self.grab_set()
        self.wait_window(self)
        return self._result

    # ----- UI -----

    def _build_ui(self):
        outer = ttk.Frame(self, padding=16)
        outer.pack(fill=tk.BOTH, expand=True)

        ttk.Label(
            outer,
            text="请用「公卫3.0 全员业务办理」小程序扫描下方二维码",
            font=("Microsoft YaHei", 11, "bold"),
        ).pack(pady=(0, 4))

        ttk.Label(
            outer,
            text="扫码后在手机端确认即可，本窗口会自动完成登录",
            foreground="gray",
        ).pack(pady=(0, 12))

        if not _PIL_OK:
            ttk.Label(
                outer,
                text="⚠ 缺少 Pillow 依赖，无法显示二维码图像\n"
                "请运行: pip install Pillow",
                foreground="#dc2626",
                justify="center",
            ).pack(pady=20)
            ttk.Button(
                outer, text="改用网页扫码 (打开浏览器)",
                command=self._on_fallback_browser,
            ).pack(pady=(0, 8))
            ttk.Button(outer, text="取消", command=self._on_cancel).pack()
            return

        # QR 图像区
        self._img_label = ttk.Label(outer, width=30, anchor="center")
        self._img_label.pack(pady=(0, 8))

        # 状态行
        self._status_var = tk.StringVar(value="正在生成二维码...")
        ttk.Label(
            outer, textvariable=self._status_var,
            font=("Microsoft YaHei", 10),
        ).pack(pady=(0, 4))

        # 计时
        self._tick_var = tk.StringVar(value="")
        ttk.Label(
            outer, textvariable=self._tick_var, foreground="gray",
        ).pack(pady=(0, 12))

        # 按钮行
        btn_row = ttk.Frame(outer)
        btn_row.pack(fill=tk.X)

        self._refresh_btn = ttk.Button(
            btn_row, text="🔄 刷新二维码",
            command=self._on_refresh,
        )
        self._refresh_btn.pack(side=tk.LEFT, padx=(0, 8))

        ttk.Button(
            btn_row, text="改用网页扫码",
            command=self._on_fallback_browser,
        ).pack(side=tk.LEFT, padx=(0, 8))

        ttk.Button(
            btn_row, text="取消", command=self._on_cancel,
        ).pack(side=tk.RIGHT)

    # ----- 二维码生成 -----

    def _generate_qr(self):
        if self._closed:
            return
        self._set_status("正在生成二维码...", "#2563eb")

        def worker():
            try:
                ok, tokenimage, catoken, err = self._client.qr_login_generate()
            except Exception as e:
                ok, tokenimage, catoken, err = False, "", "", str(e)
            self._safe(lambda: self._on_qr_generated(ok, tokenimage, catoken, err))

        threading.Thread(target=worker, daemon=True).start()

    def _on_qr_generated(self, ok: bool, tokenimage: str,
                         catoken: str, err: str):
        if self._closed:
            return
        if not ok:
            self._set_status("二维码生成失败: %s" % err, "#dc2626")
            return

        if not _PIL_OK:
            return  # UI 已显示提示

        try:
            # tokenimage 形如 "data:image/png;base64,iVBOR..."
            payload = tokenimage.split(",", 1)[1] if "," in tokenimage else tokenimage
            raw = base64.b64decode(payload)
            img = Image.open(io.BytesIO(raw))
            img = img.resize(_QR_DISPLAY_SIZE, Image.NEAREST)
            self._photo = ImageTk.PhotoImage(img)
            self._img_label.configure(image=self._photo)
        except Exception as e:
            self._set_status("解析二维码图像失败: %s" % e, "#dc2626")
            return

        self._catoken = catoken
        self._elapsed_s = 0
        self._set_status("等待扫码...", "#16a34a")
        self._tick_var.set("已等待 0 秒")
        self._schedule_tick()
        self._schedule_poll()

    def _on_refresh(self):
        # 取消所有计时器, 重新生成
        self._cancel_timers()
        self._photo = None
        self._catoken = ""
        self._generate_qr()

    # ----- 轮询扫码状态 -----

    def _schedule_poll(self):
        if self._closed:
            return
        self._poll_after_id = self.after(_POLL_INTERVAL_MS, self._poll_once)

    def _poll_once(self):
        if self._closed or not self._catoken:
            return

        catoken = self._catoken

        def worker():
            try:
                code, msg = self._client.qr_login_query(catoken)
            except Exception as e:
                code, msg = -1, str(e)
            self._safe(lambda c=code, m=msg: self._on_poll_result(c, m))

        threading.Thread(target=worker, daemon=True).start()

    def _on_poll_result(self, code: int, msg: str):
        if self._closed:
            return

        if code == 0:
            # 扫码并通过 → finalize
            self._set_status("扫码成功，正在完成登录...", "#16a34a")
            self._cancel_timers()

            def fin_worker():
                try:
                    ok, info = self._client.qr_login_finalize()
                except Exception as e:
                    ok, info = False, str(e)
                self._safe(lambda o=ok, i=info: self._on_finalized(o, i))

            threading.Thread(target=fin_worker, daemon=True).start()
            return

        if code == 2:
            # 等待中 → 继续轮询 (注意: 我们没有重置轮询定时器, 这里只调度下一次)
            self._schedule_poll()
            return

        if code in (1, 3, 4):
            # 错误 → 显示并允许刷新
            self._set_status("二维码错误: %s" % (msg or "未知错误"), "#dc2626")
            self._cancel_timers()
            return

        # code == -1: 网络/解析错误 — 容忍一次, 继续轮询 (打印一次 warn 即可)
        self._set_status("轮询临时异常 (%s), 正在重试..." % msg, "#d97706")
        self._schedule_poll()

    def _on_finalized(self, ok: bool, info: str):
        if ok:
            self._result = (True, info)
            self._closed = True
            self.destroy()
        else:
            self._result = (False, info)
            self._set_status("登录完成失败: %s" % info, "#dc2626")

    # ----- 计时显示 -----

    def _schedule_tick(self):
        if self._closed:
            return
        self._tick_after_id = self.after(1000, self._tick)

    def _tick(self):
        if self._closed:
            return
        self._elapsed_s += 1
        if self._elapsed_s < _REFRESH_HINT_AFTER_S:
            self._tick_var.set("已等待 %d 秒" % self._elapsed_s)
        else:
            self._tick_var.set(
                "已等待 %d 秒 — 如长时间无响应, 点击 [🔄 刷新二维码]" %
                self._elapsed_s
            )
        self._schedule_tick()

    # ----- 通用 -----

    def _set_status(self, text: str, color: str = "#000000"):
        try:
            self._status_var.set(text)
        except Exception:
            pass

    def _cancel_timers(self):
        for attr in ("_poll_after_id", "_tick_after_id"):
            aid = getattr(self, attr, None)
            if aid:
                try:
                    self.after_cancel(aid)
                except Exception:
                    pass
                setattr(self, attr, None)

    def _safe(self, fn):
        try:
            self.after(0, fn)
        except Exception:
            pass

    def _on_cancel(self):
        self._closed = True
        self._cancel_timers()
        self._result = (False, "用户取消扫码")
        self.destroy()

    def _on_fallback_browser(self):
        """让用户回到原来的网页扫码路径 (作为兜底)."""
        self._closed = True
        self._cancel_timers()
        self._result = (False, "用户选择改用网页扫码")
        self.destroy()
