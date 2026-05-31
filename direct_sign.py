# -*- coding: utf-8 -*-
"""
直签 (Direct-Sign) — 基于已抓取的 [家医签约] POST 模板, 替换居民身份字段
后通过 PH3Client.session 重放, 试图复刻其它团队工具看到的 "STATUS=0
直接签约" 行为.

工作流程
========
1. 用户启用 [流量抓包] 代理, 在浏览器里点一次官方公卫3.0 [家医签约] 按钮
2. ``proxy_capture.OpenIDProxy`` 自动 dump 该 POST 为 JSON 模板, 落在
   ``.dbg/sign_captures/sign_<ts>_<action>.json``
3. ``SignTemplate.from_capture(path)`` 装载该模板
4. ``SignTemplate.replay_for(client, person_id, name=...)`` 以模板为底
   板, 替换 ``person_id`` 出现过的所有字段后通过 client.session POST 重放
5. 返回 ``DirectSignResult``, 与 ``ph3_api.SignResult`` 字段一致, 可被
   ``sign_engine`` / batch_processor 直接消费

设计要点
========
- **不臆造字段名**: 我们不预设服务器期望的字段名是 ``personId`` 还是
  ``RKBM`` 还是 ``DABH``. 而是按 *值* 匹配 — 模板里凡是出现原始 person_id
  的字段, 都按比例替换.
- **会话隔离**: 所有 POST 走 client.session, 这样自动带上 ASP.NET
  cookies / SSO token; 不依赖被抓包时的 cookie 头 (那个会过期).
- **诚实失败**: opType!=0 / 非 JSON / 异常 一律 success=False, 不假成功.
"""
from __future__ import annotations

import copy
import json
import logging
import os
import re
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlencode

logger = logging.getLogger(__name__)


@dataclass
class DirectSignResult:
    """直签结果, 字段对齐 ``ph3_api.SignResult`` 以便上游统一处理."""
    success: bool
    person_id: str
    name: str = ""
    contract_code: str = ""
    error: str = ""
    step: str = "direct_sign"
    elapsed: float = 0.0
    raw_response: str = ""
    op_type: Optional[int] = None
    template_action: str = ""


@dataclass
class SignTemplate:
    """表示一次抓到的 [家医签约] POST 请求, 可被参数化重放."""

    host: str
    path: str
    query: Dict[str, str] = field(default_factory=dict)
    headers: Dict[str, str] = field(default_factory=dict)
    body_form: Dict[str, str] = field(default_factory=dict)
    body_text: str = ""
    action: str = ""
    captured_at: str = ""
    source_file: str = ""

    # 抓取这次 POST 时使用的居民 person_id (用于值匹配替换). 可能未知.
    captured_person_id: str = ""
    captured_name: str = ""

    # ---------- I/O ----------

    @classmethod
    def from_capture(cls, path: str) -> "SignTemplate":
        with open(path, "r", encoding="utf-8") as f:
            obj = json.load(f)
        return cls.from_dict(obj, source_file=path)

    @classmethod
    def from_dict(cls, obj: dict, source_file: str = "") -> "SignTemplate":
        body_form = obj.get("body_form") or {}
        # 自动嗅探 captured_person_id (任何 18 位数字字段)
        cid = ""
        cname = ""
        for k, v in body_form.items():
            if not isinstance(v, str):
                continue
            # 18 位身份证或 32-36 位 GUID 都算候选
            if re.fullmatch(r"\d{17}[0-9Xx]", v) and not cid:
                cid = v
            elif re.fullmatch(r"[A-Fa-f0-9-]{32,36}", v) and not cid:
                cid = v
            # 中文姓名 (2-4 位汉字)
            if re.fullmatch(r"[\u4e00-\u9fa5]{2,4}", v) and not cname:
                cname = v

        return cls(
            host=obj.get("host", ""),
            path=obj.get("path", ""),
            query=dict(obj.get("query") or {}),
            headers=dict(obj.get("headers") or {}),
            body_form=dict(body_form),
            body_text=obj.get("body_text", ""),
            action=obj.get("action", ""),
            captured_at=obj.get("timestamp", ""),
            source_file=source_file,
            captured_person_id=cid,
            captured_name=cname,
        )

    def to_dict(self) -> dict:
        return {
            "host": self.host,
            "path": self.path,
            "query": dict(self.query),
            "headers": dict(self.headers),
            "body_form": dict(self.body_form),
            "body_text": self.body_text,
            "action": self.action,
            "captured_at": self.captured_at,
            "source_file": self.source_file,
            "captured_person_id": self.captured_person_id,
            "captured_name": self.captured_name,
        }

    # ---------- inspection ----------

    def summary(self) -> str:
        n_fields = len(self.body_form)
        return (
            "[%s] %s ACTION=%s 字段数=%d cid=%s name=%s 抓于=%s"
            % (
                self.host, self.path, self.action or "?",
                n_fields,
                self.captured_person_id or "?",
                self.captured_name or "?",
                self.captured_at or "?",
            )
        )

    def likely_personid_fields(self) -> List[str]:
        """返回 body_form 中, 值等于 captured_person_id 的所有字段名 — 这
        些就是重放时要替换的字段."""
        if not self.captured_person_id:
            return []
        return [
            k for k, v in self.body_form.items()
            if v == self.captured_person_id
        ]

    def likely_name_fields(self) -> List[str]:
        if not self.captured_name:
            return []
        return [
            k for k, v in self.body_form.items()
            if v == self.captured_name
        ]

    # ---------- replay ----------

    def build_form_for(
        self,
        person_id: str,
        name: str = "",
        extra_overrides: Optional[Dict[str, str]] = None,
    ) -> Dict[str, str]:
        """生成针对一名新居民的 body_form (不发请求, 仅构造)."""
        new_form = copy.deepcopy(self.body_form)

        # 1) 按值替换 person_id (覆盖率最高的策略)
        if self.captured_person_id and person_id:
            for k, v in list(new_form.items()):
                if v == self.captured_person_id:
                    new_form[k] = person_id

        # 2) 按值替换 name — 仅当调用方提供了 name 时才换, 否则保留原名
        #    (如果原 name 字段被服务器作 name->personId 反向校验, 不换更安全;
        #    如果服务器只看 personId 不看 name, 留着也无害.)
        if name and self.captured_name:
            for k, v in list(new_form.items()):
                if v == self.captured_name:
                    new_form[k] = name

        # 3) 调用方指定的覆盖 — 兼容机构/团队/医生切换
        if extra_overrides:
            for k, v in extra_overrides.items():
                new_form[k] = v

        return new_form

    def replay_for(
        self,
        client,
        person_id: str,
        name: str = "",
        extra_overrides: Optional[Dict[str, str]] = None,
        verify_logged_in: bool = True,
        timeout: Optional[int] = None,
    ) -> DirectSignResult:
        """通过 ``client.session`` (PH3Client 的) 重放本模板.

        关键: 不带模板里抓到的 cookie 头 — 它会过期; 让 client.session 用
        当前活跃 cookies. 但保留 Content-Type / Referer / X-Requested-With
        等无状态头.
        """
        t0 = time.time()

        # --- 必要前置检查 ---
        if verify_logged_in:
            if not getattr(client, "logged_in", False):
                return DirectSignResult(
                    False, person_id, name,
                    error="客户端未登录",
                    step="direct_sign",
                    template_action=self.action,
                )
            if getattr(client, "qr_pending", False):
                return DirectSignResult(
                    False, person_id, name,
                    error="登录不完整: 需要二维码验证",
                    step="direct_sign",
                    template_action=self.action,
                )
            if not getattr(client, "org_code", ""):
                return DirectSignResult(
                    False, person_id, name,
                    error="缺少机构代码 (org_code), 请同步配置",
                    step="direct_sign",
                    template_action=self.action,
                )

        if not person_id:
            return DirectSignResult(
                False, person_id, name,
                error="person_id 为空", step="direct_sign",
                template_action=self.action,
            )

        if not self.captured_person_id:
            return DirectSignResult(
                False, person_id, name,
                error=(
                    "模板里没识别出 captured_person_id, 无法替换字段; "
                    "请重新抓取一次包含明确 18 位身份证或 GUID 的请求"
                ),
                step="direct_sign",
                template_action=self.action,
            )

        # --- 构造目标 URL (走 client.base_url, 不直连 captured host) ---
        base_url = getattr(client, "base_url", "") or ("https://" + self.host)
        url = base_url.rstrip("/") + self.path
        if self.query:
            url = url + "?" + urlencode(self.query)

        # --- 构造 form ---
        form = self.build_form_for(person_id, name, extra_overrides)

        # --- 构造 headers — 仅保留无状态 / 重放安全的 ---
        SAFE_HEADERS = {
            "Content-Type", "X-Requested-With", "Accept", "Accept-Language",
            "Origin", "Referer", "User-Agent",
        }
        headers = {
            k: v for k, v in self.headers.items()
            if k in SAFE_HEADERS or k.lower() in {h.lower() for h in SAFE_HEADERS}
        }
        # 保证有 X-Requested-With (公卫 3.0 服务器以此区分 AJAX vs 表单)
        headers.setdefault("X-Requested-With", "XMLHttpRequest")

        # --- 发请求 ---
        try:
            resp = client.session.post(
                url, data=form, headers=headers,
                timeout=timeout if timeout is not None
                else getattr(client, "_timeout", 60),
            )
        except Exception as e:
            return DirectSignResult(
                False, person_id, name,
                error="网络异常: %s" % e,
                step="direct_sign", elapsed=time.time() - t0,
                template_action=self.action,
            )

        elapsed = time.time() - t0

        if resp.status_code != 200:
            return DirectSignResult(
                False, person_id, name,
                error="HTTP %d" % resp.status_code,
                step="direct_sign", elapsed=elapsed,
                raw_response=resp.text[:1000] if resp.text else "",
                template_action=self.action,
            )

        text = (resp.text or "").strip()

        # --- 解析响应 ---
        try:
            obj = json.loads(text)
            op = obj.get("opType")
            try:
                op_int = int(op) if op is not None else None
            except (TypeError, ValueError):
                op_int = None

            if op_int == 0:
                cc = (
                    obj.get("type", "")
                    or obj.get("CONTRACT_CODE", "")
                    or obj.get("contract_code", "")
                    or ""
                )
                return DirectSignResult(
                    True, person_id, name,
                    contract_code=cc,
                    step="direct_sign",
                    elapsed=elapsed,
                    raw_response=text[:1000],
                    op_type=op_int,
                    template_action=self.action,
                )
            return DirectSignResult(
                False, person_id, name,
                error=str(obj.get("msg")) if obj.get("msg") else
                      ("opType=%s" % op),
                step="direct_sign",
                elapsed=elapsed,
                raw_response=text[:1000],
                op_type=op_int,
                template_action=self.action,
            )
        except (ValueError, TypeError):
            # 非 JSON 响应 — 公卫 3.0 偶尔返回 HTML 错误页; 启发式判断
            cc_m = re.search(
                r'[Cc]ontract.?[Cc]ode["\s]*[=:]["\s]*([a-f0-9-]{36})',
                text, re.IGNORECASE,
            )
            if cc_m:
                return DirectSignResult(
                    True, person_id, name,
                    contract_code=cc_m.group(1),
                    step="direct_sign",
                    elapsed=elapsed,
                    raw_response=text[:1000],
                    template_action=self.action,
                )
            return DirectSignResult(
                False, person_id, name,
                error="非 JSON 响应 (前 120 字符: %s...)" % text[:120],
                step="direct_sign",
                elapsed=elapsed,
                raw_response=text[:1000],
                template_action=self.action,
            )


# =====================================================================
# 模板存储管理
# =====================================================================

DEFAULT_CAPTURE_DIR = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    ".dbg", "sign_captures",
)


def list_captures(capture_dir: str = DEFAULT_CAPTURE_DIR) -> List[str]:
    """列出所有抓到的签约 JSON 模板, 按修改时间倒序."""
    if not os.path.isdir(capture_dir):
        return []
    files = []
    for fn in os.listdir(capture_dir):
        if fn.endswith(".json") and fn.startswith("sign_"):
            fp = os.path.join(capture_dir, fn)
            try:
                files.append((os.path.getmtime(fp), fp))
            except OSError:
                continue
    files.sort(reverse=True)
    return [fp for _, fp in files]


def load_latest(capture_dir: str = DEFAULT_CAPTURE_DIR) -> Optional[SignTemplate]:
    """加载最新一次抓到的签约模板; 没有则返回 None."""
    files = list_captures(capture_dir)
    if not files:
        return None
    return SignTemplate.from_capture(files[0])


def batch_replay(
    client,
    template: SignTemplate,
    person_ids: List[str],
    names: Optional[List[str]] = None,
    delay: float = 0.3,
    on_progress=None,
) -> List[DirectSignResult]:
    """对一批居民串行重放同一模板 (避免并发触发服务器的速率/CSRF 防护)."""
    results: List[DirectSignResult] = []
    names = names or []
    for i, pid in enumerate(person_ids):
        nm = names[i] if i < len(names) else ""
        r = template.replay_for(client, pid, name=nm)
        results.append(r)
        if on_progress:
            try:
                on_progress(i + 1, len(person_ids), r)
            except Exception:
                pass
        if i + 1 < len(person_ids) and delay > 0:
            time.sleep(delay)
    return results
