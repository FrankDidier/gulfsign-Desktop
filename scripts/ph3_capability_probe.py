# -*- coding: utf-8 -*-
"""
公卫 3.0 / 周边入口「能力哨兵」探测脚本（Future-facing sentinel）

在不改动桌面 GUI 的前提下，定期探测：
  - 登录是否仍可用
  - /Vue/、/cx/ 等路径是否从 403/404 变为可用
  - FormMain / 菜单文本是否出现「签约登记」「代签」等新入口关键词
  - 家医列表查询（Do_B0105_Handler action=4）是否正常
  - 健康卡平台 services.ashx 是否仍返回预期的「需要 token」类响应

凭据优先顺序（不向控制台打印密码）：
  环境变量 PH3_ACCOUNT / PH3_PASSWORD / PH3_BASE_URL
  可选：--password-file 单行密码文件
  可选：--config 指向 gulfsign_config.json（读取 url、account；密码仍须 env 或 password-file）

用法：
  export PH3_ACCOUNT=xxx
  export PH3_PASSWORD=yyy
  python scripts/ph3_capability_probe.py

  # 每 6 小时跑一次（cron）
  python scripts/ph3_capability_probe.py --interval 21600 --log-file probe_history.jsonl

退出码：登录失败或致命错误为 1；单次探测成功为 0。
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import time

import requests
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

# gulfsign-desktop root (parent of scripts/)
_SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
_DESKTOP_ROOT = os.path.dirname(_SCRIPT_DIR)
if _DESKTOP_ROOT not in sys.path:
    sys.path.insert(0, _DESKTOP_ROOT)

from ph3_api import PH3Client  # noqa: E402


def _utc_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _short_snippet(text: str, n: int = 120) -> str:
    if not text:
        return ""
    t = text.replace("\r", " ").replace("\n", " ").strip()
    return t[:n] + ("…" if len(t) > n else "")


def _http_probe(session, base: str, path: str, timeout: int = 20) -> Dict[str, Any]:
    url = base.rstrip("/") + path
    try:
        r = session.get(url, timeout=timeout)
        body = r.text or ""
        return {
            "url": path,
            "http_status": r.status_code,
            "content_length": len(r.content),
            "snippet": _short_snippet(body, 160),
        }
    except Exception as e:
        return {"url": path, "error": str(e)[:200]}


def _hash_main(html: str) -> str:
    return hashlib.sha256(html.encode("utf-8", errors="ignore")).hexdigest()[:16]


def _menu_keyword_scan(html: str) -> Dict[str, bool]:
    keys = [
        "签约登记",
        "代签",
        "长信",
        "批量导入",
        "签约审核",
        "/cx/",
        "daiqian",
        "changxin",
        "免审",
    ]
    return {k: (k in html) for k in keys}


def _load_credentials(
    config_path: Optional[str],
    password_file: Optional[str],
) -> Tuple[str, str, str]:
    base_url = (os.environ.get("PH3_BASE_URL") or "").strip()
    account = (os.environ.get("PH3_ACCOUNT") or "").strip()
    password = (os.environ.get("PH3_PASSWORD") or "").strip()

    cfg_file = config_path or os.path.join(_DESKTOP_ROOT, "gulfsign_config.json")
    if os.path.isfile(cfg_file):
        try:
            with open(cfg_file, "r", encoding="utf-8") as f:
                cfg = json.load(f)
            if not base_url and cfg.get("url"):
                base_url = str(cfg["url"]).strip()
            if not account and cfg.get("account"):
                account = str(cfg["account"]).strip()
        except Exception:
            pass

    if not base_url:
        base_url = "https://ggws.hnhfpc.gov.cn"

    if password_file and os.path.isfile(password_file):
        try:
            with open(password_file, "r", encoding="utf-8") as f:
                password = f.read().strip()
        except Exception:
            pass

    return base_url, account, password


def run_probe_once(
    base_url: str,
    account: str,
    password: str,
) -> Tuple[Dict[str, Any], bool]:
    """返回 (report_dict, login_ok)。"""
    report: Dict[str, Any] = {
        "ts": _utc_iso(),
        "base_url": base_url,
        "account": account[:6] + "…" if len(account) > 8 else ("***" if account else ""),
    }

    client = PH3Client()
    ok, login_msg = client.login(base_url, account, password)
    report["login_ok"] = ok
    report["login_message"] = login_msg[:300] if login_msg else ""

    if not ok:
        report["fatal"] = "login_failed"
        return report, False

    sess = client.session
    base = client.base_url.rstrip("/")

    # --- Static path probes (same session cookies) ---
    report["paths"] = {
        "vue_slash": _http_probe(sess, base, "/Vue/"),
        "cx_slash": _http_probe(sess, base, "/cx/"),
        "b0105_view_lower": _http_probe(sess, base, "/Sys_JCWS/b0105/Pg_View_B0105.aspx"),
        "b0105_view_upper": _http_probe(sess, base, "/Sys_JCWS/B0105/Pg_View_B0105.aspx"),
        "form_main": _http_probe(sess, base, "/FormMain.aspx"),
    }

    fm = report["paths"].get("form_main") or {}
    if fm.get("http_status") == 200 and fm.get("content_length", 0) > 100:
        try:
            r = sess.get(base + "/FormMain.aspx", timeout=25)
            html = r.text or ""
            report["form_main_sha256_prefix"] = _hash_main(html)
            report["menu_keyword_hits"] = _menu_keyword_scan(html)
        except Exception as e:
            report["form_main_parse_error"] = str(e)[:200]

    # --- Common.ashx menu attempts ---
    menu_attempts: List[Dict[str, Any]] = []
    for action in ("GETMENU", "GetMenu", "getmenu", "MENU"):
        try:
            r = sess.get(
                base + "/ashx/Common.ashx",
                params={"action": action},
                timeout=15,
            )
            menu_attempts.append({
                "action": action,
                "http_status": r.status_code,
                "length": len(r.content),
                "snippet": _short_snippet(r.text or "", 80),
            })
        except Exception as e:
            menu_attempts.append({"action": action, "error": str(e)[:120]})
    report["common_ashx_menu"] = menu_attempts

    # --- B0105 list query (validates encrypted grid path) ---
    try:
        pts, total = client.query_patients(status="0", page=1)
        report["b0105_query_signed_total"] = total
        report["b0105_query_signed_sample_rows"] = len(pts)
    except Exception as e:
        report["b0105_query_error"] = str(e)[:200]

    try:
        pts5, total5 = client.query_patients(status="5", page=1)
        report["b0105_query_doctor_pending_total"] = total5
    except Exception as e:
        report["b0105_query_doctor_pending_error"] = str(e)[:200]

    # --- GETCARDSSTATUSFORM sample (needs a contract; skip if none) ---
    try:
        pts0, tot0 = client.query_patients(status="0", page=1)
        if pts0 and getattr(pts0[0], "contract_code", "") and pts0[0].person_id:
            p0 = pts0[0]
            r = sess.get(
                base + "/Sys_JCWS/B0105/Do_B0105_Handler.ashx",
                params={
                    "ACTION": "GETCARDSSTATUSFORM",
                    "GUID": p0.contract_code,
                    "PERSONID": p0.person_id,
                },
                timeout=15,
            )
            report["getcardsstatusform_ok"] = r.status_code == 200
            report["getcardsstatusform_len"] = len(r.content)
            report["getcardsstatusform_snippet"] = _short_snippet(r.text or "", 120)
    except Exception as e:
        report["getcardsstatusform_error"] = str(e)[:200]

    # --- Health card platform (no login): token expectation ---
    try:
        from ph3_api import _LooseTLSAdapter

        hc = requests.Session()
        hc.trust_env = False
        hc.mount("https://", _LooseTLSAdapter())
        hc.verify = False
        hr = hc.get(
            "https://jkkyljl.hnhfpc.gov.cn/httpapi/services.ashx",
            params={"ACTION": "newlist"},
            timeout=12,
        )
        report["jkkyljl_newlist"] = {
            "http_status": hr.status_code,
            "length": len(hr.content),
            "snippet": _short_snippet(hr.text or "", 120),
        }
    except Exception as e:
        report["jkkyljl_newlist_error"] = str(e)[:200]

    # --- Interpretation hints (machine-friendly) ---
    vue = report["paths"].get("vue_slash") or {}
    cx = report["paths"].get("cx_slash") or {}
    mh = report.get("menu_keyword_hits") or {}
    report["signals"] = {
        # True = 入口可能已开放（由 403/404 变为可浏览）
        "vue_returns_200": vue.get("http_status") == 200,
        "cx_returns_200": cx.get("http_status") == 200,
        "签约登记_in_form_main": bool(mh.get("签约登记")),
        "代签_in_form_main": bool(mh.get("代签")),
    }

    return report, True


def main() -> int:
    parser = argparse.ArgumentParser(description="PH3 capability probe sentinel")
    parser.add_argument(
        "--config",
        default=None,
        help="Path to gulfsign_config.json (url/account only)",
    )
    parser.add_argument(
        "--password-file",
        default=None,
        help="Single-line password file (optional)",
    )
    parser.add_argument(
        "--log-file",
        default=None,
        help="Append JSON lines here (default: scripts/ph3_probe_history.jsonl)",
    )
    parser.add_argument(
        "--interval",
        type=int,
        default=0,
        help="Seconds between runs; 0 = run once and exit",
    )
    args = parser.parse_args()

    base_url, account, password = _load_credentials(args.config, args.password_file)

    if not account or not password:
        print(
            "Missing PH3_ACCOUNT / PH3_PASSWORD (or password file).\n"
            "Example:\n  export PH3_ACCOUNT=your_account\n"
            "  export PH3_PASSWORD=your_password\n"
            "  python scripts/ph3_capability_probe.py",
            file=sys.stderr,
        )
        return 1

    log_path = args.log_file or os.path.join(_SCRIPT_DIR, "ph3_probe_history.jsonl")

    interval = max(0, int(args.interval))

    def one_round() -> int:
        report, ok = run_probe_once(base_url, account, password)
        line = json.dumps(report, ensure_ascii=False)
        print(line)
        try:
            with open(log_path, "a", encoding="utf-8") as f:
                f.write(line + "\n")
        except Exception:
            pass
        return 0 if ok else 1

    if interval <= 0:
        return one_round()

    while True:
        rc = one_round()
        if rc != 0:
            return rc
        time.sleep(interval)


if __name__ == "__main__":
    sys.exit(main())
