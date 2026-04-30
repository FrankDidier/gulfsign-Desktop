# -*- coding: utf-8 -*-
"""
PH3 permission-surface diff

Goal:
  Detect whether any session/context operation (e.g. org-switch-like actions)
  changes visible capability surface (menu entries, form keywords, endpoint access).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

_SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
_DESKTOP_ROOT = os.path.dirname(_SCRIPT_DIR)
if _DESKTOP_ROOT not in sys.path:
    sys.path.insert(0, _DESKTOP_ROOT)

from ph3_api import PH3Client  # noqa: E402


def _utc_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _sha16(s: str) -> str:
    return hashlib.sha256((s or "").encode("utf-8", errors="ignore")).hexdigest()[:16]


def _load_credentials(config_path: Optional[str], password_file: Optional[str]) -> Tuple[str, str, str]:
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


def _keyword_map(form_main: str, menu_xml: str) -> Dict[str, bool]:
    txt = (form_main or "") + "\n" + (menu_xml or "")
    keys = ["签约登记", "代签", "批量导入", "签约审核", "/cx/", "daiqian", "changxin", "Pg_Change_Status"]
    return {k: (k in txt) for k in keys}


def _snapshot(c: PH3Client, tag: str) -> Dict[str, Any]:
    base = c.base_url.rstrip("/")
    fm = c.session.get(base + "/FormMain.aspx", timeout=20).text
    menu = c.session.get(base + "/ashx/LoginHandler.ashx", params={"action": "GETMENU"}, timeout=20).text

    # visible org marker in FormMain
    org_codes = sorted(set(re.findall(r"\b\d{12,18}\b", fm)))[:20]

    checks = {}
    for p in [
        "/Sys_JCWS/B0105/Pg_View_B0105.aspx",
        "/Sys_JCWS/B0105/Pg_Change_Status.aspx",
        "/Sys_JCWS/ApiApplication/Pg_View_TBLBUS_ApiApplication.aspx",
        "/Sys_JCWS/TBLSYS_ExportExcel/Pg_View_TBLSYS_ExportExcel.aspx",
    ]:
        r = c.session.get(base + p, timeout=15)
        checks[p] = {"status": r.status_code, "len": len(r.text)}

    return {
        "tag": tag,
        "form_main_sha16": _sha16(fm),
        "menu_sha16": _sha16(menu),
        "form_main_len": len(fm),
        "menu_len": len(menu),
        "org_codes_sample": org_codes,
        "keywords": _keyword_map(fm, menu),
        "checks": checks,
    }


def run_diff(base_url: str, account: str, password: str) -> Tuple[Dict[str, Any], bool]:
    report: Dict[str, Any] = {
        "ts": _utc_iso(),
        "base_url": base_url,
        "account": account[:6] + "…" if len(account) > 8 else ("***" if account else ""),
    }
    c = PH3Client()
    ok, msg = c.login(base_url, account, password)
    report["login_ok"] = ok
    report["login_message"] = msg[:240] if msg else ""
    if not ok:
        report["fatal"] = "login_failed"
        return report, False

    base_snap = _snapshot(c, "baseline")
    report["baseline"] = base_snap

    # Candidate context-switch actions against LoginHandler.
    action_variants = [
        ("SWITCHORG", {"ORGCODE": "430726000000"}),
        ("SWITCHORG", {"ORGCODE": "430726100000"}),
        ("CHANGEORG", {"ORGCODE": "430726000000"}),
        ("CHANGEORG", {"ID": "430726000000"}),
        ("SETORG", {"ORGCODE": "430726000000"}),
        ("SELECTORG", {"ORGCODE": "430726000000"}),
        ("SETRIGHTORG", {"ORGCODE": "430726000000"}),
        ("SWITCHORG", {"ORGCODE": "430726000001024"}),
        ("CHANGEORG", {"ORGCODE": "430726000001024"}),
    ]

    probes: List[Dict[str, Any]] = []
    for i, (act, params) in enumerate(action_variants, 1):
        p = {"action": act}
        p.update(params)
        entry: Dict[str, Any] = {"index": i, "action": act, "params": params}
        try:
            rg = c.session.get(c.base_url + "/ashx/LoginHandler.ashx", params=p, timeout=12)
            rp = c.session.post(c.base_url + "/ashx/LoginHandler.ashx", params={"action": act}, data=params, timeout=12)
            entry["get_status"] = rg.status_code
            entry["get_len"] = len(rg.text)
            entry["post_status"] = rp.status_code
            entry["post_len"] = len(rp.text)

            snap = _snapshot(c, "after_%s_%d" % (act, i))
            entry["snapshot"] = snap
            entry["surface_changed"] = (
                snap["form_main_sha16"] != base_snap["form_main_sha16"]
                or snap["menu_sha16"] != base_snap["menu_sha16"]
                or snap["keywords"] != base_snap["keywords"]
            )
        except Exception as e:
            entry["error"] = str(e)[:200]
        probes.append(entry)

    report["probes"] = probes
    report["any_surface_changed"] = any(p.get("surface_changed") for p in probes)
    return report, True


def main() -> int:
    parser = argparse.ArgumentParser(description="PH3 permission surface diff")
    parser.add_argument("--config", default=None, help="Path to gulfsign_config.json")
    parser.add_argument("--password-file", default=None, help="Single-line password file")
    parser.add_argument("--out", default=None, help="Write JSON report to file")
    args = parser.parse_args()

    base_url, account, password = _load_credentials(args.config, args.password_file)
    if not account or not password:
        print("Missing PH3_ACCOUNT / PH3_PASSWORD (or password file).", file=sys.stderr)
        return 1

    report, ok = run_diff(base_url, account, password)
    blob = json.dumps(report, ensure_ascii=False, indent=2)
    print(blob)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(blob + "\n")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
