# -*- coding: utf-8 -*-
"""
Deep probe ApiApplication workflow: upload/create/query/audit routes.
"""

from __future__ import annotations

import argparse
import io
import json
import os
import re
import sys
import time
from datetime import datetime, timezone
from typing import Optional, Tuple

_SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
_DESKTOP_ROOT = os.path.dirname(_SCRIPT_DIR)
if _DESKTOP_ROOT not in sys.path:
    sys.path.insert(0, _DESKTOP_ROOT)

from ph3_api import PH3Client  # noqa: E402


def _utc_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _load_credentials(config_path: Optional[str], password_file: Optional[str]) -> Tuple[str, str, str]:
    base_url = (os.environ.get("PH3_BASE_URL") or "").strip()
    account = (os.environ.get("PH3_ACCOUNT") or "").strip()
    password = (os.environ.get("PH3_PASSWORD") or "").strip()
    cfg_file = config_path or os.path.join(_DESKTOP_ROOT, "gulfsign_config.json")
    if os.path.isfile(cfg_file):
        with open(cfg_file, "r", encoding="utf-8") as f:
            cfg = json.load(f)
        if not base_url:
            base_url = str(cfg.get("url", "")).strip()
        if not account:
            account = str(cfg.get("account", "")).strip()
    if not base_url:
        base_url = "https://ggws.hnhfpc.gov.cn"
    if password_file and os.path.isfile(password_file):
        with open(password_file, "r", encoding="utf-8") as f:
            password = f.read().strip()
    return base_url, account, password


def run(base_url: str, account: str, password: str) -> Tuple[dict, bool]:
    c = PH3Client()
    ok, msg = c.login(base_url, account, password)
    report = {"ts": _utc_iso(), "login_ok": ok, "login_message": msg}
    if not ok:
        return report, False

    h = c.base_url + "/Sys_JCWS/ApiApplication/Do_ApiApplication_Handler.ashx"
    insert_html = c.session.get(
        c.base_url + "/Sys_JCWS/ApiApplication/Pg_Insert_TBLBUS_ApiApplication.aspx",
        timeout=20,
    ).text
    form_defaults = {}
    for m in re.finditer(r"<input\b([^>]+)>", insert_html, re.I):
        attrs = m.group(1)
        tp = re.search(r'type=["\']([^"\']+)', attrs, re.I)
        typ = tp.group(1).lower() if tp else "text"
        if typ in ("submit", "reset", "button", "file"):
            continue
        n = re.search(r'name=["\']([^"\']+)', attrs, re.I)
        v = re.search(r'value=["\']([^"\']*)', attrs, re.I)
        if n:
            form_defaults[n.group(1)] = v.group(1) if v else ""
    for m in re.finditer(r"<textarea\b([^>]*)>(.*?)</textarea>", insert_html, re.I | re.S):
        n = re.search(r'name=["\']([^"\']+)', m.group(1), re.I)
        if n:
            form_defaults[n.group(1)] = m.group(2).strip()

    # upload two pdfs
    pdf = b"%PDF-1.4\n1 0 obj<<>>endobj\ntrailer<<>>\n%%EOF\n"
    up_paths = []
    for fn in ("a.pdf", "b.pdf", "review.pdf"):
        r = c.session.post(
            h,
            data={"ACTION": "UploadFile"},
            files={"file": (fn, io.BytesIO(pdf), "application/pdf")},
            timeout=20,
        )
        try:
            obj = json.loads(r.text or "{}")
        except Exception:
            obj = {}
        up_paths.append({"file": fn, "http": r.status_code, "resp": (r.text or "")[:220], "path": obj.get("type", "")})
    report["upload_tests"] = up_paths
    path1 = up_paths[0]["path"] if up_paths else ""
    path2 = up_paths[1]["path"] if len(up_paths) > 1 else ""
    path3 = up_paths[2]["path"] if len(up_paths) > 2 else ""

    base = dict(form_defaults)
    base.update({
        "ACTION": "1",
        "APPLYORG": "石门县卫生健康局",
        "CONTACTPERSON": "测试联系人",
        "CONNUMBER": "13800138000",
        "CONSTRUCTORNAME": "测试平台承建方有限公司",
        "CONSTRUCTORCONTACT": "测试承建联系人",
        "CONTACTNUMBER": "13800138001",
        "SYSTEMNAME": "接口申请测试_%s" % time.strftime("%H%M%S"),
        "DEPLOYMENTLOC": "湖南省石门县",
        "SERVERIP": "10.10.10.10",
        "INTRODUCTIONSYSTEM": "用于接口联调测试，满足平台申请字段要求并验证可见性。",
        "INPUT1": path1,
        "INPUT2": path2,
    })

    # create variants
    creates = []
    variants = [
        ("normal_org", {}),
        ("spoof_county_org", {"ORGCODE": "430726000000", "ORGNAME": "石门县卫生健康局", "SBDW": "430726000000"}),
    ]
    for name, extra in variants:
        body = dict(base)
        body.update(extra)
        r = c.session.post(h, data=body, headers=c._csrf_header(), timeout=20)
        creates.append({"variant": name, "http": r.status_code, "resp": (r.text or "")[:260]})
    report["create_tests"] = creates

    # query matrix for action=4
    query_results = []
    query_form = {"PAGEINDEX": "1", "APPLYORG": "", "SBRQ_BEGIN": "", "SBRQ_END": "", "SHZT": ""}
    for oc in ["", "0", "430726000001024", "430726100000", "430726000000"]:
        r = c.session.post(h, params={"action": "4", "PAGENO": "1", "ORGCODE1": oc}, data=query_form, timeout=20)
        query_results.append({"ORGCODE1": oc, "http": r.status_code, "len": len(r.text), "head": (r.text or "")[:260]})
    report["query_matrix"] = query_results

    # action 5 / 8 smoke attempts with synthetic guid candidates
    # (if list is empty, still preserve attempts for vendor)
    test_guids = []
    for q in query_results:
        m = re.search(r'<row\s+id="([^"]+)"', q["head"])
        if m:
            test_guids.append(m.group(1))
    if not test_guids:
        test_guids = ["(none)"]
    sh = []
    for g in test_guids[:3]:
        if g == "(none)":
            sh.append({"guid": g, "skip": "no list row available"})
            continue
        b5 = {"ACTION": "5", "GUID": g, "SHZT": "1", "SHFILE": path3, "REMARK": "自动化审核测试"}
        r5 = c.session.post(h, params={"ACTION": "5"}, data=b5, headers=c._csrf_header(), timeout=20)
        b8 = {"ACTION": "8", "GUID": g, "REMARK": "自动化补充测试"}
        r8 = c.session.post(h, params={"ACTION": "8"}, data=b8, headers=c._csrf_header(), timeout=20)
        sh.append({
            "guid": g,
            "action5": {"http": r5.status_code, "resp": (r5.text or "")[:260]},
            "action8": {"http": r8.status_code, "resp": (r8.text or "")[:260]},
        })
    report["shenhe_tests"] = sh
    return report, True


def main() -> int:
    ap = argparse.ArgumentParser(description="ApiApplication deep probe")
    ap.add_argument("--config", default=None)
    ap.add_argument("--password-file", default=None)
    ap.add_argument("--out", default=None)
    args = ap.parse_args()
    base_url, account, password = _load_credentials(args.config, args.password_file)
    if not account or not password:
        print("Missing PH3_ACCOUNT / PH3_PASSWORD", file=sys.stderr)
        return 1
    report, ok = run(base_url, account, password)
    blob = json.dumps(report, ensure_ascii=False, indent=2)
    print(blob)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(blob + "\n")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())

