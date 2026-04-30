# -*- coding: utf-8 -*-
"""
Probe B0105 UI-triggered flow endpoints from live pages and test on temp contract.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

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


def _status(c: PH3Client, cc: str, pid: str) -> str:
    r = c.session.get(
        c.base_url + "/Sys_JCWS/B0105/Do_B0105_Handler.ashx",
        params={"ACTION": "GETCARDSSTATUSFORM", "GUID": cc, "PERSONID": pid},
        timeout=15,
    )
    m = re.search(r"<STATUS>([^<]*)</STATUS>", r.text or "")
    return m.group(1).strip() if m else ""


def run(base_url: str, account: str, password: str) -> Tuple[dict, bool]:
    c = PH3Client()
    ok, msg = c.login(base_url, account, password)
    report = {"ts": _utc_iso(), "login_ok": ok, "login_message": msg}
    if not ok:
        return report, False

    # discover UI flow actions from B0105 pages
    pages = [
        "/Sys_JCWS/B0105/Pg_View_B0105.aspx",
        "/Sys_JCWS/B0105/Pg_Queren_Status.aspx",
        "/Sys_JCWS/B0105/Pg_Change_Status.aspx",
        "/Sys_JCWS/JKDA/Page_Index_B0105.aspx",
    ]
    discovered = []
    actions = set()
    for p in pages:
        r = c.session.get(c.base_url + p, timeout=20)
        body = r.text or ""
        for m in re.finditer(r'(Do_[A-Za-z0-9_]+\.ashx|Pg_[A-Za-z0-9_]+\.aspx|ACTION\s*[:=]\s*["\']([A-Za-z0-9_]+)["\'])', body, re.I):
            discovered.append(m.group(0))
        for m in re.finditer(r'ACTION\s*[:=]\s*["\']([A-Za-z0-9_]+)["\']', body, re.I):
            actions.add(m.group(1))
    report["discovered_tokens"] = discovered[:200]
    report["discovered_actions"] = sorted(actions)

    # create temp contract and test discovered actions against Do_B0105_Handler
    pts, _ = c.query_patients(status="", page=1)
    target = next((p for p in pts if not p.contract_code), None)
    if not target:
        report["fatal"] = "no_target"
        return report, True

    r1 = c.initiate_signing(target.person_id, agreement_start="20260101", agreement_end="20261231", period="1")
    if not r1.success or not r1.contract_code:
        report["fatal"] = "temp_create_failed"
        report["error"] = r1.error
        return report, True

    cc = r1.contract_code
    pid = target.person_id
    before = _status(c, cc, pid)
    probes: List[Dict] = []
    h = c.base_url + "/Sys_JCWS/B0105/Do_B0105_Handler.ashx"

    candidate_actions = list(sorted(actions)) + ["2", "9", "DOUPDATE", "UPDATE", "DOSAVE"]
    seen = set()
    for a in candidate_actions:
        if a in seen:
            continue
        seen.add(a)
        body = {
            "ACTION": a,
            "GUID": cc,
            "CONTRACT_CODE": cc,
            "PERSONID": pid,
            "STATUS": "0",
            "QYZFBS": "0",
            "B0105_13": "0",
            "REMARK": "uiflow-probe",
        }
        rr = c.session.post(h, params={"ACTION": a}, data=body, headers=c._csrf_header(), timeout=20)
        now = _status(c, cc, pid)
        probes.append({
            "action": a,
            "http": rr.status_code,
            "resp": (rr.text or "")[:220],
            "status_before": before,
            "status_after": now,
            "changed": now != before,
            "to_zero": now == "0",
        })
        before = now
        if now == "0":
            break

    report["temp_contract"] = {"person_id": pid, "contract_code": cc}
    report["probes"] = probes
    report["any_to_zero"] = any(p.get("to_zero") for p in probes)
    report["cleanup_deleted"] = bool(c.delete_signing(cc))
    return report, True


def main() -> int:
    ap = argparse.ArgumentParser(description="B0105 UI flow probe")
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

