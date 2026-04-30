# -*- coding: utf-8 -*-
"""
PH3 status-origin diff

Goal:
  Compare data fingerprints between existing STATUS=0 contracts and temporary
  STATUS=5 contracts created by our known doctor-side flow, to detect origin clues.
"""

from __future__ import annotations

import argparse
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

from ph3_api import PH3Client, PH3Crypto, _DEFAULT_QUERY_FORM  # noqa: E402


def _utc_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


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


def _parse_hidden_inputs(html: str) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for m in re.finditer(r"<input\b([^>]+)>", html, re.I):
        attrs = m.group(1)
        n = re.search(r'name=["\']([^"\']+)', attrs, re.I)
        v = re.search(r'value=["\']([^"\']*)', attrs, re.I)
        if not n:
            continue
        out[n.group(1)] = v.group(1) if v else ""
    return out


def _fetch_row_attr_map(c: PH3Client, status: str = "0") -> Dict[str, Dict[str, str]]:
    out: Dict[str, Dict[str, str]] = {}
    pe, sg = PH3Crypto.sign_pageno(1, c.org_code, c.token_en, c.token_th)
    form = dict(_DEFAULT_QUERY_FORM)
    form["CONTRACT_STATES"] = status
    form["PAGEINDEX"] = "1"
    r = c.session.post(
        c.base_url + "/Sys_JCWS/b0105/Do_B0105_Handler.ashx",
        params={
            "action": "4",
            "PAGENO": pe,
            "sign": sg,
            "ORGCODE": c.org_code,
            "ADDRCODE": "",
            "TABCODE": "a2",
        },
        data=form,
        timeout=20,
    )
    xml = (r.text or "").split("@@")[0]
    for row_m in re.finditer(r'<row\s+id="([^"]+)"([^>]*)>', xml, re.DOTALL):
        pid = row_m.group(1)
        attrs_str = row_m.group(2)
        attrs = dict(re.findall(r'([A-Za-z0-9_]+)="([^"]*)"', attrs_str))
        cc = attrs.get("contract_code", "")
        if cc:
            out[cc] = {"person_id": pid, **attrs}
    return out


def run_diff(
    base_url: str,
    account: str,
    password: str,
) -> Tuple[Dict[str, Any], bool]:
    report: Dict[str, Any] = {
        "ts": _utc_iso(),
        "base_url": base_url,
        "account": account[:6] + "…" if len(account) > 8 else ("***" if account else ""),
    }

    c = PH3Client()
    ok, msg = c.login(base_url, account, password)
    report["login_ok"] = ok
    report["login_message"] = msg[:300] if msg else ""
    if not ok:
        report["fatal"] = "login_failed"
        return report, False

    s0, _ = c.query_patients(status="0", page=1)
    s5, _ = c.query_patients(status="5", page=1)
    report["status0_sample_count"] = len(s0)
    report["status5_sample_count"] = len(s5)

    row_attrs_0 = _fetch_row_attr_map(c, status="0")
    row_attrs_5 = _fetch_row_attr_map(c, status="5")

    # Build baseline samples from existing records.
    sample0 = s0[0] if s0 else None
    sample5_existing = s5[0] if s5 else None

    # Create one temp STATUS=5 using known flow for controlled comparison.
    temp_created = {}
    try:
        pool, _ = c.query_patients(status="", page=1)
        target = next((p for p in pool if not p.contract_code), None)
        if target:
            r = c.initiate_signing(
                target.person_id,
                agreement_start="20260101",
                agreement_end="20261231",
                period="1",
            )
            if r.success and r.contract_code:
                temp_created = {
                    "person_id": target.person_id,
                    "contract_code": r.contract_code,
                    "name": target.name,
                }
    except Exception as e:
        report["temp_create_error"] = str(e)[:240]

    report["temp_created"] = temp_created

    # Pull edit forms and status forms.
    def pull_profile(person_id: str, contract_code: str) -> Dict[str, Any]:
        profile: Dict[str, Any] = {
            "person_id": person_id,
            "contract_code": contract_code,
        }
        # Edit form
        try:
            r1 = c.session.get(
                c.base_url + "/Sys_JCWS/B0105/Pg_Edit_B0105.aspx",
                params={"GUID": contract_code, "PERSONID": person_id},
                timeout=20,
            )
            profile["edit_http_status"] = r1.status_code
            fields = _parse_hidden_inputs(r1.text or "")
            keep = [
                "ACTION", "QYZFBS", "QYZFSJ", "SBR", "SBSJ", "SBDW",
                "XGR", "XGDW", "XGSJ", "QYRQ", "XYKSRQ", "XYJSRQ", "QYLX_INPUT",
                "QYYS", "CONTRACT_CODE", "GUID", "PERSONID",
            ]
            profile["edit_fields"] = {k: fields.get(k, "") for k in keep}
        except Exception as e:
            profile["edit_error"] = str(e)[:240]

        # GETCARDSSTATUSFORM
        try:
            r2 = c.session.get(
                c.base_url + "/Sys_JCWS/B0105/Do_B0105_Handler.ashx",
                params={"ACTION": "GETCARDSSTATUSFORM", "GUID": contract_code, "PERSONID": person_id},
                timeout=15,
            )
            profile["status_form_http"] = r2.status_code
            profile["status_form_raw"] = (r2.text or "")[:300]
        except Exception as e:
            profile["status_form_error"] = str(e)[:240]

        # row attrs
        if contract_code in row_attrs_0:
            profile["row_attrs_status0"] = row_attrs_0[contract_code]
        if contract_code in row_attrs_5:
            profile["row_attrs_status5"] = row_attrs_5[contract_code]
        return profile

    profiles: Dict[str, Any] = {}
    if sample0 and sample0.contract_code:
        profiles["existing_status0"] = pull_profile(sample0.person_id, sample0.contract_code)
    if sample5_existing and sample5_existing.contract_code:
        profiles["existing_status5"] = pull_profile(sample5_existing.person_id, sample5_existing.contract_code)
    if temp_created.get("contract_code"):
        profiles["temp_status5"] = pull_profile(temp_created["person_id"], temp_created["contract_code"])

    report["profiles"] = profiles

    # Build explicit key-level differences for quick triage.
    diff_fields: Dict[str, Dict[str, str]] = {}
    p0 = profiles.get("existing_status0", {}).get("edit_fields", {})
    p5 = profiles.get("temp_status5", {}).get("edit_fields", {})
    for k in sorted(set(p0.keys()) | set(p5.keys())):
        v0, v5 = p0.get(k, ""), p5.get(k, "")
        if v0 != v5:
            diff_fields[k] = {"status0": v0, "temp_status5": v5}
    report["edit_field_diffs_status0_vs_temp5"] = diff_fields

    # Cleanup temporary contract.
    if temp_created.get("contract_code"):
        try:
            report["temp_cleanup_deleted"] = bool(c.delete_signing(temp_created["contract_code"]))
        except Exception as e:
            report["temp_cleanup_error"] = str(e)[:240]

    return report, True


def main() -> int:
    parser = argparse.ArgumentParser(description="PH3 status-origin diff")
    parser.add_argument("--config", default=None, help="Path to gulfsign_config.json")
    parser.add_argument("--password-file", default=None, help="Single-line password file")
    parser.add_argument("--out", default=None, help="Write JSON report to file")
    args = parser.parse_args()

    base_url, account, password = _load_credentials(args.config, args.password_file)
    if not account or not password:
        print("Missing PH3_ACCOUNT / PH3_PASSWORD (or password file).", file=sys.stderr)
        return 1

    report, ok = run_diff(base_url=base_url, account=account, password=password)
    blob = json.dumps(report, ensure_ascii=False, indent=2)
    print(blob)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(blob + "\n")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
