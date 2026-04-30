# -*- coding: utf-8 -*-
"""
B0105 synthesized action probe

Purpose:
  Try candidate ACTION values against Do_B0105_Handler.ashx using realistic payloads
  from live form pages (insert/edit), on temporary contracts only.

Safety:
  - Every test case creates its own temp STATUS=5 contract.
  - Cleanup attempts run after each case.
  - No existing contracts are modified.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

_SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
_DESKTOP_ROOT = os.path.dirname(_SCRIPT_DIR)
if _DESKTOP_ROOT not in sys.path:
    sys.path.insert(0, _DESKTOP_ROOT)

from ph3_api import PH3Client, PH3Crypto  # noqa: E402


def _utc_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _short(text: str, n: int = 200) -> str:
    t = (text or "").replace("\r", " ").replace("\n", " ").strip()
    return t[:n] + ("…" if len(t) > n else "")


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


def _parse_inputs(html: str) -> Dict[str, str]:
    data: Dict[str, str] = {}
    for m in re.finditer(r"<input\b([^>]+)>", html, re.I):
        attrs = m.group(1)
        tp = re.search(r'type=["\']([^"\']+)', attrs, re.I)
        ftype = tp.group(1).lower() if tp else "text"
        if ftype in ("checkbox", "radio", "submit", "reset", "button", "file"):
            continue
        n = re.search(r'name=["\']([^"\']+)', attrs, re.I)
        v = re.search(r'value=["\']([^"\']*)', attrs, re.I)
        if n:
            data[n.group(1)] = v.group(1) if v else ""

    # include checked radios as explicit values
    for m in re.finditer(
        r'<input[^>]*type=["\']radio["\'][^>]*name=["\']([^"\']+)["\'][^>]*value\s*=\s*["\']([^"\']+)["\'][^>]*checked',
        html, re.I,
    ):
        data[m.group(1)] = m.group(2)
    return data


def _get_status_form(c: PH3Client, contract_code: str, person_id: str) -> Dict[str, str]:
    r = c.session.get(
        c.base_url + "/Sys_JCWS/B0105/Do_B0105_Handler.ashx",
        params={"ACTION": "GETCARDSSTATUSFORM", "GUID": contract_code, "PERSONID": person_id},
        timeout=15,
    )
    txt = r.text or ""
    out = {"raw": _short(txt, 260)}
    ms = re.search(r"<STATUS>([^<]*)</STATUS>", txt)
    out["status"] = ms.group(1).strip() if ms else ""
    return out


def _build_insert_payload(c: PH3Client, person_id: str) -> Dict[str, str]:
    ts = str(int(time.time() * 1000))
    enc_guid = PH3Crypto.crptosEn(person_id + "|" + ts, c.token_en)
    sign = PH3Crypto.crptosTH(enc_guid + c.token_th)
    r = c.session.get(
        c.base_url + "/Sys_JCWS/B0105/Pg_Insert_B0105.aspx",
        params={"GUID": enc_guid, "sign": sign},
        timeout=20,
    )
    html = r.text or ""
    data = _parse_inputs(html)
    today = time.strftime("%Y%m%d")
    data.update({
        "QYLX": data.get("QYLX", "2"),
        "QYLX_INPUT": data.get("QYLX_INPUT", "2"),
        "QYZQ": data.get("QYZQ", "1"),
        "QYZQ_INPUT": data.get("QYZQ_INPUT", "1"),
        "QYRQ": data.get("QYRQ", today),
        "XYKSRQ": data.get("XYKSRQ", "20260101"),
        "XYJSRQ": data.get("XYJSRQ", "20261231"),
        "YFJE": data.get("YFJE", "0"),
        "BZJE": data.get("BZJE", "0"),
        "ZJJE": data.get("ZJJE", "0"),
        "ACTION": "1",
        "SBDW": c.org_code or data.get("XGDW", ""),
    })
    # Ensure team/package fields are filled from live APIs.
    teams = c._load_teams(html)
    tid, tname = c._find_team(teams, team_name=c.team_name, team_id="")
    if tid:
        data["QYTD"] = tid
    if tname:
        data["QYTDMC"] = tname
    fwb_list, fwb_mc = c._load_service_packs("0")
    if fwb_list:
        data["FWBLIST"] = fwb_list
    if fwb_mc:
        data["FWBMCLIST"] = fwb_mc
    data.pop("btnSave", None)
    data.pop("btnReset", None)
    return data


def _build_edit_payload(c: PH3Client, contract_code: str, person_id: str) -> Dict[str, str]:
    r = c.session.get(
        c.base_url + "/Sys_JCWS/B0105/Pg_Edit_B0105.aspx",
        params={"GUID": contract_code, "PERSONID": person_id},
        timeout=20,
    )
    data = _parse_inputs(r.text or "")
    # Keep common required fields robust.
    data.setdefault("QYLX", data.get("QYLX_INPUT", "2"))
    data.setdefault("QYZQ", data.get("QYZQ_INPUT", "1"))
    data.setdefault("YFJE", "0")
    data.setdefault("BZJE", "0")
    data.setdefault("ZJJE", "0")
    data.setdefault("GUID", contract_code)
    data.setdefault("CONTRACT_CODE", contract_code)
    data.setdefault("PERSONID", person_id)
    data.setdefault("ACTION", "2")
    fwb_list, fwb_mc = c._load_service_packs("0")
    data.setdefault("FWBLIST", fwb_list)
    data.setdefault("FWBMCLIST", fwb_mc)
    data.pop("btnSave", None)
    data.pop("btnReset", None)
    return data


def _choose_target_person(c: PH3Client) -> Optional[Tuple[str, str]]:
    pts, _ = c.query_patients(status="", page=1)
    target = next((p for p in pts if not p.contract_code), None)
    if not target:
        return None
    return target.person_id, target.name


def run_probe(
    base_url: str,
    account: str,
    password: str,
    actions: List[str],
) -> Tuple[Dict[str, Any], bool]:
    report: Dict[str, Any] = {
        "ts": _utc_iso(),
        "base_url": base_url,
        "account": account[:6] + "…" if len(account) > 8 else ("***" if account else ""),
        "actions": actions,
    }
    c = PH3Client()
    ok, msg = c.login(base_url, account, password)
    report["login_ok"] = ok
    report["login_message"] = msg[:300] if msg else ""
    if not ok:
        report["fatal"] = "login_failed"
        return report, False

    test_results: List[Dict[str, Any]] = []
    target = _choose_target_person(c)
    if not target:
        report["fatal"] = "no_target_person"
        return report, False
    person_id, person_name = target
    report["target_person"] = {"person_id": person_id, "name": person_name}

    handler = c.base_url + "/Sys_JCWS/B0105/Do_B0105_Handler.ashx"

    for action in actions:
        case: Dict[str, Any] = {"action": action}
        contract_code = ""
        try:
            init = c.initiate_signing(
                person_id=person_id,
                agreement_start="20260101",
                agreement_end="20261231",
                period="1",
            )
            case["create_success"] = bool(init.success)
            case["create_error"] = init.error
            contract_code = init.contract_code or ""
            case["contract_code"] = contract_code
            if not init.success or not contract_code:
                test_results.append(case)
                continue

            before = _get_status_form(c, contract_code, person_id)
            case["status_before"] = before

            edit_body = _build_edit_payload(c, contract_code, person_id)
            edit_body["ACTION"] = action

            # Attempt A: realistic edit body
            ra = c.session.post(
                handler,
                params={"ACTION": action},
                data=edit_body,
                headers=c._csrf_header(),
                timeout=20,
            )
            case["attempt_edit_http"] = ra.status_code
            case["attempt_edit_resp"] = _short(ra.text, 220)

            # Attempt B: same with forced status hints
            edit_body_force = dict(edit_body)
            today = time.strftime("%Y%m%d")
            edit_body_force.update({
                "STATUS": "0",
                "B0105_13": "0",
                "QYZFBS": "0",
                "XGR": account,
                "XGDW": c.org_code,
                "XGSJ": today,
                "QYRQ": today,
            })
            rb = c.session.post(
                handler,
                params={"ACTION": action},
                data=edit_body_force,
                headers=c._csrf_header(),
                timeout=20,
            )
            case["attempt_force_http"] = rb.status_code
            case["attempt_force_resp"] = _short(rb.text, 220)

            # Attempt C: confirm-style minimal body (relevant to action=9 but harmless others)
            mini = {
                "ACTION": action,
                "GUID": contract_code,
                "CONTRACT_CODE": contract_code,
                "PERSONID": person_id,
                "STATUS": "1",
                "REMARK": "",
                "QYZFBS": "0",
            }
            rc = c.session.post(
                handler,
                params={"ACTION": action},
                data=mini,
                headers=c._csrf_header(),
                timeout=20,
            )
            case["attempt_mini_http"] = rc.status_code
            case["attempt_mini_resp"] = _short(rc.text, 220)

            after = _get_status_form(c, contract_code, person_id)
            case["status_after"] = after
            case["status_changed"] = after.get("status") != before.get("status")
            case["status_to_zero"] = after.get("status") == "0"
        except Exception as e:
            case["error"] = str(e)[:240]
        finally:
            if contract_code:
                try:
                    case["cleanup_deleted"] = bool(c.delete_signing(contract_code))
                except Exception as e:
                    case["cleanup_error"] = str(e)[:200]
        test_results.append(case)

    report["cases"] = test_results
    report["any_status_to_zero"] = any(ca.get("status_to_zero") for ca in test_results)
    return report, True


def main() -> int:
    parser = argparse.ArgumentParser(description="B0105 synthesized action probe")
    parser.add_argument("--config", default=None, help="Path to gulfsign_config.json")
    parser.add_argument("--password-file", default=None, help="Single-line password file")
    parser.add_argument(
        "--actions",
        default="2,9,DOUPDATE,UPDATE,DOSAVE,12,13,14,15,16,17,18,19,20",
        help="Comma-separated ACTION list",
    )
    parser.add_argument("--out", default=None, help="Write JSON report to file")
    args = parser.parse_args()

    base_url, account, password = _load_credentials(args.config, args.password_file)
    if not account or not password:
        print("Missing PH3_ACCOUNT / PH3_PASSWORD (or password file).", file=sys.stderr)
        return 1

    actions = [a.strip() for a in args.actions.split(",") if a.strip()]
    report, ok = run_probe(base_url, account, password, actions)
    blob = json.dumps(report, ensure_ascii=False, indent=2)
    print(blob)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(blob + "\n")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
