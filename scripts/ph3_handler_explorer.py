# -*- coding: utf-8 -*-
"""
PH3 handler explorer

Goal:
  Probe discovered handlers/actions to identify useful operational channels.

Safety:
  - Default mode is read-oriented probing (GET + minimal POST).
  - Optional --active-b0105 creates one temporary STATUS=5 contract, tests selected
    actions, then auto-deletes the test contract.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple

_SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
_DESKTOP_ROOT = os.path.dirname(_SCRIPT_DIR)
if _DESKTOP_ROOT not in sys.path:
    sys.path.insert(0, _DESKTOP_ROOT)

from ph3_api import PH3Client  # noqa: E402


def _utc_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _short(text: str, n: int = 180) -> str:
    t = (text or "").replace("\r", " ").replace("\n", " ").strip()
    return t[:n] + ("…" if len(t) > n else "")


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


def _default_candidates() -> Dict[str, Set[str]]:
    return {
        "/Sys_JCWS/B0105/Do_B0105_Handler.ashx": {
            "1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "11",
            "DOUPDATE", "UPDATE", "DOSAVE", "GETCARDSSTATUSFORM",
        },
        "/Sys_JCWS/ApiApplication/Do_ApiApplication_Handler.ashx": {
            "1", "2", "3", "4", "5", "6", "7", "8", "9", "10",
        },
        "/Sys_JCWS/TBLSYS_ExportExcel/Do_TBLSYS_ExportExcel_Handler.ashx": {
            "1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "11",
            "IMPORT", "EXPORT", "LIST",
        },
        "/Sys_JCWS/JKDA/Do_Query_Handler.ashx": {"B0105"},
        "/Sys_JCWS/B0107/Do_B0107_Handler.ashx": {"1", "2", "3", "4"},
        "/Sys_JCWS/B0110/Do_B0110_Handler.ashx": {"1", "2", "3", "4", "7", "10"},
    }


def _load_candidates_from_cartography(path: str) -> Dict[str, Set[str]]:
    out: Dict[str, Set[str]] = {}
    if not path or not os.path.isfile(path):
        return out
    try:
        with open(path, "r", encoding="utf-8") as f:
            obj = json.load(f)
        handlers = obj.get("handlers", {}) if isinstance(obj, dict) else {}
        for hp, hv in handlers.items():
            acts = set(hv.get("actions_found", []) if isinstance(hv, dict) else [])
            out[hp] = acts
    except Exception:
        return {}
    return out


def _probe_one(
    client: PH3Client,
    handler_path: str,
    action: str,
    extra_params: Optional[Dict[str, str]] = None,
    extra_data: Optional[Dict[str, str]] = None,
) -> Dict[str, Any]:
    params = {"ACTION": action}
    if extra_params:
        params.update(extra_params)
    data = {"ACTION": action, "PAGEINDEX": "1"}
    if extra_data:
        data.update(extra_data)
    url = client.base_url.rstrip("/") + handler_path

    out: Dict[str, Any] = {
        "handler": handler_path,
        "action": action,
    }
    try:
        rg = client.session.get(url, params=params, timeout=12)
        out["get_status"] = rg.status_code
        out["get_len"] = len(rg.content)
        out["get_snippet"] = _short(rg.text, 200)
    except Exception as e:
        out["get_error"] = str(e)[:200]

    try:
        rp = client.session.post(
            url, params={"ACTION": action}, data=data,
            headers=client._csrf_header(), timeout=12,
        )
        out["post_status"] = rp.status_code
        out["post_len"] = len(rp.content)
        out["post_snippet"] = _short(rp.text, 200)
    except Exception as e:
        out["post_error"] = str(e)[:200]
    return out


def run_explorer(
    base_url: str,
    account: str,
    password: str,
    cartography_file: Optional[str] = None,
    active_b0105: bool = False,
) -> Tuple[Dict[str, Any], bool]:
    report: Dict[str, Any] = {
        "ts": _utc_iso(),
        "base_url": base_url,
        "account": account[:6] + "…" if len(account) > 8 else ("***" if account else ""),
        "active_b0105": active_b0105,
    }

    c = PH3Client()
    ok, msg = c.login(base_url, account, password)
    report["login_ok"] = ok
    report["login_message"] = msg[:300] if msg else ""
    if not ok:
        report["fatal"] = "login_failed"
        return report, False

    candidates = _default_candidates()
    from_map = _load_candidates_from_cartography(cartography_file or "")
    for hp, acts in from_map.items():
        candidates.setdefault(hp, set()).update(acts)

    probes: List[Dict[str, Any]] = []

    # Optional active test context for B0105
    active_ctx: Dict[str, str] = {}
    if active_b0105:
        try:
            pts, _ = c.query_patients(status="", page=1)
            target = next((p for p in pts if not p.contract_code), None)
            if target:
                r = c.initiate_signing(
                    target.person_id,
                    agreement_start="20260101",
                    agreement_end="20261231",
                    period="1",
                )
                if r.success and r.contract_code:
                    active_ctx = {
                        "PERSONID": target.person_id,
                        "GUID": r.contract_code,
                        "CONTRACT_CODE": r.contract_code,
                        "STATUS": "1",
                    }
                    report["active_contract"] = {
                        "person_id": target.person_id,
                        "contract_code": r.contract_code,
                    }
        except Exception as e:
            report["active_setup_error"] = str(e)[:240]

    for handler_path in sorted(candidates.keys()):
        acts = sorted(a for a in candidates[handler_path] if a)
        if not acts:
            acts = ["4"]
        for action in acts:
            extra = active_ctx if (active_ctx and "B0105" in handler_path) else {}
            probes.append(_probe_one(c, handler_path, action, extra_data=extra))

    report["probes"] = probes

    # Cleanup active contract.
    if active_ctx.get("CONTRACT_CODE"):
        try:
            deleted = c.delete_signing(active_ctx["CONTRACT_CODE"])
            report["active_cleanup_deleted"] = bool(deleted)
        except Exception as e:
            report["active_cleanup_error"] = str(e)[:240]

    # Summaries
    interesting = []
    for p in probes:
        snippet = (p.get("get_snippet", "") + " " + p.get("post_snippet", "")).lower()
        if any(k in snippet for k in ("成功", "已签约", "审核", "导入", "上传", "optype")):
            interesting.append({
                "handler": p["handler"],
                "action": p["action"],
                "get": p.get("get_snippet", ""),
                "post": p.get("post_snippet", ""),
            })
    report["interesting"] = interesting
    return report, True


def main() -> int:
    parser = argparse.ArgumentParser(description="PH3 handler explorer")
    parser.add_argument("--config", default=None, help="Path to gulfsign_config.json")
    parser.add_argument("--password-file", default=None, help="Single-line password file")
    parser.add_argument("--cartography", default=None, help="Cartography JSON file")
    parser.add_argument("--active-b0105", action="store_true", help="Create temp B0105 contract for action probes")
    parser.add_argument("--out", default=None, help="Write JSON report to file")
    args = parser.parse_args()

    base_url, account, password = _load_credentials(args.config, args.password_file)
    if not account or not password:
        print("Missing PH3_ACCOUNT / PH3_PASSWORD (or password file).", file=sys.stderr)
        return 1

    report, ok = run_explorer(
        base_url=base_url,
        account=account,
        password=password,
        cartography_file=args.cartography,
        active_b0105=args.active_b0105,
    )
    blob = json.dumps(report, ensure_ascii=False, indent=2)
    print(blob)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(blob + "\n")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
