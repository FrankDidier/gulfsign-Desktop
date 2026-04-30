# -*- coding: utf-8 -*-
"""
PH3 linked-system status probe

Goal:
  Efficiently discover menu-linked handler endpoints and test whether any
  cross-module action can mutate B0105 contract status from 5 -> 0.

Safety:
  - Uses a temporary STATUS=5 contract created during run.
  - Checks status after every probe.
  - Deletes temporary contract on exit.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urljoin

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


def _menu_links(menu_xml: str, base_url: str) -> List[str]:
    links = re.findall(r"<!\[CDATA\[\s*([^\]]+?)\s*\]\]>", menu_xml, re.IGNORECASE)
    out = []
    seen = set()
    for l in links:
        x = l.strip()
        if not x:
            continue
        if x.startswith("http://") or x.startswith("https://"):
            if "ggws.hnhfpc.gov.cn" in x:
                x = x.replace(base_url.rstrip("/"), "")
            else:
                continue
        if not x.startswith("/"):
            x = "/" + x
        if x not in seen:
            seen.add(x)
            out.append(x)
    return out


def _extract_handlers_and_actions(base_url: str, page_url: str, body: str) -> List[Tuple[str, str]]:
    handlers: Set[str] = set()
    actions: Set[str] = set()

    # explicit Do_*.ashx references
    for m in re.finditer(r'["\']([^"\']*Do_[A-Za-z0-9_./-]+\.ashx(?:\?[^"\']*)?)["\']', body, re.IGNORECASE):
        raw = m.group(1).strip()
        abs_url = urljoin(page_url, raw)
        if abs_url.startswith(base_url):
            handlers.add(abs_url.replace(base_url, ""))

    # action literals
    for m in re.finditer(r'\bACTION\s*[:=]\s*["\']([A-Za-z0-9_]+)["\']', body, re.IGNORECASE):
        actions.add(m.group(1))
    for m in re.finditer(r'\baction\s*[:=]\s*["\']([A-Za-z0-9_]+)["\']', body, re.IGNORECASE):
        actions.add(m.group(1))

    pairs: List[Tuple[str, str]] = []
    if not actions:
        actions = {"1", "2", "3", "4", "5", "8", "9", "10", "11"}
    for h in sorted(handlers):
        for a in sorted(actions):
            pairs.append((h, a))
    return pairs


def _status_form(c: PH3Client, contract_code: str, person_id: str) -> str:
    r = c.session.get(
        c.base_url + "/Sys_JCWS/B0105/Do_B0105_Handler.ashx",
        params={"ACTION": "GETCARDSSTATUSFORM", "GUID": contract_code, "PERSONID": person_id},
        timeout=15,
    )
    m = re.search(r"<STATUS>([^<]*)</STATUS>", r.text or "")
    return m.group(1).strip() if m else ""


def run_probe(base_url: str, account: str, password: str, max_pairs: int = 120) -> Tuple[Dict[str, Any], bool]:
    report: Dict[str, Any] = {
        "ts": _utc_iso(),
        "base_url": base_url,
        "account": account[:6] + "…" if len(account) > 8 else ("***" if account else ""),
        "max_pairs": max_pairs,
    }
    c = PH3Client()
    ok, msg = c.login(base_url, account, password)
    report["login_ok"] = ok
    report["login_message"] = msg[:240] if msg else ""
    if not ok:
        report["fatal"] = "login_failed"
        return report, False

    # Create temp contract to test real status mutation.
    pts, _ = c.query_patients(status="", page=1)
    target = next((p for p in pts if not p.contract_code), None)
    if not target:
        report["fatal"] = "no_target_person"
        return report, False
    init = c.initiate_signing(target.person_id, agreement_start="20260101", agreement_end="20261231", period="1")
    if not init.success or not init.contract_code:
        report["fatal"] = "temp_create_failed"
        report["temp_create_error"] = init.error
        return report, False

    person_id = target.person_id
    contract_code = init.contract_code
    report["temp_contract"] = {"person_id": person_id, "contract_code": contract_code, "name": target.name}

    # Discover candidate handler/action pairs from menu-linked pages.
    menu = c.session.get(c.base_url + "/ashx/LoginHandler.ashx", params={"action": "GETMENU"}, timeout=20).text
    links = _menu_links(menu, c.base_url)
    report["menu_link_count"] = len(links)

    all_pairs: List[Tuple[str, str]] = []
    scanned_pages: List[str] = []
    for p in links:
        # keep it efficient and relevant to integration/admin modules
        p_low = p.lower()
        if not any(k in p_low for k in ["sys_jcws", "apiapplication", "tblysys_exportexcel", "wthome", "b0105"]):
            continue
        try:
            r = c.session.get(c.base_url + p, timeout=15)
            if r.status_code != 200:
                continue
            scanned_pages.append(p)
            all_pairs.extend(_extract_handlers_and_actions(c.base_url, c.base_url + p, r.text or ""))
        except Exception:
            continue

    # Add known high-value handlers explicitly.
    seed_pairs = []
    for a in ["2", "9", "DOUPDATE", "UPDATE", "DOSAVE", "12", "13", "14", "15", "16", "17", "18", "19", "20"]:
        seed_pairs.append(("/Sys_JCWS/B0105/Do_B0105_Handler.ashx", a))
    for a in ["1", "2", "3", "4", "5", "6", "7", "8", "9", "10"]:
        seed_pairs.append(("/Sys_JCWS/ApiApplication/Do_ApiApplication_Handler.ashx", a))
    all_pairs.extend(seed_pairs)

    # Deduplicate and rank by relevance.
    uniq = []
    seen = set()
    for h, a in all_pairs:
        key = (h, a)
        if key in seen:
            continue
        seen.add(key)
        uniq.append(key)

    def score(pair: Tuple[str, str]) -> int:
        h, a = pair
        h_low = h.lower()
        s = 0
        if "b0105" in h_low:
            s += 100
        if "apiapplication" in h_low or "exportexcel" in h_low:
            s += 40
        if "do_" in h_low and h_low.endswith(".ashx"):
            s += 20
        if a in {"9", "2", "DOUPDATE", "UPDATE", "DOSAVE", "5", "8", "10", "11"}:
            s += 30
        return s

    uniq.sort(key=score, reverse=True)
    candidates = uniq[:max_pairs]
    report["candidate_pair_count"] = len(candidates)
    report["scanned_pages"] = scanned_pages[:80]

    # Probe each candidate and detect live status transitions.
    probes: List[Dict[str, Any]] = []
    before = _status_form(c, contract_code, person_id)
    for h, a in candidates:
        entry: Dict[str, Any] = {"handler": h, "action": a}
        try:
            url = c.base_url + h
            payload = {
                "ACTION": a,
                "GUID": contract_code,
                "CONTRACT_CODE": contract_code,
                "PERSONID": person_id,
                "STATUS": "0",
                "B0105_13": "0",
                "QYZFBS": "0",
                "REMARK": "linked-probe",
            }
            r = c.session.post(url, params={"ACTION": a}, data=payload, headers=c._csrf_header(), timeout=15)
            entry["http_status"] = r.status_code
            entry["resp"] = _short(r.text, 180)

            now = _status_form(c, contract_code, person_id)
            entry["status_before"] = before
            entry["status_after"] = now
            entry["changed"] = (now != before)
            entry["to_zero"] = (now == "0")
            before = now
        except Exception as e:
            entry["error"] = str(e)[:200]
        probes.append(entry)
        if entry.get("to_zero"):
            break

    report["probes"] = probes
    report["any_to_zero"] = any(p.get("to_zero") for p in probes)

    # Cleanup
    try:
        report["cleanup_deleted"] = bool(c.delete_signing(contract_code))
    except Exception as e:
        report["cleanup_error"] = str(e)[:200]

    # Re-check menu keywords after full run.
    fm = c.session.get(c.base_url + "/FormMain.aspx", timeout=20).text
    report["formmain_keywords"] = {
        "签约登记": ("签约登记" in fm),
        "代签": ("代签" in fm),
        "批量导入": ("批量导入" in fm),
        "签约审核": ("签约审核" in fm),
        "/cx/": ("/cx/" in fm),
    }
    return report, True


def main() -> int:
    parser = argparse.ArgumentParser(description="PH3 linked-system status probe")
    parser.add_argument("--config", default=None, help="Path to gulfsign_config.json")
    parser.add_argument("--password-file", default=None, help="Single-line password file")
    parser.add_argument("--max-pairs", type=int, default=120, help="Max handler/action pairs to test")
    parser.add_argument("--out", default=None, help="Write JSON report to file")
    args = parser.parse_args()

    base_url, account, password = _load_credentials(args.config, args.password_file)
    if not account or not password:
        print("Missing PH3_ACCOUNT / PH3_PASSWORD (or password file).", file=sys.stderr)
        return 1

    report, ok = run_probe(base_url, account, password, max_pairs=max(20, args.max_pairs))
    blob = json.dumps(report, ensure_ascii=False, indent=2)
    print(blob)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(blob + "\n")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
