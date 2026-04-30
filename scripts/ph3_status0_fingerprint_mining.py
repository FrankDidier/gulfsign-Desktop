# -*- coding: utf-8 -*-
"""
Mine fingerprints of existing STATUS=0 contracts to infer likely source channels.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

_SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
_DESKTOP_ROOT = os.path.dirname(_SCRIPT_DIR)
if _DESKTOP_ROOT not in sys.path:
    sys.path.insert(0, _DESKTOP_ROOT)

from ph3_api import PH3Client, Patient  # noqa: E402


def _utc_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


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
        with open(password_file, "r", encoding="utf-8") as f:
            password = f.read().strip()
    return base_url, account, password


def _edit_fields(c: PH3Client, pid: str, cc: str) -> Dict[str, str]:
    r = c.session.get(
        c.base_url + "/Sys_JCWS/B0105/Pg_Edit_B0105.aspx",
        params={"GUID": cc, "PERSONID": pid},
        timeout=20,
    )
    out = {}
    for m in re.finditer(r"<input\b([^>]+)>", r.text or "", re.I):
        attrs = m.group(1)
        n = re.search(r'name=["\']([^"\']+)', attrs, re.I)
        v = re.search(r'value=["\']([^"\']*)', attrs, re.I)
        if n:
            out[n.group(1)] = v.group(1) if v else ""
    return out


def run(base_url: str, account: str, password: str, max_records: int) -> Tuple[dict, bool]:
    c = PH3Client()
    ok, msg = c.login(base_url, account, password)
    report = {
        "ts": _utc_iso(),
        "base_url": base_url,
        "login_ok": ok,
        "login_message": msg,
        "max_records": max_records,
    }
    if not ok:
        return report, False

    # pull all signed records then cap
    signed: List[Patient] = c.query_all_patients(status="0", org_code="", extra_filters={})
    report["signed_total"] = len(signed)
    signed = signed[:max_records]
    report["analyzed_count"] = len(signed)

    # profile counters
    qyzfbs_counter = Counter()
    xgr_flag = Counter()
    xgdw_flag = Counter()
    xgsj_flag = Counter()
    qyys_shape = Counter()
    sign_date_counter = Counter()
    cluster_counter = Counter()
    samples = []

    for p in signed:
        if not p.contract_code:
            continue
        f = _edit_fields(c, p.person_id, p.contract_code)
        qyzfbs = f.get("QYZFBS", "")
        xgr = "1" if f.get("XGR", "").strip() else "0"
        xgdw = "1" if f.get("XGDW", "").strip() else "0"
        xgsj = "1" if f.get("XGSJ", "").strip() else "0"
        qyys = f.get("QYYS", "").strip()
        if re.fullmatch(r"\d{15,}WS", qyys or ""):
            qshape = "account_code"
        elif qyys:
            qshape = "doctor_name"
        else:
            qshape = "empty"
        qyrq = f.get("QYRQ", "")[:8]

        qyzfbs_counter[qyzfbs or "(empty)"] += 1
        xgr_flag[xgr] += 1
        xgdw_flag[xgdw] += 1
        xgsj_flag[xgsj] += 1
        qyys_shape[qshape] += 1
        sign_date_counter[qyrq or "(empty)"] += 1

        cluster_key = "QYZFBS=%s|XGR=%s|XGDW=%s|XGSJ=%s|QYYS=%s" % (
            qyzfbs or "(empty)", xgr, xgdw, xgsj, qshape
        )
        cluster_counter[cluster_key] += 1
        if len(samples) < 20:
            samples.append({
                "person_id": p.person_id,
                "name": p.name,
                "contract_code": p.contract_code,
                "QYZFBS": qyzfbs,
                "XGR": f.get("XGR", ""),
                "XGDW": f.get("XGDW", ""),
                "XGSJ": f.get("XGSJ", ""),
                "QYYS": qyys,
                "QYRQ": qyrq,
            })

    report["feature_counts"] = {
        "QYZFBS": dict(qyzfbs_counter),
        "XGR_present": dict(xgr_flag),
        "XGDW_present": dict(xgdw_flag),
        "XGSJ_present": dict(xgsj_flag),
        "QYYS_shape": dict(qyys_shape),
        "QYRQ_top20": dict(sign_date_counter.most_common(20)),
    }
    report["top_clusters"] = [{"cluster": k, "count": v} for k, v in cluster_counter.most_common(20)]
    report["samples"] = samples
    return report, True


def main() -> int:
    ap = argparse.ArgumentParser(description="STATUS=0 fingerprint mining")
    ap.add_argument("--config", default=None)
    ap.add_argument("--password-file", default=None)
    ap.add_argument("--max-records", type=int, default=220)
    ap.add_argument("--out", default=None)
    args = ap.parse_args()

    base_url, account, password = _load_credentials(args.config, args.password_file)
    if not account or not password:
        print("Missing PH3_ACCOUNT / PH3_PASSWORD", file=sys.stderr)
        return 1
    report, ok = run(base_url, account, password, max_records=max(20, args.max_records))
    blob = json.dumps(report, ensure_ascii=False, indent=2)
    print(blob)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(blob + "\n")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())

