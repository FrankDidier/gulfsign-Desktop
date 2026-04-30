# -*- coding: utf-8 -*-
"""
PH3 endpoint cartography

Goal:
  Build an authenticated endpoint/action map from reachable pages/scripts so we can
  discover hidden handlers (batch/import/audit channels) beyond the known B0105 flow.

Output:
  JSON report written to stdout and optional --out file.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urljoin

# gulfsign-desktop root (parent of scripts/)
_SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
_DESKTOP_ROOT = os.path.dirname(_SCRIPT_DIR)
if _DESKTOP_ROOT not in sys.path:
    sys.path.insert(0, _DESKTOP_ROOT)

from ph3_api import PH3Client  # noqa: E402


def _utc_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _short(text: str, n: int = 120) -> str:
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


_ENDPOINT_PATTERNS = [
    r'["\']((?:\.\./|/)?(?:Sys_[^"\']+?|ashx/[^"\']+?)\.(?:aspx|ashx)(?:\?[^"\']*)?)["\']',
    r'["\']((?:/)?js/[^"\']+?\.js(?:\?[^"\']*)?)["\']',
    r'["\']((?:/)?Vue/[^"\']*?)["\']',
]

_ACTION_PATTERNS = [
    r'\bACTION\s*[:=]\s*["\']([A-Za-z0-9_]+)["\']',
    r'\baction\s*[:=]\s*["\']([A-Za-z0-9_]+)["\']',
]


def _normalize_path(base_url: str, source_url: str, raw: str) -> str:
    raw = (raw or "").strip()
    if not raw:
        return raw
    # Common in this system: paths like "Sys_JCWS/..." or "js/..." are root-like.
    if raw.startswith(("Sys_", "ashx/", "js/", "Vue/")):
        raw = "/" + raw
    if raw.startswith("http://") or raw.startswith("https://"):
        return raw
    absolute = urljoin(source_url, raw)
    if absolute.startswith(base_url):
        return absolute[len(base_url):] or "/"
    return absolute


def _extract_paths_and_actions(
    base_url: str,
    source_url: str,
    body: str,
) -> Tuple[Set[str], Set[str]]:
    paths: Set[str] = set()
    actions: Set[str] = set()

    for p in _ENDPOINT_PATTERNS:
        for m in re.finditer(p, body, re.IGNORECASE):
            paths.add(_normalize_path(base_url, source_url, m.group(1).strip()))

    # Also parse form actions explicitly.
    for m in re.finditer(r'<form[^>]+action\s*=\s*["\']([^"\']+)["\']', body, re.IGNORECASE):
        paths.add(_normalize_path(base_url, source_url, m.group(1).strip()))

    for p in _ACTION_PATTERNS:
        for m in re.finditer(p, body, re.IGNORECASE):
            actions.add(m.group(1).strip())

    return paths, actions


def _is_same_site_path(path_or_url: str) -> bool:
    if path_or_url.startswith("http://") or path_or_url.startswith("https://"):
        return "hnhfpc.gov.cn" in path_or_url
    return True


def run_cartography(
    base_url: str,
    account: str,
    password: str,
    max_nodes: int = 120,
) -> Tuple[Dict[str, Any], bool]:
    report: Dict[str, Any] = {
        "ts": _utc_iso(),
        "base_url": base_url,
        "account": account[:6] + "…" if len(account) > 8 else ("***" if account else ""),
        "max_nodes": max_nodes,
    }

    client = PH3Client()
    ok, login_msg = client.login(base_url, account, password)
    report["login_ok"] = ok
    report["login_message"] = login_msg[:300] if login_msg else ""
    if not ok:
        report["fatal"] = "login_failed"
        return report, False

    base = client.base_url.rstrip("/")
    sess = client.session

    seed_paths = [
        "/FormMain.aspx",
        "/Sys_JCWS/b0105/Pg_View_B0105.aspx",
        "/Sys_JCWS/B0105/Pg_View_B0105.aspx",
        "/Sys_JCWS/B0105/Pg_Insert_B0105.aspx",
        "/Sys_JCWS/B0105/Pg_Queren_Status.aspx",
        "/Sys_JCWS/ApiApplication/Pg_View_TBLBUS_ApiApplication.aspx",
        "/Sys_JCWS/TBLSYS_ExportExcel/Pg_View_TBLSYS_ExportExcel.aspx",
    ]

    # Add edit page seeds if we can fetch sample contracts.
    try:
        s0, _ = client.query_patients(status="0", page=1)
        if s0 and s0[0].contract_code and s0[0].person_id:
            seed_paths.append(
                "/Sys_JCWS/B0105/Pg_Edit_B0105.aspx?GUID=%s&PERSONID=%s"
                % (s0[0].contract_code, s0[0].person_id)
            )
    except Exception:
        pass

    visited: Set[str] = set()
    queue: List[str] = list(dict.fromkeys(seed_paths))
    nodes: List[Dict[str, Any]] = []
    endpoint_actions: Dict[str, Set[str]] = {}

    while queue and len(visited) < max_nodes:
        path = queue.pop(0)
        if path in visited:
            continue
        visited.add(path)
        if not _is_same_site_path(path):
            continue

        url = path if path.startswith("http") else (base + path)
        try:
            r = sess.get(url, timeout=20)
            body = r.text or ""
            node = {
                "path": path,
                "http_status": r.status_code,
                "content_length": len(r.content),
                "snippet": _short(body, 160),
            }
            nodes.append(node)
            if r.status_code != 200 or not body:
                continue

            found_paths, found_actions = _extract_paths_and_actions(base, url, body)

            # Only attach actions to handler-like nodes.
            if path.lower().endswith(".ashx") or "do_" in path.lower():
                endpoint_actions.setdefault(path, set()).update(found_actions)

            # Queue newly discovered same-site paths.
            for fp in sorted(found_paths):
                if not _is_same_site_path(fp):
                    continue
                if fp.startswith("http://") or fp.startswith("https://"):
                    # keep absolute same-site links
                    if "hnhfpc.gov.cn" not in fp:
                        continue
                if fp not in visited and fp not in queue:
                    queue.append(fp)
        except Exception as e:
            nodes.append({"path": path, "error": str(e)[:240]})

    report["nodes"] = nodes
    report["visited_count"] = len(visited)

    # Build endpoint summary
    handlers: Dict[str, Dict[str, Any]] = {}
    for n in nodes:
        p = n.get("path", "")
        if not p:
            continue
        p_low = p.lower().split("?", 1)[0]
        is_handler = p_low.endswith(".ashx") or "do_" in p_low
        if not is_handler:
            continue
        handlers[p] = {
            "http_status": n.get("http_status"),
            "content_length": n.get("content_length"),
            "actions_found": sorted(endpoint_actions.get(p, set())),
        }
    report["handlers"] = handlers

    # Quick candidate list for next-stage probing.
    report["probe_candidates"] = sorted([
        p for p, h in handlers.items()
        if h.get("http_status") == 200
    ])

    return report, True


def main() -> int:
    parser = argparse.ArgumentParser(description="PH3 endpoint cartography")
    parser.add_argument("--config", default=None, help="Path to gulfsign_config.json")
    parser.add_argument("--password-file", default=None, help="Single-line password file")
    parser.add_argument("--max-nodes", type=int, default=120, help="Max URLs to crawl")
    parser.add_argument("--out", default=None, help="Write JSON report to this file")
    args = parser.parse_args()

    base_url, account, password = _load_credentials(args.config, args.password_file)
    if not account or not password:
        print(
            "Missing PH3_ACCOUNT / PH3_PASSWORD (or password file).",
            file=sys.stderr,
        )
        return 1

    report, ok = run_cartography(
        base_url=base_url,
        account=account,
        password=password,
        max_nodes=max(20, args.max_nodes),
    )
    blob = json.dumps(report, ensure_ascii=False, indent=2)
    print(blob)

    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(blob + "\n")

    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
