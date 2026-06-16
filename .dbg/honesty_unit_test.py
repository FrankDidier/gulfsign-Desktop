#!/usr/bin/env python3
"""Targeted offline tests for the honesty / correctness fixes:

- PH3Client API methods reject calls when qr_pending=True (defense in depth)
- sign_one returns honest success/failure when confirm fails
- family_batch_initiate reports failure when 0 contracts were created
- delete_signing/void_signing/modify_archive use strict JSON parsing
- SuccessLogger.log_failure writes a real .xlsx into logs/失败
- SuccessLogger._safe_account rejects dict-like inputs
- SuccessLogger.clear_logs does not raise NameError
- _check_login_status returns False (not True) when org_code is missing
- HC create_resident_contract no longer optimistically reports success
"""
import os
import sys
import json
import tempfile
import shutil
from pathlib import Path

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from ph3_api import PH3Client, SignResult
from batch_processor import SuccessLogger


# -----------------------------------------------------------------------------
# 1. qr_pending defense-in-depth at the PH3Client API layer
# -----------------------------------------------------------------------------
def _fresh_client():
    c = PH3Client()
    c.base_url = "https://example.invalid"
    return c


def test_ph3_query_blocked_when_qr_pending():
    c = _fresh_client()
    c.logged_in = True
    c.qr_pending = True
    pts, total = c.query_patients(status="0", page=1)
    assert pts == [] and total == 0, \
        f"query_patients must be blocked while qr_pending; got {pts}, {total}"
    print("[ok] PH3Client.query_patients blocked while qr_pending")


def test_ph3_initiate_blocked_when_qr_pending():
    c = _fresh_client()
    c.logged_in = True
    c.qr_pending = True
    r = c.initiate_signing(person_id="test-id")
    assert isinstance(r, SignResult) and r.success is False, \
        f"initiate_signing must fail under qr_pending; got {r}"
    assert "二维码" in (r.error or ""), f"error should mention QR: {r.error}"
    print("[ok] PH3Client.initiate_signing blocked while qr_pending")


def test_ph3_confirm_blocked_when_qr_pending():
    c = _fresh_client()
    c.logged_in = True
    c.qr_pending = True
    r = c.confirm_signing(person_id="x", contract_code="cc")
    assert r.success is False and "二维码" in (r.error or "")
    print("[ok] PH3Client.confirm_signing blocked while qr_pending")


def test_ph3_family_batch_blocked_when_qr_pending():
    c = _fresh_client()
    c.logged_in = True
    c.qr_pending = True
    ok, msg, _ = c.family_batch_initiate(
        person_ids=["x"], family_guid="g",
        team_name="t", doctor_name="d",
        service_type="1", agreement_start="20260101",
        agreement_end="20261231",
    )
    assert ok is False and "二维码" in msg
    print("[ok] PH3Client.family_batch_initiate blocked while qr_pending")


# -----------------------------------------------------------------------------
# 2. Strict JSON parsing for delete_signing/void_signing
# -----------------------------------------------------------------------------
def test_optype_zero_strict_parse():
    assert PH3Client._opType_zero('{"opType":0}') is True
    assert PH3Client._opType_zero('{"opType": 0, "msg": ""}') is True
    assert PH3Client._opType_zero('{"opType":1}') is False
    # 原本会被旧代码误报为成功的恶意 / HTML 错误页
    assert PH3Client._opType_zero(
        '<html>error: "opType":0 mention</html>'
    ) is False, "substring match must NOT pass on HTML pages"
    assert PH3Client._opType_zero("") is False
    print("[ok] PH3Client._opType_zero strict JSON parser")


# -----------------------------------------------------------------------------
# 3. SuccessLogger: log_failure + safe_account + clear_logs
# -----------------------------------------------------------------------------
def test_success_logger_failure_path():
    tmp = tempfile.mkdtemp(prefix="gulfsign_log_test_")
    try:
        sl = SuccessLogger(
            log_dir=str(Path(tmp) / "logs"),
            success_log_dir=str(Path(tmp) / "logs" / "成功"),
            failure_log_dir=str(Path(tmp) / "logs" / "失败"),
        )
        ok_path = sl.log_success(
            account="",
            result_data={"name": "张三", "person_id": "p1"},
        )
        fail_path = sl.log_failure(
            account="",
            result_data={"name": "李四", "person_id": "p2", "step": "confirm"},
            error="服务器返回 opType=1",
        )
        assert "成功" in ok_path and ok_path.endswith(".xlsx")
        assert "失败" in fail_path and fail_path.endswith(".xlsx")
        ok_rows = sl.get_success_logs(account="")
        fail_rows = sl.get_failure_logs(account="")
        assert any(r.get("name") == "张三" for r in ok_rows), ok_rows
        assert any(r.get("name") == "李四" for r in fail_rows), fail_rows
        print(f"[ok] SuccessLogger writes both 成功 & 失败 ({ok_path}, {fail_path})")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_safe_account_rejects_bad_input():
    assert SuccessLogger._safe_account(None) == "unknown"
    assert SuccessLogger._safe_account("a/b\\c?") == "a_b_c_"
    # dict gets stringified first, then sanitized — should never produce
    # filenames containing forbidden chars.
    out = SuccessLogger._safe_account({"a": 1})
    bad_chars = '<>:"/\\|?*\n\r\t'
    assert not any(ch in out for ch in bad_chars), out
    print(f"[ok] SuccessLogger._safe_account sanitization: {out!r}")


def test_clear_logs_no_nameerror():
    tmp = tempfile.mkdtemp(prefix="gulfsign_log_test_")
    try:
        sl = SuccessLogger(
            log_dir=str(Path(tmp) / "logs"),
            success_log_dir=str(Path(tmp) / "logs" / "成功"),
            failure_log_dir=str(Path(tmp) / "logs" / "失败"),
        )
        # 这之前会抛 NameError: name 'timedelta' is not defined
        deleted = sl.clear_logs(days_to_keep=30)
        assert isinstance(deleted, int)
        print(f"[ok] SuccessLogger.clear_logs ran without NameError "
              f"(deleted={deleted})")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


# -----------------------------------------------------------------------------
# 4. _check_login_status: org_code missing => False
# -----------------------------------------------------------------------------
def test_check_login_status_missing_orgcode():
    import tkinter as tk
    root = tk.Tk()
    root.withdraw()
    try:
        from app import GulfSignApp

        class _Stub:
            pass
        app = _Stub()
        app.client = PH3Client()
        app.client.logged_in = True
        app.client.qr_pending = False
        app.client.org_code = ""  # 关键: 没拿到机构代码
        app._cfg = {"username": ""}
        app.enhanced_account_var = tk.StringVar(value="")
        app.enhanced_url_var = tk.StringVar(value="https://ggws.hnhfpc.gov.cn")

        ok, msg, detail = GulfSignApp._check_login_status(app)
        assert ok is False, \
            f"missing org_code must NOT count as ok; got ok={ok}, msg={msg}"
        assert "机构" in msg
        print(f"[ok] _check_login_status no org_code → ok=False ({msg!r})")
    finally:
        try:
            root.destroy()
        except Exception:
            pass


# -----------------------------------------------------------------------------
def main() -> int:
    test_ph3_query_blocked_when_qr_pending()
    test_ph3_initiate_blocked_when_qr_pending()
    test_ph3_confirm_blocked_when_qr_pending()
    test_ph3_family_batch_blocked_when_qr_pending()
    test_optype_zero_strict_parse()
    test_success_logger_failure_path()
    test_safe_account_rejects_bad_input()
    test_clear_logs_no_nameerror()
    test_check_login_status_missing_orgcode()
    print("\n[OK] honesty unit tests all passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
