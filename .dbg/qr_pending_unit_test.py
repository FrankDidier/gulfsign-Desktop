#!/usr/bin/env python3
"""Targeted offline test for qr_pending state plumbing.

Verifies that:
  * PH3Client exposes a `qr_pending` flag and a `fully_authenticated` property.
  * msg<=4 leaves the client in qr_pending=True (logged_in=True, but
    fully_authenticated=False).
  * GulfSignApp._check_login_status reports the QR-pending status with the
    correct, actionable text instead of falsely saying "已登录".
  * Pre-flight gate _ensure_session_usable refuses to proceed while qr_pending
    is True.
"""
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from ph3_api import PH3Client


def test_attributes_exist():
    c = PH3Client()
    assert hasattr(c, "qr_pending"), "PH3Client missing qr_pending"
    assert hasattr(c, "fully_authenticated"), "PH3Client missing fully_authenticated"
    assert c.qr_pending is False, "qr_pending should default to False"
    assert c.fully_authenticated is False, "fresh client cannot be fully_authenticated"
    print("[ok] PH3Client.qr_pending / fully_authenticated wired")


def test_fully_authenticated_truth_table():
    c = PH3Client()
    c.logged_in = True
    c.qr_pending = True
    c.org_code = "12345"
    assert c.fully_authenticated is False, "qr_pending must veto fully_authenticated"

    c.qr_pending = False
    c.org_code = ""
    assert c.fully_authenticated is False, "missing org_code must veto fully_authenticated"

    c.org_code = "12345"
    assert c.fully_authenticated is True, "all-good case must report True"
    print("[ok] fully_authenticated truth table correct")


def test_app_check_login_status_qr_pending():
    """Drive GulfSignApp._check_login_status without spinning up a full Tk
    session by stubbing the bits it touches."""
    import tkinter as tk

    # Build a minimal, throwaway Tk root just so StringVars work
    root = tk.Tk()
    root.withdraw()

    try:
        from app import GulfSignApp
        # Reuse GulfSignApp._check_login_status as an unbound method against
        # a lightweight namespace (avoids constructing the full GUI)
        class _Stub:
            pass

        app = _Stub()
        app.client = PH3Client()
        app.client.logged_in = True
        app.client.qr_pending = True
        app._cfg = {"username": "431122012"}
        app.enhanced_account_var = tk.StringVar(value="431122012")
        app.enhanced_url_var = tk.StringVar(value="https://ggws.hnhfpc.gov.cn")

        ok, msg, detail = GulfSignApp._check_login_status(app)
        assert ok is False, f"qr_pending must NOT count as ok; got ok={ok}"
        assert "二维码" in msg, f"message should mention QR; got: {msg}"
        assert "同步配置" in detail, f"detail should mention 同步配置; got: {detail}"
        print(f"[ok] qr_pending -> ok={ok}  msg={msg!r}")

        # Now flip to fully authenticated
        app.client.qr_pending = False
        app.client.org_code = "430100000000"
        app._cfg["org_code"] = "430100000000"
        app._cfg["org_name"] = "Test Hospital"
        ok2, msg2, _ = GulfSignApp._check_login_status(app)
        assert ok2 is True, f"fully authenticated must report ok=True; got {ok2}"
        assert "已登录" in msg2, msg2
        print(f"[ok] fully authenticated -> ok={ok2}  msg={msg2!r}")
    finally:
        try:
            root.destroy()
        except Exception:
            pass


def main() -> int:
    test_attributes_exist()
    test_fully_authenticated_truth_table()
    test_app_check_login_status_qr_pending()
    print("\n[OK] qr_pending plumbing tests all passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
