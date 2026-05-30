#!/usr/bin/env python3
"""GUI smoke test for湾流签约助手 — boots the app, verifies tabs and core
widgets exist, then shuts the Tk root cleanly without entering mainloop."""
import os
import sys
import time
import traceback

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)


def run_smoke_test() -> int:
    print("[smoke] importing GulfSignApp ...")
    from app import GulfSignApp, APP_TITLE, VERSION

    print("[smoke] APP_TITLE = %s" % APP_TITLE)
    print("[smoke] VERSION   = %s" % VERSION)

    print("[smoke] constructing Tk root window ...")
    app = GulfSignApp()

    try:
        print("[smoke] running update_idletasks ...")
        app.update_idletasks()

        nb = app.notebook
        tabs = [nb.tab(i, "text").strip() for i in range(nb.index("end"))]
        print("[smoke] notebook tabs (%d): %s" % (len(tabs), tabs))
        expected = {"3.0系统签约", "健康卡确认", "获取OpenID", "流量抓包", "许可证配置"}
        actual = {t.strip() for t in tabs}
        missing = expected - actual
        assert not missing, "missing tabs: %s" % missing
        print("[smoke] ✓ all 5 tabs present")

        widget_attrs = (
            "var_url", "var_account", "var_password",
            "var_org", "var_doctor", "var_team",
            "var_hc_openid", "var_license_user", "var_license_server",
        )
        for attr in widget_attrs:
            assert hasattr(app, attr), "missing widget var: %s" % attr
        print("[smoke] ✓ key UI variables present")

        for attr in ("client", "hc_client", "sign_engine",
                     "license_client", "config_manager", "batch_processor"):
            assert hasattr(app, attr), "missing core component: %s" % attr
        print("[smoke] ✓ all core components instantiated")

        cfg = app._cfg
        assert isinstance(cfg, dict), "config not a dict"
        print("[smoke] config keys: %d" % len(cfg))
        print("[smoke] sample keys: %s ..." % sorted(cfg.keys())[:8])

        print("[smoke] requesting clean shutdown ...")
        try:
            app.destroy()
        except Exception:
            pass
        print("[smoke] ✓ GUI smoke test PASSED")
        # Daemon worker threads (network probes) may still be running here;
        # they cannot crash the test thanks to _safe_after, and they will be
        # terminated when the interpreter exits via os._exit.
        os._exit(0)
    except Exception as e:
        print("[smoke] ✗ GUI smoke test FAILED: %s" % e)
        traceback.print_exc()
        try:
            app.destroy()
        except Exception:
            pass
        return 1


if __name__ == "__main__":
    raise SystemExit(run_smoke_test())
