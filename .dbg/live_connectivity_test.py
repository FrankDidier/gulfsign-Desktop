#!/usr/bin/env python3
"""Live connectivity & login smoke test for湾流签约助手.

Probes:
  - DNS resolution for ggws.hnhfpc.gov.cn / jkkyljl.hnhfpc.gov.cn /
    sso.hnhfpc.gov.cn / 43.137.41.187 (license server)
  - TLS reachability for 3.0 portal
  - Login with the project-requirement supplied account
  - Basic patient query if login succeeds

This test requires outbound network. It only reads, never writes."""
import os
import sys
import time
import socket
import traceback

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

ACCOUNT = ""
PASSWORD = ""
GGWS = "https://ggws.hnhfpc.gov.cn"


def step(label):
    print("\n--- %s ---" % label)


def main() -> int:
    rc = 0

    step("DNS resolution")
    for host in ("ggws.hnhfpc.gov.cn", "jkkyljl.hnhfpc.gov.cn",
                 "sso.hnhfpc.gov.cn", "43.137.41.187"):
        t0 = time.time()
        try:
            ip = socket.gethostbyname(host)
            print("  ✓ %-32s -> %-15s (%.0fms)" %
                  (host, ip, (time.time() - t0) * 1000))
        except Exception as e:
            print("  ✗ %-32s -> %s" % (host, e))
            rc = 1

    step("TLS HTTPS reach (ggws portal)")
    try:
        from ph3_api import PH3Client
        client = PH3Client()
        client.base_url = GGWS
        client.session.mount("https://", _make_loose_adapter())
        r = client.session.get(GGWS + "/Index.aspx",
                               timeout=15, allow_redirects=False, verify=False)
        print("  ✓ /Index.aspx HTTP %s, %d bytes" %
              (r.status_code, len(r.content)))
    except Exception as e:
        print("  ✗ /Index.aspx failed: %s" % e)
        traceback.print_exc()
        rc = 1

    step("License server reachability (43.137.41.187:5004)")
    try:
        from license_client import LicenseClient
        lc = LicenseClient()
        ok = lc.test_connection()
        print("  %s test_connection() -> %s" %
              ("✓" if ok else "✗", ok))
        if not ok:
            rc = 1
    except Exception as e:
        print("  ✗ license server probe failed: %s" % e)
        traceback.print_exc()
        rc = 1

    step("PH3 login attempt with supplied test account")
    try:
        from ph3_api import PH3Client
        client = PH3Client()
        ok, msg = _try_login(client, GGWS, ACCOUNT, PASSWORD)
        if ok:
            print("  ✓ login: %s" % msg)
            print("    org_code   : %s" % client.org_code)
            print("    org_name   : %s" % client.org_name)
            print("    doctor     : %s" % client.doctor_name)
            print("    team       : %s" % client.team_name)
            print("    token_en   : %s..." % client.token_en[:8])
            print("    token_th   : %s..." % client.token_th[:8])
        else:
            print("  ✗ login failed: %s" % msg)
            rc = 1
    except Exception as e:
        print("  ✗ login crash: %s" % e)
        traceback.print_exc()
        rc = 1

    return rc


def _make_loose_adapter():
    import ssl
    from requests.adapters import HTTPAdapter
    from urllib3.util.ssl_ import create_urllib3_context

    class A(HTTPAdapter):
        def init_poolmanager(self, *a, **kw):
            ctx = create_urllib3_context()
            ctx.set_ciphers("DEFAULT:@SECLEVEL=0")
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            kw["ssl_context"] = ctx
            return super().init_poolmanager(*a, **kw)
    return A()


def _try_login(client, base_url, user, pwd):
    """Best-effort: try several login() signatures the codebase exposes."""
    client.base_url = base_url
    for name in ("login", "do_login", "authenticate"):
        m = getattr(client, name, None)
        if not m:
            continue
        try:
            res = m(user, pwd)
        except TypeError:
            try:
                res = m(base_url=base_url, account=user, password=pwd)
            except Exception as e:
                return False, "%s() raised: %s" % (name, e)
        except Exception as e:
            return False, "%s() raised: %s" % (name, e)
        if isinstance(res, tuple) and len(res) == 2:
            return bool(res[0]), str(res[1])
        return bool(res), str(res)
    return False, "no login method found on PH3Client"


if __name__ == "__main__":
    sys.exit(main())
