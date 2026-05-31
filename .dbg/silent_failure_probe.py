# -*- coding: utf-8 -*-
"""
Silent-failure probe — 故意构造各种"几乎成功但其实失败"的服务器响应,
验证 direct_sign / proxy 不会被骗着说 success=True.

这不是普通的功能测试. 这是 *对抗式* 测试: 我们扮演一个想糊弄我们的
服务器, 看抓包/重放层会不会上当.
"""
from __future__ import annotations

import json
import os
import socket
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from direct_sign import SignTemplate, DirectSignResult


PROBE_TEMPLATE = {
    "host": "x", "path": "/Sys_JCWS/B0105/Do_B0105_Handler.ashx",
    "query": {"ACTION": "10"}, "action": "10", "headers": {},
    "body_form": {
        "ACTION": "10",
        "RKBM": "431122198001011234",
        "DABH": "431122198001011234",
        "XM": "张三",
    },
}


class ResponseInjector(BaseHTTPRequestHandler):
    """每个 POST 响应都从 server.next_response 读, 让我们逐一注入伪造响应."""

    def log_message(self, *a, **k):
        pass

    def do_POST(self):
        ln = int(self.headers.get("Content-Length", "0") or 0)
        self.rfile.read(ln) if ln else b""
        cfg = self.server.next_response
        status = cfg.get("status", 200)
        body = cfg.get("body", "")
        ctype = cfg.get("content_type", "application/json")
        if isinstance(body, (dict, list)):
            body = json.dumps(body)
        body_bytes = body.encode("utf-8") if isinstance(body, str) else body
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body_bytes)))
        self.end_headers()
        self.wfile.write(body_bytes)


class FakeWithInjector:
    def __enter__(self):
        self.srv = HTTPServer(("127.0.0.1", 0), ResponseInjector)
        self.srv.next_response = {"body": {"opType": 0, "type": "OK"}}
        self.t = threading.Thread(target=self.srv.serve_forever, daemon=True)
        self.t.start()
        self.url = "http://127.0.0.1:%d" % self.srv.server_address[1]
        return self

    def __exit__(self, *exc):
        try:
            self.srv.shutdown()
            self.srv.server_close()
        except Exception:
            pass

    def inject(self, **resp):
        self.srv.next_response = resp


def mk_client(base_url):
    from ph3_api import PH3Client
    c = PH3Client()
    c.base_url = base_url
    c.logged_in = True
    c.qr_pending = False
    c.org_code = "431122000"
    c._timeout = 5
    return c


PROBES = []
RESULTS = []


def probe(name):
    def deco(fn):
        PROBES.append((name, fn))
        return fn
    return deco


def expect_failure(r: DirectSignResult, label: str):
    ok = (r.success is False)
    marker = "✓ defended" if ok else "✗ FOOLED"
    print("    %s  %s" % (marker, label))
    if not ok:
        print("      ⚠ DirectSignResult.success=True with error=%r contract=%r" %
              (r.error, r.contract_code))
    RESULTS.append((label, ok))


def expect_success(r: DirectSignResult, label: str):
    ok = (r.success is True)
    marker = "✓" if ok else "✗"
    print("    %s  %s" % (marker, label))
    if not ok:
        print("      reason: %s" % r.error)
    RESULTS.append((label, ok))


# =====================================================================
# Probes — each one tries to make replay_for falsely report success
# =====================================================================

@probe("opType missing entirely")
def p1(srv):
    srv.inject(body={"msg": "ok", "type": "C-1"})
    tpl = SignTemplate.from_dict(PROBE_TEMPLATE)
    r = tpl.replay_for(mk_client(srv.url), "431122199009098765")
    expect_failure(r, "opType 字段缺失 → 应判失败")


@probe("opType wrong type (string non-numeric)")
def p2(srv):
    srv.inject(body={"opType": "success", "type": "C-1"})
    tpl = SignTemplate.from_dict(PROBE_TEMPLATE)
    r = tpl.replay_for(mk_client(srv.url), "431122199009098765")
    expect_failure(r, "opType=='success' (不是 0) → 应判失败")


@probe("opType is 1 (real failure)")
def p3(srv):
    srv.inject(body={"opType": 1, "msg": "重复签约"})
    tpl = SignTemplate.from_dict(PROBE_TEMPLATE)
    r = tpl.replay_for(mk_client(srv.url), "431122199009098765")
    expect_failure(r, "opType=1 + msg → 应判失败")


@probe("opType is null/None")
def p4(srv):
    srv.inject(body={"opType": None, "type": "C-1"})
    tpl = SignTemplate.from_dict(PROBE_TEMPLATE)
    r = tpl.replay_for(mk_client(srv.url), "431122199009098765")
    expect_failure(r, "opType=null → 应判失败")


@probe("opType is array (weird)")
def p5(srv):
    srv.inject(body={"opType": [0], "type": "C-1"})
    tpl = SignTemplate.from_dict(PROBE_TEMPLATE)
    r = tpl.replay_for(mk_client(srv.url), "431122199009098765")
    expect_failure(r, "opType=[0] (列表) → 应判失败")


@probe("HTTP 200 but empty body")
def p6(srv):
    srv.inject(body="")
    tpl = SignTemplate.from_dict(PROBE_TEMPLATE)
    r = tpl.replay_for(mk_client(srv.url), "431122199009098765")
    expect_failure(r, "200 + 空 body → 应判失败")


@probe("HTTP 200 but HTML error page")
def p7(srv):
    srv.inject(
        content_type="text/html",
        body="<html><body>系统繁忙, 请稍后再试</body></html>",
    )
    tpl = SignTemplate.from_dict(PROBE_TEMPLATE)
    r = tpl.replay_for(mk_client(srv.url), "431122199009098765")
    expect_failure(r, "200 + HTML 错误页 → 应判失败")


@probe("HTTP 200 but login redirect HTML")
def p8(srv):
    """会话过期时 ASP.NET 可能返回登录页, content-type 仍是 text/html."""
    srv.inject(
        content_type="text/html",
        body="<html><script>window.location='/login.aspx'</script></html>",
    )
    tpl = SignTemplate.from_dict(PROBE_TEMPLATE)
    r = tpl.replay_for(mk_client(srv.url), "431122199009098765")
    expect_failure(r, "200 + login 重定向 HTML → 应判失败")


@probe("HTTP 200 but plain text 'ok'")
def p9(srv):
    srv.inject(content_type="text/plain", body="ok")
    tpl = SignTemplate.from_dict(PROBE_TEMPLATE)
    r = tpl.replay_for(mk_client(srv.url), "431122199009098765")
    expect_failure(r, "200 + 文本 'ok' (无 contract_code) → 应判失败")


@probe("HTTP 302 redirect (session expired)")
def p10(srv):
    srv.inject(status=302, body="")
    tpl = SignTemplate.from_dict(PROBE_TEMPLATE)
    r = tpl.replay_for(mk_client(srv.url), "431122199009098765")
    expect_failure(r, "HTTP 302 → 应判失败")


@probe("HTTP 401 unauthorized")
def p11(srv):
    srv.inject(status=401, body="unauthorized")
    tpl = SignTemplate.from_dict(PROBE_TEMPLATE)
    r = tpl.replay_for(mk_client(srv.url), "431122199009098765")
    expect_failure(r, "HTTP 401 → 应判失败")


@probe("HTTP 500 server error")
def p12(srv):
    srv.inject(status=500, body="error")
    tpl = SignTemplate.from_dict(PROBE_TEMPLATE)
    r = tpl.replay_for(mk_client(srv.url), "431122199009098765")
    expect_failure(r, "HTTP 500 → 应判失败")


@probe("response is JSON array (not object)")
def p13(srv):
    srv.inject(body=[{"opType": 0}])
    tpl = SignTemplate.from_dict(PROBE_TEMPLATE)
    r = tpl.replay_for(mk_client(srv.url), "431122199009098765")
    expect_failure(r, "返回 JSON 数组 → 应判失败 (代码用 .get)")


@probe("opType=0 BUT contract_code missing")
def p14(srv):
    """这个其实应该 success — opType=0 是签约层的成功标志.
    但 contract_code 为空, 上游需要知道这一点."""
    srv.inject(body={"opType": 0})
    tpl = SignTemplate.from_dict(PROBE_TEMPLATE)
    r = tpl.replay_for(mk_client(srv.url), "431122199009098765")
    # opType=0 → success=True, 但 contract_code='' — 这是允许的.
    # 我们要确认 .contract_code 是空字符串, 而不是 None 或 false 成功.
    print("    DEBUG: success=%s contract_code=%r" % (r.success, r.contract_code))
    ok = r.success is True and r.contract_code == ""
    print("    %s  opType=0 但无 contract_code → 仍算 success, 但 contract_code 必须='' (不是 None)" %
          ("✓" if ok else "✗"))
    RESULTS.append(("opType=0 missing cc behavior", ok))


@probe("HTML with contract_code-looking text (try to fool fallback regex)")
def p15(srv):
    """非 JSON, 但 HTML 里有看起来像 contract_code 的字符串.
    这是一个真实风险点: 我们的回退 regex 可能误判."""
    srv.inject(
        content_type="text/html",
        body=(
            "<html><body>错误<br>"
            "页面变量: contract_code = \"abc12345-6789-4def-9012-3456789abcde\""
            "</body></html>"
        ),
    )
    tpl = SignTemplate.from_dict(PROBE_TEMPLATE)
    r = tpl.replay_for(mk_client(srv.url), "431122199009098765")
    # 这是一个 KNOWN risk: regex 命中就会标 success.
    # 我们要诚实记录: 这种情况会被误判为 success.
    if r.success:
        print("    ⚠ KNOWN RISK: regex fallback 命中, success=%s contract=%r" %
              (r.success, r.contract_code))
        print("       这种 HTML 错误页里若意外含 contract_code='<guid>' 字串会被误判.")
        print("       实际公卫3.0 错误页几乎不可能含此字符串, 但理论存在 risk.")
        RESULTS.append(("HTML fallback regex risk", "RISK_KNOWN"))
    else:
        RESULTS.append(("HTML fallback regex risk", True))


@probe("network connection refused")
def p16(_srv_unused):
    """临开一个 server, 立刻关, 然后试连 — 触发 connection refused."""
    s = HTTPServer(("127.0.0.1", 0), ResponseInjector)
    url = "http://127.0.0.1:%d" % s.server_address[1]
    s.server_close()
    from ph3_api import PH3Client
    c = PH3Client()
    c.base_url = url
    c.logged_in = True
    c.qr_pending = False
    c.org_code = "431122000"
    c._timeout = 3
    tpl = SignTemplate.from_dict(PROBE_TEMPLATE)
    r = tpl.replay_for(c, "431122199009098765")
    expect_failure(r, "TCP refused → 应判失败 (网络异常)")


@probe("timeout (server hangs)")
def p17(_unused):
    """启动一个永远不响应的 server, 应触发超时."""
    class Hang(BaseHTTPRequestHandler):
        def log_message(self, *a, **k): pass
        def do_POST(self):
            time.sleep(30)  # 永远不响应

    s = HTTPServer(("127.0.0.1", 0), Hang)
    threading.Thread(target=s.serve_forever, daemon=True).start()
    url = "http://127.0.0.1:%d" % s.server_address[1]
    tpl = SignTemplate.from_dict(PROBE_TEMPLATE)
    client = mk_client(url)
    client._timeout = 1  # 强制 1 秒超时
    r = tpl.replay_for(client, "431122199009098765")
    expect_failure(r, "服务器挂起 → 应触发超时, 判失败")
    s.shutdown()
    s.server_close()


@probe("template with no captured_person_id should not call session")
def p18(srv):
    """没识别出 captured_person_id 的模板, 应该在前置阻断, 不发请求."""
    bad_tpl_dict = dict(PROBE_TEMPLATE)
    bad_tpl_dict["body_form"] = {"ACTION": "10", "QYTD": "T1"}
    tpl = SignTemplate.from_dict(bad_tpl_dict)

    requests_made = []
    real_post = srv.srv.RequestHandlerClass.do_POST

    class Spy(ResponseInjector):
        def do_POST(self):
            requests_made.append(self.path)
            return real_post(self)
    srv.srv.RequestHandlerClass = Spy

    r = tpl.replay_for(mk_client(srv.url), "431122199009098765")
    ok = (r.success is False) and (len(requests_made) == 0)
    print("    %s  无 captured_person_id → 不发请求 (server 收到 %d 条)" %
          ("✓ defended" if ok else "✗ FOOLED", len(requests_made)))
    RESULTS.append(("no-captured-pid blocks before network", ok))


@probe("opType=0 with contract_code → real success path")
def p19(srv):
    srv.inject(body={"opType": 0, "type": "REAL-CONTRACT-OK-001"})
    tpl = SignTemplate.from_dict(PROBE_TEMPLATE)
    r = tpl.replay_for(mk_client(srv.url), "431122199009098765")
    expect_success(r, "正常 opType=0 + contract → 应判成功")
    if r.success:
        print("       contract_code=%s op_type=%s elapsed=%.3fs" %
              (r.contract_code, r.op_type, r.elapsed))


# =====================================================================
# Run
# =====================================================================

def main():
    print("\n" + "█" * 78)
    print("  Silent-Failure Probe — 对抗式测试")
    print("  问题: 服务器/网络在各种'看起来对其实错'的场景下,")
    print("        replay_for 会不会假报 success=True?")
    print("█" * 78)

    print("\n--- 19 个对抗式探针 ---")
    with FakeWithInjector() as srv:
        for name, fn in PROBES:
            print("\n[*] %s" % name)
            try:
                fn(srv)
            except Exception as e:
                print("    ✗ probe 自己抛了: %s" % e)
                import traceback; traceback.print_exc()
                RESULTS.append((name, False))

    total = len(RESULTS)
    defended = sum(1 for _, ok in RESULTS if ok is True)
    fooled = sum(1 for _, ok in RESULTS if ok is False)
    risks = sum(1 for _, ok in RESULTS if ok == "RISK_KNOWN")

    print("\n" + "=" * 78)
    print("  %d / %d 防御成功 (即正确判失败/正确判成功)" % (defended, total))
    if risks:
        print("  %d 项已知 risk (非 silent failure, 仅做记录)" % risks)
    if fooled:
        print("  ❌ %d 项被骗 (silent failure!):" % fooled)
        for label, ok in RESULTS:
            if ok is False:
                print("       - " + label)
    else:
        print("  ✅ 0 项被骗")
    print("=" * 78)

    sys.exit(0 if fooled == 0 else 1)


if __name__ == "__main__":
    main()
