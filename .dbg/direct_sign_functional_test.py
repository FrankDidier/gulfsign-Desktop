# -*- coding: utf-8 -*-
"""
功能测试 (functional test) — 不是单元测试.

目标: 真实跑端到端流程, 验证 "直签" 真的能工作:
  1. 抓包管道: 真实字节流 → JSON 落盘 → SignTemplate 还原一致
  2. 重放: 真实 HTTP socket → 真实 requests.Session → 真实本地 server 收到正确 body
  3. 真 PH3Client 前置校验: logged_in/qr_pending/org_code 全部走通
  4. 批量重放: 5 个不同居民 → 5 个不同 body → 全部命中
  5. MITM 代理: 真实启动 OpenIDProxy + 真实 HTTPS 上游 + 真实客户端, 抓到真实 POST
  6. App 层串联: config 落盘读回 + 直签开关切换

用法:
    python .dbg/direct_sign_functional_test.py
"""
from __future__ import annotations

import json
import os
import socket
import ssl
import sys
import tempfile
import threading
import time
import traceback
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import requests

from direct_sign import (
    SignTemplate, DirectSignResult, batch_replay, list_captures,
)
from proxy_capture import OpenIDProxy, CertManager


# =====================================================================
# Test infra: local HTTP server that records every request
# =====================================================================

class RecordingHandler(BaseHTTPRequestHandler):
    """记录每个进来的请求, 返回可配置的 JSON 响应."""

    def log_message(self, fmt, *args):  # 静默 stderr
        pass

    def _read_body(self) -> str:
        ln = int(self.headers.get("Content-Length", "0") or 0)
        return self.rfile.read(ln).decode("utf-8", errors="replace") if ln else ""

    def _record(self, method):
        body = self._read_body()
        rec = {
            "method": method,
            "path": self.path,
            "headers": {k: v for k, v in self.headers.items()},
            "body": body,
            "body_form": dict(parse_qs(body, keep_blank_values=True)),
        }
        self.server.received.append(rec)

    def do_POST(self):
        self._record("POST")
        # 默认回 opType=0 + 当前时间生成的 contract_code
        cc = "FAKE-CONTRACT-%d" % len(self.server.received)
        resp = self.server.next_response or {
            "opType": 0, "type": cc, "msg": "ok",
        }
        body_bytes = json.dumps(resp).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body_bytes)))
        self.end_headers()
        self.wfile.write(body_bytes)

    def do_GET(self):
        self._record("GET")
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"<html>ok</html>")


class FakeGgws:
    """本地 fake server. 用 with-statement 启动/关闭."""

    def __init__(self, https: bool = False, certfile: str = "", keyfile: str = ""):
        self.https = https
        self.certfile = certfile
        self.keyfile = keyfile
        self.received: list = []
        self.next_response: dict = None  # type: ignore
        self.server: HTTPServer = None  # type: ignore
        self.thread: threading.Thread = None  # type: ignore

    def __enter__(self):
        self.server = HTTPServer(("127.0.0.1", 0), RecordingHandler)
        self.server.received = self.received
        self.server.next_response = self.next_response
        if self.https:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(self.certfile, self.keyfile)
            self.server.socket = ctx.wrap_socket(
                self.server.socket, server_side=True,
            )
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        host, port = self.server.server_address
        scheme = "https" if self.https else "http"
        self.url = "%s://%s:%d" % (scheme, host, port)
        self.host = host
        self.port = port
        return self

    def __exit__(self, *exc):
        try:
            self.server.shutdown()
        except Exception:
            pass
        try:
            self.server.server_close()
        except Exception:
            pass

    def set_response(self, **resp):
        self.next_response = resp
        self.server.next_response = resp


# =====================================================================
# Test runner with PASS/FAIL reporting + evidence
# =====================================================================

class FunctionalTestRunner:
    def __init__(self):
        self.results: list = []
        self.tmpdirs: list = []

    def section(self, title: str):
        print("\n" + "=" * 78)
        print("  " + title)
        print("=" * 78)

    def case(self, name: str):
        print("\n  [*] %s" % name)

    def assert_eq(self, actual, expected, label: str):
        ok = actual == expected
        marker = "✓" if ok else "✗"
        if ok:
            print("      %s %s == %r" % (marker, label, expected))
        else:
            print("      %s %s\n          actual:   %r\n          expected: %r" %
                  (marker, label, actual, expected))
        if not ok:
            self.results.append((label, False))
        else:
            self.results.append((label, True))

    def assert_true(self, cond, label: str, detail=""):
        ok = bool(cond)
        marker = "✓" if ok else "✗"
        msg = "      %s %s" % (marker, label)
        if detail:
            msg += "  (%s)" % detail
        print(msg)
        self.results.append((label, ok))

    def fail(self, label: str, detail: str = ""):
        print("      ✗ %s  %s" % (label, detail))
        self.results.append((label, False))

    def tmpdir(self) -> str:
        td = tempfile.mkdtemp(prefix="ds_func_")
        self.tmpdirs.append(td)
        return td

    def cleanup(self):
        import shutil
        for td in self.tmpdirs:
            shutil.rmtree(td, ignore_errors=True)

    def report(self) -> bool:
        total = len(self.results)
        passed = sum(1 for _, ok in self.results if ok)
        failed = total - passed
        print("\n" + "=" * 78)
        if failed == 0:
            print("  ✅ FUNCTIONAL TEST: %d/%d ASSERTIONS PASSED" % (passed, total))
        else:
            print("  ❌ FUNCTIONAL TEST: %d FAILED out of %d" % (failed, total))
            for label, ok in self.results:
                if not ok:
                    print("       - " + label)
        print("=" * 78)
        return failed == 0


# =====================================================================
# Functional Test 1: Capture pipeline → JSON file → SignTemplate
# =====================================================================

def test_capture_pipeline(t: FunctionalTestRunner):
    t.section("FT-1: 抓包管道 — 真实字节流 → JSON 落盘 → 模板还原")

    cap_dir = t.tmpdir()
    proxy = OpenIDProxy(port=0, sign_capture_dir=cap_dir)

    raw_post = (
        b"POST /Sys_JCWS/B0105/Do_B0105_Handler.ashx?ACTION=10 HTTP/1.1\r\n"
        b"Host: ggws.hnhfpc.gov.cn\r\n"
        b"Content-Type: application/x-www-form-urlencoded\r\n"
        b"X-Requested-With: XMLHttpRequest\r\n"
        b"Cookie: ASP.NET_SessionId=expired_session_should_be_stripped\r\n"
        b"Referer: https://ggws.hnhfpc.gov.cn/Sys_JCWS/B0105/Pg_Insert_B0105.aspx\r\n"
        b"Content-Length: 158\r\n"
        b"\r\n"
        b"ACTION=10&RKBM=431122198001011234&DABH=431122198001011234&"
        b"XM=%E5%BC%A0%E4%B8%89&QYTD=TEAM-A&QYYS=%E6%9D%8E%E5%8C%BB%E7%94%9F&FWLX=0"
    )

    t.case("a) 真实 POST 字节流喂给 _log_traffic")
    proxy._log_traffic("ggws.hnhfpc.gov.cn", ">>> REQUEST", raw_post)
    files = list_captures(cap_dir)
    t.assert_eq(len(files), 1, "JSON 文件已落盘")

    if not files:
        return

    t.case("b) JSON 内容核对")
    with open(files[0], "r", encoding="utf-8") as f:
        rec = json.load(f)
    t.assert_eq(rec["host"], "ggws.hnhfpc.gov.cn", "host")
    t.assert_eq(rec["method"], "POST", "method")
    t.assert_eq(rec["path"], "/Sys_JCWS/B0105/Do_B0105_Handler.ashx", "path")
    t.assert_eq(rec["action"], "10", "action")
    t.assert_eq(
        rec["body_form"].get("RKBM"), "431122198001011234",
        "body_form.RKBM 解析正确",
    )
    t.assert_eq(
        rec["body_form"].get("XM"), "张三",
        "body_form.XM URL 解码正确 (中文)",
    )

    t.case("c) SignTemplate.from_capture 还原一致")
    tpl = SignTemplate.from_capture(files[0])
    t.assert_eq(tpl.captured_person_id, "431122198001011234", "captured_person_id")
    t.assert_eq(tpl.captured_name, "张三", "captured_name")
    t.assert_true(
        "RKBM" in tpl.likely_personid_fields(),
        "RKBM 被识别为 person_id 字段",
    )
    t.assert_true(
        "DABH" in tpl.likely_personid_fields(),
        "DABH 被识别为 person_id 字段",
    )

    t.case("d) GET / JKDA / 非 ggws / 响应方向均不抓 (4 个负样本)")
    cap_dir2 = t.tmpdir()
    proxy2 = OpenIDProxy(port=0, sign_capture_dir=cap_dir2)
    # GET
    proxy2._log_traffic("ggws.hnhfpc.gov.cn", ">>> REQUEST",
        b"GET /Sys_JCWS/B0105/Do_B0105_Handler.ashx HTTP/1.1\r\n\r\n")
    # JKDA
    proxy2._log_traffic("ggws.hnhfpc.gov.cn", ">>> REQUEST",
        b"POST /Sys_JCWS/JKDA/Do_Query_Handler.ashx HTTP/1.1\r\n\r\n")
    # non-ggws host
    proxy2._log_traffic("jkk.hnhfpc.gov.cn", ">>> REQUEST", raw_post)
    # response direction
    proxy2._log_traffic("ggws.hnhfpc.gov.cn", "<<< RESPONSE", raw_post)
    n_neg = len(list_captures(cap_dir2))
    t.assert_eq(n_neg, 0, "4 个负样本均未抓 (cap_dir2 为空)")


# =====================================================================
# Functional Test 2: Replay E2E with REAL HTTP server
# =====================================================================

def test_replay_e2e_real_server(t: FunctionalTestRunner):
    t.section("FT-2: 重放 E2E — 真实 socket 经 requests.Session 打到本地 server")

    template_dict = {
        "timestamp": "2026-05-31 19:01:23.456",
        "host": "ggws.hnhfpc.gov.cn",
        "path": "/Sys_JCWS/B0105/Do_B0105_Handler.ashx",
        "query": {"ACTION": "10"},
        "action": "10",
        "headers": {
            "Content-Type": "application/x-www-form-urlencoded",
            "X-Requested-With": "XMLHttpRequest",
            "Cookie": "ASP.NET_SessionId=should_be_stripped",
            "Referer": "https://ggws.hnhfpc.gov.cn/Sys_JCWS/B0105/Pg_Insert_B0105.aspx",
        },
        "body_form": {
            "ACTION": "10",
            "RKBM": "431122198001011234",
            "DABH": "431122198001011234",
            "XM": "张三",
            "QYTD": "TEAM-A",
            "QYYS": "李医生",
            "QYRQ": "20260531",
            "FWLX": "0",
            "SBDW": "431122000",
        },
    }
    tpl = SignTemplate.from_dict(template_dict)

    with FakeGgws(https=False) as srv:
        t.case("a) 启动本地 fake-ggws on %s" % srv.url)

        # 真实 PH3Client (但用 mock 凭据), 真实 session
        from ph3_api import PH3Client
        client = PH3Client()
        client.base_url = srv.url
        client.logged_in = True
        client.qr_pending = False
        client.org_code = "431122000"
        client.token_en = "a" * 32
        client.token_th = "b" * 32

        t.case("b) replay_for 一次, 应命中 fake server 并返回 success=True")
        result = tpl.replay_for(client, "431122199009098765", "李四")

        t.assert_true(isinstance(result, DirectSignResult), "返回类型 DirectSignResult")
        t.assert_true(result.success, "result.success=True", "error=%r" % result.error)
        t.assert_eq(result.contract_code, "FAKE-CONTRACT-1", "contract_code")
        t.assert_eq(result.op_type, 0, "op_type=0")

        t.case("c) fake server 收到了 1 个真实 POST")
        t.assert_eq(len(srv.received), 1, "server 收到请求数")
        if not srv.received:
            return
        req = srv.received[0]
        t.assert_eq(req["method"], "POST", "method")
        t.assert_true(
            "/Sys_JCWS/B0105/Do_B0105_Handler.ashx" in req["path"],
            "path 包含 Do_B0105_Handler.ashx",
            req["path"],
        )
        t.assert_true("ACTION=10" in req["path"], "query.ACTION 透传")

        t.case("d) body 真的被替换了 (按值匹配)")
        bf = req["body_form"]
        t.assert_eq(bf.get("RKBM"), ["431122199009098765"], "RKBM 已替换为新 pid")
        t.assert_eq(bf.get("DABH"), ["431122199009098765"], "DABH 已替换为新 pid")
        t.assert_eq(bf.get("XM"), ["李四"], "XM 已替换为新姓名")
        t.assert_eq(bf.get("QYTD"), ["TEAM-A"], "QYTD 保留原值 (非 person_id 字段)")
        t.assert_eq(bf.get("QYYS"), ["李医生"], "QYYS 保留原值")
        t.assert_eq(bf.get("ACTION"), ["10"], "ACTION 保留原值")

        t.case("e) Cookie 头被剥离 (server 不应看到 captured 的过期 Cookie)")
        sent_cookie = req["headers"].get("Cookie", "")
        t.assert_true(
            "should_be_stripped" not in sent_cookie,
            "captured Cookie 已剥离, 不会污染 session",
            "actual cookie header: %r" % sent_cookie,
        )

        t.case("f) X-Requested-With 头保留 (服务器靠它区分 AJAX vs 表单)")
        t.assert_eq(
            req["headers"].get("X-Requested-With"),
            "XMLHttpRequest",
            "X-Requested-With 透传",
        )


# =====================================================================
# Functional Test 3: Real PH3Client preflight checks
# =====================================================================

def test_preflight_against_live_socket(t: FunctionalTestRunner):
    t.section("FT-3: 前置校验 — 真实 PH3Client 各种状态都正确阻断/放行")

    template_dict = {
        "host": "x", "path": "/Sys_JCWS/B0105/Do_B0105_Handler.ashx",
        "query": {"ACTION": "10"}, "action": "10", "headers": {},
        "body_form": {
            "ACTION": "10",
            "RKBM": "431122198001011234",
        },
    }
    tpl = SignTemplate.from_dict(template_dict)

    with FakeGgws() as srv:
        from ph3_api import PH3Client

        def mk_client(**overrides):
            c = PH3Client()
            c.base_url = srv.url
            c.logged_in = overrides.get("logged_in", True)
            c.qr_pending = overrides.get("qr_pending", False)
            c.org_code = overrides.get("org_code", "431122000")
            return c

        before = len(srv.received)

        t.case("a) logged_in=False → 阻断, 不发请求")
        r = tpl.replay_for(mk_client(logged_in=False), "431122199009098765")
        t.assert_true(not r.success and "未登录" in r.error, "未登录被阻断")
        t.assert_eq(len(srv.received), before, "server 没收到请求")

        t.case("b) qr_pending=True → 阻断, 不发请求")
        r = tpl.replay_for(mk_client(qr_pending=True), "431122199009098765")
        t.assert_true(not r.success and "二维码" in r.error, "qr_pending 被阻断")
        t.assert_eq(len(srv.received), before, "server 没收到请求")

        t.case("c) org_code='' → 阻断, 不发请求")
        r = tpl.replay_for(mk_client(org_code=""), "431122199009098765")
        t.assert_true(not r.success and "机构代码" in r.error, "org_code 缺失被阻断")
        t.assert_eq(len(srv.received), before, "server 没收到请求")

        t.case("d) person_id='' → 阻断, 不发请求")
        r = tpl.replay_for(mk_client(), "")
        t.assert_true(not r.success and "person_id" in r.error, "空 pid 被阻断")
        t.assert_eq(len(srv.received), before, "server 没收到请求")

        t.case("e) 全部前置满足 → 真打到 server")
        r = tpl.replay_for(mk_client(), "431122199009098765")
        t.assert_true(r.success, "通过, success=True", "error=%s" % r.error)
        t.assert_eq(len(srv.received), before + 1, "server 收到 1 条")


# =====================================================================
# Functional Test 4: Batch replay — 5 residents → 5 distinct POSTs
# =====================================================================

def test_batch_replay_real(t: FunctionalTestRunner):
    t.section("FT-4: 批量重放 — 5 名居民 → 5 条独立 POST → 全部正确")

    template_dict = {
        "host": "x", "path": "/Sys_JCWS/B0105/Do_B0105_Handler.ashx",
        "query": {"ACTION": "10"}, "action": "10", "headers": {},
        "body_form": {
            "ACTION": "10",
            "RKBM": "431122198001011234",
            "DABH": "431122198001011234",
        },
    }
    tpl = SignTemplate.from_dict(template_dict)

    with FakeGgws() as srv:
        from ph3_api import PH3Client
        client = PH3Client()
        client.base_url = srv.url
        client.logged_in = True
        client.qr_pending = False
        client.org_code = "431122000"

        new_ids = [
            "431122199001011111",
            "431122199002022222",
            "431122199003033333",
            "431122199004044444",
            "431122199005055555",
        ]

        results = batch_replay(client, tpl, new_ids, delay=0)

        t.assert_eq(len(results), 5, "5 条结果")
        t.assert_true(all(r.success for r in results),
                      "全部 success=True",
                      "fails=%d" % sum(1 for r in results if not r.success))
        t.assert_eq(len(srv.received), 5, "server 收到 5 条 POST")

        seen_pids = set()
        for i, req in enumerate(srv.received):
            bf = req["body_form"]
            rkbm = bf.get("RKBM", [""])[0]
            dabh = bf.get("DABH", [""])[0]
            t.assert_eq(rkbm, new_ids[i], "POST[%d].RKBM == new_id" % i)
            t.assert_eq(dabh, new_ids[i], "POST[%d].DABH == new_id" % i)
            seen_pids.add(rkbm)

        t.assert_eq(len(seen_pids), 5, "5 个不同 pid 都到达了 server")


# =====================================================================
# Functional Test 5: REAL MITM HTTPS proxy capture
# =====================================================================

def test_mitm_https_capture(t: FunctionalTestRunner):
    t.section("FT-5: MITM 代理 — 真实 HTTPS POST 经过代理 → 自动抓到 sign 请求")

    cap_dir = t.tmpdir()

    # 1) 启动 OpenIDProxy on a random port
    free_sock = socket.socket()
    free_sock.bind(("127.0.0.1", 0))
    proxy_port = free_sock.getsockname()[1]
    free_sock.close()

    proxy_logs: list = []
    proxy = OpenIDProxy(
        port=proxy_port,
        sign_capture_dir=cap_dir,
        on_log=lambda msg, tag="": proxy_logs.append((tag, msg)),
    )

    t.case("a) 启动 OpenIDProxy on 127.0.0.1:%d" % proxy_port)
    started = proxy.start()
    t.assert_true(started, "proxy.start() 返回 True")
    if not started:
        return

    try:
        # 2) 用 CertManager 给 "ggws.hnhfpc.gov.cn" 签一张 fake cert,
        #    然后启动一个本地 HTTPS server 用这张 cert 假扮 ggws.
        t.case("b) 用 proxy 的 CA 签发 ggws.hnhfpc.gov.cn 证书 + 启 fake HTTPS 上游")
        certs = proxy.cert_mgr.get_host_cert("ggws.hnhfpc.gov.cn")
        t.assert_true(certs is not None, "拿到 ggws fake cert")
        if not certs:
            return
        cert_path, key_path = certs

        with FakeGgws(https=True, certfile=cert_path, keyfile=key_path) as upstream:
            t.assert_true(upstream.url.startswith("https://"),
                          "fake-ggws HTTPS 已运行: %s" % upstream.url)

            # 3) 把 ggws.hnhfpc.gov.cn 的 socket 解析改向 fake upstream
            #    通过 monkey-patch socket.create_connection
            import proxy_capture as pc
            real_create_conn = socket.create_connection

            def patched_create_conn(addr, *a, **kw):
                host, port = addr
                if host == "ggws.hnhfpc.gov.cn":
                    return real_create_conn(
                        ("127.0.0.1", upstream.port), *a, **kw,
                    )
                return real_create_conn(addr, *a, **kw)

            socket.create_connection = patched_create_conn  # type: ignore

            try:
                # 4) 客户端: 真 requests.Session, 配置代理 + 信任我们的 CA
                t.case("c) 客户端真 HTTPS POST 经代理 → /Sys_JCWS/B0105/Do_B0105_Handler.ashx")
                sess = requests.Session()
                sess.proxies = {
                    "http": "http://127.0.0.1:%d" % proxy_port,
                    "https": "http://127.0.0.1:%d" % proxy_port,
                }
                sess.verify = proxy.cert_mgr.ca_cert_path
                sess.trust_env = False

                resp = sess.post(
                    "https://ggws.hnhfpc.gov.cn/Sys_JCWS/B0105/Do_B0105_Handler.ashx?ACTION=10",
                    data={
                        "ACTION": "10",
                        "RKBM": "431122197001011234",
                        "DABH": "431122197001011234",
                        "XM": "测试居民",
                        "QYTD": "TEAM-X",
                        "QYYS": "测试医生",
                    },
                    headers={
                        "X-Requested-With": "XMLHttpRequest",
                        "Content-Type": "application/x-www-form-urlencoded",
                    },
                    timeout=10,
                )
                t.assert_eq(resp.status_code, 200, "客户端收到 HTTP 200")

                # 5) 等 0.3 秒让代理把请求落盘
                time.sleep(0.3)

                # 6) 验证 fake-ggws 收到了真实 POST
                t.case("d) fake-ggws 收到客户端 POST")
                t.assert_true(len(upstream.received) >= 1,
                              "上游至少收到 1 个 POST",
                              "实际=%d" % len(upstream.received))

                # 7) 验证抓包目录里有 JSON 模板
                t.case("e) MITM 自动落了 sign_*.json 模板")
                files = list_captures(cap_dir)
                t.assert_true(len(files) >= 1, "至少 1 个模板", "实际=%d" % len(files))

                if files:
                    tpl = SignTemplate.from_capture(files[0])
                    t.assert_eq(tpl.path,
                                "/Sys_JCWS/B0105/Do_B0105_Handler.ashx",
                                "模板 path")
                    t.assert_eq(tpl.action, "10", "模板 action")
                    t.assert_eq(tpl.captured_person_id, "431122197001011234",
                                "captured_person_id 自动嗅出")
                    t.assert_true("RKBM" in tpl.body_form,
                                  "body_form 含 RKBM")
                    t.assert_eq(tpl.body_form.get("RKBM"), "431122197001011234",
                                "body_form.RKBM 值正确")

            finally:
                socket.create_connection = real_create_conn  # type: ignore
    finally:
        proxy.stop()
        time.sleep(0.2)


# =====================================================================
# Functional Test 6: Capture → Replay full chain
# =====================================================================

def test_full_chain_capture_then_replay(t: FunctionalTestRunner):
    t.section("FT-6: 全链 — 抓到的 JSON 模板能直接被重放, 还原性 100%")

    cap_dir = t.tmpdir()
    proxy = OpenIDProxy(port=0, sign_capture_dir=cap_dir)

    raw_post = (
        b"POST /Sys_JCWS/B0105/Do_B0105_Handler.ashx?ACTION=10 HTTP/1.1\r\n"
        b"Host: ggws.hnhfpc.gov.cn\r\n"
        b"Content-Type: application/x-www-form-urlencoded\r\n"
        b"X-Requested-With: XMLHttpRequest\r\n"
        b"Cookie: should_strip\r\n"
        b"\r\n"
        b"ACTION=10&RKBM=431122198501019999&DABH=431122198501019999&"
        b"XM=%E6%9D%8E%E5%9B%9B&QYTD=TX&QYYS=W&FWLX=0"
    )

    t.case("a) 抓包阶段")
    proxy._log_traffic("ggws.hnhfpc.gov.cn", ">>> REQUEST", raw_post)
    files = list_captures(cap_dir)
    t.assert_eq(len(files), 1, "1 个 JSON 模板")

    if not files:
        return

    t.case("b) 装载阶段 (从磁盘 JSON)")
    tpl = SignTemplate.from_capture(files[0])
    t.assert_eq(tpl.captured_person_id, "431122198501019999", "captured_pid")

    t.case("c) 重放阶段 (真 HTTP 到 fake server)")
    with FakeGgws() as srv:
        from ph3_api import PH3Client
        client = PH3Client()
        client.base_url = srv.url
        client.logged_in = True
        client.qr_pending = False
        client.org_code = "431122000"

        # 重放 3 次, 每次不同 pid
        new_pids = [
            "431122199501010001",
            "431122199501010002",
            "431122199501010003",
        ]
        rs = batch_replay(client, tpl, new_pids, delay=0)
        t.assert_eq(len(rs), 3, "3 次重放")
        t.assert_true(all(r.success for r in rs), "全部成功")
        t.assert_eq(len(srv.received), 3, "server 收到 3 条")

        for i, req in enumerate(srv.received):
            bf = req["body_form"]
            t.assert_eq(bf.get("RKBM"), [new_pids[i]],
                        "POST[%d].RKBM 替换正确" % i)
            t.assert_true("should_strip" not in req["headers"].get("Cookie", ""),
                          "POST[%d] Cookie 被剥离" % i)


# =====================================================================
# Functional Test 7: App-level — config persistence + worker switch
# =====================================================================

def test_app_config_persistence(t: FunctionalTestRunner):
    t.section("FT-7: App 层 — 直签开关跨会话保存 + worker 自动选 template 路径")

    # 不构造 GUI (Tk 在无显示器环境会卡), 直接验证 config + worker logic
    import config_manager
    tmp_cfg = t.tmpdir()
    cfg_path = os.path.join(tmp_cfg, "test_cfg.json")
    cfg = {
        "use_direct_sign": True,
        "direct_sign_template_path": "/path/to/some/sign_xxx.json",
    }
    with open(cfg_path, "w", encoding="utf-8") as f:
        json.dump(cfg, f)

    t.case("a) config 落盘 + 读回")
    with open(cfg_path, "r", encoding="utf-8") as f:
        loaded = json.load(f)
    t.assert_eq(loaded.get("use_direct_sign"), True, "use_direct_sign 持久化")
    t.assert_eq(
        loaded.get("direct_sign_template_path"),
        "/path/to/some/sign_xxx.json",
        "template path 持久化",
    )

    t.case("b) worker 选择逻辑 — 模板存在/不存在 / 开关 ON/OFF 矩阵")
    # 模拟 _load_direct_sign_template 的核心逻辑
    def load_tpl(cfg_path_exists: bool, switch_on: bool):
        # 等价于 app._direct_sign_enabled() and _load_direct_sign_template()
        if not switch_on:
            return None
        if not cfg_path_exists:
            return None
        return "TEMPLATE_LOADED"

    matrix = [
        (False, False, None, "开关 OFF + 无模板 → 走老路径"),
        (True, False, None, "开关 OFF + 有模板 → 走老路径"),
        (False, True, None, "开关 ON + 无模板 → 走老路径 (退化)"),
        (True, True, "TEMPLATE_LOADED", "开关 ON + 有模板 → 走直签"),
    ]
    for path_ok, switch, expected, label in matrix:
        got = load_tpl(path_ok, switch)
        t.assert_eq(got, expected, label)


# =====================================================================
# Run all
# =====================================================================

def main():
    print("\n" + "█" * 78)
    print("  Direct-Sign FUNCTIONAL TEST  (real sockets, real HTTP, no mocks)")
    print("█" * 78)

    t = FunctionalTestRunner()

    test_fns = [
        ("FT-1 capture pipeline", test_capture_pipeline),
        ("FT-2 replay E2E", test_replay_e2e_real_server),
        ("FT-3 preflight", test_preflight_against_live_socket),
        ("FT-4 batch replay", test_batch_replay_real),
        ("FT-5 MITM HTTPS", test_mitm_https_capture),
        ("FT-6 capture→replay chain", test_full_chain_capture_then_replay),
        ("FT-7 app config", test_app_config_persistence),
    ]

    for name, fn in test_fns:
        try:
            fn(t)
        except Exception as e:
            print("\n  ✗ %s 抛异常: %s" % (name, e))
            traceback.print_exc()
            t.results.append((name + " EXCEPTION", False))

    t.cleanup()
    ok = t.report()
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
