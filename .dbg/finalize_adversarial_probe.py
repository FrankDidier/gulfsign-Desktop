# -*- coding: utf-8 -*-
"""对抗性探针: 状态校验 + 档案推进 在恶意/畸形服务端响应下绝不误报成功.

核心不变式 (INVARIANT):
    finalize_via_archive / sign_one(verify_final) 只有在服务器对**匹配的身份证**
    明确返回"已签约"时才允许 success=True; 任何畸形/含糊/错误响应都必须 success=False,
    且**不得崩溃**。

每个探针注入一种"看似成功实则没签"的响应, 断言结果不是误报。
"""
import json
import os
import sys
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from ph3_api import PH3Client, SignResult

SFZH = "431122198001011234"
PID = "PID-9001"


def make_handler(query_responder, modify_responder, recorder):
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _send(self, body, ctype="text/html; charset=utf-8", code=200):
            data = body.encode("utf-8") if isinstance(body, str) else body
            # 真实 ggws 响应带 charset; 补上以免 requests 把中文按 latin-1 解码
            if ctype.startswith("text/") and "charset" not in ctype:
                ctype = ctype + "; charset=utf-8"
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self):
            if "Pg_Edit_B0101" in self.path:
                self._send('<form><input name="GUID" value="%s">'
                           '<input name="SFZH" value="%s"></form>' % (PID, SFZH))
            else:
                self._send("ok")

        def do_POST(self):
            length = int(self.headers.get("Content-Length", 0))
            raw = self.rfile.read(length).decode("utf-8", "replace") if length else ""
            form = {k: v[0] for k, v in parse_qs(raw).items()}
            recorder.append((self.path, form))
            if "Do_B0105_Handler" in self.path:
                body, ctype, code = query_responder(form)
                self._send(body, ctype, code)
            elif "Do_B0101_Handler" in self.path:
                body, ctype, code = modify_responder(form)
                self._send(body, ctype, code)
            else:
                self._send("{}", "application/json")
    return H


class ProbeBase(unittest.TestCase):
    query_responder = staticmethod(lambda form: ("<rows></rows>@@0", "text/html", 200))
    modify_responder = staticmethod(
        lambda form: ('{"opType":0,"msg":"成功"}', "application/json", 200)
    )

    def setUp(self):
        self.recorder = []
        self.httpd = ThreadingHTTPServer(
            ("127.0.0.1", 0),
            make_handler(self.query_responder, self.modify_responder, self.recorder),
        )
        self.port = self.httpd.server_address[1]
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
        self.c = PH3Client()
        self.c.logged_in = True
        self.c.qr_pending = False
        self.c.org_code = "431122000"
        self.c.token_en = "0" * 32
        self.c.token_th = "0" * 64
        self.c.base_url = "http://127.0.0.1:%d" % self.port
        self.c._timeout = 5

    def tearDown(self):
        self.httpd.shutdown()
        self.httpd.server_close()

    def finalize(self):
        return self.c.finalize_via_archive(
            PID, sfzh=SFZH, name="张三", max_retries=2, _sleep=lambda *_: None
        )


def grid(status_text, sfzh=SFZH):
    cells = [""] * 22
    cells[7] = status_text
    cells[9] = "张三"
    cells[13] = sfzh
    cell_xml = "".join("<cell>%s</cell>" % x for x in cells)
    return '<rows><row id="%s" contract_code="CC">%s</row></rows>@@1' % (PID, cell_xml)


# --- 探针 1: 查询返回空网格 (查不到人) ---
class P01EmptyGrid(ProbeBase):
    query_responder = staticmethod(lambda f: ("<rows></rows>@@0", "text/html", 200))
    def test(self):
        r = self.finalize()
        self.assertFalse(r.success)


# --- 探针 2: 查询返回 HTML 错误页 (非网格) ---
class P02HtmlError(ProbeBase):
    query_responder = staticmethod(
        lambda f: ("<html><body>系统错误 500</body></html>", "text/html", 200)
    )
    def test(self):
        r = self.finalize()
        self.assertFalse(r.success)


# --- 探针 3: 查询返回未知状态文本 (不在 _STATUS_MAP) ---
class P03UnknownStatus(ProbeBase):
    query_responder = staticmethod(lambda f: (grid("某种未知状态"), "text/html", 200))
    def test(self):
        r = self.finalize()
        self.assertFalse(r.success)   # code="" -> 永不落库 -> 诚实失败


# --- 探针 4: 查询永远返回 居民申请, 但 modify 返回 opType=0 "成功" ---
#     (服务端假装档案修改成功, 但合同状态从不翻 —— 经典静默失败)
class P04ArchiveLiesSuccess(ProbeBase):
    query_responder = staticmethod(lambda f: (grid("居民申请"), "text/html", 200))
    modify_responder = staticmethod(
        lambda f: ('{"opType":0,"msg":"成功"}', "application/json", 200)
    )
    def test(self):
        r = self.finalize()
        self.assertFalse(r.success)   # 状态没翻就绝不算成功
        self.assertIn("居民申请", r.error)


# --- 探针 5: modify 返回 HTML 错误页 (但 HTTP 200) ---
class P05ModifyHtmlError(ProbeBase):
    query_responder = staticmethod(lambda f: (grid("居民申请"), "text/html", 200))
    modify_responder = staticmethod(
        lambda f: ("<html>登录超时 login.aspx</html>", "text/html", 200)
    )
    def test(self):
        r = self.finalize()
        self.assertFalse(r.success)


# --- 探针 6: modify 返回 opType=1 (失败), 状态不翻 ---
class P06ModifyOpType1(ProbeBase):
    query_responder = staticmethod(lambda f: (grid("居民申请"), "text/html", 200))
    modify_responder = staticmethod(
        lambda f: ('{"opType":1,"msg":"档案校验失败"}', "application/json", 200)
    )
    def test(self):
        r = self.finalize()
        self.assertFalse(r.success)


# --- 探针 7: 查询返回 JSON 数组 (而非网格 XML) —— 不得崩溃 ---
class P07JsonArray(ProbeBase):
    query_responder = staticmethod(
        lambda f: ('[{"opType":0}]', "application/json", 200)
    )
    def test(self):
        r = self.finalize()   # 不抛异常即可
        self.assertFalse(r.success)


# --- 探针 8: 查询 HTTP 500 ---
class P08Query500(ProbeBase):
    query_responder = staticmethod(lambda f: ("error", "text/html", 500))
    def test(self):
        r = self.finalize()
        self.assertFalse(r.success)


# --- 探针 9: 真正落库 —— 这是唯一允许成功的情形 (正向对照) ---
class P09GenuineSuccess(ProbeBase):
    _state = {"n": 0}
    @staticmethod
    def query_responder(f):
        # 第一次查 居民申请, 提交档案后查 已签约
        if P09GenuineSuccess._state["n"] >= 1:
            return (grid("已签约"), "text/html", 200)
        return (grid("居民申请"), "text/html", 200)
    @staticmethod
    def modify_responder(f):
        P09GenuineSuccess._state["n"] += 1
        return ('{"opType":0,"msg":"成功"}', "application/json", 200)
    def setUp(self):
        P09GenuineSuccess._state["n"] = 0
        super().setUp()
    def test(self):
        r = self.finalize()
        self.assertTrue(r.success)    # 服务端明确翻成已签约 -> 允许成功
        self.assertEqual(r.step, "finalize_verified")


# --- 探针 10: verify_final 下, 查询返回畸形 -> 不下调真实 confirm 成功 ---
class P10VerifyQueryGarbageKeepsResult(ProbeBase):
    query_responder = staticmethod(
        lambda f: ("<html>503 busy</html>", "text/html", 200)
    )
    def test(self):
        from unittest.mock import MagicMock
        self.c.initiate_signing = MagicMock(
            return_value=SignResult(True, PID, "张三", contract_code="CC")
        )
        self.c.confirm_signing = MagicMock(
            return_value=SignResult(True, PID, "张三", contract_code="CC",
                                    step="confirm")
        )
        r = self.c.sign_one(PID, name="张三", sfzh=SFZH,
                            verify_final=True, finalize_archive=False, delay=0)
        # 查不到真实状态(code="") -> 既不误报也不误杀, 保留成功但标记 unverified
        self.assertTrue(r.success)
        self.assertEqual(r.step, "unverified")


if __name__ == "__main__":
    unittest.main(verbosity=2)
