# -*- coding: utf-8 -*-
"""端到端功能测试: 状态校验 + 档案推进, 打真实本地 HTTP 服务器.

不 mock 任何 PH3Client 方法 —— 用真 requests.Session 经真 socket 打一个
仿真的 ggws 服务器, 验证:
  1. check_sign_status_by_sfzh 真的发出 action=4 + SFZH 的 POST, 并正确解析状态
  2. finalize_via_archive 真的走 "查状态 -> Pg_Edit 加载 -> Do_B0101 ACTION=2 -> 回查"
     的完整链路, 并在服务端把 居民申请 翻成 已签约 后返回 success
  3. 服务端始终不翻 -> finalize 诚实失败 (绝不误报)
  4. sign_one(verify_final) 集成: confirm 自称成功但真实未落库 -> 诚实改判
"""
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
CC = "CC-9001"


def grid_xml(status_text):
    """构造一条符合 _parse_grid 期望的网格行 (cell[7]=状态, [9]=姓名, [13]=身份证)."""
    cells = [""] * 22
    cells[7] = status_text
    cells[8] = "DA-001"
    cells[9] = "张三"
    cells[10] = "男"
    cells[11] = "1980-01-01"
    cells[12] = "45"
    cells[13] = SFZH
    cell_xml = "".join("<cell>%s</cell>" % x for x in cells)
    row = '<row id="%s" contract_code="%s">%s</row>' % (PID, CC, cell_xml)
    return "<rows>%s</rows>@@1" % row


class _State:
    """每个 server 实例共享的状态机."""
    def __init__(self, flip_after=1):
        self.status = "居民申请"
        self.archive_posts = 0
        self.flip_after = flip_after          # 提交档案 N 次后翻成已签约 (0=永不翻)
        self.requests = []                    # (method, path, body_form)


def make_handler(state):
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _send(self, body, ctype="text/html; charset=utf-8", code=200):
            data = body.encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self):
            if "/Sys_JCWS/B0101/Pg_Edit_B0101.aspx" in self.path:
                state.requests.append(("GET", self.path, {}))
                html = (
                    '<form><input type="text" name="GUID" value="%s">'
                    '<input type="text" name="SFZH" value="%s">'
                    '<input type="text" name="XM" value="张三">'
                    '</form>' % (PID, SFZH)
                )
                self._send(html)
            else:
                self._send("ok")

        def do_POST(self):
            length = int(self.headers.get("Content-Length", 0))
            raw = self.rfile.read(length).decode("utf-8", "replace") if length else ""
            form = {k: v[0] for k, v in parse_qs(raw).items()}
            state.requests.append(("POST", self.path, form))

            if "/Sys_JCWS/b0105/Do_B0105_Handler.ashx" in self.path:
                # 查询接口 (action=4)
                self._send(grid_xml(state.status))
            elif "/Sys_JCWS/B0101/Do_B0101_Handler.ashx" in self.path:
                # 档案修改 (ACTION=2): 计数并可能翻状态
                state.archive_posts += 1
                if state.flip_after and state.archive_posts >= state.flip_after:
                    state.status = "已签约"
                self._send('{"opType":0,"msg":"修改成功"}',
                           ctype="application/json")
            else:
                self._send('{"opType":0}', ctype="application/json")
    return H


class ServerBase(unittest.TestCase):
    flip_after = 1

    def setUp(self):
        self.state = _State(flip_after=self.flip_after)
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(self.state))
        self.port = self.httpd.server_address[1]
        self.t = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.t.start()

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


class TestStatusOverWire(ServerBase):
    def test_check_status_real_request(self):
        code, text, pid, cc = self.c.check_sign_status_by_sfzh(SFZH)
        self.assertEqual(text, "居民申请")
        self.assertEqual(code, "6")
        self.assertEqual(pid, PID)
        # 确认真的发出了 action=4 的查询, 且 SFZH 在 POST body 里
        q = [r for r in self.state.requests
             if r[0] == "POST" and "Do_B0105_Handler" in r[1]]
        self.assertTrue(q)
        self.assertEqual(q[0][2].get("SFZH"), SFZH)
        self.assertEqual(q[0][2].get("ISDAZT"), "0")


class TestFinalizePromotes(ServerBase):
    flip_after = 1

    def test_promotes_over_wire(self):
        r = self.c.finalize_via_archive(
            PID, sfzh=SFZH, name="张三", max_retries=3,
            _sleep=lambda *_: None,
        )
        self.assertTrue(r.success)
        self.assertEqual(r.step, "finalize_verified")
        # 必须真的加载过档案 (GET Pg_Edit) 并提交过 ACTION=2
        self.assertTrue(any(
            r2[0] == "GET" and "Pg_Edit_B0101" in r2[1]
            for r2 in self.state.requests
        ))
        posts = [r2 for r2 in self.state.requests
                 if r2[0] == "POST" and "Do_B0101_Handler" in r2[1]]
        self.assertTrue(posts)
        self.assertEqual(posts[0][2].get("ACTION"), "2")


class TestFinalizeNeverPromotes(ServerBase):
    flip_after = 0  # 永不翻

    def test_honest_failure_over_wire(self):
        r = self.c.finalize_via_archive(
            PID, sfzh=SFZH, name="张三", max_retries=3,
            _sleep=lambda *_: None,
        )
        self.assertFalse(r.success)          # 绝不误报
        self.assertEqual(r.step, "finalize")
        self.assertIn("居民申请", r.error)
        # 应当尝试了 3 次档案提交
        posts = [r2 for r2 in self.state.requests
                 if r2[0] == "POST" and "Do_B0101_Handler" in r2[1]]
        self.assertEqual(len(posts), 3)


class TestSignOneVerifyOverWire(ServerBase):
    flip_after = 0  # confirm 后真实状态仍是居民申请

    def test_confirm_false_positive_downgraded(self):
        # 伪造 confirm 成功 (只 mock confirm/initiate, 状态查询走真服务器)
        from unittest.mock import MagicMock
        self.c.initiate_signing = MagicMock(
            return_value=SignResult(True, PID, "张三", contract_code=CC)
        )
        self.c.confirm_signing = MagicMock(
            return_value=SignResult(True, PID, "张三", contract_code=CC,
                                    step="confirm")
        )
        r = self.c.sign_one(
            PID, name="张三", sfzh=SFZH,
            verify_final=True, finalize_archive=False, delay=0,
        )
        self.assertFalse(r.success)          # 真服务器说还没签约 -> 诚实改判
        self.assertEqual(r.step, "verify_failed")


class TestSignOneFinalizeOverWire(ServerBase):
    flip_after = 1  # 提交一次档案即落库

    def test_confirm_then_finalize_succeeds(self):
        from unittest.mock import MagicMock
        self.c.initiate_signing = MagicMock(
            return_value=SignResult(True, PID, "张三", contract_code=CC)
        )
        self.c.confirm_signing = MagicMock(
            return_value=SignResult(True, PID, "张三", contract_code=CC,
                                    step="confirm")
        )
        r = self.c.sign_one(
            PID, name="张三", sfzh=SFZH,
            verify_final=True, finalize_archive=True, delay=0,
        )
        self.assertTrue(r.success)
        self.assertEqual(r.step, "finalized_via_archive")


if __name__ == "__main__":
    unittest.main(verbosity=2)
