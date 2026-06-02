# -*- coding: utf-8 -*-
"""健康卡客户端功能 + 对抗测试: 打真实本地 HTTP 服务器, 验证加固后的诚实判定.

重点验证 (审计发现的高危点已修复):
  - update_rpc: 不再仅凭 message 含"已完成"就算成功; errno!=0 必判失败
  - connect:    data.data.token 缺失/非 dict -> 失败, 不崩
  - get_card_list: data 非 list / 含非 dict 项 -> 不崩
  - query_signing_info: data 是 list / dict / 空 -> 不崩
"""
import base64
import json
import os
import sys
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from hc_api import HealthCardClient  # noqa: E402


def fake_jwt():
    header = base64.urlsafe_b64encode(b'{"alg":"HS256"}').decode().rstrip("=")
    body = base64.urlsafe_b64encode(
        json.dumps({"exp": int(time.time()) + 3600}).encode()
    ).decode().rstrip("=")
    return "%s.%s.sig" % (header, body)


# 每个测试用 responses dict 决定各 ACTION 返回什么 (body, ctype)
class _Resp:
    current = {}


def make_handler():
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _send(self, body, ctype="application/json", code=200):
            data = body.encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", ctype + "; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def _handle(self):
            u = urlparse(self.path)
            q = {k: v[0] for k, v in parse_qs(u.query).items()}
            action = q.get("ACTION") or q.get("action") or "_default"
            body, ctype, code = _Resp.current.get(
                action, ('{"errno":0}', "application/json", 200))
            self._send(body, ctype, code)

        do_GET = _handle
        do_POST = _handle

    return H


class HCBase(unittest.TestCase):
    def setUp(self):
        _Resp.current = {}
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), make_handler())
        self.port = self.httpd.server_address[1]
        self.t = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.t.start()
        self.c = HealthCardClient(base_url="http://127.0.0.1:%d" % self.port)
        self.c._timeout = 5

    def tearDown(self):
        self.httpd.shutdown()
        self.httpd.server_close()

    def set(self, action, body, ctype="application/json", code=200):
        _Resp.current[action] = (body, ctype, code)


class TestConnect(HCBase):
    def test_connect_ok(self):
        self.set("getToken", json.dumps(
            {"errno": 0, "data": {"token": fake_jwt()}}))
        ok, msg = self.c.connect("openid-1")
        self.assertTrue(ok, msg)
        self.assertTrue(self.c.connected)
        self.assertTrue(self.c.jwt_token)

    def test_connect_errno_fail(self):
        self.set("getToken", json.dumps({"errno": 1, "message": "openid无效"}))
        ok, msg = self.c.connect("openid-x")
        self.assertFalse(ok)
        self.assertIn("openid无效", msg)

    def test_connect_missing_token_no_crash(self):
        self.set("getToken", json.dumps({"errno": 0, "data": {}}))
        ok, msg = self.c.connect("openid-2")
        self.assertFalse(ok)
        self.assertIn("token", msg)

    def test_connect_data_not_dict_no_crash(self):
        self.set("getToken", json.dumps({"errno": 0, "data": "oops"}))
        ok, msg = self.c.connect("openid-3")
        self.assertFalse(ok)

    def test_connect_html_no_crash(self):
        self.set("getToken", "<html>502</html>", ctype="text/html")
        ok, msg = self.c.connect("openid-4")
        self.assertFalse(ok)


class TestUpdateRpc(HCBase):
    def _connect(self):
        self.set("getToken", json.dumps(
            {"errno": 0, "data": {"token": fake_jwt()}}))
        self.c.connect("openid-1")

    def test_rpc_errno0_success(self):
        self._connect()
        self.set("updateRpc", json.dumps({"errno": 0, "message": "操作已完成"}))
        ok, msg = self.c.update_rpc("HC1")
        self.assertTrue(ok)

    def test_rpc_errno_nonzero_but_message_says_done_is_FAILURE(self):
        # 关键加固点: 之前 "已完成" 子串就算成功 -> 误报. 现在 errno!=0 必判失败.
        self._connect()
        self.set("updateRpc", json.dumps(
            {"errno": 9, "message": "系统异常: 上一步已完成但本次失败"}))
        ok, msg = self.c.update_rpc("HC1")
        self.assertFalse(ok)

    def test_rpc_no_errno_fallback_to_message(self):
        # 响应没有 errno 字段时, 回退到 message 含"已完成"
        self._connect()
        self.set("updateRpc", json.dumps({"message": "已完成"}))
        ok, msg = self.c.update_rpc("HC1")
        self.assertTrue(ok)

    def test_rpc_html_no_crash(self):
        self._connect()
        self.set("updateRpc", "<html>500</html>", ctype="text/html")
        ok, msg = self.c.update_rpc("HC1")
        self.assertFalse(ok)


class TestCardList(HCBase):
    def _connect(self):
        self.set("getToken", json.dumps(
            {"errno": 0, "data": {"token": fake_jwt()}}))
        self.c.connect("openid-1")

    def test_list_ok(self):
        self._connect()
        self.set("newlist", json.dumps({"errno": 0, "data": [
            {"healthCardId": "HC1", "name": "张三", "idCard": "x", "rpc": "0"},
            {"healthCardId": "HC2", "name": "李四", "idCard": "y", "rpc": "1"},
        ]}))
        cards = self.c.get_card_list()
        self.assertEqual(len(cards), 2)
        self.assertEqual(cards[1].name, "李四")
        self.assertTrue(cards[1].is_verified)

    def test_list_data_not_list_no_crash(self):
        self._connect()
        self.set("newlist", json.dumps({"errno": 0, "data": {"x": 1}}))
        self.assertEqual(self.c.get_card_list(), [])

    def test_list_mixed_items_skips_non_dict(self):
        self._connect()
        self.set("newlist", json.dumps({"errno": 0, "data": [
            {"healthCardId": "HC1", "name": "张三"}, "garbage", 123,
        ]}))
        cards = self.c.get_card_list()
        self.assertEqual(len(cards), 1)

    def test_list_errno_fail(self):
        self._connect()
        self.set("newlist", json.dumps({"errno": 5, "message": "token过期"}))
        self.assertEqual(self.c.get_card_list(), [])

    def test_list_html_no_crash(self):
        self._connect()
        self.set("newlist", "<html>err</html>", ctype="text/html")
        self.assertEqual(self.c.get_card_list(), [])


class TestQuerySigning(HCBase):
    def _connect(self):
        self.set("getToken", json.dumps(
            {"errno": 0, "data": {"token": fake_jwt()}}))
        self.c.connect("openid-1")

    def test_data_is_list(self):
        self._connect()
        self.set("querybyidcardqyjg", json.dumps(
            {"errno": 0, "data": [{"status": "5", "name": "张三"}]}))
        info = self.c.query_signing_info("HC1")
        self.assertIsInstance(info, dict)
        self.assertEqual(info["status"], "5")

    def test_data_is_dict(self):
        self._connect()
        self.set("querybyidcardqyjg", json.dumps(
            {"errno": 0, "data": {"status": "6"}}))
        info = self.c.query_signing_info("HC1")
        self.assertEqual(info["status"], "6")

    def test_data_empty_list_returns_none(self):
        self._connect()
        self.set("querybyidcardqyjg", json.dumps({"errno": 0, "data": []}))
        self.assertIsNone(self.c.query_signing_info("HC1"))

    def test_errno_fail_returns_none(self):
        self._connect()
        self.set("querybyidcardqyjg", json.dumps({"errno": 1}))
        self.assertIsNone(self.c.query_signing_info("HC1"))

    def test_html_no_crash(self):
        self._connect()
        self.set("querybyidcardqyjg", "<html>x</html>", ctype="text/html")
        self.assertIsNone(self.c.query_signing_info("HC1"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
