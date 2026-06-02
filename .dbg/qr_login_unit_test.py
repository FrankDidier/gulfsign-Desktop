# -*- coding: utf-8 -*-
"""单元测试: 二维码登录 API 方法 (真实流程: Pg_ScanQrCode.aspx + ACTION=CHECKSM).

验证:
  1. ``qr_login_generate`` 从 Pg_ScanQrCode.aspx 页面 HTML 抽取内嵌二维码图像.
  2. ``qr_login_generate`` 在页面无二维码 / HTTP 错误时返回 (False, '', '', error).
  3. ``qr_login_query`` 解析 ACTION=CHECKSM 的 opType: 0→通过(0), 1→等待(2).
  4. ``qr_login_query`` 在网络/解析异常时返回 code=-1.
  5. ``qr_login_finalize`` 在主页拉取成功后把 logged_in=True, qr_pending=False.
  6. ``qr_login_finalize`` 在拉取失败 / 缺 token 时返回 (False, ...).
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from ph3_api import PH3Client  # noqa: E402


def _fresh_client() -> PH3Client:
    c = PH3Client()
    c.base_url = "https://example.invalid"
    c.session = MagicMock()
    return c


class _FakeResp:
    def __init__(self, status_code=200, json_obj=None, text=""):
        self.status_code = status_code
        self._obj = json_obj
        self.text = text

    def json(self):
        if self._obj is None:
            raise ValueError("not json")
        return self._obj


class TestQrGenerate(unittest.TestCase):

    def test_success(self):
        c = _fresh_client()
        html = (
            '<html><body><div style="text-align:center">'
            '<img src="data:image/jpg;base64,/9j/4AAQSkZJRgABAQ_FAKE">'
            '</div></body></html>'
        )
        c.session.get = MagicMock(return_value=_FakeResp(text=html))
        ok, img, tok, err = c.qr_login_generate()
        self.assertTrue(ok, err)
        self.assertIn("data:image/jpg;base64,", img)
        self.assertEqual(tok, "session")  # 占位符, CHECKSM 用会话 cookie
        self.assertEqual(err, "")

    def test_no_qr_image(self):
        c = _fresh_client()
        c.session.get = MagicMock(return_value=_FakeResp(
            text="<html><body>无二维码</body></html>"
        ))
        ok, img, tok, err = c.qr_login_generate()
        self.assertFalse(ok)
        self.assertIn("二维码", err)

    def test_http_error(self):
        c = _fresh_client()
        c.session.get = MagicMock(return_value=_FakeResp(status_code=500, text="x"))
        ok, img, tok, err = c.qr_login_generate()
        self.assertFalse(ok)
        self.assertIn("HTTP 500", err)

    def test_no_session(self):
        c = PH3Client()
        ok, img, tok, err = c.qr_login_generate()
        self.assertFalse(ok)
        self.assertIn("尚未发起", err)


class TestQrQuery(unittest.TestCase):

    def test_optype_0_passed(self):
        c = _fresh_client()
        c.session.get = MagicMock(return_value=_FakeResp(json_obj={"opType": 0}))
        code, msg = c.qr_login_query()
        self.assertEqual(code, 0)

    def test_optype_1_waiting(self):
        c = _fresh_client()
        c.session.get = MagicMock(return_value=_FakeResp(json_obj={"opType": 1, "msg": ""}))
        code, msg = c.qr_login_query()
        self.assertEqual(code, 2)  # 等待扫码

    def test_network_err(self):
        c = _fresh_client()
        import requests
        c.session.get = MagicMock(side_effect=requests.ConnectionError("boom"))
        code, msg = c.qr_login_query()
        self.assertEqual(code, -1)
        self.assertIn("网络", msg)

    def test_non_json(self):
        c = _fresh_client()
        c.session.get = MagicMock(return_value=_FakeResp(
            json_obj=None, text="<html>err</html>"
        ))
        code, msg = c.qr_login_query()
        self.assertEqual(code, -1)

    def test_no_session(self):
        c = PH3Client()
        code, msg = c.qr_login_query()
        self.assertEqual(code, -1)


class TestQrFinalize(unittest.TestCase):

    def test_success(self):
        c = _fresh_client()
        # FormMain.aspx returns valid HTML with token_en (32 hex) + token_th (64 hex)
        # 与 _extract_tokens 里的正则一致: var en = '...', var th = '...'
        en32 = "0123456789abcdef0123456789abcdef"
        th64 = "0123456789abcdef" * 4
        html = (
            'var en = "%s"\n'
            'var th = "%s"\n' % (en32, th64)
        )
        c.session.get = MagicMock(return_value=_FakeResp(
            json_obj=None, text=html,
        ))
        # get_org_tree 调用网络, 这里 mock 成空避免拖慢测试
        c.get_org_tree = MagicMock(return_value=[])

        ok, info = c.qr_login_finalize()
        self.assertTrue(ok, "expected success but got: " + info)
        self.assertTrue(c.logged_in)
        self.assertFalse(c.qr_pending)
        self.assertEqual(c.token_en, en32)
        self.assertEqual(c.token_th, th64)

    def test_no_session(self):
        c = PH3Client()
        ok, info = c.qr_login_finalize()
        self.assertFalse(ok)
        self.assertIn("尚未发起", info)

    def test_main_page_fail(self):
        c = _fresh_client()
        c.session.get = MagicMock(return_value=_FakeResp(
            status_code=500, text="boom"
        ))
        ok, info = c.qr_login_finalize()
        self.assertFalse(ok)
        self.assertIn("HTTP 500", info)


if __name__ == "__main__":
    unittest.main(verbosity=2)
