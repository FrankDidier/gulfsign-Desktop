# -*- coding: utf-8 -*-
"""单元测试: direct_sign.SignTemplate / proxy_capture 签约抓包."""
import json
import os
import sys
import tempfile
import unittest
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from direct_sign import (
    SignTemplate, DirectSignResult, list_captures,
    load_latest, batch_replay, DEFAULT_CAPTURE_DIR,
)


# ---------------------------------------------------------------------
# Fixture: 一个仿真的 sign_capture JSON, 模拟 [家医签约] POST 模板
# ---------------------------------------------------------------------
SAMPLE_CAPTURE = {
    "timestamp": "2026-05-31 19:01:23.456",
    "host": "ggws.hnhfpc.gov.cn",
    "method": "POST",
    "path": "/Sys_JCWS/B0105/Do_B0105_Handler.ashx",
    "query": {"ACTION": "10"},
    "action": "10",
    "headers": {
        "Content-Type": "application/x-www-form-urlencoded",
        "X-Requested-With": "XMLHttpRequest",
        "Cookie": "ASP.NET_SessionId=expired_old_cookie",
        "Referer": "https://ggws.hnhfpc.gov.cn/Sys_JCWS/B0105/Pg_Insert_B0105.aspx",
    },
    "body_form": {
        "ACTION": "10",
        "RKBM": "431122198001011234",  # 老身份证 — 应被替换
        "DABH": "431122198001011234",  # 同上
        "XM": "张三",                   # 老姓名 — 可被替换
        "QYTD": "TEAM-A",
        "QYYS": "李医生",
        "QYRQ": "20260531",
        "FWLX": "0",
        "SBDW": "431122000",
    },
    "body_text": "ACTION=10&RKBM=...",
}


class TestSignTemplate(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False, encoding="utf-8",
        )
        json.dump(SAMPLE_CAPTURE, self.tmp, ensure_ascii=False)
        self.tmp.close()

    def tearDown(self):
        try:
            os.unlink(self.tmp.name)
        except OSError:
            pass

    def test_from_capture_extracts_personid(self):
        tpl = SignTemplate.from_capture(self.tmp.name)
        self.assertEqual(tpl.captured_person_id, "431122198001011234")
        self.assertEqual(tpl.captured_name, "张三")
        self.assertEqual(tpl.action, "10")
        self.assertEqual(tpl.host, "ggws.hnhfpc.gov.cn")

    def test_likely_personid_fields_finds_both(self):
        tpl = SignTemplate.from_capture(self.tmp.name)
        fields = tpl.likely_personid_fields()
        self.assertIn("RKBM", fields)
        self.assertIn("DABH", fields)
        self.assertEqual(len(fields), 2)

    def test_build_form_replaces_personid(self):
        tpl = SignTemplate.from_capture(self.tmp.name)
        new_form = tpl.build_form_for("431122199009098765", "李四")
        self.assertEqual(new_form["RKBM"], "431122199009098765")
        self.assertEqual(new_form["DABH"], "431122199009098765")
        self.assertEqual(new_form["XM"], "李四")
        # 不该改的: ACTION/QYTD/QYYS 等
        self.assertEqual(new_form["ACTION"], "10")
        self.assertEqual(new_form["QYTD"], "TEAM-A")
        self.assertEqual(new_form["QYYS"], "李医生")

    def test_build_form_keeps_name_when_not_provided(self):
        tpl = SignTemplate.from_capture(self.tmp.name)
        new_form = tpl.build_form_for("431122199009098765")  # 不传 name
        self.assertEqual(new_form["RKBM"], "431122199009098765")
        # XM 字段应保留原名 (不是""也不是新 person_id)
        self.assertEqual(new_form["XM"], "张三")

    def test_build_form_extra_overrides(self):
        tpl = SignTemplate.from_capture(self.tmp.name)
        new_form = tpl.build_form_for(
            "431122199009098765",
            extra_overrides={"QYTD": "TEAM-B", "QYYS": "王医生"},
        )
        self.assertEqual(new_form["QYTD"], "TEAM-B")
        self.assertEqual(new_form["QYYS"], "王医生")

    def test_summary_string(self):
        tpl = SignTemplate.from_capture(self.tmp.name)
        s = tpl.summary()
        self.assertIn("ggws.hnhfpc.gov.cn", s)
        self.assertIn("ACTION=10", s)
        self.assertIn("431122198001011234", s)


class TestSignTemplateGuid(unittest.TestCase):
    """captured_person_id 应支持 GUID 形式 (如果服务器用 GUID 而非身份证)."""

    def test_guid_detection(self):
        cap = dict(SAMPLE_CAPTURE)
        cap["body_form"] = {
            "ACTION": "10",
            "GUID": "abc12345-6789-4def-9012-3456789abcde",
            "RKBM": "abc12345-6789-4def-9012-3456789abcde",
        }
        tpl = SignTemplate.from_dict(cap)
        self.assertEqual(
            tpl.captured_person_id,
            "abc12345-6789-4def-9012-3456789abcde",
        )
        fields = tpl.likely_personid_fields()
        self.assertIn("GUID", fields)
        self.assertIn("RKBM", fields)


class TestReplayFor(unittest.TestCase):
    """replay_for 必须验证 logged_in/qr_pending/org_code 等前置."""

    def setUp(self):
        self.tpl = SignTemplate.from_dict(SAMPLE_CAPTURE)

    def _mk_client(
        self, logged_in=True, qr_pending=False, org_code="431122000",
        base_url="https://ggws.hnhfpc.gov.cn",
        response_text='{"opType":0,"type":"CONTRACT-NEW-001"}',
        status_code=200,
    ):
        client = MagicMock()
        client.logged_in = logged_in
        client.qr_pending = qr_pending
        client.org_code = org_code
        client.base_url = base_url
        client._timeout = 10
        resp = MagicMock()
        resp.status_code = status_code
        resp.text = response_text
        client.session.post.return_value = resp
        return client

    def test_blocked_when_not_logged_in(self):
        c = self._mk_client(logged_in=False)
        r = self.tpl.replay_for(c, "431122199009098765")
        self.assertFalse(r.success)
        self.assertIn("未登录", r.error)
        c.session.post.assert_not_called()

    def test_blocked_when_qr_pending(self):
        c = self._mk_client(qr_pending=True)
        r = self.tpl.replay_for(c, "431122199009098765")
        self.assertFalse(r.success)
        self.assertIn("二维码", r.error)
        c.session.post.assert_not_called()

    def test_blocked_when_no_orgcode(self):
        c = self._mk_client(org_code="")
        r = self.tpl.replay_for(c, "431122199009098765")
        self.assertFalse(r.success)
        self.assertIn("机构代码", r.error)
        c.session.post.assert_not_called()

    def test_blocked_when_no_personid(self):
        c = self._mk_client()
        r = self.tpl.replay_for(c, "")
        self.assertFalse(r.success)
        self.assertIn("person_id", r.error)
        c.session.post.assert_not_called()

    def test_blocked_when_template_has_no_captured_personid(self):
        cap = dict(SAMPLE_CAPTURE)
        cap["body_form"] = {"ACTION": "10", "QYTD": "T1"}
        tpl = SignTemplate.from_dict(cap)
        c = self._mk_client()
        r = tpl.replay_for(c, "431122199009098765")
        self.assertFalse(r.success)
        self.assertIn("captured_person_id", r.error)
        c.session.post.assert_not_called()

    def test_success_replay_replaces_fields(self):
        c = self._mk_client()
        r = self.tpl.replay_for(c, "431122199009098765", "李四")
        self.assertTrue(r.success)
        self.assertEqual(r.contract_code, "CONTRACT-NEW-001")
        self.assertEqual(r.op_type, 0)
        # 检查 POST 被调用且 body 已替换
        c.session.post.assert_called_once()
        kwargs = c.session.post.call_args.kwargs
        body = kwargs["data"]
        self.assertEqual(body["RKBM"], "431122199009098765")
        self.assertEqual(body["DABH"], "431122199009098765")
        self.assertEqual(body["XM"], "李四")

    def test_success_replay_strips_unsafe_headers(self):
        """应丢弃 captured 的 Cookie 头, 让 client.session 自动加 fresh cookie."""
        c = self._mk_client()
        self.tpl.replay_for(c, "431122199009098765")
        kwargs = c.session.post.call_args.kwargs
        sent_headers = kwargs.get("headers", {})
        self.assertNotIn("Cookie", sent_headers)
        # 但 Content-Type / X-Requested-With 应保留
        self.assertIn("Content-Type", sent_headers)

    def test_failure_optype_nonzero(self):
        c = self._mk_client(
            response_text='{"opType":1,"msg":"该居民已签约"}',
        )
        r = self.tpl.replay_for(c, "431122199009098765")
        self.assertFalse(r.success)
        self.assertEqual(r.op_type, 1)
        self.assertIn("已签约", r.error)

    def test_failure_http_500(self):
        c = self._mk_client(status_code=500, response_text="server error")
        r = self.tpl.replay_for(c, "431122199009098765")
        self.assertFalse(r.success)
        self.assertIn("HTTP 500", r.error)

    def test_failure_non_json_response_extracts_contract(self):
        c = self._mk_client(
            response_text='<html>contract_code = "abc12345-6789-4def-9012-3456789abcde"</html>',
        )
        r = self.tpl.replay_for(c, "431122199009098765")
        self.assertTrue(r.success)
        self.assertEqual(r.contract_code, "abc12345-6789-4def-9012-3456789abcde")

    def test_failure_non_json_no_contract(self):
        c = self._mk_client(response_text="<html>error page</html>")
        r = self.tpl.replay_for(c, "431122199009098765")
        self.assertFalse(r.success)
        self.assertIn("非 JSON", r.error)

    def test_network_exception_handled(self):
        c = self._mk_client()
        c.session.post.side_effect = Exception("connection reset")
        r = self.tpl.replay_for(c, "431122199009098765")
        self.assertFalse(r.success)
        self.assertIn("网络异常", r.error)


class TestCaptureStorage(unittest.TestCase):

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def _write(self, name, obj):
        fp = os.path.join(self.tmpdir, name)
        with open(fp, "w", encoding="utf-8") as f:
            json.dump(obj, f, ensure_ascii=False)
        return fp

    def test_list_captures_filters_and_sorts(self):
        f1 = self._write("sign_001.json", SAMPLE_CAPTURE)
        f2 = self._write("sign_002.json", SAMPLE_CAPTURE)
        self._write("not_a_sign.json", SAMPLE_CAPTURE)
        # 让 f2 更新
        os.utime(f1, (1000, 1000))
        os.utime(f2, (2000, 2000))
        files = list_captures(self.tmpdir)
        self.assertEqual(len(files), 2)
        # 按 mtime 降序
        self.assertEqual(files[0], f2)
        self.assertEqual(files[1], f1)

    def test_load_latest_empty(self):
        self.assertIsNone(load_latest(self.tmpdir))

    def test_load_latest_returns_template(self):
        self._write("sign_x.json", SAMPLE_CAPTURE)
        tpl = load_latest(self.tmpdir)
        self.assertIsNotNone(tpl)
        self.assertEqual(tpl.action, "10")


class TestBatchReplay(unittest.TestCase):

    def test_batch_replay_calls_replay_for_each(self):
        tpl = SignTemplate.from_dict(SAMPLE_CAPTURE)
        client = MagicMock()
        client.logged_in = True
        client.qr_pending = False
        client.org_code = "431122000"
        client.base_url = "https://ggws.hnhfpc.gov.cn"
        client._timeout = 10
        resp_ok = MagicMock(status_code=200, text='{"opType":0,"type":"C-1"}')
        client.session.post.return_value = resp_ok

        ids = ["431122199001011111", "431122199002022222", "431122199003033333"]
        results = batch_replay(client, tpl, ids, delay=0)
        self.assertEqual(len(results), 3)
        self.assertTrue(all(r.success for r in results))
        self.assertEqual(client.session.post.call_count, 3)


# ---------------------------------------------------------------------
# proxy_capture: _maybe_capture_sign_request 路径匹配 + JSON 落盘
# ---------------------------------------------------------------------
from proxy_capture import OpenIDProxy, SIGN_CAPTURE_PATH_PATTERNS


class TestProxyCaptureSignRequest(unittest.TestCase):

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.captured_records = []
        self.proxy = OpenIDProxy(
            port=0,
            on_sign_captured=lambda r: self.captured_records.append(r),
            sign_capture_dir=self.tmpdir,
        )

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def _post_bytes(self, path, body, host="ggws.hnhfpc.gov.cn"):
        return (
            ("POST %s HTTP/1.1\r\n" % path).encode() +
            ("Host: %s\r\n" % host).encode() +
            b"Content-Type: application/x-www-form-urlencoded\r\n"
            b"X-Requested-With: XMLHttpRequest\r\n"
            b"\r\n" +
            body.encode("utf-8")
        )

    def test_b0105_post_captured(self):
        data = self._post_bytes(
            "/Sys_JCWS/B0105/Do_B0105_Handler.ashx?ACTION=10",
            "ACTION=10&RKBM=431122198001011234&XM=%E5%BC%A0%E4%B8%89&QYTD=T1",
        )
        self.proxy._log_traffic("ggws.hnhfpc.gov.cn", ">>> REQUEST", data)
        self.assertEqual(len(self.captured_records), 1)
        rec = self.captured_records[0]
        self.assertEqual(rec["action"], "10")
        self.assertEqual(rec["body_form"]["RKBM"], "431122198001011234")
        # 落盘
        self.assertTrue(os.path.exists(rec["_saved_to"]))

    def test_get_request_not_captured(self):
        data = (
            b"GET /Sys_JCWS/B0105/Do_B0105_Handler.ashx?ACTION=Q HTTP/1.1\r\n"
            b"Host: ggws.hnhfpc.gov.cn\r\n\r\n"
        )
        self.proxy._log_traffic("ggws.hnhfpc.gov.cn", ">>> REQUEST", data)
        self.assertEqual(len(self.captured_records), 0)

    def test_unrelated_post_not_captured(self):
        data = self._post_bytes(
            "/Sys_JCWS/B0888/Do_Other.ashx",
            "foo=bar",
        )
        self.proxy._log_traffic("ggws.hnhfpc.gov.cn", ">>> REQUEST", data)
        self.assertEqual(len(self.captured_records), 0)

    def test_jkda_query_not_captured(self):
        """JKDA 是只读查询, 不应被当作签约 POST."""
        data = self._post_bytes(
            "/Sys_JCWS/JKDA/Do_Query_Handler.ashx",
            "RKBM=xxx",
        )
        self.proxy._log_traffic("ggws.hnhfpc.gov.cn", ">>> REQUEST", data)
        self.assertEqual(len(self.captured_records), 0)

    def test_response_direction_not_captured(self):
        data = self._post_bytes(
            "/Sys_JCWS/B0105/Do_B0105_Handler.ashx?ACTION=10",
            "ACTION=10&RKBM=431122198001011234",
        )
        self.proxy._log_traffic("ggws.hnhfpc.gov.cn", "<<< RESPONSE", data)
        self.assertEqual(len(self.captured_records), 0)

    def test_non_ggws_host_not_captured(self):
        data = self._post_bytes(
            "/Sys_JCWS/B0105/Do_B0105_Handler.ashx?ACTION=10",
            "ACTION=10&RKBM=431122198001011234",
        )
        self.proxy._log_traffic("jkk.hnhfpc.gov.cn", ">>> REQUEST", data)
        self.assertEqual(len(self.captured_records), 0)

    def test_b0107_post_captured(self):
        data = self._post_bytes(
            "/Sys_JCWS/B0107/Do_B0107_Handler.ashx?ACTION=20",
            "ACTION=20&team=T1",
        )
        self.proxy._log_traffic("ggws.hnhfpc.gov.cn", ">>> REQUEST", data)
        self.assertEqual(len(self.captured_records), 1)
        self.assertEqual(self.captured_records[0]["action"], "20")

    def test_path_pattern_count(self):
        # 健全性: 我们至少匹配 3 个签约相关 handler
        self.assertGreaterEqual(len(SIGN_CAPTURE_PATH_PATTERNS), 3)


if __name__ == "__main__":
    unittest.main(verbosity=2)
