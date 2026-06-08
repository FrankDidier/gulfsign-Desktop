# -*- coding: utf-8 -*-
"""hc_diagnostics 单元测试: 脱敏 / 快照 / 前后对比。"""
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import hc_diagnostics as d  # noqa: E402


class FakeClient:
    """模拟一个已连接的 HealthCardClient (只实现快照需要的接口)。"""

    def __init__(self, cards, status_by_hcid):
        self.connected = True
        self.openid = "openid-HEAD-XYZ123"
        self.jwt_token = "jwt"
        self._timeout = 5
        self._cards = cards
        self._status = status_by_hcid

    def _svc_url(self):
        return "http://x/svc"

    def _jkxb_url(self):
        return "http://x/jkxb"

    def _jkxb_headers(self):
        return {}

    def get_card_list(self):
        from hc_api import HealthCard
        return [HealthCard(**c) for c in self._cards]

    # capture_snapshot 调 client.session.get -> 我们直接 monkeypatch _get_json
    @property
    def session(self):
        raise AssertionError("不应直接用 session (测试已 patch _get_json)")


class TestMask(unittest.TestCase):
    def test_mask_idcard_by_key(self):
        m = d.mask_obj({"idCard": "430000199001011234", "name": "张三"})
        self.assertTrue(m["idCard"].startswith("430"))
        self.assertIn("*", m["idCard"])
        self.assertTrue(m["idCard"].endswith("1234"))
        self.assertEqual(m["name"], "张三")

    def test_mask_idlike_value(self):
        m = d.mask_obj({"GUID": "430000199001011234"})
        self.assertIn("*", m["GUID"])

    def test_mask_keeps_short_values(self):
        m = d.mask_obj({"status": "1", "rpc": "0"})
        self.assertEqual(m["status"], "1")
        self.assertEqual(m["rpc"], "0")

    def test_mask_disabled(self):
        m = d.mask_obj({"idCard": "430000199001011234"}, enable=False)
        self.assertEqual(m["idCard"], "430000199001011234")


class TestSnapshot(unittest.TestCase):
    def setUp(self):
        self._orig = d._get_json

    def tearDown(self):
        d._get_json = self._orig

    def test_capture_builds_entries(self):
        cards = [
            {"health_card_id": "HC1", "name": "张老", "id_card": "x",
             "age": "76", "rpc": "0", "relation": "父母"},
        ]
        status = {"HC1": "1"}

        def fake_get(client, url, params):
            action = params.get("action") or params.get("ACTION")
            if action == "newlist":
                return {"http": 200, "json": {"errno": 0, "data": "..."}}
            if action == "querybyidcardqyjg":
                hcid = params["healthCardId"]
                return {"http": 200, "json": {"errno": 0, "data": [
                    {"GUID": "P-" + hcid,
                     "CONTRACT_STATES": status.get(hcid, "1")}]}}
            if action == "queryqyxxall":
                return {"http": 200, "json": {"errno": 0, "data": []}}
            return {"http": 200, "json": {}}

        d._get_json = fake_get
        client = FakeClient(cards, status)
        snap = d.capture_snapshot(client, raw=False)
        self.assertEqual(len(snap["cards"]), 1)
        e = snap["cards"][0]
        self.assertEqual(e["healthCardId"], "HC1")
        self.assertEqual(e["person_id"], "P-HC1")
        self.assertIn("signing_info_raw", e)
        self.assertIn("contracts_raw", e)

    def test_capture_requires_connection(self):
        client = FakeClient([], {})
        client.connected = False
        with self.assertRaises(RuntimeError):
            d.capture_snapshot(client)


class TestDiff(unittest.TestCase):
    def _snap(self, ts, cards):
        return {"ts": ts, "cards": cards}

    def test_detects_new_card_and_status(self):
        before = self._snap("t0", [{
            "healthCardId": "HC1", "name": "张老", "rpc": "0",
            "signing_info_raw": {"json": {"data": [
                {"GUID": "P1", "CONTRACT_STATES": "1"}]}}}])
        after = self._snap("t1", [
            {"healthCardId": "HC1", "name": "张老", "rpc": "1",
             "signing_info_raw": {"json": {"data": [
                 {"GUID": "P1", "CONTRACT_STATES": "0"}]}}},
            {"healthCardId": "HC2", "name": "张小", "rpc": "1",
             "signing_info_raw": {"json": {"data": [
                 {"GUID": "P2", "CONTRACT_STATES": "0"}]}}}])
        lines, summary = d.diff_snapshots(before, after)
        txt = "\n".join(lines)
        self.assertEqual(summary["added_cards"], 1)
        self.assertGreaterEqual(summary["status_changes"], 2)  # rpc + states
        self.assertIn("★状态", txt)
        self.assertIn("新增的卡", txt)

    def test_no_change(self):
        snap = self._snap("t0", [{"healthCardId": "HC1", "name": "A", "rpc": "1"}])
        lines, summary = d.diff_snapshots(snap, snap)
        self.assertEqual(summary["added_cards"], 0)
        self.assertEqual(summary["status_changes"], 0)
        self.assertIn("无任何变化", "\n".join(lines))

    def test_removed_card(self):
        before = self._snap("t0", [
            {"healthCardId": "HC1", "name": "A", "rpc": "1"},
            {"healthCardId": "HC2", "name": "B", "rpc": "1"}])
        after = self._snap("t1", [{"healthCardId": "HC1", "name": "A", "rpc": "1"}])
        lines, summary = d.diff_snapshots(before, after)
        self.assertEqual(summary["removed_cards"], 1)
        self.assertIn("消失的卡", "\n".join(lines))


if __name__ == "__main__":
    unittest.main(verbosity=2)
