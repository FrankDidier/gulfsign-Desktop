# -*- coding: utf-8 -*-
"""端到端功能测试: 完整签约生命周期, 打真实本地 HTTP 服务器, 不 mock 任何 API 方法.

补齐 finalize_functional_test 未覆盖的"真实"链路:
  - initiate_signing  真发 GET Pg_Insert + POST ACTION=1 (含表单抓取/团队/服务包)
  - confirm_signing   真发 ACTION=9 (status=6 接受 / status=5 拒绝)
  - delete_signing / void_signing  真发 ACTION=3 / ACTION=11
  - query_patients    真解析多状态网格
  - sign_one          真 initiate + 真 confirm, 走完整状态机, 不 mock

服务端用 SM4 解密客户端发来的 GUID 还原 person_id —— 顺带验证真实加解密往返.
档案推进机制 (B0101 ACTION=2) 只对"居民申请(6)"放行翻成"已签约(0)",
对"医生申请(5)"不放行 -> 验证 finalize 对 5 的诚实失败.
"""
import json
import os
import sys
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from ph3_api import PH3Client, SignResult  # noqa: E402
from gmssl.sm4 import CryptSM4, SM4_DECRYPT  # noqa: E402

TOKEN_EN = "0123456789abcdef0123456789abcdef"  # 32 chars, 与生产同长度
TOKEN_TH = "0" * 64
ORG = "431122000"

STATUS_TEXT = {"0": "已签约", "1": "未签约", "4": "拒绝签约",
               "5": "医生申请", "6": "居民申请"}


def sm4_decrypt_field(cipher_hex):
    """crptosEn 的逆运算: SM4-ECB 解密 -> ascii(hex) -> utf-8 明文."""
    sm4 = CryptSM4()
    sm4.set_key(TOKEN_EN.encode("ascii"), SM4_DECRYPT)
    raw = sm4.crypt_ecb(bytes.fromhex(cipher_hex))
    hex_ascii = raw.decode("ascii")
    return bytes.fromhex(hex_ascii).decode("utf-8")


def person_id_from_guid(cipher_hex):
    """GUID = crptosEn(person_id + '|' + ts) -> 取 '|' 前段."""
    return sm4_decrypt_field(cipher_hex).split("|")[0]


class World:
    """共享状态机: person_id -> dict(name, sfzh, status, cc)."""

    def __init__(self):
        self.people = {}
        self.requests = []
        self._cc_seq = 0

    def add(self, pid, name, sfzh, status="1", cc=""):
        self.people[pid] = {"name": name, "sfzh": sfzh, "status": status, "cc": cc}

    def new_cc(self):
        self._cc_seq += 1
        # 36 位 uuid 样式, 让 initiate 的 JSON type 字段像真合同号
        return "00000000-0000-0000-0000-%012d" % self._cc_seq

    def by_cc(self, cc):
        for pid, p in self.people.items():
            if p["cc"] == cc:
                return pid, p
        return None, None

    def grid(self, sfzh_filter=""):
        rows = []
        n = 0
        for pid, p in self.people.items():
            if sfzh_filter and p["sfzh"] != sfzh_filter:
                continue
            n += 1
            cells = [""] * 22
            cells[7] = STATUS_TEXT.get(p["status"], "未签约")
            cells[8] = "DA-" + pid
            cells[9] = p["name"]
            cells[10] = "男"
            cells[11] = "1980-01-01"
            cells[12] = "45"
            cells[13] = p["sfzh"]
            cells[14] = "某地址"
            cells[16] = "团队A"
            cells[18] = "王医生"
            cell_xml = "".join("<cell>%s</cell>" % c for c in cells)
            rows.append('<row id="%s" contract_code="%s">%s</row>'
                        % (pid, p["cc"], cell_xml))
        return "<rows>%s</rows>@@%d" % ("".join(rows), n)


def make_handler(world):
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

        # ---- GET ----
        def do_GET(self):
            u = urlparse(self.path)
            q = {k: v[0] for k, v in parse_qs(u.query).items()}
            world.requests.append(("GET", u.path, q))
            action = q.get("ACTION") or q.get("action") or ""

            if "/B0105/Pg_Insert_B0105.aspx" in u.path:
                return self._insert_form(q)
            if "/B0101/Pg_Edit_B0101.aspx" in u.path:
                return self._edit_form(q)
            if "Do_B0105_Handler.ashx" in u.path:
                if action == "3":   # delete
                    return self._delete(q.get("GUID", ""))
                if action == "11":  # void
                    return self._void(q.get("GUID", ""))
                if action == "8":   # service packs (有时走 GET)
                    return self._service_packs()
            self._send("ok")

        # ---- POST ----
        def do_POST(self):
            u = urlparse(self.path)
            qp = {k: v[0] for k, v in parse_qs(u.query).items()}
            length = int(self.headers.get("Content-Length", 0))
            raw = self.rfile.read(length).decode("utf-8", "replace") if length else ""
            form = {k: v[0] for k, v in parse_qs(raw).items()}
            world.requests.append(("POST", u.path, form))
            action = (qp.get("ACTION") or qp.get("action")
                      or form.get("ACTION") or form.get("action") or "")

            if "Do_B0105_Handler.ashx" in u.path.lower() or \
               "do_b0105_handler.ashx" in u.path.lower():
                if action == "4":
                    return self._send(world.grid(form.get("SFZH", "")))
                if action == "8":
                    return self._service_packs()
                if action == "1":
                    return self._initiate(form)
                if action == "9":
                    return self._confirm(form)
                if action == "10":
                    return self._send('{"opType":0,"msg":"批量发起"}',
                                      ctype="application/json")
            if "Do_B0101_Handler.ashx" in u.path:
                return self._modify_archive(form)
            self._send('{"opType":0}', ctype="application/json")

        # ---- handlers ----
        def _insert_form(self, q):
            try:
                pid = person_id_from_guid(q.get("GUID", ""))
            except Exception:
                pid = ""
            p = world.people.get(pid, {"name": "未知"})
            html = (
                '<form>'
                '<input type="text" name="XM" value="%s">'
                '<input type="hidden" name="PERSONID" value="%s">'
                '<input type="text" name="SBR" value="王医生">'
                '<input type="text" name="XGDW" value="%s">'
                '<script>$("#QYTD").drawMultipleTree({zNodes: '
                '[{"id":"T1","name":"团队A"}],});</script>'
                '</form>' % (p["name"], pid, ORG)
            )
            self._send(html)

        def _edit_form(self, q):
            try:
                pid = person_id_from_guid(q.get("GUID", ""))
            except Exception:
                pid = ""
            p = world.people.get(pid, {"name": "未知", "sfzh": ""})
            html = (
                '<form>'
                '<input type="text" name="GUID" value="%s">'
                '<input type="text" name="SFZH" value="%s">'
                '<input type="text" name="XM" value="%s">'
                '</form>' % (pid, p["sfzh"], p["name"])
            )
            self._send(html)

        def _service_packs(self):
            self._send(json.dumps(
                {"B0110": [{"GUID": "FWB-1", "B0110_01": "基础服务包"}]}),
                ctype="application/json")

        def _initiate(self, form):
            pid = form.get("PERSONID", "")
            p = world.people.get(pid)
            if not p:
                return self._send('{"opType":1,"msg":"无此人"}',
                                  ctype="application/json")
            if p["status"] == "0":
                return self._send('{"opType":1,"msg":"已签约"}',
                                  ctype="application/json")
            cc = world.new_cc()
            p["status"] = "5"   # 医生端发起一律 STATUS=5
            p["cc"] = cc
            self._send('{"opType":0,"type":"%s"}' % cc, ctype="application/json")

        def _confirm(self, form):
            cc = form.get("GUID", "")
            pid, p = world.by_cc(cc)
            if not p:
                return self._send('{"opType":1,"msg":"无此合同"}',
                                  ctype="application/json")
            if p["status"] == "6":
                p["status"] = "0"   # 居民申请 -> 确认 -> 已签约
                return self._send('{"opType":0}', ctype="application/json")
            # status=5 (医生申请) 确认被拒
            self._send('{"opType":1,"msg":"该类型不能处理"}',
                       ctype="application/json")

        def _delete(self, cc):
            pid, p = world.by_cc(cc)
            if p:
                p["status"] = "1"
                p["cc"] = ""
            self._send('{"opType":0}', ctype="application/json")

        def _void(self, cc):
            pid, p = world.by_cc(cc)
            if p and p["status"] == "0":
                p["status"] = "1"
                p["cc"] = ""
                return self._send('{"opType":0}', ctype="application/json")
            self._send('{"opType":1,"msg":"非已签约不可作废"}',
                       ctype="application/json")

        def _modify_archive(self, form):
            pid = form.get("GUID", "")
            p = world.people.get(pid)
            # 档案重提交: 只对"居民申请(6)"放行翻成已签约 (对标竞品机制)
            if p and p["status"] == "6":
                p["status"] = "0"
            self._send('{"opType":0,"msg":"修改成功"}', ctype="application/json")

    return H


class FlowBase(unittest.TestCase):
    def setUp(self):
        self.world = World()
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(self.world))
        self.port = self.httpd.server_address[1]
        self.t = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.t.start()

        c = PH3Client()
        c.logged_in = True
        c.qr_pending = False
        c.org_code = ORG
        c.doctor_name = "王医生"
        c.team_name = "团队A"
        c.token_en = TOKEN_EN
        c.token_th = TOKEN_TH
        c.base_url = "http://127.0.0.1:%d" % self.port
        c._timeout = 5
        self.c = c

    def tearDown(self):
        self.httpd.shutdown()
        self.httpd.server_close()


class TestCryptoRoundTrip(FlowBase):
    def test_guid_decrypts(self):
        from ph3_api import PH3Crypto
        enc = PH3Crypto.crptosEn("PID-7|123", TOKEN_EN)
        self.assertEqual(person_id_from_guid(enc), "PID-7")


class TestQuery(FlowBase):
    def test_query_all_statuses(self):
        self.world.add("P1", "甲", "430000199001011111", status="1")
        self.world.add("P5", "乙", "430000199002022222", status="5", cc="C5")
        self.world.add("P6", "丙", "430000199003033333", status="6", cc="C6")
        self.world.add("P0", "丁", "430000199004044444", status="0", cc="C0")
        pts, total = self.c.query_patients()
        self.assertEqual(total, 4)
        by_id = {p.person_id: p for p in pts}
        self.assertEqual(by_id["P5"].contract_status, "5")
        self.assertEqual(by_id["P6"].status_text, "居民申请")
        self.assertEqual(by_id["P0"].contract_status, "0")
        self.assertEqual(by_id["P6"].id_card, "430000199003033333")

    def test_status_filter_by_sfzh(self):
        self.world.add("P6", "丙", "430000199003033333", status="6", cc="C6")
        self.world.add("P0", "丁", "430000199004044444", status="0", cc="C0")
        code, text, pid, cc = self.c.check_sign_status_by_sfzh("430000199003033333")
        self.assertEqual(code, "6")
        self.assertEqual(text, "居民申请")
        self.assertEqual(pid, "P6")
        self.assertEqual(cc, "C6")

    def test_status_unknown_person_returns_empty(self):
        code, text, pid, cc = self.c.check_sign_status_by_sfzh("430000190001019999")
        self.assertEqual((code, text, pid, cc), ("", "", "", ""))


class TestInitiateReal(FlowBase):
    def test_initiate_creates_status5(self):
        self.world.add("PNEW", "新人", "430000199005055555", status="1")
        r = self.c.initiate_signing("PNEW")
        self.assertTrue(r.success, r.error)
        self.assertTrue(r.contract_code)
        self.assertEqual(r.name, "新人")
        self.assertEqual(self.world.people["PNEW"]["status"], "5")
        # 真发了 GET 表单 + POST ACTION=1
        self.assertTrue(any(m == "GET" and "Pg_Insert_B0105" in p
                            for m, p, _ in self.world.requests))
        post1 = [f for m, p, f in self.world.requests
                 if m == "POST" and f.get("ACTION") == "1"]
        self.assertTrue(post1)
        self.assertEqual(post1[0].get("QYTD"), "T1")          # 团队解析成功
        self.assertEqual(post1[0].get("FWBLIST"), "FWB-1")    # 服务包解析成功

    def test_initiate_rejected_when_already_signed(self):
        self.world.add("PS", "已签", "430000199006066666", status="0", cc="C0")
        r = self.c.initiate_signing("PS")
        self.assertFalse(r.success)


class TestConfirmReal(FlowBase):
    def test_confirm_resident_application_succeeds(self):
        self.world.add("P6", "居民", "430000199003033333", status="6", cc="C6")
        r = self.c.confirm_signing("P6", "C6", "居民")
        self.assertTrue(r.success, r.error)
        self.assertEqual(self.world.people["P6"]["status"], "0")

    def test_confirm_doctor_application_rejected(self):
        self.world.add("P5", "医生申请", "430000199002022222", status="5", cc="C5")
        r = self.c.confirm_signing("P5", "C5", "医生申请")
        self.assertFalse(r.success)
        self.assertIn("该类型不能处理", r.error)


class TestDeleteVoidReal(FlowBase):
    def test_delete_status5(self):
        self.world.add("P5", "医申", "430000199002022222", status="5", cc="C5")
        self.assertTrue(self.c.delete_signing("C5"))
        self.assertEqual(self.world.people["P5"]["status"], "1")

    def test_void_status0(self):
        self.world.add("P0", "已签", "430000199004044444", status="0", cc="C0")
        self.assertTrue(self.c.void_signing("C0"))
        self.assertEqual(self.world.people["P0"]["status"], "1")

    def test_void_non_signed_fails(self):
        self.world.add("P5", "医申", "430000199002022222", status="5", cc="C5")
        self.assertFalse(self.c.void_signing("C5"))


class TestSignOneRealNoMock(FlowBase):
    def test_initiate_then_verify_real_status_is_5_downgraded(self):
        # 全程不 mock: initiate 发起 -> 服务端置 5 -> sign_one 自动尝试 confirm(5->0)
        # -> 服务端按规则 B 拒绝("该类型不能处理") -> 诚实失败. 这正是报告里
        # "医生端只能产生 5, 5->0 不可达" 的真实复现.
        self.world.add("PNEW", "新人", "430000199005055555", status="1")
        r = self.c.sign_one(
            "PNEW", name="新人", sfzh="430000199005055555",
            verify_final=True, finalize_archive=False, delay=0,
        )
        self.assertTrue(r.contract_code)
        self.assertFalse(r.success)              # 真实仅 5, 绝不报成功
        self.assertEqual(r.step, "confirm")      # confirm 被拒, 原样失败

    def test_initiate_then_finalize_on_status5_honest_failure(self):
        # status=5 档案重提交不放行 -> finalize 诚实失败, 不误报
        self.world.add("PNEW", "新人", "430000199005055555", status="1")
        r = self.c.sign_one(
            "PNEW", name="新人", sfzh="430000199005055555",
            verify_final=True, finalize_archive=True, finalize_retries=2,
            delay=0,
        )
        self.assertFalse(r.success)
        self.assertEqual(r.step, "verify_failed")  # 档案推进对 5 无效, 诚实判负

    def test_resident_app_confirm_then_verified_signed(self):
        # 居民申请(6): 真 confirm -> 真实翻 0 -> verify 通过
        self.world.add("P6", "居民", "430000199003033333", status="6", cc="C6")
        r = self.c.sign_one(
            "P6", name="居民", contract_status="6", contract_code="C6",
            sfzh="430000199003033333", verify_final=True, delay=0,
        )
        self.assertTrue(r.success, r.error)
        self.assertEqual(r.step, "verified_signed")
        self.assertEqual(self.world.people["P6"]["status"], "0")

    def test_resident_app_confirm_then_finalize_via_archive(self):
        # 居民申请: confirm 失败场景靠 finalize 推进? 这里 confirm 成功即 0,
        # 用一个 confirm 不翻、靠档案推进的人验证 finalize 落库.
        # 制造: status=6 但 confirm 接口此人被特殊处理 -> 用档案推进路径.
        # 简化为: 直接验证 finalize_via_archive 对 6 放行.
        self.world.add("P6", "居民", "430000199003033333", status="6", cc="C6")
        r = self.c.finalize_via_archive(
            "P6", sfzh="430000199003033333", name="居民",
            max_retries=3, _sleep=lambda *_: None,
        )
        self.assertTrue(r.success, r.error)
        self.assertEqual(r.step, "finalize_verified")
        self.assertEqual(self.world.people["P6"]["status"], "0")


if __name__ == "__main__":
    unittest.main(verbosity=2)
