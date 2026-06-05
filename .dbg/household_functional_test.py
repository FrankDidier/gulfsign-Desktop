# -*- coding: utf-8 -*-
"""户主代申请 端到端功能测试 (真 socket, 不 mock 客户端方法).

起一个【有状态】的仿真健康卡平台, 用真实的 HealthCardClient + SigningEngine
跑 process_household, 验证:

  1. newlist 返回的"一户家庭成员"全部被逐人处理;
  2. 每一次 insertJtysqy(建居民申请) 与 editqr(确认) 都真的发出 HTTP 请求,
     且 **携带的 openid 始终是户主 openid** (户主代申请的本质);
  3. 仿真服务端按真实语义推进状态: 未签(1) → 居民申请(6) → 已签约(0);
  4. 户主本人若早已是已签约(0) 则跳过, 不重复签;
  5. 全程同一个 JWT / 同一个 openid, 不需要为成员逐人换号或绑卡.
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
from sign_engine import SigningEngine  # noqa: E402


HEAD_OPENID = "openid-HEAD-户主-XYZ"


def fake_jwt():
    header = base64.urlsafe_b64encode(b'{"alg":"HS256"}').decode().rstrip("=")
    body = base64.urlsafe_b64encode(
        json.dumps({"exp": int(time.time()) + 3600}).encode()
    ).decode().rstrip("=")
    return "%s.%s.sig" % (header, body)


def parse_multipart_fields(raw: bytes, content_type: str) -> dict:
    """极简 multipart/form-data 解析, 仅取 name->value (够测试用)。"""
    fields = {}
    if "boundary=" not in content_type:
        return fields
    boundary = content_type.split("boundary=", 1)[1].strip()
    sep = ("--" + boundary).encode()
    for part in raw.split(sep):
        if b'name="' not in part:
            continue
        try:
            head, _, value = part.partition(b"\r\n\r\n")
            name = head.split(b'name="', 1)[1].split(b'"', 1)[0].decode()
            val = value.rsplit(b"\r\n", 1)[0].decode("utf-8", "replace")
            fields[name] = val
        except Exception:
            continue
    return fields


class HouseholdState:
    """仿真平台状态: 一户家庭 + 每张卡的签约状态。"""

    def __init__(self):
        # healthCardId -> 卡信息
        self.cards = [
            {"healthCardId": "HC-HEAD", "name": "张三",
             "idCard": "430000199001011234", "age": "36", "rpc": "1",
             "relation": "本人"},
            {"healthCardId": "HC-OLD", "name": "张老",
             "idCard": "430000195001011234", "age": "76", "rpc": "0",
             "relation": "父母"},
            {"healthCardId": "HC-KID", "name": "张小",
             "idCard": "430000201501011234", "age": "11", "rpc": "0",
             "relation": "子女"},
        ]
        # healthCardId -> CONTRACT_STATES
        self.status = {"HC-HEAD": "0", "HC-OLD": "1", "HC-KID": "1"}
        # 审计: 关键接口收到的 openid
        self.insert_openids = []
        self.editqr_openids = []
        self.rpc_calls = []
        # guid -> healthCardId
        self.contracts = {}

    def person_id(self, hcid):
        return "PID-" + hcid


def make_handler(state: HouseholdState):
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _json(self, obj, code=200):
            data = json.dumps(obj).encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def _body(self):
            n = int(self.headers.get("Content-Length", 0) or 0)
            return self.rfile.read(n) if n else b""

        def _route(self):
            u = urlparse(self.path)
            q = {k: v[0] for k, v in parse_qs(u.query).items()}
            action = q.get("ACTION") or q.get("action") or ""

            # multipart POST body fields (insertJtysqy)
            fields = {}
            if self.command == "POST":
                raw = self._body()
                fields = parse_multipart_fields(
                    raw, self.headers.get("Content-Type", ""))
                if not action:
                    action = fields.get("ACTION", "")

            if action == "getToken":
                return self._json({"errno": 0, "data": {"token": fake_jwt()}})

            if action == "newlist":
                return self._json({"errno": 0, "data": state.cards})

            if action == "updateRpc":
                state.rpc_calls.append(q.get("healthCardId"))
                return self._json({"errno": 0, "message": "操作已完成"})

            if action == "querybyidcardqyjg":
                hcid = q.get("healthCardId", "")
                return self._json({"errno": 0, "data": [{
                    "GUID": state.person_id(hcid),
                    "CONTRACT_STATES": state.status.get(hcid, "1"),
                    "gdjgcode": "ORG1",
                }]})

            if action == "queryqyxxall":
                hcid = q.get("healthCardId", "")
                st = state.status.get(hcid, "1")
                rows = []
                if st in ("5", "6"):
                    rows.append({
                        "guid": "G-" + hcid, "jgbm": "ORG1", "jgmc": "机构",
                        "qyzfbs": st, "qyys": "医生",
                    })
                return self._json({"errno": 0, "data": rows})

            if action == "insertJtysqy":
                # 关键: 记录建合同用的 openid
                oid = fields.get("openid", "")
                hcid = fields.get("healthCardId", "")
                state.insert_openids.append(oid)
                state.status[hcid] = "6"
                state.contracts["G-" + hcid] = hcid
                return self._json({"errno": 0, "data": "ok"})

            if action == "editqr":
                # 关键: 记录确认用的 openid
                oid = q.get("openid", "")
                guid = q.get("guid", "")
                state.editqr_openids.append(oid)
                hcid = state.contracts.get(guid) or q.get("healthCardId", "")
                state.status[hcid] = "0"
                return self._json({"errno": 0, "data": "confirmed"})

            return self._json({"errno": 0})

        do_GET = _route
        do_POST = _route

    return H


class TestHouseholdEndToEnd(unittest.TestCase):
    def setUp(self):
        self.state = HouseholdState()
        self.httpd = ThreadingHTTPServer(
            ("127.0.0.1", 0), make_handler(self.state))
        self.port = self.httpd.server_address[1]
        self.t = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.t.start()
        self.hc = HealthCardClient(base_url="http://127.0.0.1:%d" % self.port)
        self.hc._timeout = 5
        ok, _ = self.hc.connect(HEAD_OPENID)
        self.assertTrue(ok)
        self.eng = SigningEngine(self.hc)

    def tearDown(self):
        self.httpd.shutdown()
        self.httpd.server_close()

    def test_household_signs_all_members_with_head_openid(self):
        s = self.eng.process_household(
            orgcode="ORG1", team_guid="T1", team_name="家医团队",
            package_guids="P1", package_names="基础包", doctor_name="王医生",
            delay=0,
        )

        # 3 口人全部处理
        self.assertEqual(s.total, 3, s.error)
        self.assertEqual(s.failed, 0)
        self.assertTrue(s.success)
        self.assertEqual(s.head_name, "张三")

        # 户主已签约 -> 跳过; 老人/小孩 -> 新建居民申请 + 确认
        self.assertEqual(s.already_signed, 1)
        self.assertEqual(s.created, 2)
        self.assertEqual(s.confirmed, 2)

        # 关键断言: 所有 insertJtysqy / editqr 都携带户主 openid
        self.assertEqual(len(self.state.insert_openids), 2)
        self.assertEqual(len(self.state.editqr_openids), 2)
        for oid in self.state.insert_openids + self.state.editqr_openids:
            self.assertEqual(oid, HEAD_OPENID)

        # 仿真服务端状态真的被推进到已签约
        self.assertEqual(self.state.status["HC-OLD"], "0")
        self.assertEqual(self.state.status["HC-KID"], "0")

        # 未实名/未绑卡的成员未被逐人换号 — 全程同一 openid
        self.assertEqual(self.hc.openid, HEAD_OPENID)

    def test_filter_no_face_only(self):
        # 只签免人脸人群 (老人/小孩), 跳过成年户主本人
        def no_face(card):
            try:
                a = int(card.age)
            except Exception:
                return False
            return a < 18 or a >= 60

        s = self.eng.process_household(
            orgcode="ORG1", team_guid="T1", package_guids="P1",
            relation_filter=no_face, delay=0,
        )
        self.assertEqual(s.total, 2)
        self.assertEqual(s.confirmed, 2)
        self.assertEqual(s.failed, 0)
        for oid in self.state.insert_openids + self.state.editqr_openids:
            self.assertEqual(oid, HEAD_OPENID)


if __name__ == "__main__":
    unittest.main(verbosity=2)
