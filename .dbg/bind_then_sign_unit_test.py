#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""bind_then_sign 单元测试 (mock HealthCardClient, 不联网)。

验证免人脸人群 (<18/>60) 自动绑卡→签约 的编排逻辑与各类守卫:
  - 年龄门槛: 18-60 直接拒 (需人脸); <18/>60 放行
  - 缺 Wechatcode / 身份证非 18 位 → 明确失败, 不调注册
  - 绑卡失败 → 透传错误
  - 绑卡成功 → 复用 process_card_full 完成 create+confirm
"""
import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from hc_api import HealthCard, HCContract, HCConfirmResult  # noqa: E402
from sign_engine import SigningEngine, calc_id_check_digit  # noqa: E402


def _mk_id(birth: str) -> str:
    base = "110101" + birth + "001"  # 6 region + 8 birth + 3 seq = 17
    return base + calc_id_check_digit(base)


MINOR = _mk_id("20150305")   # ~11 岁
ELDER = _mk_id("19500305")   # ~76 岁
ADULT = _mk_id("19900305")   # ~36 岁


class FakeHC:
    """最小可用的健康卡客户端替身, 驱动 process_card_full 的成功路径。"""

    def __init__(self, register_ok=True, register_msg="ok"):
        self.connected = True
        self.register_ok = register_ok
        self.register_msg = register_msg
        self.register_calls = []
        self._created = False

    def register_health_card(self, wechatcode, id_card, name,
                             phone="", nation="01", relation="本人",
                             **kw):
        self.register_calls.append({
            "wechatcode": wechatcode, "id_card": id_card,
            "name": name, "relation": relation,
        })
        return self.register_ok, self.register_msg

    def get_card_list(self):
        # 绑卡后才出现该卡; rpc=1 以跳过 updateRpc
        return [HealthCard(health_card_id="HCID1", name="张三",
                           id_card=MINOR, age="11", rpc="1")]

    def update_rpc(self, hcid):
        return True, "已完成"

    def query_signing_info(self, hcid):
        # 未签约 (status=1) → 触发 auto_create
        return {"GUID": "PID1", "CONTRACT_STATES": "1", "gdjgcode": "ORG1"}

    def get_person_guid(self, hcid):
        return "PID1"

    def query_contracts(self, person_id, hcid):
        if not self._created:
            return []
        return [HCContract(guid="G1", person_id=person_id,
                           health_card_id=hcid, orgcode="ORG1", status="6")]

    def create_resident_contract(self, **kw):
        self._created = True
        return True, "居民申请创建成功"

    def confirm_one(self, contract):
        return HCConfirmResult(True, name=contract.name,
                               health_card_id=contract.health_card_id)


class TestBindThenSign(unittest.TestCase):

    def _engine(self, **kw):
        return SigningEngine(FakeHC(**kw))

    def test_minor_full_success(self):
        eng = self._engine()
        r = eng.bind_then_sign(
            name="张三", id_card=MINOR, orgcode="ORG1", wechatcode="WC1",
            team_guid="TG", package_guids="PG", doctor_name="李医生",
        )
        self.assertTrue(r.success, r.error)
        self.assertTrue(r.contract_confirmed)
        self.assertEqual(eng.hc.register_calls[0]["wechatcode"], "WC1")

    def test_elder_allowed(self):
        eng = self._engine()
        # 老人用同样替身 (卡列表返回 MINOR 身份证, 但匹配按姓名+尾号; 这里
        # 仅验证 >60 不被人脸门槛拦下 → 会进入绑卡)
        r = eng.bind_then_sign(
            name="张三", id_card=ELDER, orgcode="ORG1", wechatcode="WC1",
            team_guid="TG", package_guids="PG",
        )
        # 进入了绑卡 (注册被调用)
        self.assertEqual(len(eng.hc.register_calls), 1)

    def test_adult_blocked_needs_face(self):
        eng = self._engine()
        r = eng.bind_then_sign(
            name="张三", id_card=ADULT, orgcode="ORG1", wechatcode="WC1",
        )
        self.assertFalse(r.success)
        self.assertEqual(r.step, "bind_needs_face")
        self.assertEqual(len(eng.hc.register_calls), 0)  # 不应尝试绑卡

    def test_missing_wechatcode(self):
        eng = self._engine()
        r = eng.bind_then_sign(
            name="张三", id_card=MINOR, orgcode="ORG1", wechatcode="",
        )
        self.assertFalse(r.success)
        self.assertEqual(r.step, "bind_no_wechatcode")
        self.assertEqual(len(eng.hc.register_calls), 0)

    def test_bad_idcard(self):
        eng = self._engine()
        r = eng.bind_then_sign(
            name="张三", id_card="123", orgcode="ORG1", wechatcode="WC1",
        )
        self.assertFalse(r.success)
        self.assertEqual(r.step, "bind_input")

    def test_register_failure_propagates(self):
        eng = self._engine(register_ok=False, register_msg="微信身份码不存在")
        r = eng.bind_then_sign(
            name="张三", id_card=MINOR, orgcode="ORG1", wechatcode="WC1",
        )
        self.assertFalse(r.success)
        self.assertEqual(r.step, "bind")
        self.assertIn("微信身份码不存在", r.error)


if __name__ == "__main__":
    unittest.main(verbosity=2)
