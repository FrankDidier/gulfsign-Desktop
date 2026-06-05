# -*- coding: utf-8 -*-
"""户主代申请 (process_household) 单元测试.

用 FakeHC 模拟健康卡平台, 验证 SigningEngine.process_household 的:
  - 自动拉取户主名下全部成员卡 (newlist) 并逐人签约
  - 全程使用同一个户主 openid (关键: 不给成员逐人绑卡/换号)
  - 聚合统计 (succeeded / confirmed / created / already_signed / failed)
  - relation_filter 过滤
  - 未连接 / 空户 / 部分失败 等边界
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from hc_api import HealthCard, HCContract, HCConfirmResult  # noqa: E402
from sign_engine import SigningEngine  # noqa: E402


HEAD_OPENID = "openid-HEAD-户主"


class FakeHC:
    """模拟一个户主 openid 名下的家庭: 记录每张卡的状态, 并断言 openid 不变。"""

    def __init__(self, cards, statuses=None, create_fails=None,
                 confirm_fails=None):
        self.connected = True
        self.openid = HEAD_OPENID
        self._cards = cards
        # health_card_id -> CONTRACT_STATES ("1"未签 / "5"/"6"待确认 / "0"已签)
        self._status = dict(statuses or {})
        self._create_fails = set(create_fails or [])
        self._confirm_fails = set(confirm_fails or [])
        # 审计: 每次调用用到的 openid, 用于断言"户主代申请全程同一 openid"
        self.openids_used = []
        self.created = []
        self.confirmed = []

    # --- list ---
    def get_card_list(self):
        return list(self._cards)

    # --- per card flow ---
    def update_rpc(self, health_card_id):
        return True, "已完成"

    def query_signing_info(self, health_card_id):
        st = self._status.get(health_card_id, "1")
        return {
            "GUID": "PID-" + health_card_id,
            "CONTRACT_STATES": st,
            "gdjgcode": "ORG1",
        }

    def query_contracts(self, person_id, health_card_id):
        st = self._status.get(health_card_id, "1")
        if st in ("5", "6"):
            return [HCContract(
                guid="G-" + health_card_id, person_id=person_id,
                health_card_id=health_card_id, orgcode="ORG1", status=st,
            )]
        return []

    def get_person_guid(self, health_card_id):
        return "PID-" + health_card_id

    def create_resident_contract(self, **kw):
        # 关键断言: 居民申请用的是户主 openid
        self.openids_used.append(("create", self.openid))
        hcid = kw["health_card_id"]
        if hcid in self._create_fails:
            return False, "模拟创建失败"
        self._status[hcid] = "6"
        self.created.append(hcid)
        return True, "居民申请创建成功"

    def confirm_one(self, contract):
        self.openids_used.append(("confirm", self.openid))
        if contract.health_card_id in self._confirm_fails:
            return HCConfirmResult(False, name=contract.name,
                                   health_card_id=contract.health_card_id,
                                   error="模拟确认失败")
        self._status[contract.health_card_id] = "0"
        self.confirmed.append(contract.health_card_id)
        return HCConfirmResult(True, name=contract.name,
                               health_card_id=contract.health_card_id)


def _household():
    """一户 4 口: 户主(成年,已签) + 老人(未签) + 未成年(未签) + 配偶(待确认6)。"""
    return [
        HealthCard("HC-HEAD", "张三", "430000199001011234", age="36",
                   rpc="1", relation="本人"),
        HealthCard("HC-OLD", "张老", "430000195001011234", age="76",
                   rpc="0", relation="父母"),
        HealthCard("HC-KID", "张小", "430000201501011234", age="11",
                   rpc="0", relation="子女"),
        HealthCard("HC-SPOUSE", "李四", "430000199203034567", age="34",
                   rpc="1", relation="配偶"),
    ]


class TestProcessHousehold(unittest.TestCase):

    def _engine(self, **kw):
        hc = FakeHC(**kw)
        return SigningEngine(hc), hc

    def test_full_household_all_processed_same_openid(self):
        eng, hc = self._engine(
            cards=_household(),
            statuses={"HC-HEAD": "0", "HC-OLD": "1", "HC-KID": "1",
                      "HC-SPOUSE": "6"},
        )
        s = eng.process_household(
            orgcode="ORG1", team_guid="T1", team_name="团队",
            package_guids="P1", package_names="包", doctor_name="医生",
            delay=0,
        )
        self.assertEqual(s.total, 4)
        self.assertEqual(s.failed, 0)
        self.assertTrue(s.success)
        # 户主已签 -> already_signed; 老人/小孩 -> create+confirm; 配偶 -> confirm
        self.assertEqual(s.already_signed, 1)
        self.assertEqual(s.created, 2)
        self.assertEqual(s.confirmed, 3)  # OLD, KID, SPOUSE
        # 关键: 所有 create/confirm 都用户主 openid
        self.assertTrue(hc.openids_used)
        for _kind, oid in hc.openids_used:
            self.assertEqual(oid, HEAD_OPENID)

    def test_head_name_detected(self):
        eng, hc = self._engine(
            cards=_household(),
            statuses={"HC-HEAD": "0", "HC-OLD": "1", "HC-KID": "1",
                      "HC-SPOUSE": "6"},
        )
        s = eng.process_household(orgcode="ORG1", team_guid="T1",
                                  package_guids="P1", delay=0)
        self.assertEqual(s.head_name, "张三")

    def test_relation_filter_minors_and_elderly_only(self):
        eng, hc = self._engine(
            cards=_household(),
            statuses={"HC-HEAD": "0", "HC-OLD": "1", "HC-KID": "1",
                      "HC-SPOUSE": "6"},
        )
        # 只签未成年/老人 (免人脸人群)
        def only_no_face(card):
            return card.relation in ("父母", "子女")
        s = eng.process_household(
            orgcode="ORG1", team_guid="T1", package_guids="P1",
            relation_filter=only_no_face, delay=0,
        )
        self.assertEqual(s.total, 2)
        self.assertEqual(s.confirmed, 2)
        self.assertEqual(s.failed, 0)

    def test_partial_failure_counts(self):
        eng, hc = self._engine(
            cards=_household(),
            statuses={"HC-HEAD": "1", "HC-OLD": "1", "HC-KID": "1",
                      "HC-SPOUSE": "6"},
            confirm_fails={"HC-SPOUSE"},
        )
        s = eng.process_household(orgcode="ORG1", team_guid="T1",
                                  package_guids="P1", delay=0)
        self.assertEqual(s.total, 4)
        self.assertEqual(s.failed, 1)         # SPOUSE confirm fails
        self.assertFalse(s.success)           # 有失败 -> 整户不算全绿
        self.assertEqual(s.confirmed, 3)      # HEAD, OLD, KID

    def test_create_failure_is_failure(self):
        eng, hc = self._engine(
            cards=_household(),
            statuses={"HC-HEAD": "1", "HC-OLD": "1", "HC-KID": "1",
                      "HC-SPOUSE": "1"},
            create_fails={"HC-KID"},
        )
        s = eng.process_household(orgcode="ORG1", team_guid="T1",
                                  package_guids="P1", delay=0)
        self.assertEqual(s.failed, 1)
        self.assertFalse(s.success)

    def test_not_connected(self):
        hc = FakeHC(cards=_household())
        hc.connected = False
        eng = SigningEngine(hc)
        s = eng.process_household(orgcode="ORG1", team_guid="T1",
                                  package_guids="P1", delay=0)
        self.assertFalse(s.success)
        self.assertIn("未连接", s.error)
        self.assertEqual(s.total, 0)

    def test_empty_household(self):
        eng, hc = self._engine(cards=[])
        s = eng.process_household(orgcode="ORG1", team_guid="T1",
                                  package_guids="P1", delay=0)
        self.assertFalse(s.success)
        self.assertIn("未查到任何健康卡", s.error)

    def test_explicit_members_override(self):
        eng, hc = self._engine(
            cards=_household(),
            statuses={"HC-KID": "1"},
        )
        only_kid = [c for c in _household() if c.health_card_id == "HC-KID"]
        s = eng.process_household(orgcode="ORG1", team_guid="T1",
                                  package_guids="P1", members=only_kid,
                                  delay=0)
        self.assertEqual(s.total, 1)
        self.assertEqual(s.confirmed, 1)

    def test_stop_check_aborts(self):
        eng, hc = self._engine(
            cards=_household(),
            statuses={"HC-HEAD": "1", "HC-OLD": "1", "HC-KID": "1",
                      "HC-SPOUSE": "1"},
        )
        calls = {"n": 0}

        def stop():
            calls["n"] += 1
            return calls["n"] > 2  # 处理 2 人后中止

        s = eng.process_household(orgcode="ORG1", team_guid="T1",
                                  package_guids="P1", stop_check=stop,
                                  delay=0)
        self.assertLessEqual(len(s.results), 4)
        self.assertGreaterEqual(len(s.results), 1)

    def test_list_household_members(self):
        eng, hc = self._engine(cards=_household())
        members = eng.list_household_members()
        self.assertEqual(len(members), 4)
        names = {m.name for m in members}
        self.assertIn("张三", names)
        self.assertIn("张小", names)


if __name__ == "__main__":
    unittest.main(verbosity=2)
