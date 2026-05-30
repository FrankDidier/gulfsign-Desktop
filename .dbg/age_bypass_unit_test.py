# -*- coding: utf-8 -*-
"""单元测试: 年龄绕行编排 + 资格预检 + 审计日志.

验证以下场景, 全部不打真实生产服务器:

  1. ``check_age_bypass_eligibility`` 通过 ``load_archive`` fallback 路径
     正确判定 likely_eligible / likely_blocked.

  2. ``check_age_bypass_eligibility`` 通过 ``query_province_wide`` 权威路径
     在 is_realname=True 时返回 likely_eligible=False.

  3. ``process_card_with_age_bypass``:
     - 预检阻断时 *不* 调用 prepare_age_bypass.
     - 成功路径走完 prepare → process_card_full → restore.
     - prepare 失败时不调 process_card_full, 不调 restore.
     - process_card_full 失败时仍调 restore (transactional 保证).
     - restore 失败时把 success 强制设为 False, step="age_bypass_restore_failed".

  4. ``AgeBypassAuditLogger`` 写入 Excel 行能被回读.
"""
from __future__ import annotations

import os
import sys
import tempfile
import unittest
from unittest.mock import MagicMock
from pathlib import Path
from typing import List

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from sign_engine import (  # noqa: E402
    SigningEngine, AgeBypassEligibility, FullSignResult,
    generate_bypass_sfzh, get_age_from_id, needs_age_bypass,
)
from hc_api import HealthCard, HealthCardClient  # noqa: E402
from ph3_api import PH3Client, ProvinceMatch  # noqa: E402
from batch_processor import AgeBypassAuditLogger  # noqa: E402

import pandas as pd


def make_18yo_sfzh_today() -> str:
    """生成一个今年生人 35 岁左右的 18 位 SFZH 用于测试。"""
    # 出生年份 1990, 假设当前 >= 2026 年, 年龄 >= 35.
    # 区域码用 110101, 顺序码 001, 性别男(奇)
    id17 = "110101199001010012"[:17]
    from sign_engine import calc_id_check_digit
    return id17 + calc_id_check_digit(id17)


def make_logged_in_ph3() -> PH3Client:
    """构造一个已登录, 已扫码, 有 org_code 的 PH3Client (假身份)."""
    c = PH3Client()
    c.logged_in = True
    c.qr_pending = False
    c.org_code = "110101001"
    c.org_name = "测试机构"
    c.doctor_name = "测试医生"
    return c


class TestAgeBypassEligibility(unittest.TestCase):

    def test_load_archive_fallback_eligible(self):
        ph3 = make_logged_in_ph3()
        ph3.load_archive = MagicMock(return_value=(True, {
            "GUID": "PID001",
            "SFZH": make_18yo_sfzh_today(),
            "XM": "张三",
        }, ""))
        engine = SigningEngine(hc=MagicMock(spec=HealthCardClient), ph3=ph3)
        elig = engine.check_age_bypass_eligibility("PID001", name="张三")
        self.assertTrue(elig.archive_loaded)
        self.assertTrue(elig.needs_bypass)
        self.assertTrue(elig.likely_eligible)
        self.assertEqual(elig.detected_realname_marks, [])

    def test_load_archive_fallback_blocked_by_realname(self):
        ph3 = make_logged_in_ph3()
        ph3.load_archive = MagicMock(return_value=(True, {
            "GUID": "PID002",
            "SFZH": make_18yo_sfzh_today(),
            "XM": "李四",
            "B0101_19": "2023-05-15",  # 实名认证日期非空
            "SMRZ_BJ": "1",
        }, ""))
        engine = SigningEngine(hc=MagicMock(spec=HealthCardClient), ph3=ph3)
        elig = engine.check_age_bypass_eligibility("PID002", name="李四")
        self.assertTrue(elig.archive_loaded)
        self.assertTrue(elig.needs_bypass)
        self.assertFalse(elig.likely_eligible)
        self.assertGreater(len(elig.detected_realname_marks), 0)
        self.assertIn("已实名", elig.block_reason)

    def test_province_search_authoritative_blocked(self):
        ph3 = make_logged_in_ph3()
        ph3.query_province_wide = MagicMock(return_value=(
            [ProvinceMatch(
                person_id="PID003", name="王五",
                id_card=make_18yo_sfzh_today(),
                age="35", gender="1",
                is_realname=True, is_visited=True,
            )], 1, "",
        ))
        # 即使 load_archive 也存在, 优先路径应返回 blocked
        ph3.load_archive = MagicMock(return_value=(True, {}, ""))
        engine = SigningEngine(hc=MagicMock(spec=HealthCardClient), ph3=ph3)
        sfzh = make_18yo_sfzh_today()
        elig = engine.check_age_bypass_eligibility(
            "PID003", name="王五",
            expected_sfzh=sfzh, province_password="testpw",
        )
        self.assertTrue(elig.archive_loaded)
        self.assertFalse(elig.likely_eligible)
        self.assertIn("已实名", elig.block_reason)
        self.assertIn("已面访", elig.block_reason)
        # 走了权威路径, load_archive 不应被调用
        ph3.load_archive.assert_not_called()

    def test_qr_pending_returns_error(self):
        ph3 = PH3Client()
        ph3.logged_in = True
        ph3.qr_pending = True
        engine = SigningEngine(hc=MagicMock(spec=HealthCardClient), ph3=ph3)
        elig = engine.check_age_bypass_eligibility("PID")
        self.assertIn("二维码", elig.error)


class TestAgeBypassOrchestration(unittest.TestCase):

    def _make_engine_with_mocks(self):
        ph3 = make_logged_in_ph3()
        ph3.load_archive = MagicMock(return_value=(True, {
            "GUID": "PID010",
            "SFZH": make_18yo_sfzh_today(),
            "XM": "陈六",
        }, ""))
        ph3.modify_archive = MagicMock(return_value=(True, "修改成功"))
        hc = MagicMock(spec=HealthCardClient)
        engine = SigningEngine(hc=hc, ph3=ph3)
        # mock process_card_full to return a successful result
        engine.process_card_full = MagicMock(return_value=FullSignResult(
            success=True, name="陈六", health_card_id="HC001",
            step="confirmed", contract_confirmed=True, rpc_set=True,
        ))
        return engine, ph3, hc

    def _make_card(self):
        return HealthCard(
            health_card_id="HC001",
            name="陈六",
            id_card=make_18yo_sfzh_today(),
        )

    def test_blocked_does_not_modify(self):
        engine, ph3, hc = self._make_engine_with_mocks()
        ph3.load_archive = MagicMock(return_value=(True, {
            "SFZH": make_18yo_sfzh_today(),
            "B0101_19": "2023-01-01",  # 实名标记
        }, ""))
        result = engine.process_card_with_age_bypass(
            self._make_card(),
            person_id="PID010",
            orgcode="110101001",
        )
        self.assertFalse(result.success)
        self.assertEqual(result.step, "age_bypass_blocked")
        self.assertTrue(result.age_bypass_attempted)
        self.assertFalse(result.age_bypass_applied)
        self.assertFalse(result.age_bypass_restored)
        ph3.modify_archive.assert_not_called()
        engine.process_card_full.assert_not_called()

    def test_force_overrides_blocked(self):
        engine, ph3, hc = self._make_engine_with_mocks()
        ph3.load_archive = MagicMock(return_value=(True, {
            "SFZH": make_18yo_sfzh_today(),
            "B0101_19": "2023-01-01",
        }, ""))
        result = engine.process_card_with_age_bypass(
            self._make_card(),
            person_id="PID010",
            orgcode="110101001",
            force=True,
        )
        # force=True → 仍尝试; modify_archive 被调用
        self.assertTrue(result.age_bypass_applied)
        self.assertEqual(ph3.modify_archive.call_count, 2)  # prepare + restore

    def test_happy_path_full_cycle(self):
        engine, ph3, hc = self._make_engine_with_mocks()
        result = engine.process_card_with_age_bypass(
            self._make_card(),
            person_id="PID010",
            orgcode="110101001",
        )
        self.assertTrue(result.success)
        self.assertEqual(result.step, "confirmed")
        self.assertTrue(result.age_bypass_attempted)
        self.assertTrue(result.age_bypass_applied)
        self.assertTrue(result.age_bypass_restored)
        # modify_archive 调用 2 次: prepare + restore
        self.assertEqual(ph3.modify_archive.call_count, 2)

    def test_prepare_failure_does_not_call_inner_or_restore(self):
        engine, ph3, hc = self._make_engine_with_mocks()
        ph3.modify_archive = MagicMock(return_value=(False, "已实名认证不允许修改"))
        result = engine.process_card_with_age_bypass(
            self._make_card(),
            person_id="PID010",
            orgcode="110101001",
            force=True,  # 跳过预检的阻断
        )
        self.assertFalse(result.success)
        self.assertEqual(result.step, "age_bypass_prepare")
        self.assertFalse(result.age_bypass_applied)
        # restore 不应被调用 (因为没改成功)
        self.assertEqual(ph3.modify_archive.call_count, 1)
        engine.process_card_full.assert_not_called()

    def test_inner_failure_still_restores(self):
        engine, ph3, hc = self._make_engine_with_mocks()
        engine.process_card_full = MagicMock(return_value=FullSignResult(
            success=False, name="陈六", error="模拟内层失败",
            step="confirm", health_card_id="HC001",
        ))
        result = engine.process_card_with_age_bypass(
            self._make_card(),
            person_id="PID010",
            orgcode="110101001",
        )
        self.assertFalse(result.success)
        self.assertTrue(result.age_bypass_applied)
        # 关键: 即使内部签约失败, restore 仍被调用
        self.assertTrue(result.age_bypass_restored)
        self.assertEqual(ph3.modify_archive.call_count, 2)

    def test_restore_failure_marks_critical(self):
        engine, ph3, hc = self._make_engine_with_mocks()
        # modify_archive 第一次 (prepare) 成功, 第二次 (restore) 失败
        ph3.modify_archive = MagicMock(side_effect=[
            (True, "修改成功"),
            (False, "服务器错误 — 恢复失败"),
        ])
        result = engine.process_card_with_age_bypass(
            self._make_card(),
            person_id="PID010",
            orgcode="110101001",
        )
        # 即便内层成功, 恢复失败也要把 success 拉回 False
        self.assertFalse(result.success)
        self.assertEqual(result.step, "age_bypass_restore_failed")
        self.assertTrue(result.age_bypass_applied)
        self.assertFalse(result.age_bypass_restored)
        self.assertIn("严重", result.error)


class TestAuditLogger(unittest.TestCase):

    def test_log_attempt_writes_excel(self):
        with tempfile.TemporaryDirectory() as tmp:
            audit = AgeBypassAuditLogger(account="testacct", audit_dir=tmp)
            audit.log_attempt({
                "phase": "precheck",
                "person_id": "PID999",
                "name": "测试人",
                "status": "eligible",
            })
            audit.log_attempt({
                "phase": "prepare",
                "person_id": "PID999",
                "ok": True,
            })
            # 找日期目录下的 testacct.xlsx
            files = list(Path(tmp).rglob("testacct.xlsx"))
            self.assertEqual(len(files), 1)
            df = pd.read_excel(files[0])
            self.assertEqual(len(df), 2)
            phases = set(df["phase"].tolist())
            self.assertSetEqual(phases, {"precheck", "prepare"})

    def test_export_eligibility_report(self):
        with tempfile.TemporaryDirectory() as tmp:
            audit = AgeBypassAuditLogger(account="testacct", audit_dir=tmp)
            elig = AgeBypassEligibility(
                person_id="PID888", name="王小明",
                age=35, needs_bypass=True, likely_eligible=False,
                archive_loaded=True,
                block_reason="已实名认证",
                detected_realname_marks=["全省查询: 已实名"],
                original_sfzh=make_18yo_sfzh_today(),
            )
            path = audit.export_eligibility_report([elig])
            self.assertTrue(path)
            self.assertTrue(Path(path).exists())
            df = pd.read_excel(path)
            self.assertEqual(len(df), 1)
            self.assertEqual(df.iloc[0]["status"], "likely_blocked")


if __name__ == "__main__":
    unittest.main(verbosity=2)
