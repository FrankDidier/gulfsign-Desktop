# -*- coding: utf-8 -*-
"""单元测试: 对标竞品的状态校验 + 档案推进 (checkSignStatus / updateDanganInfo).

覆盖:
  - PH3Client.check_sign_status_by_sfzh  (只读状态查询)
  - PH3Client.finalize_via_archive       (档案推进到"已签约"的重试循环)
  - PH3Client._verify_and_finalize       (诚实改判逻辑)
  - PH3Client.sign_one(verify_final/finalize_archive) 集成

全部用 mock, 不触网。重点是状态机正确性与"绝不误报成功"。
"""
import os
import sys
import unittest
from unittest.mock import MagicMock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from ph3_api import PH3Client, Patient, SignResult


def make_client(logged_in=True, qr_pending=False, org_code="431122000"):
    c = PH3Client()
    c.logged_in = logged_in
    c.qr_pending = qr_pending
    c.org_code = org_code
    c.token_en = "0" * 32
    c.token_th = "0" * 64
    c.base_url = "https://example.invalid"
    return c


def patient(sfzh="431122198001011234", status_code="6", status_text="居民申请",
            pid="PID-1", cc="CC-1", name="张三"):
    return Patient(
        person_id=pid, name=name, id_card=sfzh, contract_code=cc,
        contract_status=status_code, status_text=status_text,
    )


class TestCheckStatus(unittest.TestCase):
    def test_empty_sfzh(self):
        c = make_client()
        self.assertEqual(c.check_sign_status_by_sfzh(""), ("", "", "", ""))

    def test_not_logged_in(self):
        c = make_client(logged_in=False)
        self.assertEqual(
            c.check_sign_status_by_sfzh("431122198001011234"), ("", "", "", "")
        )

    def test_qr_pending(self):
        c = make_client(qr_pending=True)
        self.assertEqual(
            c.check_sign_status_by_sfzh("431122198001011234"), ("", "", "", "")
        )

    def test_match_by_sfzh(self):
        c = make_client()
        sfzh = "431122198001011234"
        c.query_patients = MagicMock(return_value=([
            patient(sfzh="999", pid="OTHER"),
            patient(sfzh=sfzh, status_code="0", status_text="已签约",
                    pid="PID-X", cc="CC-X"),
        ], 2))
        code, text, pid, cc = c.check_sign_status_by_sfzh(sfzh)
        self.assertEqual(code, "0")
        self.assertEqual(text, "已签约")
        self.assertEqual(pid, "PID-X")
        self.assertEqual(cc, "CC-X")

    def test_no_match_falls_back_to_first(self):
        c = make_client()
        c.query_patients = MagicMock(return_value=([
            patient(sfzh="masked****", status_code="6", pid="PID-1"),
        ], 1))
        code, text, pid, cc = c.check_sign_status_by_sfzh("431122198001011234")
        self.assertEqual(pid, "PID-1")  # 服务端脱敏时退而取第一条

    def test_empty_result(self):
        c = make_client()
        c.query_patients = MagicMock(return_value=([], 0))
        self.assertEqual(
            c.check_sign_status_by_sfzh("431122198001011234"), ("", "", "", "")
        )

    def test_query_raises(self):
        c = make_client()
        c.query_patients = MagicMock(side_effect=RuntimeError("boom"))
        self.assertEqual(
            c.check_sign_status_by_sfzh("431122198001011234"), ("", "", "", "")
        )

    def test_passes_filters(self):
        c = make_client()
        c.query_patients = MagicMock(return_value=([], 0))
        c.check_sign_status_by_sfzh("431122198001011234", name="张三")
        _, kwargs = c.query_patients.call_args
        self.assertEqual(kwargs["extra_filters"]["SFZH"], "431122198001011234")
        self.assertEqual(kwargs["extra_filters"]["XM"], "张三")


class TestFinalizeViaArchive(unittest.TestCase):
    def test_not_logged_in(self):
        c = make_client(logged_in=False)
        r = c.finalize_via_archive("PID", sfzh="431122198001011234")
        self.assertFalse(r.success)

    def test_qr_pending(self):
        c = make_client(qr_pending=True)
        r = c.finalize_via_archive("PID", sfzh="431122198001011234")
        self.assertFalse(r.success)
        self.assertIn("二维码", r.error)

    def test_already_signed_first_check(self):
        c = make_client()
        c.check_sign_status_by_sfzh = MagicMock(
            return_value=("0", "已签约", "PID", "CC")
        )
        c.modify_archive = MagicMock()
        r = c.finalize_via_archive(
            "PID", sfzh="431122198001011234", _sleep=lambda *_: None
        )
        self.assertTrue(r.success)
        self.assertEqual(r.step, "finalize_verified")
        c.modify_archive.assert_not_called()  # 已签约不应再提交档案

    def test_promotes_after_archive(self):
        c = make_client()
        # 第一次查=居民申请, 提交档案后第二次查=已签约
        c.check_sign_status_by_sfzh = MagicMock(side_effect=[
            ("6", "居民申请", "PID", "CC"),
            ("0", "已签约", "PID", "CC"),
        ])
        c.modify_archive = MagicMock(return_value=(True, "修改成功"))
        sleeps = []
        r = c.finalize_via_archive(
            "PID", sfzh="431122198001011234", max_retries=3,
            _sleep=lambda s: sleeps.append(s),
        )
        self.assertTrue(r.success)
        self.assertEqual(r.step, "finalize_verified")
        c.modify_archive.assert_called_once()

    def test_never_promotes_honest_fail(self):
        c = make_client()
        c.check_sign_status_by_sfzh = MagicMock(
            return_value=("6", "居民申请", "PID", "CC")
        )
        c.modify_archive = MagicMock(return_value=(True, "修改成功"))
        sleeps = []
        r = c.finalize_via_archive(
            "PID", sfzh="431122198001011234", max_retries=3,
            _sleep=lambda s: sleeps.append(s),
        )
        self.assertFalse(r.success)              # 绝不误报
        self.assertEqual(r.step, "finalize")
        self.assertIn("居民申请", r.error)
        self.assertEqual(c.modify_archive.call_count, 3)  # 重试 3 次
        self.assertEqual(len(sleeps), 2)         # retries-1 次 sleep

    def test_modify_fail_but_eventually_signed(self):
        c = make_client()
        c.check_sign_status_by_sfzh = MagicMock(side_effect=[
            ("6", "居民申请", "PID", "CC"),
            ("0", "已签约", "PID", "CC"),
        ])
        # 档案提交失败不致命, 仍可在下一轮发现已签约
        c.modify_archive = MagicMock(return_value=(False, "HTTP 500"))
        r = c.finalize_via_archive(
            "PID", sfzh="431122198001011234", _sleep=lambda *_: None
        )
        self.assertTrue(r.success)

    def test_no_sfzh_cannot_confirm(self):
        c = make_client()
        c.modify_archive = MagicMock(return_value=(True, "修改成功"))
        r = c.finalize_via_archive("PID", sfzh="", _sleep=lambda *_: None)
        self.assertFalse(r.success)              # 无法确认 -> 不报成功
        self.assertIn("无法确认", r.error)


class TestVerifyAndFinalize(unittest.TestCase):
    def test_disabled_passthrough(self):
        c = make_client()
        c.check_sign_status_by_sfzh = MagicMock()
        r = SignResult(True, "PID", "张三", step="confirm")
        out = c._verify_and_finalize(r, "PID", sfzh="x", verify_final=False)
        self.assertTrue(out.success)
        c.check_sign_status_by_sfzh.assert_not_called()

    def test_no_sfzh_passthrough(self):
        c = make_client()
        c.check_sign_status_by_sfzh = MagicMock()
        r = SignResult(True, "PID", "张三", step="confirm")
        out = c._verify_and_finalize(r, "PID", sfzh="", verify_final=True)
        self.assertTrue(out.success)
        c.check_sign_status_by_sfzh.assert_not_called()

    def test_real_status_signed_marks_success(self):
        c = make_client()
        c.check_sign_status_by_sfzh = MagicMock(
            return_value=("0", "已签约", "PID", "CC-real")
        )
        r = SignResult(True, "PID", "张三", step="confirm")
        out = c._verify_and_finalize(
            r, "PID", sfzh="431122198001011234", verify_final=True
        )
        self.assertTrue(out.success)
        self.assertEqual(out.step, "verified_signed")
        self.assertEqual(out.contract_code, "CC-real")

    def test_confirm_success_but_real_pending_downgraded(self):
        c = make_client()
        c.check_sign_status_by_sfzh = MagicMock(
            return_value=("6", "居民申请", "PID", "CC")
        )
        r = SignResult(True, "PID", "张三", step="confirm")
        out = c._verify_and_finalize(
            r, "PID", sfzh="431122198001011234",
            verify_final=True, finalize_archive=False,
        )
        self.assertFalse(out.success)            # 关键: 诚实改判
        self.assertEqual(out.step, "verify_failed")

    def test_finalize_archive_promotes(self):
        c = make_client()
        c.check_sign_status_by_sfzh = MagicMock(
            return_value=("6", "居民申请", "PID", "CC")
        )
        c.finalize_via_archive = MagicMock(
            return_value=SignResult(True, "PID", "张三", contract_code="CC2",
                                    step="finalize_verified")
        )
        r = SignResult(True, "PID", "张三", step="confirm")
        out = c._verify_and_finalize(
            r, "PID", sfzh="431122198001011234",
            verify_final=True, finalize_archive=True,
        )
        self.assertTrue(out.success)
        self.assertEqual(out.step, "finalized_via_archive")

    def test_finalize_archive_fails(self):
        c = make_client()
        c.check_sign_status_by_sfzh = MagicMock(
            return_value=("5", "医生申请", "PID", "CC")
        )
        c.finalize_via_archive = MagicMock(
            return_value=SignResult(False, "PID", "张三",
                                    error="仍未落库", step="finalize")
        )
        r = SignResult(True, "PID", "张三", step="confirm")
        out = c._verify_and_finalize(
            r, "PID", sfzh="431122198001011234",
            verify_final=True, finalize_archive=True,
        )
        self.assertFalse(out.success)
        self.assertEqual(out.step, "verify_failed")

    def test_query_failure_does_not_downgrade(self):
        # 关键: 回查失败(code="")不能把真实成功误杀, 但要标记 unverified 以示未经证实
        c = make_client()
        c.check_sign_status_by_sfzh = MagicMock(return_value=("", "", "", ""))
        r = SignResult(True, "PID", "张三", step="confirm")
        out = c._verify_and_finalize(
            r, "PID", sfzh="431122198001011234", verify_final=True
        )
        self.assertTrue(out.success)             # 保持原结果(不误杀)
        self.assertEqual(out.step, "unverified")  # 但明确标注未经证实


class TestSignOneIntegration(unittest.TestCase):
    def test_initiate_confirm_with_verify_promotes(self):
        c = make_client()
        c.initiate_signing = MagicMock(
            return_value=SignResult(True, "PID", "张三", contract_code="CC",
                                    step="initiate")
        )
        c.confirm_signing = MagicMock(
            return_value=SignResult(True, "PID", "张三", contract_code="CC",
                                    step="confirm")
        )
        # confirm 后真实仍为居民申请 -> finalize 推进成功
        c.check_sign_status_by_sfzh = MagicMock(
            return_value=("6", "居民申请", "PID", "CC")
        )
        c.finalize_via_archive = MagicMock(
            return_value=SignResult(True, "PID", "张三", contract_code="CC",
                                    step="finalize_verified")
        )
        r = c.sign_one(
            "PID", name="张三", sfzh="431122198001011234",
            verify_final=True, finalize_archive=True, delay=0,
        )
        self.assertTrue(r.success)
        self.assertEqual(r.step, "finalized_via_archive")

    def test_confirm_false_positive_caught(self):
        # confirm 自称成功, 真实状态仍是居民申请, 不开 finalize -> 必须失败
        c = make_client()
        c.initiate_signing = MagicMock(
            return_value=SignResult(True, "PID", "张三", contract_code="CC")
        )
        c.confirm_signing = MagicMock(
            return_value=SignResult(True, "PID", "张三", contract_code="CC",
                                    step="confirm")
        )
        c.check_sign_status_by_sfzh = MagicMock(
            return_value=("6", "居民申请", "PID", "CC")
        )
        r = c.sign_one(
            "PID", name="张三", sfzh="431122198001011234",
            verify_final=True, finalize_archive=False, delay=0,
        )
        self.assertFalse(r.success)
        self.assertEqual(r.step, "verify_failed")

    def test_no_verify_keeps_legacy_behavior(self):
        c = make_client()
        c.initiate_signing = MagicMock(
            return_value=SignResult(True, "PID", "张三", contract_code="CC")
        )
        c.confirm_signing = MagicMock(
            return_value=SignResult(True, "PID", "张三", contract_code="CC",
                                    step="confirm")
        )
        c.check_sign_status_by_sfzh = MagicMock()
        r = c.sign_one("PID", name="张三", delay=0)  # verify_final 默认 False
        self.assertTrue(r.success)
        c.check_sign_status_by_sfzh.assert_not_called()


if __name__ == "__main__":
    unittest.main(verbosity=2)
