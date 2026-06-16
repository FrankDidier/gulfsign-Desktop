#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""单条·真·联机签约实验 (写操作, 仅 1 条, 全程清理) —— 打真实 ggws.

目的: 在生产服务器上用 **1 个未签约居民** 验证核心问题链:
  1. 医生端 initiate 是否真能创建合同, 落库状态是 5 还是别的? (验证报告规则 A)
  2. 对该 5 直接 confirm(ACTION=9) 服务端是否拒绝? (验证报告规则 B)
  3. 竞品式"档案重提交"(finalize_via_archive / B0101 ACTION=2) 能否把它推进到
     已签约(0)? —— 这是本项目最关键的未决问题。
  4. 不论结果如何, **最后都把这条测试合同删除/作废**, 不在生产数据留痕。

安全开关:
  - 必须设 CONFIRM_WRITE=1 才会执行任何写操作 (否则只读演练并退出)。
  - 只处理 1 条; 步步打印真实返回; 任何异常都打印。
  - 默认尝试档案推进 (DO_PROMOTE=1 关掉则跳过第 3 步, 只做 initiate+清理)。

需要人扫码 (微信扫一扫, 5 分钟内)。
"""
import os
import sys
import time
import traceback

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from live_full_test import do_qr_flow, banner, mask_sfzh, mask_name  # noqa: E402
from ph3_api import PH3Client  # noqa: E402

ACCOUNT = os.environ.get("PH3_ACCOUNT", "")
PASSWORD = os.environ.get("PH3_PASSWORD", "")
GGWS = "https://ggws.hnhfpc.gov.cn"
CONFIRM_WRITE = os.environ.get("CONFIRM_WRITE") == "1"
DO_PROMOTE = os.environ.get("DO_PROMOTE", "1") == "1"


def pick_unsigned(c):
    """取一名 未签约(status=1) 居民 (person_id 非空)。"""
    pts, total = c.query_patients(status="1", page=1)
    for p in pts:
        if p.person_id:
            return p
    return None


def cleanup(c, cc, label="清理"):
    """根据真实状态删除/作废测试合同, 不留痕。"""
    banner("%s: 删除/作废测试合同 %s" % (label, cc[:8]))
    # 先尝试 delete(适用于 5/6), 失败再 void(适用于 0)
    ok_del = c.delete_signing(cc)
    print("  delete_signing -> %s" % ok_del)
    if ok_del:
        return True
    ok_void = c.void_signing(cc)
    print("  void_signing  -> %s" % ok_void)
    return ok_void


def main():
    banner("单条联机签约实验 账号 %s  (CONFIRM_WRITE=%s, DO_PROMOTE=%s)"
           % (ACCOUNT, CONFIRM_WRITE, DO_PROMOTE))
    if not CONFIRM_WRITE:
        print("  ⚠ 未设 CONFIRM_WRITE=1 — 只读演练, 不执行任何写操作。")

    c = PH3Client()
    ok, msg = c.login(GGWS, ACCOUNT, PASSWORD)
    print("  login -> %s | %s" % (ok, msg))
    if c.qr_pending:
        if not do_qr_flow(c):
            print("  ✗ 未完成扫码, 退出。")
            return 1
    if not c.fully_authenticated:
        print("  ✗ 未达 fully_authenticated (org_code=%r), 退出。" % c.org_code)
        return 1
    print("  ✓ 已完整登录: org=%s(%s) doctor=%r team=%r"
          % (c.org_code, c.org_name, c.doctor_name, c.team_name))

    # ---- 选人 ----
    banner("STEP A: 选取 1 名未签约居民")
    p = pick_unsigned(c)
    if not p:
        print("  ✗ 未找到未签约居民, 退出。")
        return 1
    print("  选中: %s | %s | pid=%s | 现状=%s(%s)"
          % (mask_name(p.name), mask_sfzh(p.id_card), p.person_id,
             p.status_text, p.contract_status))

    # ---- 拿全身份证 (用于后续状态回查) ----
    full_sfzh = ""
    ok_a, fields, err = c.load_archive(p.person_id)
    if ok_a:
        full_sfzh = (fields.get("SFZH") or "").strip()
        print("  load_archive -> ok, SFZH(脱敏)=%s (取到全证号: %s)"
              % (mask_sfzh(full_sfzh), "是" if len(full_sfzh) >= 15 else "否/被脱敏"))
    else:
        print("  load_archive -> 失败: %s (后续将无法用 SFZH 回查)" % err)

    if not CONFIRM_WRITE:
        print("\n  (只读演练结束 — 选人/读档正常。设 CONFIRM_WRITE=1 才会真正发起签约。)")
        return 0

    cc = ""
    try:
        # ---- STEP B: 发起 (写) ----
        banner("STEP B: 发起医生申请 initiate_signing (真实写)")
        r = c.initiate_signing(p.person_id)
        print("  initiate -> success=%s step=%s cc=%s err=%s"
              % (r.success, r.step, (r.contract_code or "")[:8], r.error))
        cc = r.contract_code
        if not r.success or not cc:
            print("  ✗ 发起未成功或无合同号, 终止 (无需清理)。")
            return 1

        # ---- STEP C: 回查真实状态 ----
        banner("STEP C: 回查真实落库状态")
        if full_sfzh and len(full_sfzh) >= 15:
            code, text, pid, vcc = c.check_sign_status_by_sfzh(full_sfzh, p.name)
            print("  真实状态 -> code=%r text=%r cc=%s" % (code, text, (vcc or "")[:8]))
            print("  >>> 验证报告规则A: 医生端发起应落库为 5(医生申请). 实测=%r" % code)
        else:
            print("  (无全证号, 跳过 SFZH 回查; 仅凭 initiate 返回判断)")

        # ---- STEP D: 直接 confirm (验证规则 B: 应被拒) ----
        banner("STEP D: 对该 5 直接 confirm(ACTION=9) — 预期被服务端拒绝")
        rc = c.confirm_signing(p.person_id, cc, p.name)
        print("  confirm -> success=%s err=%s" % (rc.success, rc.error))
        print("  >>> 验证报告规则B: 5→0 直接确认应被拒. 实测 success=%s" % rc.success)

        # ---- STEP E: 档案推进 (关键实验) ----
        if DO_PROMOTE and full_sfzh and len(full_sfzh) >= 15:
            banner("STEP E: 档案重提交推进 finalize_via_archive — 能否 →已签约(0)?")
            rf = c.finalize_via_archive(
                p.person_id, sfzh=full_sfzh, name=p.name,
                max_retries=2, sleep_between=3.0,
            )
            print("  finalize_via_archive -> success=%s step=%s err=%s"
                  % (rf.success, rf.step, rf.error))
            print("  >>> 关键结论: 档案推进 %s 把医生申请(5)推进到已签约(0)"
                  % ("成功" if rf.success else "未能"))
            # 复核
            code2, text2, _, _ = c.check_sign_status_by_sfzh(full_sfzh, p.name)
            print("  推进后真实状态 -> code=%r text=%r" % (code2, text2))
        else:
            print("\n  (跳过档案推进: DO_PROMOTE=%s, 全证号=%s)"
                  % (DO_PROMOTE, "有" if len(full_sfzh) >= 15 else "无"))

    except Exception as e:
        print("  ✗ 实验中异常: %s" % e)
        traceback.print_exc()
    finally:
        # ---- 清理: 务必删除/作废, 不留痕 ----
        if cc:
            done = cleanup(c, cc)
            print("  清理结果: %s" % ("已移除" if done else "⚠ 未能移除, 请人工核查!"))
            if full_sfzh and len(full_sfzh) >= 15:
                code3, text3, _, _ = c.check_sign_status_by_sfzh(full_sfzh, p.name)
                print("  清理后状态 -> code=%r text=%r (应回到 未签约/空)"
                      % (code3, text3))

    banner("结论")
    print("  本次仅操作 1 条并已尝试清理。以上每步均为真实服务器返回。")
    return 0


if __name__ == "__main__":
    sys.exit(main())
