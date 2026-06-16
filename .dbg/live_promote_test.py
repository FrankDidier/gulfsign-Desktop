#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""档案推进实验 (5→0?) —— 真·联机, 1 条, 全程清理, 用 person_id 校验状态.

回答唯一问题: 竞品式"重新提交 B0101 核心档案 (ACTION=2)"能否把
一条 **医生申请(5)** 的家医签约推进到 **已签约(0)**?

与 live_one_sign_test.py 的区别: 不依赖身份证号 (上一轮发现编辑表单里
SFZH 被脱敏)。改用 list_personal_b0105(person_id) 直接按 person_id 读取
该居民名下家医签约记录的 status_text 来判断真实状态。

流程 (全程仅 1 条):
  1. login + 扫码
  2. 选 1 名 未签约 居民
  3. initiate -> 创建合同, 读 b0105 确认落库为 "医生申请"
  4. 循环 N 次: modify_archive(person_id, {}) 重提交 B0101 -> sleep -> 复查 b0105
  5. 判定: 是否出现 "已签约"
  6. 清理: 已签约 -> void; 否则 delete; 复查确认已移除
全程打印真实返回。需 CONFIRM_WRITE=1。
"""
import os
import sys
import time
import traceback

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from live_full_test import do_qr_flow, banner, mask_name  # noqa: E402
from ph3_api import PH3Client  # noqa: E402

ACCOUNT = os.environ.get("PH3_ACCOUNT", "")
PASSWORD = os.environ.get("PH3_PASSWORD", "")
GGWS = "https://ggws.hnhfpc.gov.cn"
CONFIRM_WRITE = os.environ.get("CONFIRM_WRITE") == "1"
RETRIES = int(os.environ.get("PROMOTE_RETRIES", "3"))
SLEEP_BETWEEN = float(os.environ.get("PROMOTE_SLEEP", "3.0"))


def b0105_status(c, person_id, cc=""):
    """返回 (status_text, voided, matched_record) —— 按 person_id 读取真实状态。

    若给了 cc, 精确匹配该合同; 否则取最新一条非作废记录。
    """
    recs = c.list_personal_b0105(person_id)
    if not recs:
        return "", False, None
    if cc:
        for r in recs:
            if r.get("contract_code") == cc:
                return r.get("status_text", ""), r.get("voided", False), r
    # 没指定 cc: 优先非作废
    for r in recs:
        if not r.get("voided"):
            return r.get("status_text", ""), False, r
    r = recs[0]
    return r.get("status_text", ""), r.get("voided", False), r


def main():
    banner("档案推进实验 5→0?  账号 %s  (CONFIRM_WRITE=%s, retries=%d)"
           % (ACCOUNT, CONFIRM_WRITE, RETRIES))
    if not CONFIRM_WRITE:
        print("  ⚠ 未设 CONFIRM_WRITE=1 — 只读演练。")

    c = PH3Client()
    ok, msg = c.login(GGWS, ACCOUNT, PASSWORD)
    print("  login -> %s | %s" % (ok, msg))
    if c.qr_pending:
        if not do_qr_flow(c):
            print("  ✗ 未完成扫码, 退出。")
            return 1
    if not c.fully_authenticated:
        print("  ✗ 未达 fully_authenticated, 退出。")
        return 1
    print("  ✓ 已完整登录: org=%s doctor=%r" % (c.org_code, c.doctor_name))

    banner("STEP A: 选 1 名未签约居民")
    pts, _ = c.query_patients(status="1", page=1)
    p = next((x for x in pts if x.person_id), None)
    if not p:
        print("  ✗ 未找到未签约居民。")
        return 1
    print("  选中: %s | pid=%s | 现状=%s" % (mask_name(p.name), p.person_id, p.status_text))

    # 入场前快照: 该居民名下是否已有签约记录 (避免误判/误删)
    pre = c.list_personal_b0105(p.person_id)
    pre_codes = {r.get("contract_code") for r in pre}
    print("  入场前 b0105 记录数=%d codes=%s"
          % (len(pre), [x[:8] for x in pre_codes]))

    if not CONFIRM_WRITE:
        print("\n  (只读演练结束。设 CONFIRM_WRITE=1 才会真正写。)")
        return 0

    cc = ""
    try:
        banner("STEP B: initiate (真实写) + b0105 确认落库状态")
        r = c.initiate_signing(p.person_id)
        cc = r.contract_code
        print("  initiate -> success=%s cc=%s err=%s" % (r.success, (cc or "")[:8], r.error))
        if not r.success or not cc:
            print("  ✗ 发起失败, 终止 (无需清理)。")
            return 1
        if cc in pre_codes:
            print("  ⚠ 合同号与入场前重复, 为安全起见终止并不做清理, 请人工核查。")
            cc = ""
            return 1
        st, voided, _ = b0105_status(c, p.person_id, cc)
        print("  b0105 落库状态 -> %r (voided=%s)" % (st, voided))
        print("  >>> 规则A: 医生端发起应为 '医生申请'. 实测=%r" % st)

        banner("STEP C: 重复提交 B0101 (ACTION=2) 尝试推进 -> 已签约?")
        promoted = False
        final_st = st
        for i in range(RETRIES):
            st_now, _, _ = b0105_status(c, p.person_id, cc)
            final_st = st_now
            print("  [第%d轮] 当前状态=%r" % (i + 1, st_now))
            if "已签约" in (st_now or ""):
                promoted = True
                break
            ok_m, msg_m = c.modify_archive(p.person_id, {})
            print("    modify_archive(B0101 ACTION=2) -> ok=%s msg=%s" % (ok_m, (msg_m or "")[:80]))
            if i < RETRIES - 1:
                time.sleep(SLEEP_BETWEEN)
        # 末次复查
        st_fin, _, _ = b0105_status(c, p.person_id, cc)
        final_st = st_fin or final_st
        if "已签约" in (st_fin or ""):
            promoted = True

        banner("关键结论")
        if promoted:
            print("  ✅✅ 档案重提交 **成功** 把医生申请推进到 已签约(0)! 状态=%r" % final_st)
            print("      => 竞品 updateDanganInfo 机制对医生端发起同样有效。")
        else:
            print("  ❌ 档案重提交 **未能** 推进到已签约。最终状态=%r" % final_st)
            print("      => 仅靠重提交 B0101 不足以让医生端发起落库 (诚实结论)。")

    except Exception as e:
        print("  ✗ 实验异常: %s" % e)
        traceback.print_exc()
    finally:
        if cc:
            banner("清理: 移除测试合同 %s" % cc[:8])
            st_c, voided_c, _ = b0105_status(c, p.person_id, cc)
            print("  清理前状态=%r voided=%s" % (st_c, voided_c))
            done = False
            if "已签约" in (st_c or ""):
                done = c.void_signing(cc)
                print("  void_signing -> %s" % done)
            else:
                done = c.delete_signing(cc)
                print("  delete_signing -> %s" % done)
                if not done:
                    done = c.void_signing(cc)
                    print("  (回退) void_signing -> %s" % done)
            st_after, voided_after, rec_after = b0105_status(c, p.person_id, cc)
            still = rec_after is not None and not voided_after
            print("  清理后: 状态=%r voided=%s 仍存在有效记录=%s"
                  % (st_after, voided_after, still))
            print("  清理结果: %s" % ("已移除/作废" if (done or not still) else "⚠ 未能移除, 请人工核查!"))

    return 0


if __name__ == "__main__":
    sys.exit(main())
