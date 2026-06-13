# -*- coding: utf-8 -*-
"""【探针电池】一次扫码, 跑一连串只读+小写实验, 摸清"申请→确认→已签约"的真实门路。

每次扫码很贵, 所以一次登录里把能问的都问清楚, 全部打印服务端【原始返回】:

  P1 单条发起 initiate_signing(ACTION=1) → 看落库成什么状态 (应为 医生申请5)
  P2 读这个人的签约记录 (list_personal_b0105, 不需要身份证, 直接看状态文本+合同号)
  P3 对该合同试 confirm_signing(ACTION=9, STATUS=1) → 抓原始返回
  P4 再直接试 ACTION=9 但 STATUS=0 / 其它变体 → 抓原始返回 (找能翻成已签约的姿势)
  P5 finalize_via_archive → 抓结果
  P6 读最终状态
  P7 清理: 删除/作废本次创建的合同 (KEEP=1 保留)

只动 1 个未签约的人, 做完清理。
"""
import base64
import os
import re
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ph3_api import PH3Client  # noqa: E402

BASE = "https://ggws.hnhfpc.gov.cn"
ACCOUNT = "431122012"
PASSWORD = "wei1147609775@"
QR_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "qr_login.png")
KEEP = os.environ.get("KEEP") == "1"


def banner(t):
    print("\n" + "=" * 56)
    print(" " + t)
    print("=" * 56)


def save_qr(data_url):
    m = re.match(r"data:image/[^;]+;base64,(.+)$", data_url, re.S)
    if not m:
        return False
    with open(QR_PATH, "wb") as f:
        f.write(base64.b64decode(m.group(1)))
    return True


def do_login(c):
    banner("登录")
    ok, msg = c.login(BASE, ACCOUNT, PASSWORD)
    print("login:", ok, "|", msg.replace("\n", " "))
    if not c.logged_in:
        return False
    if not c.qr_pending:
        return True
    ok, data_url, _, err = c.qr_login_generate()
    if not ok or not save_qr(data_url):
        print("二维码生成/解码失败:", err)
        return False
    wait_s = int(os.environ.get("QR_WAIT", "900"))
    print(">>> 二维码已保存: %s  请扫码 (最多 %d 秒)" % (QR_PATH, wait_s))
    deadline = time.time() + wait_s
    last = 0
    while time.time() < deadline:
        code, m = c.qr_login_query()
        if code == 0:
            print("扫码通过")
            ok2, info = c.qr_login_finalize()
            print("登录完成:", ok2, "|", info)
            if not c.org_code:
                try:
                    orgs = c.get_org_tree("0")
                    if orgs:
                        c._drill_org_tree(orgs)
                except Exception as e:
                    print("补抓机构树失败:", e)
            print("org_code=%s doctor=%s" % (c.org_code, c.doctor_name))
            return bool(ok2 and c.logged_in and not c.qr_pending)
        now = time.time()
        if now - last > 30:
            print("...等待扫码 (剩 %d 秒)" % int(deadline - now))
            last = now
        time.sleep(3)
    print("超时未扫码")
    return False


def read_records(c, pid):
    """直接读这个人的家医签约记录, 返回 list[{contract_code,status_text,voided}]。"""
    try:
        return c.list_personal_b0105(pid)
    except Exception as e:
        print("read_records 异常:", e)
        return []


def show_records(c, pid, tag):
    recs = read_records(c, pid)
    print("[%s] 记录数=%d" % (tag, len(recs)))
    for r in recs:
        print("    contract=%s status=%s voided=%s start=%s" % (
            r.get("contract_code"), r.get("status_text"),
            r.get("voided"), r.get("agreement_start")))
    return recs


def raw_action9(c, pid, cc, status_val):
    """直接打 ACTION=9, 用不同 STATUS 值, 抓原始返回。"""
    try:
        resp = c.session.post(
            c._url("/Sys_JCWS/B0105/Do_B0105_Handler.ashx"),
            params={"ACTION": "9"},
            data={"STATUS": status_val, "REMARK": "", "GUID": cc, "PERSONID": pid},
            headers=c._csrf_header(),
            timeout=c._timeout,
        )
        return "HTTP %d | %s" % (resp.status_code, resp.text.strip()[:200])
    except Exception as e:
        return "异常: %s" % e


def main():
    c = PH3Client()
    if not do_login(c):
        print("\n登录未完成, 中止。")
        return

    banner("选未签约居民")
    pts, total = c.query_patients(status="1", page=1)
    print("未签约命中 %d (total=%s)" % (len(pts), total))
    target = next((p for p in pts if p.person_id), None)
    if not target:
        print("没有可用目标, 中止。")
        return
    pid = target.person_id
    print("目标: %s person_id=%s" % (target.name, pid))

    created_cc = ""
    try:
        banner("P0 发起前记录")
        before = show_records(c, pid, "BEFORE")
        before_codes = {r.get("contract_code") for r in before}

        banner("P1 单条发起 initiate_signing (ACTION=1, 常规)")
        r = c.initiate_signing(pid)
        print("initiate:", r.success, "| step=%s cc=%s err=%s" % (
            r.step, r.contract_code, r.error))
        created_cc = r.contract_code or ""

        banner("P2 发起后记录 (落库成什么状态?)")
        after = show_records(c, pid, "AFTER-INIT")
        for rec in after:
            if rec.get("contract_code") not in before_codes:
                created_cc = rec.get("contract_code") or created_cc
                print(">> 新合同: %s 状态=%s" % (
                    rec.get("contract_code"), rec.get("status_text")))

        if not created_cc:
            print(">> 没拿到新合同号, 后续确认实验跳过。")
        else:
            banner("P3 confirm_signing (ACTION=9, STATUS=1) 原始返回")
            print("raw:", raw_action9(c, pid, created_cc, "1"))
            show_records(c, pid, "AFTER-CONFIRM(1)")

            banner("P4 试 ACTION=9 其它 STATUS 变体")
            for sv in ("0", "6", "2"):
                print("STATUS=%s -> %s" % (sv, raw_action9(c, pid, created_cc, sv)))
                time.sleep(0.4)
            show_records(c, pid, "AFTER-VARIANTS")

            banner("P5 finalize_via_archive")
            rf = c.finalize_via_archive(pid, name=target.name, max_retries=2)
            print("finalize:", rf.success, "| step=%s err=%s" % (rf.step, rf.error))

        banner("P6 最终记录")
        show_records(c, pid, "FINAL")

    finally:
        banner("P7 清理")
        if KEEP:
            print("KEEP=1: 不清理。")
        elif created_cc:
            try:
                # 已签约(0)先作废, 再删
                recs = read_records(c, pid)
                st = next((x.get("status_text") for x in recs
                           if x.get("contract_code") == created_cc), "")
                if st == "已签约":
                    print("作废:", c.void_signing(created_cc))
                print("删除 %s -> %s" % (created_cc, c.delete_signing(created_cc)))
                show_records(c, pid, "CLEANED")
            except Exception as e:
                print("清理异常(请手工核对):", e)
        else:
            print("无新建合同, 无需清理。")
        print("\n探针结束。")


if __name__ == "__main__":
    main()
