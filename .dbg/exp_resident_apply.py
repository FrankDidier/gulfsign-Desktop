# -*- coding: utf-8 -*-
"""【实验】复现竞品：以"居民申请(status=6)"姿势发起 → 医生确认 → 看是否落库已签约。

只对【1 个未签约居民】操作，结束后【自动清理】(删除本次创建的合同)，
默认不留痕。全程把每一步的真实返回打出来，用证据判断破法是否成立。

流程:
  1) 账号登录 → 需要扫码: 把二维码存成 .dbg/qr_login.png, 等你扫
  2) 扫码通过 → 完成登录
  3) 选 1 个"未签约"居民 (或用 TEST_SFZH 指定)
  4) 记录 BEFORE 状态
  5) family_batch_initiate(applicant_status="6")  ← 关键实验开关
  6) 记录 insert 后状态 (服务端是否采信 6=居民申请?)
  7) 若为居民申请(6) → confirm_signing(ACTION=9) → 记录
  8) 仍未落库 → finalize_via_archive → 记录
  9) 记录 FINAL 状态
 10) 清理: 删除/作废本次创建的合同 (KEEP=1 可保留)

环境变量:
  TEST_SFZH   指定测试居民身份证 (可选; 默认自动挑一个未签约的)
  KEEP=1      实验后不清理 (默认会清理)
  APPLICANT_STATUS  默认 "6"
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
APPLICANT_STATUS = os.environ.get("APPLICANT_STATUS", "6")
KEEP = os.environ.get("KEEP") == "1"
TEST_SFZH = os.environ.get("TEST_SFZH", "").strip()


def mask(s, keep=4):
    if not s:
        return ""
    return s[: keep - 2] + "***" + s[-2:] if len(s) > keep else "***"


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
    banner("第1步 账号登录")
    ok, msg = c.login(BASE, ACCOUNT, PASSWORD)
    print("login:", ok, "|", msg.replace("\n", " "))
    if not c.logged_in:
        return False
    if not c.qr_pending:
        print(">>> 无需扫码, 已登录")
        return True

    banner("第2步 扫码 (请用该账号的微信扫码)")
    ok, data_url, _, err = c.qr_login_generate()
    if not ok:
        print("生成二维码失败:", err)
        return False
    if not save_qr(data_url):
        print("二维码解码失败")
        return False
    wait_s = int(os.environ.get("QR_WAIT", "600"))
    print(">>> 二维码已保存: %s" % QR_PATH)
    print(">>> 请【打开该图片并用微信扫码】, 我在等待 (最多 %d 秒)..." % wait_s)

    deadline = time.time() + wait_s
    last_print = 0
    while time.time() < deadline:
        code, m = c.qr_login_query()
        if code == 0:
            print("扫码通过:", m)
            ok2, info = c.qr_login_finalize()
            print("登录完成:", ok2, "|", info)
            if not c.org_code:
                print("⚠ org_code 为空, 尝试补抓机构树...")
                try:
                    orgs = c.get_org_tree("0")
                    if orgs:
                        c._drill_org_tree(orgs)
                except Exception as e:
                    print("补抓机构树失败:", e)
            print("登录后 org_code=%s" % c.org_code)
            return bool(ok2 and c.logged_in and not c.qr_pending)
        now = time.time()
        if now - last_print > 30:
            print("...仍在等待扫码 (剩余约 %d 秒)" % int(deadline - now))
            last_print = now
        time.sleep(3)
    print("超时: 未在 %d 秒内扫码" % wait_s)
    return False


def status_of(c, sfzh, name):
    """返回 (code, text, pid, cc)。"""
    try:
        return c.check_sign_status_by_sfzh(sfzh, name)
    except Exception as e:
        return "", "查询异常:%s" % e, "", ""


def pick_target(c):
    if TEST_SFZH:
        print("使用指定 TEST_SFZH:", mask(TEST_SFZH))
        # 用全省/本机构查询拿 person_id
        pts, _ = c.query_patients(status="", page=1)
        for p in pts:
            if p.id_card == TEST_SFZH:
                return p
        # 退而求其次: 仅有 sfzh, person_id 待 check_status 反查
        from ph3_api import Patient
        return Patient(person_id="", name="", id_card=TEST_SFZH)
    print("自动挑选一个【未签约(状态=1)】的居民...")
    pts, total = c.query_patients(status="1", page=1)
    print("未签约查询: 命中 %d 人 (total=%s)" % (len(pts), total))
    for p in pts:
        if p.person_id and p.id_card:
            return p
    return None


def main():
    c = PH3Client()
    if not do_login(c):
        print("\n>>> 登录未完成, 实验中止。")
        return
    print("\norg_code=%s org_name=%s doctor=%s" % (
        c.org_code, c.org_name, c.doctor_name))

    banner("第3步 选取测试居民")
    p = pick_target(c)
    if not p:
        print(">>> 没找到可用的未签约居民, 中止。")
        return
    print("目标: 姓名=%s 身份证=%s person_id=%s" % (
        p.name, mask(p.id_card), p.person_id))

    banner("第4步 BEFORE 状态")
    code0, text0, pid0, cc0 = status_of(c, p.id_card, p.name)
    pid = p.person_id or pid0
    print("BEFORE: code=%s text=%s person_id=%s contract=%s" % (
        code0, text0, pid, cc0))
    if code0 == "0":
        print(">>> 此人已是已签约, 换一个人更干净。中止以免干扰真实数据。")
        return
    if not pid:
        print(">>> 拿不到 person_id, 无法实验。中止。")
        return

    created_cc = ""
    try:
        banner("第5步 实验: 以 applicant_status=%s 发起" % APPLICANT_STATUS)
        ok, msg, created = c.family_batch_initiate(
            person_ids=[pid],
            contact_phone="13800000000",
            applicant_status=APPLICANT_STATUS,
        )
        print("family_batch_initiate:", ok, "|", msg)
        print("created:", created)
        for it in created:
            if str(it.get("person_id")) == str(pid) or it.get("contract_code"):
                created_cc = it.get("contract_code", "") or created_cc

        banner("第6步 insert 后状态 (服务端是否采信 6?)")
        time.sleep(1)
        code1, text1, pid1, cc1 = status_of(c, p.id_card, p.name)
        created_cc = created_cc or cc1
        print("AFTER-INSERT: code=%s text=%s contract=%s" % (code1, text1, created_cc))

        if code1 == "6" and created_cc:
            banner("第7步 居民申请(6) → 医生确认 ACTION=9")
            r = c.confirm_signing(pid, created_cc, p.name)
            print("confirm:", r.success, "| step=%s err=%s" % (r.step, r.error))
            time.sleep(1)
            code2, text2, _, _ = status_of(c, p.id_card, p.name)
            print("AFTER-CONFIRM: code=%s text=%s" % (code2, text2))
        elif code1 == "5":
            print(">>> 服务端把它落成了【医生申请(5)】, 没采信 6。确认会被拒。")
        else:
            print(">>> 状态=%s, 非预期, 看上面的返回。" % code1)

        banner("第8步 若仍未落库 → finalize_via_archive")
        codeN, textN, _, _ = status_of(c, p.id_card, p.name)
        if codeN in ("5", "6"):
            rf = c.finalize_via_archive(pid, sfzh=p.id_card, name=p.name, max_retries=3)
            print("finalize:", rf.success, "| step=%s err=%s" % (rf.step, rf.error))

        banner("第9步 FINAL 状态")
        codeF, textF, _, ccF = status_of(c, p.id_card, p.name)
        created_cc = created_cc or ccF
        print("FINAL: code=%s text=%s contract=%s" % (codeF, textF, created_cc))
        if codeF == "0":
            print("\n★★★ 成功: 居民没动手, 我们把它做到了【已签约】! 破法成立。")
        else:
            print("\n--- 未到已签约 (当前: %s)。记录证据, 继续调。" % (textF or codeF))

    finally:
        banner("第10步 清理")
        if KEEP:
            print("KEEP=1: 保留本次合同, 不清理。contract=%s" % created_cc)
        elif created_cc:
            try:
                codeC, _, _, _ = status_of(c, p.id_card, p.name)
                if codeC == "0":
                    c.void_signing(created_cc)
                    print("已作废 (status=0):", created_cc)
                okd = c.delete_signing(created_cc)
                print("已删除本次合同:", created_cc, "->", okd)
            except Exception as e:
                print("清理异常 (请手工核对):", e)
        else:
            print("无新建合同, 无需清理。")
        print("\n实验结束。")


if __name__ == "__main__":
    main()
