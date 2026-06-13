# -*- coding: utf-8 -*-
"""【闭环验证】居民端已造出一个"居民申请(6)"(魏忠忠), 现在用医生账号确认它 → 看是否变"已签约"。

这一步【不创建新数据】, 只确认刚才居民端真实发起的那一条。
若成功 = 整条链路打通:
    居民端 insertJtysqy(b0105_13=6) → 居民申请(6) → 医生 ACTION=9 确认 → 已签约。
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
TARGET_NAME = os.environ.get("TARGET_NAME", "魏忠忠")
SUBORG = os.environ.get("SUBORG", "431122100002004")


def banner(t):
    print("\n" + "=" * 56 + "\n " + t + "\n" + "=" * 56)


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
        print("二维码失败:", err)
        return False
    wait_s = int(os.environ.get("QR_WAIT", "900"))
    print(">>> 二维码已存: %s  请扫码 (最多 %d 秒)" % (QR_PATH, wait_s))
    deadline = time.time() + wait_s
    last = 0
    while time.time() < deadline:
        code, m = c.qr_login_query()
        if code == 0:
            ok2, info = c.qr_login_finalize()
            print("登录完成:", ok2, "|", info)
            if not c.org_code:
                try:
                    orgs = c.get_org_tree("0")
                    if orgs:
                        c._drill_org_tree(orgs)
                except Exception:
                    pass
            print("org_code=%s doctor=%s" % (c.org_code, c.doctor_name))
            return bool(ok2 and c.logged_in and not c.qr_pending)
        now = time.time()
        if now - last > 30:
            print("...等待扫码 (剩 %d 秒)" % int(deadline - now))
            last = now
        time.sleep(3)
    print("超时未扫码")
    return False


def find_target(c):
    """在医生可见范围里找到 TARGET_NAME 的【居民申请(6)】。返回 Patient 或 None。"""
    for oc in (c.org_code, SUBORG, ""):
        for page in (1, 2, 3):
            try:
                pts, total = c.query_patients(status="6", org_code=oc, page=page)
            except Exception as e:
                print("query(oc=%s,p=%s)异常: %s" % (oc, page, e))
                continue
            print("查居民申请(6) oc=%s page=%s -> %d 人 (total=%s)" % (
                oc or "(默认)", page, len(pts), total))
            for p in pts:
                if p.name == TARGET_NAME:
                    return p
            if len(pts) < 1 or page * 20 >= int(total or 0):
                break
    return None


def main():
    c = PH3Client()
    if not do_login(c):
        print("\n登录未完成, 中止。")
        return

    banner("找 %s 的居民申请(6)" % TARGET_NAME)
    p = find_target(c)
    if not p:
        print(">>> 没在居民申请(6)列表里找到 %s。" % TARGET_NAME)
        print(">>> 可能在别的机构/分页, 或 ggws 侧还没同步。打印第1页看看:")
        pts, _ = c.query_patients(status="6", page=1)
        for x in pts[:20]:
            print("   ", x.name, "person_id=", x.person_id, "cc=", x.contract_code)
        return

    print("找到: %s person_id=%s contract=%s status=%s" % (
        p.name, p.person_id, p.contract_code, p.status_text))

    banner("发起前: 读该人签约记录")
    recs = c.list_personal_b0105(p.person_id)
    cc = p.contract_code
    for r in recs:
        print("   contract=%s status=%s start=%s" % (
            r.get("contract_code"), r.get("status_text"), r.get("agreement_start")))
        if r.get("status_text") == "居民申请":
            cc = r.get("contract_code") or cc
    print("将确认的合同号:", cc)

    banner("医生确认 (ACTION=9, STATUS=1)")
    # 直接抓原始返回
    try:
        resp = c.session.post(
            c._url("/Sys_JCWS/B0105/Do_B0105_Handler.ashx"),
            params={"ACTION": "9"},
            data={"STATUS": "1", "REMARK": "", "GUID": cc, "PERSONID": p.person_id},
            headers=c._csrf_header(),
            timeout=c._timeout,
        )
        print("raw:", resp.status_code, "|", resp.text.strip()[:200])
    except Exception as e:
        print("确认异常:", e)

    banner("确认后: 再读状态")
    time.sleep(1)
    recs2 = c.list_personal_b0105(p.person_id)
    final = ""
    for r in recs2:
        print("   contract=%s status=%s" % (
            r.get("contract_code"), r.get("status_text")))
        if r.get("contract_code") == cc:
            final = r.get("status_text")
    print("\n该合同最终状态:", final or "(未找到)")
    if final == "已签约":
        print("\n★★★ 闭环成立: 居民申请(6) + 医生确认 → 已签约!")
    else:
        print("\n--- 仍未到已签约, 见上面原始返回。")


if __name__ == "__main__":
    main()
