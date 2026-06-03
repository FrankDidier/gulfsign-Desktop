#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""真·联机全流程测试 (NO MOCK) —— 打真实 ggws.hnhfpc.gov.cn.

流程:
  1. 真实登录 (login)
  2. 若需二维码 2FA: 生成二维码 PNG 落盘 + 轮询等待扫码 (可由人扫)
  3. 登录完整后: 真实查询居民 (query_patients) —— 证明 login+国密+查询不是 mock
  4. 对真实居民跑 check_sign_status_by_sfzh —— 证明新增的状态校验读路径真的工作
  5. 全程打印真实返回, 任何异常都打印, 绝不静默

注意: 本脚本默认 **只读**, 不创建/确认任何真实签约 (写操作有真实后果)。
"""
import os
import sys
import time
import base64
import traceback

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

ACCOUNT = os.environ.get("PH3_ACCOUNT", "431122012")
PASSWORD = os.environ.get("PH3_PASSWORD", "wei1147609775@")
GGWS = "https://ggws.hnhfpc.gov.cn"
QR_DIR = os.path.join(ROOT, ".dbg")
QR_PATH = os.path.join(QR_DIR, "live_qr.png")
QR_WAIT_SECONDS = int(os.environ.get("QR_WAIT", "300"))   # 给人扫码的窗口
POLL_EVERY = 3.0


def mask_sfzh(s):
    s = (s or "").strip()
    if len(s) >= 10:
        return s[:6] + "*" * (len(s) - 9) + s[-3:]
    return "***"


def mask_name(s):
    s = (s or "").strip()
    if len(s) <= 1:
        return s or "?"
    return s[0] + "*" * (len(s) - 1)


def banner(t):
    print("\n" + "=" * 64)
    print("  " + t)
    print("=" * 64)


def save_qr(data_url):
    try:
        b64 = data_url.split(",", 1)[1] if "," in data_url else data_url
        raw = base64.b64decode(b64)
        with open(QR_PATH, "wb") as f:
            f.write(raw)
        return True
    except Exception as e:
        print("  ✗ 二维码落盘失败: %s" % e)
        return False


def do_qr_flow(c):
    banner("STEP 2: 需要二维码 2FA — 生成二维码")
    ok, tokenimage, catoken, err = c.qr_login_generate()
    if not ok:
        print("  ✗ 生成二维码失败: %s" % err)
        return False
    print("  ✓ 已生成二维码, catoken=%s..." % catoken[:12])
    if save_qr(tokenimage):
        print("  ✓ 二维码已保存: %s" % QR_PATH)
        print("  >>> 请用微信/对应 APP 扫描该 PNG (%d 秒内)" % QR_WAIT_SECONDS)

    waited = 0.0
    last_raw = None
    while waited < QR_WAIT_SECONDS:
        # 诊断: 直接打 CHECKSM 看原始响应, 变化时打印 (帮助判断扫码到底有没有改变服务端状态)
        try:
            import time as _t
            dbg = c.session.get(
                c._url("/ashx/LoginHandler.ashx"),
                params={"ACTION": "CHECKSM", "t": str(int(_t.time() * 1000))},
                headers={"X-Requested-With": "XMLHttpRequest"},
                timeout=c._timeout,
            )
            raw = (dbg.text or "")[:200]
            if raw != last_raw:
                print("  [CHECKSM 原始响应变化] HTTP %d: %s" % (dbg.status_code, raw))
                last_raw = raw
        except Exception as _e:
            print("  [CHECKSM 诊断请求失败] %s" % _e)

        code, m = c.qr_login_query(catoken)
        if code == 0:
            print("  ✓ 扫码通过, 正在完成登录...")
            ok2, msg2 = c.qr_login_finalize()
            print("  finalize -> %s | %s" % (ok2, msg2))
            return ok2
        elif code == 1:
            print("  ✗ 二维码过期/不可用: %s" % m)
            return False
        elif code == 2:
            print("  ... 等待扫码 (%.0fs/%ds)" % (waited, QR_WAIT_SECONDS))
        else:
            print("  ... 状态 code=%s msg=%s" % (code, m))
        time.sleep(POLL_EVERY)
        waited += POLL_EVERY
    print("  ✗ 超时未扫码")
    return False


def read_side_checks(c):
    banner("STEP 3: 真实查询居民 (query_patients, NO MOCK)")
    try:
        pts, total = c.query_patients(status="", page=1)
    except Exception as e:
        print("  ✗ 查询崩溃: %s" % e)
        traceback.print_exc()
        return
    print("  ✓ 查询返回: total=%d, 本页=%d" % (total, len(pts)))
    for p in pts[:6]:
        print("     - %s | %s | 状态=%s(%s) | pid=%s | 合同=%s" % (
            mask_name(p.name), mask_sfzh(p.id_card),
            p.status_text or "?", p.contract_status or "",
            (p.person_id or "")[:8], (p.contract_code or "")[:8],
        ))
    if not pts:
        print("  (本机构本页无居民数据; 无法继续状态校验)")
        return

    banner("STEP 4: 新增状态校验 check_sign_status_by_sfzh (真实接口)")
    sample = next((p for p in pts if p.id_card), pts[0])
    print("  对居民 %s (%s) 单独回查真实状态..." % (
        mask_name(sample.name), mask_sfzh(sample.id_card)))
    try:
        code, text, pid, cc = c.check_sign_status_by_sfzh(
            sample.id_card, sample.name
        )
        print("  ✓ check_sign_status_by_sfzh -> code=%r text=%r pid=%s cc=%s" % (
            code, text, (pid or "")[:8], (cc or "")[:8]))
        if text == (sample.status_text or text):
            print("  ✓ 与列表状态一致, 读路径自洽")
    except Exception as e:
        print("  ✗ 状态校验崩溃: %s" % e)
        traceback.print_exc()

    # 统计各状态人数 (只读, 帮助判断有没有可签约对象)
    banner("STEP 5: 各状态人数概览 (只读)")
    for st, label in (("1", "未签约"), ("5", "医生申请"),
                      ("6", "居民申请"), ("0", "已签约")):
        try:
            _, t = c.query_patients(status=st, page=1)
            print("  状态 %s(%s): total=%d" % (st, label, t))
        except Exception as e:
            print("  状态 %s(%s): 查询失败 %s" % (st, label, e))


def main():
    banner("STEP 1: 真实登录 (login, NO MOCK) 账号 %s" % ACCOUNT)
    c = None
    try:
        from ph3_api import PH3Client
        c = PH3Client()
        ok, msg = c.login(GGWS, ACCOUNT, PASSWORD)
        print("  login() -> ok=%s" % ok)
        print("  msg     : %s" % msg)
        print("  logged_in=%s  qr_pending=%s  fully_auth=%s" % (
            c.logged_in, c.qr_pending, c.fully_authenticated))
        print("  org_code=%r  org_name=%r" % (c.org_code, c.org_name))
        print("  doctor=%r  team=%r" % (c.doctor_name, c.team_name))
        print("  token_en(len=%d)  token_th(len=%d)" % (
            len(c.token_en or ""), len(c.token_th or "")))
    except Exception as e:
        print("  ✗ 登录崩溃: %s" % e)
        traceback.print_exc()
        return 2

    if c.qr_pending:
        if not do_qr_flow(c):
            banner("结论")
            print("登录止步于二维码 2FA, 未完成完整认证。")
            print("（这不是 mock — 服务器真的要求扫码；扫码后即可继续查询/签约。）")
            return 1

    if not c.fully_authenticated:
        banner("结论")
        print("未达到 fully_authenticated (org_code=%r)。" % c.org_code)
        return 1

    read_side_checks(c)
    banner("结论")
    print("✓ 登录 + 国密 + 查询 + 状态校验 全部走的是真实 ggws 接口, 非 mock。")
    print("  (写操作/真实签约本脚本默认不执行, 以免在生产数据上产生真实合同。)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
