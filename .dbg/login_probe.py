# -*- coding: utf-8 -*-
"""快速探测：给定账号能否直接登录 3.0 系统，还是需要扫码(QR 2FA)。

只做登录 + 读状态，不做任何写操作。
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ph3_api import PH3Client  # noqa: E402

BASE = "https://ggws.hnhfpc.gov.cn"
ACCOUNT = "431122012"
PASSWORD = "wei1147609775@"


def main():
    c = PH3Client()
    print("=== 登录探测 ===")
    print("base_url =", BASE)
    print("account  =", ACCOUNT)
    ok, msg = c.login(BASE, ACCOUNT, PASSWORD)
    print("login ok =", ok)
    print("login msg=", msg)
    print("logged_in   =", getattr(c, "logged_in", None))
    print("qr_pending  =", getattr(c, "qr_pending", None))
    print("org_code    =", getattr(c, "org_code", None))
    print("org_name    =", getattr(c, "org_name", None))
    print("doctor_name =", getattr(c, "doctor_name", None))
    print("ready       =", c.ready if hasattr(c, "ready") else "n/a")
    if getattr(c, "qr_pending", False):
        print("\n>>> 结论: 该账号需要扫码二维码(2FA), 无法在后台自动完成登录。")
    elif ok and getattr(c, "logged_in", False):
        print("\n>>> 结论: 该账号可直接账号密码登录, 可继续做实验。")
    else:
        print("\n>>> 结论: 登录失败, 见上面 msg。")


if __name__ == "__main__":
    main()
