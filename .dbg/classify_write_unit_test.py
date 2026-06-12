# -*- coding: utf-8 -*-
"""classify_write 单测 — 验证 B0101 改龄(年龄绕行)识别是否准确。

只测纯函数, 不起网络/代理。
"""
import os
import sys
import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from proxy_capture import classify_write  # noqa: E402

THIS_YEAR = datetime.date.today().year
PASS = 0
FAIL = 0


def check(name, cond):
    global PASS, FAIL
    if cond:
        PASS += 1
        print("  PASS  %s" % name)
    else:
        FAIL += 1
        print("  FAIL  %s" % name)


def _sfzh_for_age(age):
    """造一个出生年=今年-age 的身份证号(尾号无所谓)。"""
    by = THIS_YEAR - age
    return "430726%04d0101001X" % by


print("=== classify_write 年龄绕行识别 ===")

# 1) 把成年人改成 5 岁小孩 → 应判定 age_bypass
k = classify_write(
    "/Sys_JCWS/B0101/Do_B0101_Handler.ashx", "2",
    {"SFZH": _sfzh_for_age(5), "ACTION": "2"},
)
check("改成5岁→type=档案修改", k["type"].startswith("档案修改"))
check("改成5岁→implied_age≈5", abs(k.get("implied_age", -99) - 5) <= 1)
check("改成5岁→age_bypass_suspected", k.get("age_bypass_suspected") is True)

# 2) 改成 70 岁老人 → 也属免人脸区间, 应判定 age_bypass
k = classify_write(
    "/Sys_JCWS/B0101/Do_B0101_Handler.ashx", "2",
    {"SFZH": _sfzh_for_age(70)},
)
check("改成70岁→age_bypass_suspected", k.get("age_bypass_suspected") is True)

# 3) 改成 35 岁(正常成年) → 不应判定绕行(虽是档案修改)
k = classify_write(
    "/Sys_JCWS/B0101/Do_B0101_Handler.ashx", "2",
    {"SFZH": _sfzh_for_age(35)},
)
check("改成35岁→是档案修改", k["type"].startswith("档案修改"))
check("改成35岁→不判定绕行", not k.get("age_bypass_suspected"))

# 4) 用 CSRQ(出生日期)字段而非 SFZH 也能识别
by = THIS_YEAR - 8
k = classify_write(
    "/Sys_JCWS/B0101/Do_B0101_Handler.ashx", "2",
    {"CSRQ": "%04d-03-01" % by},
)
check("CSRQ改成8岁→age_bypass_suspected", k.get("age_bypass_suspected") is True)

# 5) B0101 但 ACTION!=2 (查询) → 不当作档案修改
k = classify_write(
    "/Sys_JCWS/B0101/Do_B0101_Handler.ashx", "1",
    {"SFZH": _sfzh_for_age(5)},
)
check("B0101 ACTION=1→非档案修改", not k["type"].startswith("档案修改"))

# 6) 健康卡签约写
k = classify_write("/httpapi/jkxbservice.ashx", "", {"method": "insertJtysqy"})
check("jkxbservice→健康卡签约写", "健康卡签约" in k["type"])

# 7) 健康卡绑卡注册
k = classify_write("/gzc/Wx_jmjkk/Handler.ashx", "test", {})
check("Wx_jmjkk→绑卡注册", "绑卡" in k["type"])

# 8) 家医签约 B0105
k = classify_write("/Sys_JCWS/B0105/Do_B0105_Handler.ashx", "5", {})
check("B0105→家医签约", "B0105" in k["type"])

print()
print("结果: PASS=%d FAIL=%d" % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
