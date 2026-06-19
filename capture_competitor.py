# -*- coding: utf-8 -*-
"""
竞品全程录制 · 命令行一键版

给客户用的极简版本: 双击配套的「一键录制.bat」(以管理员身份运行) 即可。
脚本会:
  1. 生成并安装本地 CA 证书
  2. 设置系统代理 (127.0.0.1:8888)
  3. 设置证书信任环境变量 (让对方软件的 Python requests 也信任我们)
  4. 打开全程录制, 提示"录制已就绪"
  5. 客户去重启并操作对方软件 (登录 + 签约)
  6. 回到本窗口按回车 → 自动停止、还原系统、把全部日志打包成桌面上的 ZIP

无需任何界面操作, 全程命令行提示。
"""
import os
import sys
import time
import datetime

# 让 Windows 控制台能正确显示中文 (配合 bat 里的 chcp 65001)
try:
    sys.stdout.reconfigure(encoding="utf-8")
    sys.stderr.reconfigure(encoding="utf-8")
except Exception:
    pass

# 保证能 import 到同目录的 proxy_capture.py
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

try:
    from proxy_capture import (
        OpenIDProxy,
        set_system_proxy, clear_system_proxy, install_ca_to_system,
        set_requests_ca_env, clear_requests_ca_env,
    )
except Exception as e:  # pragma: no cover
    print("！无法加载录制模块 (proxy_capture.py)，请确认它和本文件在同一文件夹。")
    print("  错误:", e)
    try:
        input("按回车关闭...")
    except Exception:
        pass
    sys.exit(1)


PORT = 8888
_proxy = None
_trust_on = False
_cleaned = False


def _line(ch="=", n=64):
    print(ch * n)


def _desktop_dir() -> str:
    for cand in (
        os.path.join(os.path.expanduser("~"), "Desktop"),
        os.path.join(os.path.expanduser("~"), "OneDrive", "Desktop"),
        os.path.join(os.path.expanduser("~"), "桌面"),
    ):
        if os.path.isdir(cand):
            return cand
    return os.path.expanduser("~")


def cleanup():
    """还原系统设置 (无论正常结束还是异常退出都执行)。"""
    global _cleaned
    if _cleaned:
        return
    _cleaned = True
    try:
        clear_system_proxy()
    except Exception:
        pass
    if _trust_on:
        try:
            clear_requests_ca_env()
        except Exception:
            pass
    try:
        if _proxy:
            _proxy.stop()
    except Exception:
        pass


def _on_log(msg, tag=""):
    prefix = {
        "ok": "  ✓ ", "err": "  ✗ ", "warn": "  ⚠ ", "info": "    ",
    }.get(tag, "    ")
    # 写请求 / 关键流的实时提示对客户最直观, 保留; 其它噪音降级
    try:
        print(prefix + str(msg))
    except Exception:
        try:
            print(prefix + str(msg).encode("ascii", "replace").decode())
        except Exception:
            pass


def _on_flow(rec):
    hits = rec.get("highlights") or []
    if rec.get("is_write") or hits:
        flag = "  ★关键流" if hits else ""
        try:
            print("    [捕获] #%s  %s %s  ACTION=%s%s" % (
                rec.get("seq"), rec.get("method"), rec.get("path"),
                rec.get("action") or "-", flag,
            ))
        except Exception:
            pass


def main():
    global _proxy, _trust_on

    _line()
    print("            竞品全程录制 · 一键版")
    _line()
    print()
    print("本工具会把对方软件签约时的全部网络流量完整录下来，供我们分析。")
    print("整个过程不影响你正常上网；结束后会自动还原系统设置。")
    print()

    # 默认开启"让对方软件信任证书"(对方软件多为 Python，需要它才能抓到)。
    print("是否需要抓取『对方软件本体』的请求？")
    print("  - 对方签约软件大多是这种情况，建议输入 y")
    print("  - 只想抓网页(浏览器)流量则输入 n")
    try:
        ans = input("请输入 [Y/n] 后回车 (直接回车=Y): ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        ans = "y"
    _trust_on = (ans in ("", "y", "yes"))

    print()
    print("正在启动录制环境，请稍候...")
    _proxy = OpenIDProxy(port=PORT, on_log=_on_log, on_flow=_on_flow,
                         capture_all=True)

    if not _proxy.start():
        print()
        print("！启动失败：端口 %d 可能被占用，或缺少 cryptography 库。" % PORT)
        print("  请关闭其它抓包/代理软件后重试；或确认已用 bat 安装好依赖。")
        try:
            input("按回车关闭...")
        except Exception:
            pass
        return

    # 安装 CA 证书
    if install_ca_to_system(_proxy.ca_cert_path):
        print("  ✓ 本地证书已安装并信任")
    else:
        print("  ⚠ 证书安装可能未成功（如弹出确认请选『是』）")

    # 系统代理
    if set_system_proxy("127.0.0.1", PORT):
        print("  ✓ 系统代理已设置 (127.0.0.1:%d)" % PORT)
    else:
        print("  ✗ 系统代理设置失败")

    # 证书信任环境变量 (增强捕获)
    if _trust_on:
        bundle = _proxy.cert_mgr.ensure_combined_bundle()
        if bundle and set_requests_ca_env(bundle):
            print("  ✓ 已让对方软件信任证书 (增强捕获已开启)")
        else:
            print("  ⚠ 增强捕获设置失败，将仅能抓浏览器流量")

    print()
    _line("-")
    print("  ★★★  录制已就绪 (READY)  ★★★")
    _line("-")
    print()
    print("  现在请按顺序操作：")
    if _trust_on:
        print("   1) ★完全关闭★ 对方软件（如果它已经开着，必须先彻底关掉）")
        print("   2) 重新打开对方软件，登录（扫码）")
        print("   3) 像平时一样用它完成一次签约，直到提示成功")
    else:
        print("   1) 打开浏览器/对方软件，登录")
        print("   2) 像平时一样完成一次签约，直到提示成功")
    print()
    print("  操作过程中，下面会实时显示捕获到的请求（带 ★关键流 的最重要）。")
    print()
    print("  全部做完后，回到本窗口，按【回车】键结束录制并打包。")
    print()

    try:
        input(">>> 完成签约后，在此按【回车】结束录制 <<<\n")
    except (EOFError, KeyboardInterrupt):
        print("\n收到结束信号...")

    print()
    print("正在结束录制并还原系统设置...")

    summary = {}
    try:
        summary = _proxy.session_summary()
    except Exception:
        pass

    cleanup()

    total = summary.get("total", 0)
    writes = summary.get("writes", 0)
    highlights = summary.get("highlights", 0)
    print("  ✓ 系统设置已还原（代理、证书信任已取消）")
    print("  录制结果：共 %d 条流量（写请求 %d 条，关键流 %d 条）"
          % (total, writes, highlights))
    print()

    if total == 0:
        print("  ⚠ 没有录到任何公卫系统流量。常见原因：")
        print("     - 对方软件在『录制已就绪』之前就开着（必须录制就绪后再重启它）")
        print("     - 这次没有真正发起签约")
        print("  可以直接再运行一次本工具重试。")
        print()

    # 打包 ZIP 到桌面
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    zip_path = os.path.join(_desktop_dir(), "竞品录制_%s.zip" % ts)
    ok = False
    try:
        ok = _proxy.export_session_zip(zip_path)
    except Exception as e:
        print("  打包出错:", e)

    _line()
    if ok and os.path.exists(zip_path):
        size_kb = os.path.getsize(zip_path) / 1024.0
        print("  ✓ 录制包已生成：")
        print()
        print("      %s" % zip_path)
        print()
        print("      （大小约 %.1f KB）" % size_kb)
        print()
        print("  请把【这个 ZIP 文件】发回给我们即可。")
        print("  它就在你的【桌面】上，文件名是上面那个。")
    else:
        print("  ⚠ 未能生成 ZIP（可能这次没录到东西）。")
        print("  原始文件夹：%s" % getattr(_proxy, "session_dir", "(无)"))
    _line()
    print()

    try:
        input("按回车关闭本窗口...")
    except Exception:
        pass


if __name__ == "__main__":
    import atexit
    atexit.register(cleanup)
    try:
        main()
    except Exception as e:
        print("\n！运行出错：", e)
        cleanup()
        try:
            input("按回车关闭...")
        except Exception:
            pass
