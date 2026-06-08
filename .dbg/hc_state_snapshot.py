# -*- coding: utf-8 -*-
"""健康卡状态快照 + 前后对比 (命令行版, 逻辑复用 hc_diagnostics.py).

图形界面里同样的能力在 [状态取证] 标签; 此 CLI 便于开发/排查。全程只读。

用法:
  python hc_state_snapshot.py snap <openid> [outfile] [--raw]
  python hc_state_snapshot.py diff <before.json> <after.json>
"""
import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from hc_api import HealthCardClient  # noqa: E402
import hc_diagnostics as diag  # noqa: E402

SNAP_DIR = os.path.join(os.path.dirname(__file__), "snapshots")


def snapshot(openid, outfile=None, raw=False):
    client = HealthCardClient()
    client._timeout = 30
    ok, msg = client.connect(openid)
    print("[connect] %s — %s" % ("OK" if ok else "FAIL", msg))
    if not ok:
        return None
    snap = diag.capture_snapshot(client, raw=raw, log=lambda m: print(m))
    if not outfile:
        os.makedirs(SNAP_DIR, exist_ok=True)
        outfile = os.path.join(SNAP_DIR, time.strftime("%Y%m%d_%H%M%S") + ".json")
    diag.save_snapshot(snap, outfile)
    print("\n[saved] %s  (脱敏=%s)" % (outfile, "否" if raw else "是"))
    return outfile


def diff(before_file, after_file):
    b = diag.load_snapshot(before_file)
    a = diag.load_snapshot(after_file)
    lines, _summary = diag.diff_snapshots(b, a)
    print("\n".join(lines))


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return
    cmd = sys.argv[1]
    if cmd == "snap":
        if len(sys.argv) < 3:
            print("用法: snap <openid> [outfile] [--raw]")
            return
        openid = sys.argv[2]
        raw = "--raw" in sys.argv
        outfile = next((a for a in sys.argv[3:] if not a.startswith("--")), None)
        snapshot(openid, outfile, raw)
    elif cmd == "diff":
        if len(sys.argv) < 4:
            print("用法: diff <before.json> <after.json>")
            return
        diff(sys.argv[2], sys.argv[3])
    else:
        print(__doc__)


if __name__ == "__main__":
    main()
