# -*- coding: utf-8 -*-
"""健康卡状态取证 — 快照 + 前后对比 (只读)。

把"绑卡/签约前后"健康卡平台返回的**原始字段**完整抓下来并对比, 用来
*精确看出*到底哪些字段/状态发生了变化 (而不是靠猜)。全程只读 (只发 GET
查询接口), 不写任何数据。

被 app.py (图形界面 [状态取证] 标签) 与 .dbg/hc_state_snapshot.py (命令行)
共同复用, 保证两边逻辑一致。
"""
import json
import re
import time

# 状态类字段 (对比时高亮) —— 这些变化最能说明"已生效数据"是怎么产生的
STATUS_KEYS = {
    "contract_states", "qyzfbs", "rpc", "status", "states", "qyzt",
}
# 需要脱敏的字段名子串 (落盘前)
PII_KEY_HINTS = ("idcard", "sfzh", "身份证", "phone", "mobile", "tel", "手机")
_ID18 = re.compile(r"\d{15}(\d{2}[0-9Xx])?")


def _mask_scalar(v):
    if not isinstance(v, str):
        return v
    s = v.strip()
    if len(s) >= 11 and _ID18.fullmatch(s):
        return s[:3] + "*" * (len(s) - 7) + s[-4:]
    return v


def mask_obj(obj, enable=True):
    """递归脱敏: 命中 PII 字段名的值, 以及形如身份证的字符串。"""
    if not enable:
        return obj
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            kl = str(k).lower()
            if (any(h in kl for h in PII_KEY_HINTS)
                    and isinstance(v, str) and len(v) >= 7):
                out[k] = v[:3] + "*" * max(0, len(v) - 7) + v[-4:]
            else:
                out[k] = mask_obj(v, enable)
        return out
    if isinstance(obj, list):
        return [mask_obj(x, enable) for x in obj]
    return _mask_scalar(obj)


def _get_json(client, url, params):
    try:
        r = client.session.get(
            url, params=params, headers=client._jkxb_headers(),
            timeout=client._timeout,
        )
        try:
            return {"http": r.status_code, "json": r.json()}
        except Exception:
            return {"http": r.status_code, "text": r.text[:500]}
    except Exception as e:
        return {"error": str(e)}


def capture_snapshot(client, raw=False, log=None):
    """对一个**已连接**的 HealthCardClient 抓取完整状态快照。

    返回一个可 json 序列化的 dict。``log(msg)`` 可选, 用于进度回显。
    """
    def _log(m):
        if log:
            try:
                log(m)
            except Exception:
                pass

    if not getattr(client, "connected", False):
        raise RuntimeError("健康卡平台未连接 — 请先用 OpenID 连接")

    openid = getattr(client, "openid", "") or ""
    snap = {
        "ts": time.strftime("%Y-%m-%d %H:%M:%S"),
        "openid_tail": openid[-6:],
        "cards": [],
    }

    # 原始 newlist
    nl = _get_json(
        client, client._svc_url(),
        {"ACTION": "newlist", "Openid": openid, "token": client.jwt_token},
    )
    snap["newlist_raw"] = mask_obj(nl, not raw)

    cards = client.get_card_list()
    _log("卡列表: %d 张" % len(cards))

    for c in cards:
        hcid = c.health_card_id
        entry = {
            "healthCardId": hcid,
            "name": c.name,
            "relation": c.relation,
            "age": c.age,
            "rpc": c.rpc,
        }
        si = _get_json(
            client, client._jkxb_url(),
            {"action": "querybyidcardqyjg", "healthCardId": hcid},
        )
        entry["signing_info_raw"] = mask_obj(si, not raw)

        person_id = ""
        sj = si.get("json") if isinstance(si, dict) else None
        if isinstance(sj, dict):
            inner = sj.get("data")
            row = None
            if isinstance(inner, list) and inner:
                row = inner[0]
            elif isinstance(inner, dict):
                row = inner
            if isinstance(row, dict):
                person_id = row.get("GUID", "") or row.get("personId", "")
        entry["person_id"] = person_id

        if person_id:
            ct = _get_json(
                client, client._jkxb_url(),
                {"action": "queryqyxxall", "personId": person_id,
                 "healthCardId": hcid},
            )
            entry["contracts_raw"] = mask_obj(ct, not raw)

        snap["cards"].append(entry)
        _log("  - %s (关系=%s, rpc=%s)" % (c.name, c.relation or "?", c.rpc))

    return snap


def save_snapshot(snap, path):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(snap, f, ensure_ascii=False, indent=2)
    return path


def load_snapshot(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


# --------------------------------------------------------------------------
# Diff
# --------------------------------------------------------------------------

def _flatten(obj, prefix=""):
    out = {}
    if isinstance(obj, dict):
        for k, v in obj.items():
            out.update(_flatten(v, "%s.%s" % (prefix, k) if prefix else str(k)))
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            out.update(_flatten(v, "%s[%d]" % (prefix, i)))
    else:
        out[prefix] = obj
    return out


def _index_cards(snap):
    return {c.get("healthCardId", "?"): c for c in snap.get("cards", [])}


def diff_snapshots(before, after):
    """对比两份快照, 返回 (lines, summary_dict)。

    ``lines`` 为可直接打印/写文件的中文文本行列表;
    ``summary_dict`` 给出机器可读的统计 (新增卡数/状态变化数 等)。
    """
    lines = []
    L = lines.append

    L("=" * 74)
    L("  健康卡状态取证 — 前后对比报告")
    L("  BEFORE 快照时间: %s" % before.get("ts"))
    L("  AFTER  快照时间: %s" % after.get("ts"))
    L("=" * 74)

    bcards, acards = _index_cards(before), _index_cards(after)
    bset, aset = set(bcards), set(acards)
    added = sorted(aset - bset)
    removed = sorted(bset - aset)

    summary = {
        "added_cards": len(added),
        "removed_cards": len(removed),
        "status_changes": 0,
        "other_changes": 0,
        "cards_changed": 0,
    }

    if added:
        L("")
        L("[+ 新增的卡] (说明发生了绑卡)")
        for hcid in added:
            L("    + %s  %s" % (hcid[:14], acards[hcid].get("name")))
    if removed:
        L("")
        L("[- 消失的卡] (解绑?)")
        for hcid in removed:
            L("    - %s  %s" % (hcid[:14], bcards[hcid].get("name")))

    L("")
    L("[~ 各卡字段变化]")
    any_change = False
    for hcid in sorted(bset & aset):
        fb = _flatten(bcards[hcid])
        fa = _flatten(acards[hcid])
        rows = []
        for k in sorted(set(fb) | set(fa)):
            vb, va = fb.get(k, "∅"), fa.get(k, "∅")
            if vb != va:
                klow = k.lower()
                hot = any(sk in klow for sk in STATUS_KEYS)
                rows.append((hot, k, vb, va))
        if rows:
            any_change = True
            summary["cards_changed"] += 1
            name = acards[hcid].get("name", "?")
            L("")
            L("  ● %s  (%s)" % (name, hcid[:14]))
            for hot, k, vb, va in sorted(rows, key=lambda r: (not r[0], r[1])):
                if hot:
                    summary["status_changes"] += 1
                    flag = "  ★状态"
                else:
                    summary["other_changes"] += 1
                    flag = ""
                L("      %-46s %s  →  %s%s" % (k, vb, va, flag))

    if not any_change and not added and not removed:
        L("    (无任何变化 — 两次快照完全相同)")

    L("")
    L("=" * 74)
    L("  小结: 新增卡 %d 张 / 状态变化 %d 处 / 其它字段变化 %d 处"
      % (summary["added_cards"], summary["status_changes"],
         summary["other_changes"]))
    L("  解读: 重点看带 ★状态 的行 —— CONTRACT_STATES/qyzfbs 由")
    L("        1(未签)→6(居民申请)→0(已生效) 的轨迹, 就是'已生效数据'的来源。")
    L("=" * 74)
    return lines, summary
