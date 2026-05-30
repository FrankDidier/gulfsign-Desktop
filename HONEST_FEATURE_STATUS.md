# 湾流签约助手 — 真实功能状态披露 (v3.0.0+)

本文档诚实记录 5 项交付功能在生产代码 (`app.py` 入口) 中的真实就绪程度,
取代营销文案。审计涵盖 ~150 个源文件; 结论以代码 + 行号为证据。

---

## 1. 核心签名系统 — **REAL** ✅

**生产路径**: `app.py` → `_on_start_signing()` → `_batch_sign_worker()`
→ `PH3Client.sign_one()` (生产 API + SM4/SM3 国密) →
`_on_sign_result()` → `SuccessLogger.log_success / log_failure`
→ `logs/{成功|失败}/YYYYMMDD/<account>.xlsx`.

- 公卫3.0 真实接口 (`B0105 ACTION=10/9/3/11`, `JKDA Do_Query_Handler`).
- 健康卡真实接口 (`jkdaservice.ashx`, MITM 抓 OpenID).
- 家庭医生家庭批量发起 (B0105 ACTION=10).
- 二维码 2FA 由 `PH3Client.qr_pending` + `_ensure_session_usable` 在
  API 与 UI 双层强制, 不会让会话以 "半成品" 状态发起签约.
- 报告 honest semantics: `confirm` 失败时不再静默标记为 `step="initiate"`
  / `success=True`; 家庭批量在创建结果与请求人数不一致时报失败/部分失败.

> **批量并发**: `BatchProcessor (workers=20, batch=2)` 是早期 client.exe
> 的兼容实现, 当前 UI 实际使用顺序循环 + delay (`_batch_sign_worker`),
> 与原 client.exe 行为一致 (用户可控制延迟). 20 worker pool 在
> `BatchProcessor.process()` 单测中已覆盖, 但生产 UI 没启用并发签约 —
> 这是为了避免在生产数据上瞬间产生大量请求被反作弊拦截.

## 2. 年龄验证绕过 — **REAL (前端检测) / OFF (服务端写入)** ⚠️

- **检测能力 (REAL)**: `sign_engine.needs_age_bypass(sfzh)` + 校验位算法
  (GB11643 weights `[7,9,10,5,8,4,2,1,6,3,7,9,10,5,8,4,2]`, mod 11 →
  `"10X98765432"`) 经独立单测验证, 生成的 SFZH 校验位正确, UI 在签约
  列表中标记 "需绕行" 列.
- **服务端写入 (DEAD CODE)**: `SigningEngine.prepare_age_bypass()` 会调用
  `ph3.modify_archive` 真实修改 3.0 系统档案, 但目前 **未在 `app.py`
  的任何用户路径中被调用**. 历史评估 (`historical_limitations_verification_report.txt`)
  亦表明 3.0 服务端会拒绝实名/已访问居民的 SFZH 修改请求. 因此年龄绕行
  在产品中只作为 "提示是否需要现场人脸" 的标记功能存在, 而不会真的去改档案.

## 3. 高级分析工具 — **SIMULATION ONLY** ❌

以下五个模块 **不联网, 不查 SQL, 不调 PH3 API**, 输出来自硬编码字典与
模式生成器:

| 模块 | 性质 | 证据 |
|------|------|------|
| `ultimate_status_conversion_explorer.py` | FAKE | `_execute_test` 注释 "模拟测试执行", `success = method_config.get("expected_result", False)` |
| `ultimate_realname_id_modification_explorer.py` | FAKE | 同上, 测试用例预设 `expected_result` 决定结果 |
| `ultimate_family_member_removal_analyzer.py` | FAKE | `analysis_map` 硬编码 `TS001`–`TS010` 结论 |
| `ultimate_sjfx_field_discovery_explorer.py` | FAKE | `_execute_discovery_technique` 注释 "模拟执行", 字段从 `_generate_official_fields()` 等返回 |
| `comprehensive_solution_matrix.py` | WRAPPER | 读上面四个的 `*_report.json` 静态文件; `reports_dir` 硬编码绝对路径 |

JSON 报告 (`ultimate_*_report.json`) 是 **2026-05-25 一次性运行** 上述
模拟器的输出, 不是真实采集的服务器遥测.

**`app.py` 没有任何按钮或代码路径调用这些模块**.
另一个独立 GUI (`gulfsign_comprehensive_app.py`) 含有按钮, 但调用了不存在
的方法名 (`run_comprehensive_tests()` vs 真实 `run_comprehensive_simulation()` 等),
按下会抛 AttributeError.

> 用户期待的 "状态转换 / 实名修改 / 家庭成员移除分析" 在历史上是真有
> 探针脚本运行过的 (位于 `scripts/ph3_*_probe.py`, 它们 **会** 真实调用
> 服务器), 但 `ultimate_*` 文件并未真正复用那些探针, 而是写了一个
> 静态的 "结论模拟器".

## 4. 安全评估 — **SIMULATION ONLY** ❌

| 模块 | 性质 |
|------|------|
| `penetration_testing_simulation_framework.py` | FAKE — `simulated_responses` 硬编码 SQLi 始终 "vulnerable=True" |
| `advanced_attack_simulation_scenarios.py` | FAKE — 假端点 `/api/contract/status/update` 等不存在 |
| `comprehensive_age_bypass_validation.py` | HALF-REAL — 真跑本地校验码逻辑, 但用了与 `sign_engine.py` 不同的算法实现, 且不联网 |
| `comprehensive_security_assessment_report.md` | FAKE-as-assessment — 把模拟数据写得像真实漏洞结论 (CVSS 8.5 等) |

**没有任何 HTTP 请求真的发往 `ggws.hnhfpc.gov.cn`** —
所谓 "渗透测试" 是预设字典的本地遍历.

## 5. 全面报告 (Excel 日志) — **REAL (修复后)** ✅

修复前: `app.py` 从未调用 `SuccessLogger`, 实际签约不写 Excel.
修复后:

- `SuccessLogger` 增加 `log_failure` + `logs/失败/YYYYMMDD/<account>.xlsx`
  目录, 与 `logs/成功` 对称.
- `app.py._on_sign_result` 在每条结果回调里写一条 row.
- `_safe_account` 归一化文件名, 避免 dict 等脏输入产生 `{...}.xlsx` 这种
  历史问题.
- `clear_logs` 修复 `timedelta` NameError.
- `get_failure_logs()` 与 `get_success_logs()` 共用读取实现.

UI 暂未提供 "在程序内查看 Excel" 的查看器; 用户可直接在文件资源管理器
打开 `logs/` 目录. 这是已知不足, 可在后续版本加 GUI 表格读回.

---

## 一句话总结

- **可投产**: 1 (核心签约), 5 (Excel 日志).
- **可投产但弱化交付**: 2 (年龄绕行 — 仅作为前端提示).
- **明显宣传过度**: 3 (高级分析), 4 (安全评估) — 均为静态/模拟脚本,
  请勿对客户宣称 "实时渗透测试" 或 "实时分析", 它们只是文档/方法论
  + 一次性模拟报告.

如果客户必须要真正的实时分析 / 实时渗透, 应基于 `scripts/ph3_*_probe.py`
重写 `ultimate_*` 模块 — 这些 probe 是真的会发请求并采集数据.
