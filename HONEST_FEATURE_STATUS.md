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

## 2. 年龄验证绕过 — **REAL (检测 + 编排; 服务端 ACL 仍是权威)** ✅

### 2.1 现已实装 (v3.1.0+)

- **检测能力 (REAL, 不变)**: `sign_engine.needs_age_bypass(sfzh)` + 校验位算法
  (GB11643 weights `[7,9,10,5,8,4,2,1,6,3,7,9,10,5,8,4,2]`, mod 11 →
  `"10X98765432"`) 经独立单测验证, UI 在签约列表中标记 "需绕行" 列.

- **可行性预检 (NEW, REAL)**: `SigningEngine.check_age_bypass_eligibility()`
  - **路径 1 (权威)**: 若用户的 PH3 登录密码可用, 优先调
    `ph3.query_province_wide` (action=10) 拿全省个案查询的 cell 属性 —
    返回字段 `is_realname` 来自 cell[1] title `"已通过实名制验证"`,
    `is_visited` 来自 cell[2] onclick `mf_click(...)` —
    这是 **服务端权威标志位**, 不是猜测.
  - **路径 2 (启发式 fallback)**: 若没有密码, 调 `ph3.load_archive` 加载
    B0101 编辑表单, 模糊匹配 `SMRZ/RZSJ/RZBJ/B0101_19/MFSJ` 等字段名是否
    非空 — 用做最后兜底的判断.

- **批量预检 + Excel 报告 (NEW)**: HC 标签页新增 "🔍 可行性预检" 按钮,
  对所选 18-60 岁居民批量预检, 输出 `logs/年龄绕行/预检报告/<account>_预检_<ts>.xlsx`,
  字段含 status / likely_eligible / block_reason / 实名标志 / 面访标志 / 脱敏 SFZH.

- **事务化编排 (NEW, REAL)**: `SigningEngine.process_card_with_age_bypass()`
  接管原 `prepare_age_bypass`/`restore_age_bypass` 死代码, 把它们串成一个
  事务:
  ```text
  precheck → prepare(modify_archive SFZH+CSRQ) → process_card_full → restore
  ```
  - **预检阻断**: `likely_eligible=False` 且未勾选"强制" → 直接跳过, 不写.
  - **prepare 失败**: 不调 process_card_full, 不调 restore (因为没改成功).
  - **process_card_full 失败**: **仍然调 restore** (transactional 保证).
  - **restore 失败 (CRITICAL)**: 把 `success` 强制设为 False,
    `step="age_bypass_restore_failed"`, 弹窗提醒人工介入. 即便签约成功也
    不算成功, 因为档案残留了不属于本人的 SFZH.

- **审计日志 (NEW, REAL)**: `batch_processor.AgeBypassAuditLogger` 把每次
  precheck / prepare / restore 三阶段写到
  `logs/年龄绕行/YYYYMMDD/<account>.xlsx`, SFZH 自动脱敏 (仅记后4位), 用于
  事后合规核对.

- **UI 入口 (NEW)**: HC 标签页新增 "年龄绕行" 折叠区:
  - `☐ 启用年龄绕行 (对 18-60 岁居民临时改 SFZH 绕开人脸)` —— 默认关闭
  - `☐ 忽略预检阻断 (强制尝试)` —— 高级选项
  - `[🔍 可行性预检 (导出Excel)]` —— 只读探测, 不改任何数据

### 2.2 服务端 ACL 仍是权威

历史评估 (`historical_limitations_verification_report.txt`, 8/8 实名样本均
被拒绝) 表明: 3.0 服务端对 **已实名认证 / 已面访** 居民会一律拒绝
SFZH 修改, 文案 `"已实名认证的对象身份证号码不允许修改"`.

我们的实装尊重这一边界:
- 预检会提前发现并跳过这类居民, 而不是徒劳尝试.
- 即使勾选 "强制", 服务端也会直接拒绝 — 我们的 honesty 改造 (
  `_opType_zero` 严格 JSON 解析) 保证不会把 HTML 错误页误判为成功.
- 因此 "年龄绕行" 的真实适用范围是: **未实名认证 + 未面访 + 18-60 岁
  的新建档居民** — 与原 client.exe 的能力等价 (它也走同一个
  `Pg_Edit_B0101.aspx` 路径, 只是用 Playwright 驱动).

### 2.3 与原 client.exe 的对照

原 `client.exe` (PyArmor BCC 保护) 的 `updateDanganInfo` 走的是
`Pg_Edit_B0101.aspx` + `Do_B0101_Handler.ashx ACTION=2` — **与我们 ph3_api.py
现在的 `modify_archive` 完全相同**. 差别在于它用 Playwright/Chromium
驱动 form 提交, 我们直接发 AJAX. 服务端 ACL 不分 client, 拒绝是相同的.

潜在改进 (未实装, 工作量大): 整合 Playwright 走真实浏览器路径, 看是否
能绕开仅对 AJAX 路径生效的反作弊检测. 这会增加 ~150MB 的发布体积
且没有证据表明能突破服务端 ACL.

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

- **可投产**: 1 (核心签约), 2 (年龄绕行 — 含可行性预检 + 事务编排 + 审计),
  5 (Excel 日志).
- **明显宣传过度**: 3 (高级分析), 4 (安全评估) — 均为静态/模拟脚本,
  请勿对客户宣称 "实时渗透测试" 或 "实时分析", 它们只是文档/方法论
  + 一次性模拟报告.

如果客户必须要真正的实时分析 / 实时渗透, 应基于 `scripts/ph3_*_probe.py`
重写 `ultimate_*` 模块 — 这些 probe 是真的会发请求并采集数据.
