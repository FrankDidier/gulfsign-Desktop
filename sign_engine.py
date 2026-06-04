# -*- coding: utf-8 -*-
"""
签约引擎 — 全流程自动化协调器

整合 3.0系统 (PH3Client) 和 健康卡平台 (HealthCardClient)，实现半自动化全人群签约。

核心能力:
  1. 标准签约: updateRpc → 查询状态 → 创建合同 → 确认签约
  2. 年龄绕行: 修改身份证号 → 绑卡(无需人脸) → 恢复身份证号
  3. 身份证校验位计算 / 年龄提取

使用方式:
  engine = SigningEngine(hc_client, ph3_client)
  result = engine.process_card_full(card, orgcode="...", team_name="...", ...)
"""
import time
import datetime
import logging
from dataclasses import dataclass, field
from typing import Optional, Tuple, Callable, List, Dict

from ph3_api import PH3Client, PH3Crypto
from hc_api import (
    HealthCardClient, HealthCard, HCContract, HCConfirmResult,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# 身份证工具
# ---------------------------------------------------------------------------

_ID_WEIGHTS = [7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2]
_ID_CHECK_CHARS = "10X98765432"


def calc_id_check_digit(id17: str) -> str:
    """Calculate the 18th character (check digit) of a Chinese ID card."""
    if len(id17) != 17 or not id17.isdigit():
        raise ValueError("需要恰好17位数字，收到: %r" % id17)
    s = sum(int(id17[i]) * _ID_WEIGHTS[i] for i in range(17))
    return _ID_CHECK_CHARS[s % 11]


def validate_id_card(id_card: str) -> bool:
    """Validate a Chinese 18-digit ID card number."""
    if len(id_card) != 18 or not id_card[:17].isdigit():
        return False
    return id_card[17].upper() == calc_id_check_digit(id_card[:17])


def get_age_from_id(id_card: str) -> int:
    """Extract age from SFZH — same logic as HC platform regist.js.

    Returns -1 if the ID is masked (contains ``*``) or too short.
    """
    if not id_card or len(id_card) < 14 or "*" in id_card:
        return -1
    try:
        birth_year = int(id_card[6:10])
        birth_month = int(id_card[10:12])
        birth_day = int(id_card[12:14])
    except ValueError:
        return -1
    today = datetime.date.today()
    age = today.year - birth_year
    if (today.month, today.day) < (birth_month, birth_day):
        age -= 1
    return age


def generate_bypass_sfzh(original_sfzh: str, target_age: int = 10) -> str:
    """Generate a modified SFZH that makes the person appear *target_age*.

    Only the birth-year digits (positions 6–9) are changed.
    The check digit (position 17) is recalculated.
    """
    if len(original_sfzh) != 18:
        raise ValueError("SFZH必须18位")
    today = datetime.date.today()
    new_birth_year = today.year - target_age
    new_id17 = original_sfzh[:6] + str(new_birth_year) + original_sfzh[10:17]
    return new_id17 + calc_id_check_digit(new_id17)


def get_csrq_from_sfzh(sfzh: str) -> str:
    """Extract birth date from SFZH as YYYY-MM-DD."""
    if len(sfzh) < 14:
        return ""
    return "%s-%s-%s" % (sfzh[6:10], sfzh[10:12], sfzh[12:14])


def needs_age_bypass(id_card_or_age) -> bool:
    """Return True if the person is 18–60 (needs face verification to bind).

    Accepts either an ID card string or a numeric age (int/str).
    Handles masked IDs (containing ``*``) gracefully.
    """
    if isinstance(id_card_or_age, int):
        return 18 <= id_card_or_age <= 60
    if isinstance(id_card_or_age, str) and "*" not in id_card_or_age:
        age = get_age_from_id(id_card_or_age)
        if age >= 0:
            return 18 <= age <= 60
    return False


# ---------------------------------------------------------------------------
# 签约结果
# ---------------------------------------------------------------------------

@dataclass
class FullSignResult:
    """Result of a full signing operation."""
    success: bool
    name: str = ""
    health_card_id: str = ""
    step: str = ""
    error: str = ""
    elapsed: float = 0.0
    contract_created: bool = False
    contract_confirmed: bool = False
    rpc_set: bool = False
    previous_status: str = ""
    age_bypass_attempted: bool = False
    age_bypass_applied: bool = False
    age_bypass_restored: bool = False
    age_bypass_blocked_reason: str = ""


# ---------------------------------------------------------------------------
# Age-bypass eligibility precheck
# ---------------------------------------------------------------------------
#
# 历史评估 (`historical_limitations_verification_report.txt`) 给出的关键事实:
#   * 健康卡平台从 SFZH 内嵌的出生年份判断年龄, 不读 3.0 档案的 CSRQ.
#   * 服务端会拒绝对 "已实名认证" / "已面访" 居民的 SFZH 修改请求,
#     错误文案: "已实名认证的对象身份证号码不允许修改".
#   * 但对未实名 / 未面访的 *新建档* 居民, 修改是可行的 (8/8 已实名样本被拒,
#     未实名样本未直接覆盖, 但服务端只在锁定的对象上拒绝).
#
# 因此在调起 `modify_archive` 前我们做一次本地启发式预检:
#   1. 加载 B0101 编辑表单; 列出全部字段.
#   2. 检查若干常见 "实名认证" / "面访" 标志字段是否非空.
#   3. 若任一标志字段非空 -> `likely_blocked` (不阻塞流程, 只是给用户警告).
#   4. 若无明显标志 -> `likely_eligible`.
#
# 服务端最终仍是权威; 我们只是减少明知会被拒绝的尝试与产出预检报告.
#
# 这些字段名是 GBT 的 B0101 标准 + 河南公卫的常见扩展; 实名/面访字段
# 在不同省份命名不一致, 因此采用包含子串的方式做模糊匹配, 并保留全部
# 加载到的原始字段供诊断.

_REALNAME_FIELD_HINTS: Tuple[str, ...] = (
    # 实名认证相关
    "SMRZ", "smrz", "RZSJ", "rzsj", "RZBJ", "rzbj",
    "SMBJ", "smbj", "SHZT", "shzt",
    "B0101_19",   # 河南: 实名认证日期 (亦用于查询过滤 BEGIN/END)
    "RZZT", "rzzt",
)

_VISITED_FIELD_HINTS: Tuple[str, ...] = (
    # 面访 / 现场访视相关
    "MFSJ", "mfsj", "MFRZ", "mfrz", "MFBJ", "mfbj",
    "B0101_24", "B0101_25",   # 常见面访日期/状态扩展槽
)


@dataclass
class AgeBypassEligibility:
    """读取档案并启发式判断: 该居民的 SFZH 是否 *可能* 允许在线修改。

    这不是一个保证: 服务端最终仍是权威. 它的目的是:
      * 在批量场景下提前剔除会被拒绝的居民, 减少不必要写操作;
      * 给操作员提供一个 "为什么这个人没法绕行" 的可读理由;
      * 给出一份审计报告 (Excel) 用于合规留痕.
    """
    person_id: str = ""
    name: str = ""
    original_sfzh: str = ""
    age: int = -1
    needs_bypass: bool = False           # 18 <= age <= 60
    archive_loaded: bool = False
    likely_eligible: bool = False        # 启发式预测: 服务端会接受
    block_reason: str = ""               # 若 likely_eligible=False, 解释原因
    detected_realname_marks: List[str] = field(default_factory=list)
    detected_visited_marks: List[str] = field(default_factory=list)
    error: str = ""                      # 加载档案本身的错误
    archive_fields: Dict[str, str] = field(default_factory=dict)

    @property
    def status(self) -> str:
        if self.error:
            return "error"
        if not self.archive_loaded:
            return "unknown"
        if not self.needs_bypass:
            if self.age >= 0 and (self.age < 18 or self.age > 60):
                return "no_bypass_needed"
            return "unknown"
        return "eligible" if self.likely_eligible else "likely_blocked"

    def to_audit_row(self) -> Dict[str, str]:
        """扁平化为审计 Excel 一行 (姓名/SFZH 仅记录前后4位避免明文外泄)."""
        def _mask(s: str) -> str:
            if not s or len(s) < 8:
                return s or ""
            return s[:4] + "*" * (len(s) - 8) + s[-4:]
        return {
            "person_id": self.person_id,
            "name": self.name,
            "age": str(self.age) if self.age >= 0 else "",
            "needs_bypass": "是" if self.needs_bypass else "否",
            "status": self.status,
            "likely_eligible": "是" if self.likely_eligible else "否",
            "block_reason": self.block_reason,
            "realname_marks": ",".join(self.detected_realname_marks),
            "visited_marks": ",".join(self.detected_visited_marks),
            "original_sfzh_masked": _mask(self.original_sfzh),
            "error": self.error,
        }


# ---------------------------------------------------------------------------
# 签约引擎
# ---------------------------------------------------------------------------

class SigningEngine:
    """全流程签约引擎。

    协调 健康卡平台 和 3.0系统 完成签约:
      1. 设置人脸认证绕过 (updateRpc)
      2. 查询签约状态
      3. 创建居民申请合同 (insertJtysqy) — 仅对未签约居民
      4. 确认合同 (editqr)

    支持年龄绕行 (修改SFZH使18-60岁居民可免人脸绑卡)。
    """

    def __init__(
        self,
        hc: HealthCardClient,
        ph3: Optional[PH3Client] = None,
    ):
        self.hc = hc
        self.ph3 = ph3
        self._cached_teams: Dict[str, list] = {}
        self._cached_packages: Dict[str, Tuple[str, str]] = {}

    # ================================================================
    # Team / Package helpers
    # ================================================================

    def resolve_team(
        self, orgcode: str, team_name: str = "",
    ) -> Tuple[str, str]:
        """Find a team GUID+name for the given org.

        Tries HC platform first, then falls back to 3.0 system.
        Returns (team_guid, team_name).
        """
        if orgcode not in self._cached_teams:
            teams = self.hc.query_teams(orgcode)
            if not teams and self.ph3 and self.ph3.logged_in:
                teams = self._teams_from_ph3()
            self._cached_teams[orgcode] = teams

        teams = self._cached_teams[orgcode]
        if not teams:
            return "", team_name

        for t in teams:
            t_name = t.get("name", t.get("qytdmc", t.get("b0105_03", "")))
            t_guid = t.get("guid", t.get("GUID", t.get("id", "")))
            if team_name and team_name in t_name:
                return t_guid, t_name

        first = teams[0]
        return (
            first.get("guid", first.get("GUID", first.get("id", ""))),
            team_name or first.get("name", first.get("qytdmc", "")),
        )

    def _teams_from_ph3(self) -> List[dict]:
        """Load teams from the 3.0 system's signing form (fallback)."""
        if not self.ph3 or not self.ph3.logged_in:
            return []
        try:
            pts, _ = self.ph3.query_patients(status="1", page=1)
            if not pts:
                pts, _ = self.ph3.query_patients(status="", page=1)
            if not pts:
                return []

            import re, json as _json
            ts = str(int(time.time() * 1000))
            enc = PH3Crypto.crptosEn(pts[0].person_id + "|" + ts, self.ph3.token_en)
            sig = PH3Crypto.crptosTH(enc + self.ph3.token_th)
            resp = self.ph3.session.get(
                self.ph3._url("/Sys_JCWS/B0105/Pg_Insert_B0105.aspx"),
                params={"GUID": enc, "sign": sig},
                timeout=self.ph3._timeout,
            )
            m = re.search(
                r'\$\("#QYTD"\)\.drawMultipleTree\(\{[^z]*zNodes:\s*(\[.*?\])\s*,',
                resp.text, re.DOTALL,
            )
            if m:
                return _json.loads(m.group(1))
        except Exception:
            pass
        return []

    def resolve_packages(
        self, orgcode: str, population_type: str = "",
    ) -> Tuple[str, str]:
        """Find service packages for the given org.

        Tries HC platform first, then falls back to 3.0 system.
        Returns (guids_csv, names_csv).
        """
        cache_key = "%s|%s" % (orgcode, population_type)
        if cache_key not in self._cached_packages:
            pkgs = self.hc.query_service_packages(orgcode, population_type)
            if pkgs:
                guids = ",".join(
                    p.get("guid", p.get("GUID", "")) for p in pkgs
                )
                names = ",".join(
                    p.get("name", p.get("b0110_01", p.get("B0110_01", "")))
                    for p in pkgs
                )
                self._cached_packages[cache_key] = (guids, names)
            else:
                fallback = self._packages_from_ph3(population_type)
                self._cached_packages[cache_key] = fallback
        return self._cached_packages[cache_key]

    def _packages_from_ph3(self, fwlx: str = "0") -> Tuple[str, str]:
        """Load service packages from the 3.0 system (fallback)."""
        if not self.ph3 or not self.ph3.logged_in:
            return "", ""
        return self.ph3._load_service_packs(fwlx or "0")

    # ================================================================
    # Full signing flow
    # ================================================================

    def process_card_full(
        self,
        card: HealthCard,
        orgcode: str,
        team_name: str = "",
        team_guid: str = "",
        doctor_name: str = "",
        package_names: str = "",
        package_guids: str = "",
        start_date: str = "",
        end_date: str = "",
        period_years: str = "3",
        auto_create: bool = True,
        log_cb: Optional[Callable] = None,
    ) -> FullSignResult:
        """Full signing flow for a single health card.

        Steps:
          1. updateRpc  → set rpc=1 (bypass face verification)
          2. querybyidcardqyjg → get PERSONID + signing status
          3. Based on status:
             - STATUS=0 (signed): skip
             - STATUS=5/6 (pending): confirm via editqr
             - STATUS=1 (unsigned) + auto_create: insertJtysqy → editqr
             - No record + auto_create: insertJtysqy → editqr

        Returns FullSignResult with details.
        """
        t0 = time.time()
        result = FullSignResult(
            success=False,
            name=card.name,
            health_card_id=card.health_card_id,
        )

        def log(msg, tag=""):
            if log_cb:
                log_cb(msg, tag)

        # Step 1: updateRpc
        if not card.is_verified:
            ok, msg = self.hc.update_rpc(card.health_card_id)
            if ok:
                log("  设置人脸认证绕过: %s" % msg, "ok")
                card.rpc = "1"
                result.rpc_set = True
            else:
                result.error = "人脸认证设置失败: %s" % msg
                result.step = "updateRpc"
                result.elapsed = time.time() - t0
                log("  ✗ %s" % result.error, "err")
                return result
        else:
            result.rpc_set = True

        # Step 2: Query signing info
        info = self.hc.query_signing_info(card.health_card_id)
        if not info:
            if not auto_create:
                result.error = "无签约记录，且未启用自动创建"
                result.step = "query"
                result.elapsed = time.time() - t0
                log("  跳过: %s" % result.error, "warn")
                return result

            log("  无现有签约记录，将创建新合同", "info")
            return self._create_and_confirm(
                card, orgcode, team_name, team_guid, doctor_name,
                package_names, package_guids, start_date, end_date,
                period_years, result, t0, log,
            )

        person_id = info.get("GUID", "")
        status = str(info.get("CONTRACT_STATES", ""))
        info_orgcode = info.get("gdjgcode", orgcode)
        result.previous_status = status

        _status_labels = {
            "0": "已签约", "1": "未签约",
            "5": "医生申请(待确认)", "6": "居民申请(待确认)",
        }
        log("  签约状态: %s" % _status_labels.get(status, "未知(%s)" % status), "info")

        # Step 3: Act on status
        if status == "0":
            result.success = True
            result.step = "already_signed"
            result.elapsed = time.time() - t0
            log("  已签约，跳过", "warn")
            return result

        if status in ("5", "6"):
            return self._confirm_existing(
                card, person_id, info_orgcode, status, result, t0, log,
            )

        if status == "1" or not status:
            contracts = self.hc.query_contracts(person_id, card.health_card_id)
            signed = [c for c in contracts if c.status == "0"]
            confirmable = [c for c in contracts if c.status in ("5", "6")]

            if confirmable:
                log("  发现 %d 份待确认合同" % len(confirmable), "info")
                return self._confirm_existing(
                    card, person_id, info_orgcode, confirmable[0].status,
                    result, t0, log,
                )

            if signed:
                result.success = True
                result.step = "already_signed"
                result.elapsed = time.time() - t0
                log("  该居民在其他机构已有签约合同，跳过", "warn")
                return result

            if not auto_create:
                result.error = "未签约，且未启用自动创建"
                result.step = "query"
                result.elapsed = time.time() - t0
                log("  跳过: %s" % result.error, "warn")
                return result

            log("  未签约，将创建居民申请合同", "info")
            return self._create_and_confirm(
                card, orgcode, team_name, team_guid, doctor_name,
                package_names, package_guids, start_date, end_date,
                period_years, result, t0, log,
                person_id=person_id,
            )

        result.error = "未知签约状态: %s" % status
        result.step = "query"
        result.elapsed = time.time() - t0
        log("  ✗ %s" % result.error, "err")
        return result

    # ----------------------------------------------------------------

    def _confirm_existing(
        self,
        card: HealthCard,
        person_id: str,
        orgcode: str,
        status: str,
        result: FullSignResult,
        t0: float,
        log: Callable,
    ) -> FullSignResult:
        """Confirm existing pending contracts (STATUS 5 or 6)."""
        contracts = self.hc.query_contracts(person_id, card.health_card_id)
        confirmable = [c for c in contracts if c.status in ("5", "6")]

        if not confirmable:
            result.error = "查询到状态=%s 但无可确认合同" % status
            result.step = "query_contracts"
            result.elapsed = time.time() - t0
            log("  无可确认合同", "warn")
            return result

        last_error = ""
        for contract in confirmable:
            contract.name = card.name
            contract.orgcode = contract.orgcode or orgcode
            log("  确认合同: %s (状态%s)" % (contract.guid[:16], contract.status), "info")

            cr = self.hc.confirm_one(contract)
            if cr.success:
                result.success = True
                result.contract_confirmed = True
                result.step = "confirmed"
                result.elapsed = time.time() - t0
                log("  ✓ 签约确认成功! (%.1fs)" % result.elapsed, "ok")
                return result

            last_error = cr.error
            log("  ✗ 确认失败: %s" % cr.error, "err")

        result.error = "所有合同确认均失败: %s" % last_error
        result.step = "confirm"
        result.elapsed = time.time() - t0
        return result

    def _create_and_confirm(
        self,
        card: HealthCard,
        orgcode: str,
        team_name: str,
        team_guid: str,
        doctor_name: str,
        package_names: str,
        package_guids: str,
        start_date: str,
        end_date: str,
        period_years: str,
        result: FullSignResult,
        t0: float,
        log: Callable,
        person_id: str = "",
    ) -> FullSignResult:
        """Create a resident contract (STATUS=6) and immediately confirm it."""
        if not person_id:
            person_id = self.hc.get_person_guid(card.health_card_id)
            if not person_id:
                result.error = "无法获取居民GUID (该卡可能未在平台注册)"
                result.step = "get_person_guid"
                result.elapsed = time.time() - t0
                log("  ✗ %s" % result.error, "err")
                return result

        if not start_date:
            start_date = time.strftime("%Y%m%d")
        if not end_date:
            yrs = int(period_years) if period_years.isdigit() else 3
            end_date = str(int(start_date[:4]) + yrs) + start_date[4:]

        if not team_guid and orgcode:
            team_guid, team_name = self.resolve_team(orgcode, team_name)
            if team_name:
                log("  签约团队: %s" % team_name, "info")

        if not team_guid:
            result.error = (
                "签约团队GUID为空 — insertJtysqy要求非空团队。\n"
                "请在「签约配置」中填写团队信息，或登录3.0系统后同步配置。"
            )
            result.step = "resolve_team"
            result.elapsed = time.time() - t0
            log("  ✗ %s" % result.error, "err")
            return result

        if not package_guids and orgcode:
            package_guids, package_names = self.resolve_packages(orgcode)
            if package_names:
                log("  服务包: %s" % package_names[:60], "info")

        if not package_guids:
            result.error = (
                "服务包GUID为空 — insertJtysqy要求非空服务包。\n"
                "请登录3.0系统后同步配置以获取服务包信息。"
            )
            result.step = "resolve_packages"
            result.elapsed = time.time() - t0
            log("  ✗ %s" % result.error, "err")
            return result

        gender = card.gender or "1"
        # 之前: 默认 "13800000000" 占位电话直接进入生产健康卡接口.
        # 现在: 缺少真实电话时记一条警告 (上游应配置真实电话).
        phone = card.phone
        if not phone:
            phone = "13800000000"
            try:
                log(
                    "  ⚠ 居民缺少手机号, 暂以占位号码 13800000000 提交 — "
                    "请补充真实电话以避免数据被退回",
                    "warn",
                )
            except Exception:
                pass

        ok, msg = self.hc.create_resident_contract(
            person_id=person_id,
            health_card_id=card.health_card_id,
            name=card.name,
            gender=gender,
            phone=phone,
            orgcode=orgcode,
            team_name=team_name,
            team_guid=team_guid,
            doctor_name=doctor_name,
            package_names=package_names,
            package_guids=package_guids,
            start_date=start_date,
            end_date=end_date,
            period_years=period_years,
        )

        if not ok:
            result.error = "创建合同失败: %s" % msg
            result.step = "create_contract"
            result.elapsed = time.time() - t0
            log("  ✗ %s" % result.error, "err")
            return result

        result.contract_created = True
        log("  ✓ 居民申请合同已创建 (STATUS=6)", "ok")

        time.sleep(0.5)

        contracts = self.hc.query_contracts(person_id, card.health_card_id)
        confirmable = [c for c in contracts if c.status == "6"]

        if not confirmable:
            result.success = True
            result.step = "created_not_confirmed"
            result.elapsed = time.time() - t0
            log("  ⚠ 合同已创建但未找到可确认记录 (稍后可手动确认)", "warn")
            return result

        last_error = ""
        for contract in confirmable:
            contract.name = card.name
            contract.orgcode = contract.orgcode or orgcode
            log("  确认合同: %s" % contract.guid[:16], "info")

            cr = self.hc.confirm_one(contract)
            if cr.success:
                result.success = True
                result.contract_confirmed = True
                result.step = "confirmed"
                result.elapsed = time.time() - t0
                log("  ✓ 签约确认成功! (%.1fs)" % result.elapsed, "ok")
                return result

            last_error = cr.error
            log("  ✗ 确认失败: %s" % cr.error, "err")

        result.contract_created = True
        result.error = "合同已创建但确认失败: %s" % last_error
        result.step = "confirm_after_create"
        result.elapsed = time.time() - t0
        return result

    # ================================================================
    # Age bypass (SFZH modification via 3.0)
    # ================================================================

    def check_age_bypass_eligibility(
        self,
        person_id: str,
        name: str = "",
        expected_sfzh: str = "",
        province_password: str = "",
    ) -> AgeBypassEligibility:
        """读取 B0101 档案并启发式判断该居民是否可能允许 SFZH 修改。

        **此方法仅做只读 GET, 不修改任何数据**.

        判定优先级:
          1. **(authoritative)** 若 ``province_password`` 提供, 优先调
             ``ph3.query_province_wide`` — 服务端会显式返回 ``is_realname``
             / ``is_visited`` (源自页面里 cell 的 title 与 onclick 属性).
          2. **(heuristic)** 否则 ``ph3.load_archive`` 拿表单字段, 启发式
             匹配 SMRZ/RZSJ/MFSJ 等字段名是否非空.

        参数:
          person_id        : 3.0 档案 GUID (B0101.GUID).
          name             : 仅用于报告/审计行 (可选).
          expected_sfzh    : 用作回退 SFZH 来源 (当档案里 SFZH 被脱敏时常见).
          province_password: 当前 PH3 账号的登录密码; 用于走全省个案查询的
                             权威路径. 不传则走启发式 fallback.
        """
        result = AgeBypassEligibility(person_id=person_id, name=name)

        if not self.ph3:
            result.error = "未配置 PH3Client"
            return result

        if not getattr(self.ph3, "fully_authenticated", False):
            # fully_authenticated 在 ph3_api 里要求 logged_in + !qr_pending + org_code
            # 缺任意一项, 我们不应该尝试拉档案 (会返回登录页 HTML).
            if not getattr(self.ph3, "logged_in", False):
                result.error = "3.0 系统未登录"
            elif getattr(self.ph3, "qr_pending", False):
                result.error = "登录不完整: 需要扫码完成二维码验证"
            elif not getattr(self.ph3, "org_code", ""):
                result.error = "登录不完整: 缺少机构编码 (请同步配置)"
            else:
                result.error = "3.0 客户端未就绪"
            return result

        # ---- 路径 1: 全省个案查询 (authoritative) ----
        if province_password and expected_sfzh and hasattr(self.ph3, "query_province_wide"):
            try:
                matches, _total, qerr = self.ph3.query_province_wide(
                    sfzh=expected_sfzh, password=province_password,
                )
            except Exception as e:
                matches, qerr = [], "全省查询异常: %s" % e
            if matches and not qerr:
                # 命中: 用第一条 (按 SFZH 通常唯一)
                m = matches[0]
                result.archive_loaded = True
                # 把权威 person_id 回写, 方便后续 modify_archive 直接用
                if not result.person_id and m.person_id:
                    result.person_id = m.person_id
                result.original_sfzh = expected_sfzh
                result.age = get_age_from_id(expected_sfzh)
                result.needs_bypass = needs_age_bypass(expected_sfzh)
                if m.is_realname:
                    result.detected_realname_marks.append(
                        "全省查询: 已通过实名制验证"
                    )
                if m.is_visited:
                    result.detected_visited_marks.append(
                        "全省查询: 已面访 (mf_click)"
                    )
                if not result.needs_bypass:
                    result.likely_eligible = True
                elif m.is_realname or m.is_visited:
                    reasons = []
                    if m.is_realname:
                        reasons.append("已实名认证")
                    if m.is_visited:
                        reasons.append("已面访")
                    result.likely_eligible = False
                    result.block_reason = (
                        "; ".join(reasons) + " (服务端权威标志) — SFZH 修改将被拒绝"
                    )
                else:
                    result.likely_eligible = True
                return result
            # 全省查询无命中或失败 → fall through 走启发式

        # ---- 路径 2: load_archive 启发式 fallback ----
        ok, fields, err = self.ph3.load_archive(person_id)
        if not ok:
            result.error = err or "档案加载失败"
            return result

        result.archive_loaded = True
        result.archive_fields = fields
        # 优先用档案 SFZH; 当档案脱敏时回退到调用方提供的 SFZH.
        sfzh_in_archive = (fields.get("SFZH") or "").strip()
        if sfzh_in_archive and "*" not in sfzh_in_archive:
            result.original_sfzh = sfzh_in_archive
        elif expected_sfzh and len(expected_sfzh) == 18:
            result.original_sfzh = expected_sfzh

        if result.original_sfzh:
            result.age = get_age_from_id(result.original_sfzh)
            result.needs_bypass = needs_age_bypass(result.original_sfzh)
        elif expected_sfzh:
            result.age = get_age_from_id(expected_sfzh)
            result.needs_bypass = needs_age_bypass(expected_sfzh)

        # 启发式: 探测可能锁定 SFZH 的字段
        for k, v in fields.items():
            v_str = str(v or "").strip()
            if not v_str:
                continue
            # 实名/认证类字段
            if any(hint in k for hint in _REALNAME_FIELD_HINTS):
                result.detected_realname_marks.append("%s=%s" % (k, v_str[:32]))
            # 面访类字段
            if any(hint in k for hint in _VISITED_FIELD_HINTS):
                result.detected_visited_marks.append("%s=%s" % (k, v_str[:32]))

        # 决策
        if not result.needs_bypass:
            # 18 岁以下或 60 岁以上, 健康卡平台不要求人脸 → 直接绑卡, 不需要绕行
            result.likely_eligible = True
            result.block_reason = "" if result.age >= 0 else "未能从档案提取年龄"
        elif result.detected_realname_marks or result.detected_visited_marks:
            result.likely_eligible = False
            reasons = []
            if result.detected_realname_marks:
                reasons.append("已实名认证 (%s)" % "/".join(
                    m.split("=")[0] for m in result.detected_realname_marks[:3]
                ))
            if result.detected_visited_marks:
                reasons.append("已面访 (%s)" % "/".join(
                    m.split("=")[0] for m in result.detected_visited_marks[:3]
                ))
            result.block_reason = "; ".join(reasons) + " — 服务端通常拒绝修改 SFZH"
        else:
            result.likely_eligible = True
            result.block_reason = ""

        return result

    def batch_check_age_bypass_eligibility(
        self,
        targets: List[Dict[str, str]],
        progress_cb: Optional[Callable[[int, int, AgeBypassEligibility], None]] = None,
        province_password: str = "",
    ) -> List[AgeBypassEligibility]:
        """对多个居民批量做只读资格预检.

        ``targets`` 每项至少含 ``person_id``; 可附 ``name`` / ``sfzh``.
        失败的项会保留 ``error``, 不会中断整批.

        ``province_password`` 若提供, 会走全省个案查询拿权威标志位.
        """
        results: List[AgeBypassEligibility] = []
        total = len(targets)
        for i, t in enumerate(targets, 1):
            pid = t.get("person_id") or t.get("guid") or ""
            sfzh = t.get("sfzh", "")
            # 即使没有 person_id, 全省查询也能跑 (用 SFZH).
            if not pid and not sfzh:
                er = AgeBypassEligibility(name=t.get("name", ""))
                er.error = "缺少 person_id 或 sfzh"
                results.append(er)
                if progress_cb:
                    progress_cb(i, total, er)
                continue
            try:
                r = self.check_age_bypass_eligibility(
                    pid, name=t.get("name", ""),
                    expected_sfzh=sfzh,
                    province_password=province_password,
                )
            except Exception as e:
                r = AgeBypassEligibility(person_id=pid, name=t.get("name", ""))
                r.error = "预检异常: %s" % str(e)
            results.append(r)
            if progress_cb:
                progress_cb(i, total, r)
        return results

    # ----------------------------------------------------------------
    # Transactional age-bypass orchestration
    # ----------------------------------------------------------------

    def process_card_with_age_bypass(
        self,
        card: HealthCard,
        person_id: str,
        orgcode: str,
        team_name: str = "",
        team_guid: str = "",
        doctor_name: str = "",
        package_names: str = "",
        package_guids: str = "",
        start_date: str = "",
        end_date: str = "",
        period_years: str = "3",
        auto_create: bool = True,
        log_cb: Optional[Callable] = None,
        audit_logger: Optional[object] = None,
        force: bool = False,
        province_password: str = "",
    ) -> FullSignResult:
        """对 18-60 岁居民: 修改 SFZH → 走完整签约 → 始终恢复 SFZH。

        语义 (transactional):
          - 步骤 A: 预检 -> 若 likely_blocked 且 force=False, 直接跳过 (不修改).
          - 步骤 B: prepare_age_bypass (modify_archive SFZH+CSRQ).
          - 步骤 C: process_card_full(card) — 该卡此时被服务端视为 <18 岁.
          - 步骤 D: restore_age_bypass — 无论 C 成功失败都尝试恢复.
            若 D 也失败, 将错误升级为 CRITICAL 写入审计 (因为档案残留了
            一个不属于本人的 SFZH).

        ``audit_logger`` 若提供, 应实现 ``log_attempt(event_dict)`` 方法
        (见 ``batch_processor.AgeBypassAuditLogger``).
        """

        def log(msg, tag=""):
            if log_cb:
                log_cb(msg, tag)

        result = FullSignResult(
            success=False,
            name=card.name,
            health_card_id=card.health_card_id,
            age_bypass_attempted=False,
        )

        sfzh = (card.id_card or "").strip()
        if len(sfzh) != 18:
            # 无法做绕行, fall back 到普通流程 (普通流程内部会因人脸要求而失败)
            log("  无 18 位身份证号, 跳过年龄绕行预处理", "warn")
            return self.process_card_full(
                card, orgcode=orgcode, team_name=team_name, team_guid=team_guid,
                doctor_name=doctor_name, package_names=package_names,
                package_guids=package_guids, start_date=start_date,
                end_date=end_date, period_years=period_years,
                auto_create=auto_create, log_cb=log_cb,
            )

        if not needs_age_bypass(sfzh):
            log("  非 18-60 岁人群, 直接走标准流程 (不需要绕行)", "info")
            return self.process_card_full(
                card, orgcode=orgcode, team_name=team_name, team_guid=team_guid,
                doctor_name=doctor_name, package_names=package_names,
                package_guids=package_guids, start_date=start_date,
                end_date=end_date, period_years=period_years,
                auto_create=auto_create, log_cb=log_cb,
            )

        # 步骤 A: 预检
        elig = self.check_age_bypass_eligibility(
            person_id, name=card.name, expected_sfzh=sfzh,
            province_password=province_password,
        )
        result.age_bypass_attempted = True
        if audit_logger:
            try:
                audit_logger.log_attempt({
                    "phase": "precheck",
                    "person_id": person_id, "name": card.name, "age": elig.age,
                    "status": elig.status, "block_reason": elig.block_reason,
                    "realname_marks": ",".join(elig.detected_realname_marks),
                    "visited_marks": ",".join(elig.detected_visited_marks),
                    "error": elig.error,
                })
            except Exception:
                pass

        if elig.error:
            result.error = "档案预检失败: %s" % elig.error
            result.step = "age_bypass_precheck"
            result.age_bypass_blocked_reason = elig.error
            log("  ✗ %s" % result.error, "err")
            return result

        if not elig.likely_eligible and not force:
            result.error = "年龄绕行被预检阻断: %s" % elig.block_reason
            result.step = "age_bypass_blocked"
            result.age_bypass_blocked_reason = elig.block_reason
            log("  ⊘ 跳过 (likely_blocked): %s" % elig.block_reason, "warn")
            return result

        # 步骤 B: prepare
        ok, new_sfzh, err = self.prepare_age_bypass(person_id, sfzh, log_cb=log_cb)
        if audit_logger:
            try:
                audit_logger.log_attempt({
                    "phase": "prepare",
                    "person_id": person_id, "name": card.name,
                    "ok": ok,
                    "error": err if not ok else "",
                    "original_sfzh_tail": sfzh[-4:],
                    "modified_sfzh_tail": (new_sfzh[-4:] if new_sfzh else ""),
                })
            except Exception:
                pass
        if not ok:
            result.error = "修改档案失败 (服务端拒绝): %s" % err
            result.step = "age_bypass_prepare"
            result.age_bypass_blocked_reason = err
            log("  ✗ %s" % result.error, "err")
            return result
        result.age_bypass_applied = True

        # 步骤 C: 真实签约 — 在 SFZH 已被改为 <18 岁的窗口内
        try:
            inner = self.process_card_full(
                card, orgcode=orgcode, team_name=team_name, team_guid=team_guid,
                doctor_name=doctor_name, package_names=package_names,
                package_guids=package_guids, start_date=start_date,
                end_date=end_date, period_years=period_years,
                auto_create=auto_create, log_cb=log_cb,
            )
        except Exception as e:
            inner = FullSignResult(
                success=False, name=card.name,
                health_card_id=card.health_card_id,
                error="签约异常: %s" % str(e),
                step="exception",
            )

        # 复制内部结果字段到外层 (除了我们自己跟踪的 age_bypass_*)
        for f in ("success", "step", "error", "elapsed", "contract_created",
                  "contract_confirmed", "rpc_set", "previous_status"):
            setattr(result, f, getattr(inner, f))
        # 重新赋好 age_bypass_*
        result.age_bypass_attempted = True
        result.age_bypass_applied = True

        # 步骤 D: 永远尝试恢复 SFZH (即使 C 失败)
        try:
            ok2, err2 = self.restore_age_bypass(person_id, sfzh, log_cb=log_cb)
        except Exception as e:
            ok2, err2 = False, "恢复异常: %s" % str(e)

        result.age_bypass_restored = bool(ok2)
        if audit_logger:
            try:
                audit_logger.log_attempt({
                    "phase": "restore",
                    "person_id": person_id, "name": card.name,
                    "ok": ok2,
                    "error": err2 if not ok2 else "",
                    "outer_success": result.success,
                })
            except Exception:
                pass

        if not ok2:
            # CRITICAL: 档案里现在留着改过的 SFZH (出生年=今年-10).
            # 把这个事实粘到 error / step, 让上游强制人工处理.
            critical = (
                "[严重] SFZH 已修改但恢复失败 — 档案 %s 当前停留在伪造的 SFZH! "
                "请立刻人工登录 3.0 系统手动恢复。错误: %s" % (person_id, err2)
            )
            log("  ✗✗✗ %s" % critical, "err")
            if not result.error:
                result.error = critical
            else:
                result.error = result.error + " | " + critical
            if result.success:
                # 即便签约成功了, 我们也不认它 — 数据完整性优先
                result.success = False
                result.step = "age_bypass_restore_failed"

        return result

    def prepare_age_bypass(
        self,
        person_id: str,
        original_sfzh: str,
        log_cb: Optional[Callable] = None,
    ) -> Tuple[bool, str, str]:
        """Modify SFZH in 3.0 archive to make person appear under 18.

        Returns (success, modified_sfzh, error_message).
        """
        if not self.ph3 or not self.ph3.logged_in:
            return False, "", "3.0系统未登录"

        def log(msg, tag=""):
            if log_cb:
                log_cb(msg, tag)

        age = get_age_from_id(original_sfzh)
        if age < 0:
            return False, "", "无法从身份证号提取年龄"
        if age < 18 or age > 60:
            log("  年龄 %d — 无需绕行 (直接绑卡免人脸)" % age, "info")
            return True, original_sfzh, ""

        new_sfzh = generate_bypass_sfzh(original_sfzh, target_age=10)
        new_csrq = get_csrq_from_sfzh(new_sfzh)

        log("  年龄绕行: 原%d岁 → 模拟10岁" % age, "info")
        log("  SFZH: %s → %s" % (original_sfzh, new_sfzh), "info")

        ok, msg = self.ph3.modify_archive(
            person_id, {"SFZH": new_sfzh, "CSRQ": new_csrq}
        )

        if ok:
            log("  ✓ 3.0档案已修改 (SFZH+CSRQ)", "ok")
            return True, new_sfzh, ""

        log("  ✗ 档案修改失败: %s" % msg, "err")
        return False, "", msg

    def restore_age_bypass(
        self,
        person_id: str,
        original_sfzh: str,
        log_cb: Optional[Callable] = None,
    ) -> Tuple[bool, str]:
        """Restore original SFZH in 3.0 archive after card binding.

        Returns (success, error_message).
        """
        if not self.ph3 or not self.ph3.logged_in:
            return False, "3.0系统未登录"

        def log(msg, tag=""):
            if log_cb:
                log_cb(msg, tag)

        original_csrq = get_csrq_from_sfzh(original_sfzh)

        ok, msg = self.ph3.modify_archive(
            person_id, {"SFZH": original_sfzh, "CSRQ": original_csrq}
        )

        if ok:
            log("  ✓ 3.0档案已恢复: %s" % original_sfzh, "ok")
            return True, ""

        log("  ✗ 档案恢复失败: %s" % msg, "err")
        return False, msg

    # ================================================================
    # Auto-bind + sign (no-face population: <18 / >60)
    # ================================================================

    def bind_then_sign(
        self,
        name: str,
        id_card: str,
        orgcode: str,
        wechatcode: str,
        phone: str = "",
        nation: str = "01",
        relation: str = "6",
        team_name: str = "",
        team_guid: str = "",
        doctor_name: str = "",
        package_names: str = "",
        package_guids: str = "",
        start_date: str = "",
        end_date: str = "",
        period_years: str = "3",
        log_cb: Optional[Callable] = None,
    ) -> FullSignResult:
        """免人脸人群 (<18 或 >60) 全自动: 绑卡 → 查询 → (建合同) → 确认。

        关键约束 (来自 ``regist.js`` + 创意突破报告 v9):
          * 健康卡注册页从 **身份证号内嵌出生年** 判断年龄;
            ``age<18`` 或 ``age>60`` → **免腾讯人脸**, 仅需一个有效 ``Wechatcode``
            (由抓包代理在微信打开健康卡页时捕获, 同一 code 可绑一整批)。
          * ``18<=age<=60`` → 注册必须过腾讯人脸 (``verifyResult``), **无法纯自动
            绑卡**; 此处诚实返回失败, 提示走人工绑卡 (或先做年龄绕行再人工绑)。

        绑卡成功后复用既有 :meth:`process_card_full` (updateRpc→query→create→editqr)。
        """

        def log(msg, tag=""):
            if log_cb:
                log_cb(msg, tag)

        res = FullSignResult(success=False, name=name)

        sfzh = (id_card or "").strip()
        if len(sfzh) != 18:
            res.error = "需要 18 位身份证号才能绑卡"
            res.step = "bind_input"
            log("  ✗ %s" % res.error, "err")
            return res

        age = get_age_from_id(sfzh)
        if age < 0:
            res.error = "无法从身份证号解析年龄 (可能被脱敏)"
            res.step = "bind_input"
            log("  ✗ %s" % res.error, "err")
            return res

        if 18 <= age <= 60:
            res.error = (
                "18-60 岁绑卡需腾讯人脸验证 (verifyResult), 无法纯自动绑卡; "
                "请人工在微信完成绑卡后再用本工具自动签约"
            )
            res.step = "bind_needs_face"
            res.age_bypass_blocked_reason = res.error
            log("  ⊘ %s" % res.error, "warn")
            return res

        if not wechatcode:
            res.error = (
                "缺少 Wechatcode — 请先在微信打开\"我的健康卡\"页, 由抓包代理捕获 "
                "(同一 Wechatcode 可绑定一批最多 9 张卡)"
            )
            res.step = "bind_no_wechatcode"
            log("  ✗ %s" % res.error, "err")
            return res

        # 1. 绑卡 (免人脸)
        log("  绑卡 (年龄 %d, 免人脸): %s" % (age, name), "info")
        ok, msg = self.hc.register_health_card(
            wechatcode=wechatcode, id_card=sfzh, name=name,
            phone=phone or "", nation=nation, relation=relation,
        )
        if not ok:
            res.error = "绑卡失败: %s" % msg
            res.step = "bind"
            log("  ✗ %s" % res.error, "err")
            return res
        log("  ✓ 健康卡已绑定: %s" % name, "ok")

        # 2. 重新拉卡列表, 找到刚绑的卡 (按姓名 + 身份证尾号匹配)
        card = None
        for c in self.hc.get_card_list():
            if c.name != name:
                continue
            cid = (c.id_card or "").strip()
            if (not cid) or ("*" in cid) or (cid[-4:] == sfzh[-4:]):
                card = c
                break
        if card is None:
            res.error = "绑卡后未在卡列表中找到该卡 (稍后可重试)"
            res.step = "bind_relist"
            log("  ✗ %s" % res.error, "err")
            return res

        # 3. 复用完整签约流程
        inner = self.process_card_full(
            card, orgcode=orgcode, team_name=team_name, team_guid=team_guid,
            doctor_name=doctor_name, package_names=package_names,
            package_guids=package_guids, start_date=start_date,
            end_date=end_date, period_years=period_years,
            auto_create=True, log_cb=log_cb,
        )
        if not inner.name:
            inner.name = name
        return inner

    # ================================================================
    # Batch processing
    # ================================================================

    def process_batch(
        self,
        cards: List[HealthCard],
        orgcode: str,
        team_name: str = "",
        team_guid: str = "",
        doctor_name: str = "",
        package_names: str = "",
        package_guids: str = "",
        start_date: str = "",
        end_date: str = "",
        period_years: str = "3",
        auto_create: bool = True,
        delay: float = 0.5,
        log_cb: Optional[Callable] = None,
        progress_cb: Optional[Callable] = None,
        stop_check: Optional[Callable] = None,
    ) -> List[FullSignResult]:
        """Process multiple health cards sequentially.

        Args:
            progress_cb: Called with (index, total, result) after each card.
            stop_check:  Returns True to abort the batch.

        Returns list of FullSignResult.
        """
        results: List[FullSignResult] = []

        for i, card in enumerate(cards):
            if stop_check and stop_check():
                break

            if log_cb:
                log_cb(
                    "处理 [%d/%d] %s (%s)" % (
                        i + 1, len(cards), card.name, card.id_card,
                    ),
                    "info",
                )

            r = self.process_card_full(
                card,
                orgcode=orgcode,
                team_name=team_name,
                team_guid=team_guid,
                doctor_name=doctor_name,
                package_names=package_names,
                package_guids=package_guids,
                start_date=start_date,
                end_date=end_date,
                period_years=period_years,
                auto_create=auto_create,
                log_cb=log_cb,
            )
            results.append(r)

            if progress_cb:
                progress_cb(i, len(cards), r)

            if delay > 0 and i < len(cards) - 1:
                time.sleep(delay)

        return results
