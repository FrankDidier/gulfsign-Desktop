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
        return self.ph3._load_service_packs(fwlx)

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
        phone = card.phone or "13800000000"

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
