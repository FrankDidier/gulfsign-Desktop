# -*- coding: utf-8 -*-
"""
健康卡联网平台 API 对接引擎

平台: https://jkkyljl.hnhfpc.gov.cn (湖南省健康卡医疗机构联网平台)

核心流程:
  1. openid → getToken → JWT
  2. JWT → newlist → 健康卡列表
  3. healthCardId → updateRpc(rpc=1) → 绕过人脸验证
  4. healthCardId → querybyidcardqyjg → 签约信息
  5. personId → queryqyxxall → 合同详情
  6. editqr → 签约确认 (STATUS 5→1)
"""
import json
import time
import base64
import logging
from dataclasses import dataclass, field
from typing import Optional, List, Tuple, Callable

import requests
import urllib3

urllib3.disable_warnings()
logger = logging.getLogger(__name__)

HC_BASE_URL = "https://jkkyljl.hnhfpc.gov.cn"


@dataclass
class HealthCard:
    health_card_id: str
    name: str
    id_card: str
    age: str = ""
    gender: str = ""
    rpc: str = ""
    relation: str = ""
    phone: str = ""

    @property
    def is_verified(self) -> bool:
        return self.rpc == "1"

    @property
    def age_category(self) -> str:
        try:
            a = int(self.age)
        except (ValueError, TypeError):
            return ""
        if a < 18:
            return "未成年"
        if a >= 60:
            return "老年人"
        return "成年人"


@dataclass
class HCContract:
    guid: str
    person_id: str
    health_card_id: str
    orgcode: str
    org_name: str = ""
    status: str = ""
    doctor: str = ""
    start_date: str = ""
    end_date: str = ""
    name: str = ""

    @property
    def is_pending(self) -> bool:
        return self.status == "5"


@dataclass
class HCConfirmResult:
    success: bool
    name: str = ""
    health_card_id: str = ""
    error: str = ""
    elapsed: float = 0.0


class HealthCardClient:
    """健康卡联网平台 HTTP 客户端。"""

    def __init__(self, base_url: str = HC_BASE_URL):
        self.base_url = base_url
        self.session = requests.Session()
        self.session.trust_env = False
        self.session.verify = False
        self.session.headers["User-Agent"] = (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/120.0.0.0 Safari/537.36"
        )
        self.jwt_token: str = ""
        self.openid: str = ""
        self.connected: bool = False
        self._timeout = 30

    def _svc_url(self) -> str:
        return f"{self.base_url}/httpapi/services.ashx"

    def _jkxb_url(self) -> str:
        return f"{self.base_url}/httpapi/jkxbservice.ashx"

    def _jkxb_headers(self) -> dict:
        return {**self.session.headers, "token": self.jwt_token}

    def connect(self, openid: str) -> Tuple[bool, str]:
        self.openid = openid
        self.connected = False
        self.jwt_token = ""

        try:
            r = self.session.get(
                self._svc_url(),
                params={"ACTION": "getToken", "Openid": openid},
                timeout=self._timeout,
            )
            data = r.json()
            if data.get("errno") != 0:
                return False, "获取Token失败: %s" % data.get("message", "未知错误")

            self.jwt_token = data["data"]["token"]
            self.connected = True

            try:
                payload = self.jwt_token.split(".")[1]
                payload += "=" * (4 - len(payload) % 4)
                decoded = json.loads(base64.urlsafe_b64decode(payload))
                from datetime import datetime
                exp = datetime.fromtimestamp(decoded["exp"])
                return True, "连接成功 — Token有效期至 %s" % exp.strftime("%Y-%m-%d %H:%M")
            except Exception:
                return True, "连接成功"

        except requests.exceptions.ConnectionError:
            return False, "连接失败：无法连接服务器"
        except requests.exceptions.Timeout:
            return False, "连接超时：服务器响应过慢"
        except Exception as e:
            return False, "连接异常: %s" % str(e)

    def get_card_list(self) -> List[HealthCard]:
        if not self.connected:
            return []

        try:
            r = self.session.get(
                self._svc_url(),
                params={
                    "ACTION": "newlist",
                    "Openid": self.openid,
                    "token": self.jwt_token,
                },
                timeout=self._timeout,
            )
            data = r.json()
            if data.get("errno") != 0:
                logger.warning("获取卡列表失败: %s", data.get("message"))
                return []

            cards = []
            for item in data.get("data", []):
                cards.append(HealthCard(
                    health_card_id=item.get("healthCardId", ""),
                    name=item.get("name", ""),
                    id_card=item.get("idCard", ""),
                    age=item.get("age", ""),
                    gender=item.get("gender", ""),
                    rpc=item.get("rpc", ""),
                    relation=item.get("relation", ""),
                    phone=item.get("phone", ""),
                ))
            return cards
        except Exception as e:
            logger.error("获取卡列表异常: %s", e)
            return []

    def update_rpc(self, health_card_id: str) -> Tuple[bool, str]:
        if not self.connected:
            return False, "未连接"

        try:
            r = self.session.get(
                self._svc_url(),
                params={
                    "ACTION": "updateRpc",
                    "Openid": self.openid,
                    "token": self.jwt_token,
                    "healthCardId": health_card_id,
                    "rpc": "1",
                },
                timeout=self._timeout,
            )
            data = r.json()
            msg = data.get("message", "")
            if "已完成" in msg:
                return True, msg
            return False, msg
        except Exception as e:
            return False, str(e)

    def query_signing_info(self, health_card_id: str) -> Optional[dict]:
        if not self.connected:
            return None

        try:
            r = self.session.get(
                self._jkxb_url(),
                params={
                    "action": "querybyidcardqyjg",
                    "healthCardId": health_card_id,
                },
                headers=self._jkxb_headers(),
                timeout=self._timeout,
            )
            data = r.json()
            if data.get("errno") == 0 and data.get("data"):
                return data["data"][0]
            return None
        except Exception as e:
            logger.error("查询签约信息异常: %s", e)
            return None

    def query_contracts(
        self, person_id: str, health_card_id: str
    ) -> List[HCContract]:
        if not self.connected:
            return []

        try:
            r = self.session.get(
                self._jkxb_url(),
                params={
                    "action": "queryqyxxall",
                    "personId": person_id,
                    "healthCardId": health_card_id,
                },
                headers=self._jkxb_headers(),
                timeout=self._timeout,
            )
            data = r.json()
            if data.get("errno") != 0:
                return []

            contracts = []
            for item in data.get("data", []):
                contracts.append(HCContract(
                    guid=item.get("guid", ""),
                    person_id=person_id,
                    health_card_id=health_card_id,
                    orgcode=item.get("jgbm", ""),
                    org_name=item.get("jgmc", ""),
                    status=str(item.get("qyzfbs", "")),
                    doctor=item.get("qyys", ""),
                    start_date=item.get("xyksrq", ""),
                    end_date=item.get("xyjsrq", ""),
                ))
            return contracts
        except Exception as e:
            logger.error("查询合同异常: %s", e)
            return []

    def confirm_one(self, contract: HCContract) -> HCConfirmResult:
        if not self.connected:
            return HCConfirmResult(False, error="未连接")

        t0 = time.time()
        try:
            r = self.session.get(
                self._jkxb_url(),
                params={
                    "action": "editqr",
                    "guid": contract.guid,
                    "b0105_13": "5",
                    "status": "1",
                    "personid": contract.person_id,
                    "openid": self.openid,
                    "orgcode": contract.orgcode,
                    "healthCardId": contract.health_card_id,
                },
                headers=self._jkxb_headers(),
                timeout=self._timeout,
            )
            elapsed = time.time() - t0
            data = r.json()

            if data.get("errno") == 0:
                return HCConfirmResult(
                    True, name=contract.name,
                    health_card_id=contract.health_card_id,
                    elapsed=elapsed,
                )
            return HCConfirmResult(
                False, name=contract.name,
                health_card_id=contract.health_card_id,
                error=data.get("message", "") or data.get("data", ""),
                elapsed=elapsed,
            )
        except Exception as e:
            return HCConfirmResult(
                False, name=contract.name,
                health_card_id=contract.health_card_id,
                error=str(e), elapsed=time.time() - t0,
            )

    def process_card(
        self,
        card: HealthCard,
        log_cb: Optional[Callable] = None,
    ) -> Optional[HCConfirmResult]:
        """Process a single health card: updateRpc → query → confirm."""

        def log(msg, tag=""):
            if log_cb:
                log_cb(msg, tag)

        if not card.is_verified:
            ok, msg = self.update_rpc(card.health_card_id)
            if ok:
                log("  设置人脸认证: %s" % msg, "ok")
                card.rpc = "1"
            else:
                log("  设置人脸认证失败: %s" % msg, "err")
                return HCConfirmResult(
                    False, name=card.name,
                    health_card_id=card.health_card_id,
                    error="设置人脸认证失败: %s" % msg,
                )

        info = self.query_signing_info(card.health_card_id)
        if not info:
            log("  无签约记录", "warn")
            return None

        person_id = info.get("GUID", "")
        status = info.get("CONTRACT_STATES", "")
        orgcode = info.get("gdjgcode", "")

        if str(status) != "5":
            status_names = {
                "0": "已签约", "1": "未签约",
                "5": "医生申请(待确认)", "6": "居民申请",
            }
            log("  状态: %s (非待确认)" % status_names.get(str(status), status), "warn")
            return None

        contracts = self.query_contracts(person_id, card.health_card_id)
        pending = [c for c in contracts if c.is_pending]

        if not pending:
            log("  无待确认合同", "warn")
            return None

        last_result = None
        for contract in pending:
            contract.name = card.name
            contract.orgcode = contract.orgcode or orgcode
            log("  确认合同: %s" % contract.guid[:16], "info")
            result = self.confirm_one(contract)
            last_result = result

            if result.success:
                log("  >> 确认成功! (%.1f秒)" % result.elapsed, "ok")
            else:
                log("  >> 确认失败: %s" % result.error, "err")

        return last_result
