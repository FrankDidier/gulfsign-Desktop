# -*- coding: utf-8 -*-
"""
公卫3.0系统 API 对接引擎 (独立版本)

逆向工程自: https://ggws.hnhfpc.gov.cn
技术栈: ASP.NET WebForms + dhtmlx + SM4/SM3国密
"""
import re
import json
import time
import logging
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Tuple, Callable

import ssl
import warnings

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.ssl_ import create_urllib3_context

logger = logging.getLogger(__name__)

warnings.filterwarnings("ignore", message=".*Unverified HTTPS.*")
warnings.filterwarnings("ignore", message=".*TLSv1.*deprecated.*")


class _LooseTLSAdapter(HTTPAdapter):
    """Allow legacy TLS ciphers required by some gov servers."""

    def init_poolmanager(self, *args, **kwargs):
        ctx = create_urllib3_context()
        ctx.set_ciphers("DEFAULT:@SECLEVEL=0")
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        kwargs["ssl_context"] = ctx
        return super().init_poolmanager(*args, **kwargs)

# ---------------------------------------------------------------------------
# SM4 / SM3 国密加密
# ---------------------------------------------------------------------------

try:
    from gmssl.sm4 import CryptSM4, SM4_ENCRYPT
    from gmssl import sm3, func
    _HAS_GMSSL = True
except ImportError:
    _HAS_GMSSL = False


class PH3Crypto:
    """SM4 加密 + SM3 签名，复现3.0系统前端 crptosEn / crptosTH。"""

    @staticmethod
    def _require_gmssl():
        if not _HAS_GMSSL:
            raise RuntimeError(
                "缺少 gmssl 库，请执行: pip install gmssl"
            )

    @classmethod
    def sm4_encrypt_ecb(cls, plaintext_hex: str, key_hex: str) -> str:
        cls._require_gmssl()
        key_bytes = key_hex.encode("ascii")
        data_bytes = plaintext_hex.encode("ascii")
        sm4 = CryptSM4()
        sm4.set_key(key_bytes, SM4_ENCRYPT)
        encrypted = sm4.crypt_ecb(data_bytes)
        return encrypted.hex().upper()

    @classmethod
    def sm3_hash(cls, data: str) -> str:
        cls._require_gmssl()
        data_bytes = data.encode("utf-8")
        hash_hex = sm3.sm3_hash(func.bytes_to_list(data_bytes))
        return hash_hex.upper()

    @classmethod
    def crptosEn(cls, plaintext: str, key_hex: str) -> str:
        plaintext_hex = plaintext.encode("utf-8").hex().lower()
        return cls.sm4_encrypt_ecb(plaintext_hex, key_hex)

    @classmethod
    def crptosTH(cls, data: str) -> str:
        return cls.sm3_hash(data)

    @classmethod
    def sign_pageno(
        cls, page_no: int, org_code: str, token_en: str, token_th: str
    ) -> Tuple[str, str]:
        ts = str(int(time.time() * 1000))
        plaintext = "%d|%s%s" % (page_no, org_code, ts)
        encrypted = cls.crptosEn(plaintext, token_en)
        signature = cls.crptosTH(encrypted + token_th)
        return encrypted, signature

    @classmethod
    def open_url_handle(
        cls, value: str, token_en: str, token_th: str
    ) -> Tuple[str, str, str]:
        """返回 (encrypted, signature, timestamp)"""
        ts = str(int(time.time() * 1000))
        encrypted = cls.crptosEn(value + "|" + ts, token_en)
        signature = cls.crptosTH(encrypted + token_th)
        return encrypted, signature, ts


# ---------------------------------------------------------------------------
# 数据结构
# ---------------------------------------------------------------------------

@dataclass
class Patient:
    person_id: str
    name: str
    id_card: str
    contract_code: str = ""
    contract_status: str = ""
    status_text: str = ""
    archive_no: str = ""
    address: str = ""
    signing_team: str = ""
    signing_doctor: str = ""
    signing_date: str = ""
    agreement_start: str = ""
    agreement_end: str = ""
    gender: str = ""
    birth_date: str = ""
    age: str = ""


@dataclass
class SignResult:
    success: bool
    person_id: str
    name: str = ""
    contract_code: str = ""
    error: str = ""
    step: str = ""
    elapsed: float = 0.0


@dataclass
class ProvinceMatch:
    """全省个案查询命中的居民档案。"""
    person_id: str
    name: str = ""
    id_card: str = ""
    gender: str = ""
    birth_date: str = ""
    age: str = ""
    address: str = ""
    current_address: str = ""
    archive_no: str = ""
    archive_date: str = ""
    doctor: str = ""
    last_followup: str = ""
    contact_name: str = ""
    contact_phone: str = ""
    is_realname: bool = False
    is_visited: bool = False


# ---------------------------------------------------------------------------
# 3.0 系统 HTTP 对接
# ---------------------------------------------------------------------------

_STATUS_MAP = {
    "0": "已签约", "1": "未签约", "4": "拒绝签约",
    "5": "医生申请", "6": "居民申请",
}
_STATUS_REVERSE = {v: k for k, v in _STATUS_MAP.items()}

POPULATION_TYPES = {
    "0": "所有",
    "1": "一般人群",
    "2": "高血压",
    "3": "糖尿病",
    "4": "脑卒中",
    "5": "孕产妇",
    "6": "0-6岁儿童",
    "7": "重点监测对象",
    "8": "严重精神障碍患者",
    "9": "肺结核",
    "10": "老年人",
    "11": "残疾人",
    "12": "计划生育特殊家庭",
    "13": "其他疾病",
    "14": "慢阻肺",
}

_DEFAULT_QUERY_FORM = {
    "JKDABM": "", "XM": "", "XM_PY": "true", "SFZH": "",
    "ZZDABH": "", "CSRQ_BEGIN": "", "CSRQ_END": "",
    "POXM": "", "XB": "", "MF_BEGIN": "", "MF_END": "",
    "HYZK": "", "B0101_19_BEGIN": "", "B0101_19_END": "",
    "GDYS": "", "CONTRACT_STATES": "",
    "ISZDRQ": "", "JARQ_BEGIN": "", "JARQ_END": "",
    "ISDAZT": "0", "LYQK": "",
    "XYJSRQ_BEGIN": "", "XYJSRQ_END": "",
    "QYRQ_BEGIN": "", "QYRQ_END": "",
    "QYYS": "", "PAGEINDEX": "1",
}


def _strip_html(s: str) -> str:
    s = re.sub(r"<!\[CDATA\[", "", s)
    s = re.sub(r"\]\]>", "", s)
    s = re.sub(r"<[^>]+>", "", s)
    return s.strip()


class PH3Client:
    """公卫3.0 同步 HTTP 客户端（桌面版，基于 requests）。"""

    def __init__(self):
        self.base_url: str = ""
        self.session: requests.Session = requests.Session()
        self.session.trust_env = False  # 忽略系统代理（避免与 OpenID/抓包代理冲突）
        self.token_en: str = ""
        self.token_th: str = ""
        self.org_code: str = ""
        self.org_name: str = ""
        self.doctor_name: str = ""
        self.team_name: str = ""
        # `logged_in` is True both for fully-authorized sessions AND for
        # sessions that have valid SSO tokens but are stuck behind the
        # server-side QR-code 2FA gate (msg<=4). Use `qr_pending` to
        # distinguish: a QR-pending session cannot run query/sign APIs.
        self.logged_in: bool = False
        self.qr_pending: bool = False
        self._timeout: int = 60

    @property
    def fully_authenticated(self) -> bool:
        """True only when login is complete AND QR/2FA was satisfied
        AND we have an org_code (without which queries are pointless)."""
        return bool(self.logged_in and not self.qr_pending and self.org_code)

    # ---- helpers ----

    def _url(self, path: str) -> str:
        return self.base_url + path

    @staticmethod
    def _extract_viewstate(html: str) -> Dict[str, str]:
        result = {}
        for name in ("__VIEWSTATE", "__VIEWSTATEGENERATOR", "__EVENTVALIDATION"):
            m = re.search(rf'id="{name}"\s+value="([^"]*)"', html)
            if m:
                result[name] = m.group(1)
        return result

    def _extract_tokens(self, html: str) -> bool:
        # 尝试多种en token模式
        en_patterns = [
            r"""en\s*:\s*['"]([A-Fa-f0-9]{32})['"]""",
            r"""en\s*=\s*['"]([A-Fa-f0-9]{32})['"]""",
            r"""var\s+en\s*=\s*['"]([A-Fa-f0-9]{32})['"]""",
            r"""crptosEn\s*:\s*['"]([A-Fa-f0-9]{32})['"]""",
            r"""crptosEn\s*=\s*['"]([A-Fa-f0-9]{32})['"]""",
        ]
        
        for pattern in en_patterns:
            en_m = re.search(pattern, html)
            if en_m:
                self.token_en = en_m.group(1)
                break
        
        # 尝试多种th token模式
        th_patterns = [
            r"""th\s*:\s*['"]([A-Fa-f0-9]{64})['"]""",
            r"""th\s*=\s*['"]([A-Fa-f0-9]{64})['"]""",
            r"""var\s+th\s*=\s*['"]([A-Fa-f0-9]{64})['"]""",
            r"""crptosTH\s*:\s*['"]([A-Fa-f0-9]{64})['"]""",
            r"""crptosTH\s*=\s*['"]([A-Fa-f0-9]{64})['"]""",
        ]
        
        for pattern in th_patterns:
            th_m = re.search(pattern, html)
            if th_m:
                self.token_th = th_m.group(1)
                break
        
        return bool(self.token_en and self.token_th)

    def _extract_user_info(self, html: str):
        # region debug-point extract-user-info-start
        try:
            import requests as debug_requests
            debug_requests.post('http://localhost:5680/log', json={
                'level': 'info',
                'category': 'extract-user-info',
                'message': '开始提取用户信息',
                'details': {
                    'html_length': len(html) if html else 0,
                    'html_preview': html[:200] if html else ''
                }
            }, timeout=2)
        except:
            pass
        # endregion
        
        # 尝试多种机构代码模式
        org_patterns = [
            # 模式1: ORGCODE = '431122012345678' 或 orgcode = "431122012345678"
            r"""(?:ORGCODE|orgcode|OrgCode)\s*[=:]\s*['"](\d{10,})['"]""",
            # 模式2: orgCode: '431122012345678'
            r"""orgCode\s*:\s*['"](\d{10,})['"]""",
            # 模式3: orgCode = '431122012345678'
            r"""orgCode\s*=\s*['"](\d{10,})['"]""",
            # 模式4: orgcode: '431122012345678'
            r"""orgcode\s*:\s*['"](\d{10,})['"]""",
            # 模式5: orgcode = '431122012345678'
            r"""orgcode\s*=\s*['"](\d{10,})['"]""",
            # 模式6: ORGCODE: '431122012345678'
            r"""ORGCODE\s*:\s*['"](\d{10,})['"]""",
            # 模式7: ORGCODE = '431122012345678'
            r"""ORGCODE\s*=\s*['"](\d{10,})['"]""",
            # 模式8: var orgCode = '431122012345678'
            r"""var\s+orgCode\s*=\s*['"](\d{10,})['"]""",
            # 模式9: var ORGCODE = '431122012345678'
            r"""var\s+ORGCODE\s*=\s*['"](\d{10,})['"]""",
            # 模式10: <input name="orgcode" value="431122012345678">
            r"""name\s*=\s*['"]orgcode['"]\s+value\s*=\s*['"](\d{10,})['"]""",
            # 模式11: <input type="hidden" name="orgcode" value="431122012345678">
            r"""type\s*=\s*['"]hidden['"]\s+name\s*=\s*['"]orgcode['"]\s+value\s*=\s*['"](\d{10,})['"]""",
            # 模式12: data-orgcode="431122012345678"
            r"""data-orgcode\s*=\s*['"](\d{10,})['"]""",
            # 模式13: orgCode="431122012345678" (无空格)
            r"""orgCode\s*=\s*['"](\d{10,})['"]""",
            # 模式14: orgcode="431122012345678" (无空格)
            r"""orgcode\s*=\s*['"](\d{10,})['"]""",
            # 模式15: ORGCODE="431122012345678" (无空格)
            r"""ORGCODE\s*=\s*['"](\d{10,})['"]""",
            # 模式16: 更通用的模式: 包含"org"和10位以上数字
            r"""org[^>]*?['"](\d{10,})['"]""",
        ]
        
        extracted = False
        for i, pattern in enumerate(org_patterns, 1):
            org_m = re.search(pattern, html, re.IGNORECASE)
            if org_m:
                self.org_code = org_m.group(1)
                logger.info(f"机构代码提取成功 (模式{i}): {self.org_code}")
                
                # region debug-point org-extracted
                try:
                    import requests as debug_requests
                    debug_requests.post('http://localhost:5680/log', json={
                        'level': 'info',
                        'category': 'extract-user-info',
                        'message': '机构代码提取成功',
                        'details': {
                            'pattern_index': i,
                            'org_code': self.org_code,
                            'match_text': org_m.group(0)[:100] if org_m.group(0) else ''
                        }
                    }, timeout=2)
                except:
                    pass
                # endregion
                
                extracted = True
                break
        
        if not extracted:
            logger.warning("机构代码提取失败，未找到匹配的模式")
            # 尝试查找所有包含"org"的片段
            org_snippets = re.findall(r'[^>]*org[^>]*', html, re.IGNORECASE)
            if org_snippets:
                logger.info(f"找到包含'org'的片段: {org_snippets[:3]}")
            
            # region debug-point org-extraction-failed
            try:
                import requests as debug_requests
                debug_requests.post('http://localhost:5680/log', json={
                    'level': 'warning',
                    'category': 'extract-user-info',
                    'message': '机构代码提取失败',
                    'details': {
                        'org_snippets_count': len(org_snippets) if org_snippets else 0,
                        'org_snippets_preview': org_snippets[:3] if org_snippets else []
                    }
                }, timeout=2)
            except:
                pass
            # endregion
        
        # 尝试多种医生姓名模式
        name_patterns = [
            # 模式1: UserName = '张三' 或 XINGMING = "李四"
            r"""(?:UserName|XINGMING|xm)\s*[=:]\s*['"]([^'"]+)['"]""",
            # 模式2: userName: '王五'
            r"""userName\s*:\s*['"]([^'"]+)['"]""",
            # 模式3: userName = '赵六'
            r"""userName\s*=\s*['"]([^'"]+)['"]""",
            # 模式4: XINGMING: '钱七'
            r"""XINGMING\s*:\s*['"]([^'"]+)['"]""",
            # 模式5: XINGMING = '孙八'
            r"""XINGMING\s*=\s*['"]([^'"]+)['"]""",
            # 模式6: xm: '周九'
            r"""xm\s*:\s*['"]([^'"]+)['"]""",
            # 模式7: xm = '吴十'
            r"""xm\s*=\s*['"]([^'"]+)['"]""",
            # 模式8: var userName = '郑十一'
            r"""var\s+userName\s*=\s*['"]([^'"]+)['"]""",
            # 模式9: var XINGMING = '王十二'
            r"""var\s+XINGMING\s*=\s*['"]([^'"]+)['"]""",
            # 模式10: <input name="userName" value="李十三">
            r"""name\s*=\s*['"]userName['"]\s+value\s*=\s*['"]([^'"]+)['"]""",
            # 模式11: <input name="XINGMING" value="张十四">
            r"""name\s*=\s*['"]XINGMING['"]\s+value\s*=\s*['"]([^'"]+)['"]""",
            # 模式12: <input name="xm" value="刘十五">
            r"""name\s*=\s*['"]xm['"]\s+value\s*=\s*['"]([^'"]+)['"]""",
            # 模式13: 更通用的模式: 包含"name"和中文姓名
            r"""(?:name|姓名|username|UserName|XINGMING|xm)[^>]*?['"]([\u4e00-\u9fa5]{2,4})['"]""",
        ]
        
        name_extracted = False
        for i, pattern in enumerate(name_patterns, 1):
            name_m = re.search(pattern, html, re.IGNORECASE)
            if name_m:
                self.doctor_name = name_m.group(1).strip()
                logger.info(f"医生姓名提取成功 (模式{i}): {self.doctor_name}")
                
                # region debug-point name-extracted
                try:
                    import requests as debug_requests
                    debug_requests.post('http://localhost:5680/log', json={
                        'level': 'info',
                        'category': 'extract-user-info',
                        'message': '医生姓名提取成功',
                        'details': {
                            'pattern_index': i,
                            'doctor_name': self.doctor_name,
                            'match_text': name_m.group(0)[:100] if name_m.group(0) else ''
                        }
                    }, timeout=2)
                except:
                    pass
                # endregion
                
                name_extracted = True
                break
        
        if not name_extracted:
            logger.warning("医生姓名提取失败，未找到匹配的模式")
            
            # region debug-point name-extraction-failed
            try:
                import requests as debug_requests
                debug_requests.post('http://localhost:5680/log', json={
                    'level': 'warning',
                    'category': 'extract-user-info',
                    'message': '医生姓名提取失败',
                    'details': {
                        'name_patterns_tried': len(name_patterns)
                    }
                }, timeout=2)
            except:
                pass
            # endregion
        
        # 尝试提取团队信息
        team_patterns = [
            # 模式1: TEAMNAME = '家庭医生团队' 或 teamName = "社区医疗团队"
            r"""(?:TEAMNAME|teamname|TeamName)\s*[=:]\s*['"]([^'"]+)['"]""",
            # 模式2: teamName: '乡镇卫生院团队'
            r"""teamName\s*:\s*['"]([^'"]+)['"]""",
            # 模式3: teamName = '村卫生室团队'
            r"""teamName\s*=\s*['"]([^'"]+)['"]""",
            # 模式4: TEAMNAME: '社区卫生服务中心团队'
            r"""TEAMNAME\s*:\s*['"]([^'"]+)['"]""",
            # 模式5: TEAMNAME = '医疗集团团队'
            r"""TEAMNAME\s*=\s*['"]([^'"]+)['"]""",
            # 模式6: var teamName = '专科医院团队'
            r"""var\s+teamName\s*=\s*['"]([^'"]+)['"]""",
            # 模式7: var TEAMNAME = '综合医院团队'
            r"""var\s+TEAMNAME\s*=\s*['"]([^'"]+)['"]""",
            # 模式8: <input name="teamName" value="中医医院团队">
            r"""name\s*=\s*['"]teamName['"]\s+value\s*=\s*['"]([^'"]+)['"]""",
            # 模式9: <input name="TEAMNAME" value="民族医院团队">
            r"""name\s*=\s*['"]TEAMNAME['"]\s+value\s*=\s*['"]([^'"]+)['"]""",
            # 模式10: 更通用的模式: 包含"team"和团队名称
            r"""(?:team|团队|teamName|TEAMNAME)[^>]*?['"]([^'"]+)['"]""",
        ]
        
        team_extracted = False
        for i, pattern in enumerate(team_patterns, 1):
            team_m = re.search(pattern, html, re.IGNORECASE)
            if team_m:
                self.team_name = team_m.group(1).strip()
                logger.info(f"团队名称提取成功 (模式{i}): {self.team_name}")
                
                # region debug-point team-extracted
                try:
                    import requests as debug_requests
                    debug_requests.post('http://localhost:5680/log', json={
                        'level': 'info',
                        'category': 'extract-user-info',
                        'message': '团队名称提取成功',
                        'details': {
                            'pattern_index': i,
                            'team_name': self.team_name,
                            'match_text': team_m.group(0)[:100] if team_m.group(0) else ''
                        }
                    }, timeout=2)
                except:
                    pass
                # endregion
                
                team_extracted = True
                break
        
        if not team_extracted:
            logger.warning("团队名称提取失败，未找到匹配的模式")
            
            # region debug-point team-extraction-failed
            try:
                import requests as debug_requests
                debug_requests.post('http://localhost:5680/log', json={
                    'level': 'warning',
                    'category': 'extract-user-info',
                    'message': '团队名称提取失败',
                    'details': {
                        'team_patterns_tried': len(team_patterns)
                    }
                }, timeout=2)
            except:
                pass
            # endregion
        
        # region debug-point extract-user-info-summary
        try:
            import requests as debug_requests
            debug_requests.post('http://localhost:5680/log', json={
                'level': 'info',
                'category': 'extract-user-info',
                'message': '用户信息提取完成',
                'details': {
                    'org_code': self.org_code,
                    'org_name': self.org_name,
                    'doctor_name': self.doctor_name,
                    'team_name': self.team_name,
                    'org_extracted': extracted,
                    'name_extracted': name_extracted,
                    'team_extracted': team_extracted
                }
            }, timeout=2)
        except:
            pass
        # endregion

    # ---- 登录 ----

    def login(self, base_url: str, account: str, password: str) -> Tuple[bool, str]:
        # region debug-point login-start
        try:
            import requests as debug_requests
            debug_data = {
                'base_url': base_url,
                'account': account,
                'password_length': len(password) if password else 0
            }
            debug_requests.post('http://localhost:5680/log', json={
                'level': 'info',
                'category': 'login',
                'message': '登录开始',
                'details': debug_data
            }, timeout=2)
        except:
            pass
        # endregion
        
        self.base_url = base_url.rstrip("/")
        self.session = requests.Session()
        self.session.trust_env = False
        self.session.mount("https://", _LooseTLSAdapter())
        self.session.verify = False
        self.session.headers.update({
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/120.0.0.0 Safari/537.36"
            ),
        })

        try:
            # 首先尝试直接访问FormMain.aspx（处理SSO重定向）
            page = self.session.get(
                self._url("/FormMain.aspx"), timeout=self._timeout
            )
            
            # region debug-point page-loaded
            try:
                import requests as debug_requests
                debug_requests.post('http://localhost:5680/log', json={
                    'level': 'info',
                    'category': 'login',
                    'message': '页面加载完成',
                    'details': {
                        'url': page.url,
                        'status_code': page.status_code,
                        'content_length': len(page.text) if page.text else 0,
                        'has_sso_redirect': 'sso.hnhfpc.gov.cn' in page.url
                    }
                }, timeout=2)
            except:
                pass
            # endregion
            
            # 检查是否被重定向到SSO服务器
            if "sso.hnhfpc.gov.cn" in page.url:
                logger.info(f"检测到SSO重定向: {page.url}")
                
                # 尝试从重定向URL中提取Token
                import urllib.parse as urlparse
                parsed = urlparse.urlparse(page.url)
                query_params = urlparse.parse_qs(parsed.query)
                
                if 'Token' in query_params:
                    token = query_params['Token'][0]
                    logger.info(f"从重定向URL提取Token: {token}")
                    
                    # 使用Token访问主页面（这会显示登录表单）
                    main_url = self._url(f"/Index.aspx?Token={token}")
                    page = self.session.get(main_url, timeout=self._timeout)
                    logger.info(f"访问登录页面成功: {page.url}")
                else:
                    # 没有找到Token，尝试传统的登录方式
                    logger.info("未找到Token，尝试传统登录方式")
            
            # 传统登录方式（原有的逻辑）
            if not self._extract_tokens(page.text):
                return False, "无法获取加密Token（页面加载失败）"

            import time as _t
            ts = str(int(_t.time() * 1000))
            enc_pwd = PH3Crypto.crptosEn(password + "|" + ts, self.token_en)
            sign_pwd = PH3Crypto.crptosTH(enc_pwd + self.token_th)

            resp = self.session.post(
                self._url("/ashx/LoginHandler.ashx"),
                params={
                    "action": "LOGIN",
                    "YONGHUMING": account,
                    "MIMA": enc_pwd,
                    "SIGN": sign_pwd,
                    "t": ts,
                    "YANZHENGMA": "",
                    "TYPE": "1",
                },
                headers={
                    "Referer": page.url,
                    "X-Requested-With": "XMLHttpRequest",
                },
                timeout=self._timeout,
            )

            import json as _json
            try:
                obj = _json.loads(resp.text)
                
                # region debug-point login-response
                try:
                    import requests as debug_requests
                    debug_requests.post('http://localhost:5680/log', json={
                        'level': 'info',
                        'category': 'login',
                        'message': '登录响应解析',
                        'details': {
                            'response_text': resp.text[:500] if resp.text else '',
                            'opType': obj.get('opType'),
                            'msg': obj.get('msg'),
                            'status_code': resp.status_code
                        }
                    }, timeout=2)
                except:
                    pass
                # endregion
                
            except Exception:
                # region debug-point login-response-error
                try:
                    import requests as debug_requests
                    debug_requests.post('http://localhost:5680/log', json={
                        'level': 'error',
                        'category': 'login',
                        'message': '登录响应解析失败',
                        'details': {
                            'response_text': resp.text[:500] if resp.text else '',
                            'status_code': resp.status_code
                        }
                    }, timeout=2)
                except:
                    pass
                # endregion
                return False, "登录异常：无法解析响应"

            op = obj.get("opType")
            if op != 0:
                # region debug-point login-failed
                try:
                    import requests as debug_requests
                    debug_requests.post('http://localhost:5680/log', json={
                        'level': 'error',
                        'category': 'login',
                        'message': '登录失败',
                        'details': {
                            'opType': op,
                            'msg': obj.get('msg', '未知错误')
                        }
                    }, timeout=2)
                except:
                    pass
                # endregion
                return False, "登录失败：%s" % obj.get("msg", "未知错误")

            # 检查是否需要二维码验证
            msg_value = obj.get("msg")
            try:
                msg_int = int(msg_value) if msg_value else 0
            except:
                msg_int = 0
            
            # region debug-point qr-check
            try:
                import requests as debug_requests
                debug_requests.post('http://localhost:5680/log', json={
                    'level': 'info',
                    'category': 'login',
                    'message': '检查二维码验证需求',
                    'details': {
                        'msg_value': msg_value,
                        'msg_int': msg_int,
                        'requires_qr': msg_int <= 4
                    }
                }, timeout=2)
            except:
                pass
            # endregion
            
            if msg_int <= 4:
                # 需要二维码验证
                logger.info(f"需要二维码验证 (msg={msg_int})")
                
                # SSO 通过、Token 已下发，但服务器仍在等待二维码扫描；
                # 此时账号在 PH3 接口看来是 "已登录但未完成 2FA"。
                # `logged_in=True` 让浏览器跳转/Cookie 复用流程可以继续，
                # `qr_pending=True` 让查询/签约/同步配置接口拒绝调用。
                self.logged_in = True
                self.qr_pending = True
                # 不再把 doctor_name 设成 "需要二维码验证" — 这只是个临时状态,
                # 不应污染后续 UI 上显示给用户的医生名字. UI 应通过
                # qr_pending 标志感知此状态.

                error_msg = f"登录成功但需要二维码验证 (msg={msg_int})"
                solution = "应用会自动弹出二维码窗口供扫描 (或使用「打开网页登录」按钮)"
                
                # region debug-point qr-required
                try:
                    import requests as debug_requests
                    debug_requests.post('http://localhost:5680/log', json={
                        'level': 'warning',
                        'category': 'login',
                        'message': '需要二维码验证',
                        'details': {
                            'msg_int': msg_int,
                            'error_msg': error_msg,
                            'solution': solution
                        }
                    }, timeout=2)
                except:
                    pass
                # endregion
                
                return True, f"{error_msg}\n{solution}"

            main_resp = self.session.get(
                self._url("/FormMain.aspx"), timeout=self._timeout
            )
            
            # region debug-point main-page-loaded
            try:
                import requests as debug_requests
                debug_requests.post('http://localhost:5680/log', json={
                    'level': 'info',
                    'category': 'login',
                    'message': '主页面加载完成',
                    'details': {
                        'url': main_resp.url,
                        'status_code': main_resp.status_code,
                        'content_length': len(main_resp.text) if main_resp.text else 0,
                        'is_main_page': 'FormMain.aspx' in main_resp.url
                    }
                }, timeout=2)
            except:
                pass
            # endregion

            if not self._extract_tokens(main_resp.text):
                return False, "登录成功但未能提取加密Token"

            self._extract_user_info(main_resp.text)

            if not self.org_code:
                orgs = self.get_org_tree("0")
                if orgs:
                    self._drill_org_tree(orgs)

            self.logged_in = True
            self.qr_pending = False  # 完整登录: 不需要二维码
            info = self.doctor_name or account
            if self.org_name:
                info += " (%s)" % self.org_name
            
            # region debug-point login-success
            try:
                import requests as debug_requests
                debug_requests.post('http://localhost:5680/log', json={
                    'level': 'info',
                    'category': 'login',
                    'message': '登录成功',
                    'details': {
                        'account': account,
                        'org_code': self.org_code,
                        'org_name': self.org_name,
                        'doctor_name': self.doctor_name,
                        'team_name': self.team_name,
                        'logged_in': self.logged_in
                    }
                }, timeout=2)
            except:
                pass
            # endregion
            
            return True, "登录成功 — %s" % info

        except requests.exceptions.ConnectionError:
            return False, "连接失败：无法连接服务器"
        except requests.exceptions.Timeout:
            return False, "连接超时：服务器响应过慢"
        except Exception as e:
            return False, "登录异常：%s" % str(e)

    # ================================================================
    # 二维码登录 (与原 client.exe getQRCodeImage / finishQRCodeLogin 同接口)
    # ================================================================
    #
    # **真实流程 (竞品反编译 + live 实测, 2026-06)**:
    #   1. GET /Pg_ScanQrCode.aspx?href=<FormMain> — 返回的 HTML 直接内嵌
    #      <img src="data:image/jpg;base64,..."> 二维码图像 (无需 ajax 生成).
    #   2. 页面 JS 每 3 秒 GET /ashx/LoginHandler.ashx?ACTION=CHECKSM&t=<ts>
    #      响应 opType 含义 (实测):
    #        0 = 扫码并通过 → 跳转 FormMain.aspx 完成登录
    #        1 = 等待用户扫码 (继续轮询)
    #   注: 旧实现用的 ACTION=GENERATE / ACTION=QUERY 在本服务器并不存在,
    #   会触发 HuNanCAServices.getTokenForNew() 404, 已废弃。
    #
    # 封装为 ``qr_login_generate()`` / ``qr_login_query()`` / ``qr_login_finalize()``,
    # 复用 self.session (cookies 来自前面的密码登录步骤), 服务端据此把扫码
    # 结果绑回本会话.

    def qr_login_generate(self) -> Tuple[bool, str, str, str]:
        """获取二维码图像 (data URL).

        **真实流程 (对照竞品反编译 + 实测 live 服务器)**: 公卫3.0 的扫码登录
        不是 ``ACTION=GENERATE`` ajax (该路径在本服务器会触发
        ``HuNanCAServices.getTokenForNew()`` 404)。真实做法是 GET
        ``/Pg_ScanQrCode.aspx?href=<FormMain>``, 该页面 HTML 里**直接内嵌**
        ``<img src="data:image/jpg;base64,...">`` 二维码; 轮询用
        ``ACTION=CHECKSM`` (基于会话 cookie), 因此无需单独的 catoken。

        Returns: (success, tokenimage_data_url, catoken, error_message)
        为兼容调用方 (qr_login_dialog), ``catoken`` 返回占位符 ``"session"``。
        """
        if not self.session or not self.base_url:
            return False, "", "", "尚未发起登录会话"

        try:
            resp = self.session.get(
                self._url("/Pg_ScanQrCode.aspx"),
                params={"href": self._url("/FormMain.aspx")},
                timeout=self._timeout,
            )
        except requests.RequestException as e:
            return False, "", "", "网络请求失败: %s" % e

        if resp.status_code != 200:
            return False, "", "", "HTTP %d" % resp.status_code

        m = re.search(
            r'<img[^>]+src=["\'](data:image/[^"\']+;base64,[^"\']+)["\']',
            resp.text, re.I,
        )
        if not m:
            return False, "", "", "二维码页面未找到二维码图像 (服务端流程可能已变化)"

        return True, m.group(1), "session", ""

    def qr_login_query(self, catoken: str = "") -> Tuple[int, str]:
        """轮询一次扫码状态.

        **真实流程**: GET ``/ashx/LoginHandler.ashx?ACTION=CHECKSM&t=<ts>`` —
        页面 JS 每 3 秒轮询, ``opType==0`` 时跳转 FormMain.aspx 表示扫码通过;
        其它 (实测 ``opType==1``) 表示仍在等待。``catoken`` 参数已废弃 (保留
        以兼容调用方), 因为 CHECKSM 完全依赖会话 cookie。

        Returns: (code, message)
          0 = 通过, 应调 ``qr_login_finalize()`` 完成登录.
          2 = 等待扫码 (继续轮询).
          -1 = 网络/解析失败 (调用方可决定继续轮询或终止).
        """
        if not self.session or not self.base_url:
            return -1, "尚未发起登录会话"

        try:
            resp = self.session.get(
                self._url("/ashx/LoginHandler.ashx"),
                params={"ACTION": "CHECKSM", "t": str(int(time.time() * 1000))},
                headers={"X-Requested-With": "XMLHttpRequest"},
                timeout=self._timeout,
            )
        except requests.RequestException as e:
            return -1, "网络请求失败: %s" % e

        if resp.status_code != 200:
            return -1, "HTTP %d" % resp.status_code

        try:
            obj = resp.json()
        except Exception:
            return -1, "服务器返回非 JSON"

        if obj.get("opType") == 0:
            return 0, obj.get("msg") or "扫码通过"
        return 2, obj.get("msg") or "等待扫码"

    def qr_login_finalize(self) -> Tuple[bool, str]:
        """扫码通过后, 完成登录: 拉 FormMain.aspx → 提取 token / 用户信息 / org_code.

        前提: ``qr_login_query()`` 刚返回 code=0; 此时服务端已把 cookie 升级为
        2FA 通过状态, 我们只要再拉一次主页就能拿全用户信息.

        Returns: (success, info_message). 成功时 ``self.qr_pending=False``,
        ``self.logged_in=True``, ``self.org_code`` 等已填充.
        """
        if not self.session or not self.base_url:
            return False, "尚未发起登录会话"

        try:
            main_resp = self.session.get(
                self._url("/FormMain.aspx"), timeout=self._timeout
            )
        except requests.RequestException as e:
            return False, "拉取主页失败: %s" % e

        if main_resp.status_code != 200:
            return False, "拉取主页失败 HTTP %d" % main_resp.status_code

        if not self._extract_tokens(main_resp.text):
            return False, "扫码完成但未能从主页提取加密 Token"

        # 复用与 login() 相同的用户信息提取逻辑
        try:
            self._extract_user_info(main_resp.text)
        except Exception as e:
            logger.warning("扫码后提取用户信息失败 (继续): %s", e)

        if not self.org_code:
            try:
                orgs = self.get_org_tree("0")
                if orgs:
                    self._drill_org_tree(orgs)
            except Exception as e:
                logger.warning("扫码后获取机构树失败: %s", e)

        self.logged_in = True
        self.qr_pending = False

        info = self.doctor_name or "已认证"
        if self.org_name:
            info += " (%s)" % self.org_name
        return True, "扫码登录成功 — %s" % info

    # ---- 机构树 ----

    def get_org_tree(self, parent_id: str = "0") -> List[Tuple[str, str]]:
        try:
            resp = self.session.get(
                self._url("/ashx/Common.ashx"),
                params={"action": "ORGTREE", "id": parent_id},
                timeout=self._timeout,
            )
            return re.findall(r'id="([^"]+)"\s+text="([^"]+)"', resp.text)
        except Exception:
            return []

    def _drill_org_tree(self, nodes: List[Tuple[str, str]], depth: int = 0):
        """递归向下找到最末端机构节点。"""
        if depth > 5:
            return
        for nid, ntext in nodes:
            children = self.get_org_tree(nid)
            if children:
                self._drill_org_tree(children, depth + 1)
            else:
                if not self.org_code or len(nid) > len(self.org_code):
                    self.org_code = nid
                    self.org_name = ntext

    # ---- 查询居民 ----

    def query_patients(
        self,
        status: str = "",
        org_code: str = "",
        page: int = 1,
        extra_filters: Optional[Dict] = None,
    ) -> Tuple[List[Patient], int]:
        # region debug-point query-start
        try:
            import requests as debug_requests
            debug_requests.post('http://localhost:5680/log', json={
                'level': 'info',
                'category': 'query',
                'message': '查询开始',
                'details': {
                    'logged_in': self.logged_in,
                    'status': status,
                    'org_code': org_code or self.org_code,
                    'page': page,
                    'has_extra_filters': bool(extra_filters)
                }
            }, timeout=2)
        except:
            pass
        # endregion
        
        if not self.logged_in or self.qr_pending:
            return [], 0

        oc = org_code or self.org_code
        pageno_enc, sign = PH3Crypto.sign_pageno(
            page, oc, self.token_en, self.token_th
        )

        params = {
            "action": "4",
            "PAGENO": pageno_enc,
            "sign": sign,
            "ORGCODE": oc,
            "ADDRCODE": "",
            "TABCODE": "a2",
        }

        form = dict(_DEFAULT_QUERY_FORM)
        form["CONTRACT_STATES"] = status
        form["PAGEINDEX"] = str(page)
        if extra_filters:
            form.update(extra_filters)

        # region debug-point query-params
        try:
            import requests as debug_requests
            debug_requests.post('http://localhost:5680/log', json={
                'level': 'info',
                'category': 'query',
                'message': '查询参数',
                'details': {
                    'params': params,
                    'form_keys': list(form.keys()),
                    'form_CONTRACT_STATES': form.get('CONTRACT_STATES'),
                    'form_PAGEINDEX': form.get('PAGEINDEX'),
                    'token_en_length': len(self.token_en) if self.token_en else 0,
                    'token_th_length': len(self.token_th) if self.token_th else 0
                }
            }, timeout=2)
        except:
            pass
        # endregion

        try:
            url = self._url("/Sys_JCWS/b0105/Do_B0105_Handler.ashx")
            # region debug-point query-url
            try:
                import requests as debug_requests
                debug_requests.post('http://localhost:5680/log', json={
                    'level': 'info',
                    'category': 'query',
                    'message': '查询URL',
                    'details': {
                        'url': url,
                        'base_url': self.base_url
                    }
                }, timeout=2)
            except:
                pass
            # endregion
            
            resp = self.session.post(
                url,
                params=params,
                data=form,
                timeout=self._timeout,
            )
            
            # region debug-point query-response
            try:
                import requests as debug_requests
                debug_requests.post('http://localhost:5680/log', json={
                    'level': 'info',
                    'category': 'query',
                    'message': '查询响应',
                    'details': {
                        'status_code': resp.status_code,
                        'url': resp.url,
                        'content_length': len(resp.text) if resp.text else 0,
                        'content_preview': resp.text[:500] if resp.text else ''
                    }
                }, timeout=2)
            except:
                pass
            # endregion
            
            if resp.status_code != 200:
                logger.warning("查询返回 HTTP %d", resp.status_code)
                return [], 0
            return self._parse_grid(resp.text)
        except Exception as e:
            logger.error("查询失败: %s", e)
            return [], 0

    def query_all_patients(
        self,
        status: str = "",
        org_code: str = "",
        extra_filters: Optional[Dict] = None,
        progress_cb: Optional[Callable] = None,
        stop_check: Optional[Callable] = None,
    ) -> List[Patient]:
        all_pts: List[Patient] = []
        page = 1
        while True:
            if stop_check and stop_check():
                break
            patients, total = self.query_patients(status, org_code, page, extra_filters)
            all_pts.extend(patients)
            if progress_cb:
                progress_cb(len(all_pts), total)
            if not patients or len(all_pts) >= total:
                break
            page += 1
        return all_pts

    def _parse_grid(self, response_text: str) -> Tuple[List[Patient], int]:
        # region debug-point parse-grid-start
        try:
            import requests as debug_requests
            debug_requests.post('http://localhost:5680/log', json={
                'level': 'info',
                'category': 'parse-grid',
                'message': '开始解析网格数据',
                'details': {
                    'response_length': len(response_text) if response_text else 0,
                    'response_preview': response_text[:200] if response_text else '',
                    'has_double_at': '@@' in response_text
                }
            }, timeout=2)
        except:
            pass
        # endregion
        
        parts = response_text.split("@@")
        xml_data = parts[0] if parts else response_text
        total_str = parts[1].strip() if len(parts) > 1 else "0"
        total = int(total_str) if total_str.isdigit() else 0

        # region debug-point parse-grid-parts
        try:
            import requests as debug_requests
            debug_requests.post('http://localhost:5680/log', json={
                'level': 'info',
                'category': 'parse-grid',
                'message': '解析网格部分',
                'details': {
                    'parts_count': len(parts),
                    'xml_data_length': len(xml_data),
                    'total_str': total_str,
                    'total': total
                }
            }, timeout=2)
        except:
            pass
        # endregion

        patients: List[Patient] = []

        for row_m in re.finditer(
            r'<row\s+id="([^"]+)"([^>]*)>(.*?)</row>', xml_data, re.DOTALL
        ):
            pid = row_m.group(1)
            attrs = row_m.group(2)
            cells_xml = row_m.group(3)

            cc_m = re.search(r'contract_code="([^"]+)"', attrs)
            contract_code = cc_m.group(1) if cc_m else ""

            cells = re.findall(r"<cell[^>]*>(.*?)</cell>", cells_xml, re.DOTALL)
            c = [_strip_html(x) for x in cells]

            def safe(idx: int) -> str:
                return c[idx] if idx < len(c) else ""

            status_text = safe(7)
            cs = _STATUS_REVERSE.get(status_text, "")

            patients.append(Patient(
                person_id=pid,
                name=safe(9),
                id_card=safe(13),
                contract_code=contract_code,
                contract_status=cs,
                status_text=status_text,
                archive_no=safe(8),
                gender=safe(10),
                birth_date=safe(11),
                age=safe(12),
                address=safe(14),
                signing_team=safe(16),
                signing_doctor=safe(18),
                signing_date=safe(19),
                agreement_start=safe(20),
                agreement_end=safe(21),
            ))

        # region debug-point parse-grid-result
        try:
            import requests as debug_requests
            debug_requests.post('http://localhost:5680/log', json={
                'level': 'info',
                'category': 'parse-grid',
                'message': '解析网格结果',
                'details': {
                    'patients_count': len(patients),
                    'total': total,
                    'sample_patient': {
                        'person_id': patients[0].person_id if patients else None,
                        'name': patients[0].name if patients else None,
                        'id_card': patients[0].id_card if patients else None
                    } if patients else None
                }
            }, timeout=2)
        except:
            pass
        # endregion
        
        return patients, total

    # ---- 全省个案查询 ----

    def query_province_wide(
        self,
        sfzh: str = "",
        name: str = "",
        hjdz: str = "430000000000",
        password: str = "",
        page: int = 1,
        exclude_cancelled: bool = False,
    ) -> Tuple[List[ProvinceMatch], int, str]:
        """全省范围个案查询（菜单：健康档案 → 全省个案查询）。

        身份证号 sfzh 与 姓名 name 至少传一个。当用姓名时，户籍地 hjdz
        必须细化到至少地市级（默认 430000000000 全省，但服务端会拒绝纯姓名 + 全省）。
        password 为当前账号的登录密码（页面里叫"动态安全码/用户密码"）。

        返回 (matches, total, error_msg)；error_msg 为空表示成功。
        """
        if not self.logged_in:
            return [], 0, "未登录"
        if self.qr_pending:
            return [], 0, "登录不完整: 需要二维码验证"
        if not sfzh and not name:
            return [], 0, "身份证号或姓名至少填一个"

        ts = str(int(time.time() * 1000))
        enc = PH3Crypto.crptosEn(ts, self.token_en)
        sig = PH3Crypto.crptosTH(enc + self.token_th)

        try:
            resp = self.session.post(
                self._url("/Sys_JCWS/B0101/Do_B0101_Handler.ashx"),
                params={
                    "ACTION": "10",
                    "PAGENO": enc,
                    "sign": sig,
                    "CHECKCA": "2",
                },
                data={
                    "GONGMINSHENFENHAOMA": sfzh.strip(),
                    "RENYUANXINGMING": name.strip(),
                    "HUJIGUANLIDI": hjdz or "430000000000",
                    "PAICHUZHUXIAORENKOU_CHK": "1" if exclude_cancelled else "0",
                    "SECURITYPASSWORD": password,
                    "PAGEINDEX": str(page),
                },
                headers=self._csrf_header(),
                timeout=self._timeout,
            )
        except requests.RequestException as e:
            return [], 0, "请求失败: %s" % e

        if resp.status_code != 200:
            return [], 0, "HTTP %d" % resp.status_code

        body = resp.text or ""
        # JSON 形式的错误（密码错/参数错）
        if body.lstrip().startswith("{"):
            try:
                obj = json.loads(body)
                return [], 0, obj.get("msg", "查询失败")
            except Exception:
                return [], 0, "查询失败：%s" % body[:120]

        # XML 行 + @@total
        parts = body.split("@@")
        xml_part = parts[0]
        total = 0
        if len(parts) > 1:
            t = parts[1].strip()
            if t.isdigit():
                total = int(t)

        matches: List[ProvinceMatch] = []
        for row_m in re.finditer(
            r'<row\s+id="([^"]+)"[^>]*>(.*?)</row>', xml_part, re.DOTALL
        ):
            pid = row_m.group(1)
            cells_xml = row_m.group(2)
            raw_cells = re.findall(
                r"<cell([^>]*)>(.*?)</cell>", cells_xml, re.DOTALL
            )
            attrs_list = [a for a, _ in raw_cells]
            text_cells = [_strip_html(t) for _, t in raw_cells]

            def safe(idx: int) -> str:
                return text_cells[idx] if idx < len(text_cells) else ""

            # cell[1] 的 title 包含 "已通过实名制验证"
            is_realname = False
            if len(attrs_list) > 1 and "实名制" in attrs_list[1]:
                is_realname = True
            # cell[2] 内 onclick="mf_click(...)" 表示已面访
            is_visited = False
            if len(raw_cells) > 2 and "mf_click" in raw_cells[2][1]:
                is_visited = True

            matches.append(ProvinceMatch(
                person_id=pid,
                name=safe(8),
                gender=safe(9),
                birth_date=safe(10),
                age=safe(11),
                id_card=safe(12),
                address=safe(5),
                current_address=safe(6),
                archive_no=safe(7),
                contact_name=safe(14),
                contact_phone=safe(15),
                archive_date=safe(18),
                doctor=safe(19),
                last_followup=safe(4),
                is_realname=is_realname,
                is_visited=is_visited,
            ))

        return matches, total, ""

    def list_personal_b0105(self, person_id: str) -> List[Dict]:
        """读取居民档案中的家医签约记录（即"家医信息"侧边列表）。

        返回每条记录: {contract_code, status_text, agreement_start,
        agreement_end, doctor}
        """
        if not self.logged_in or self.qr_pending:
            return []
        try:
            resp = self.session.get(
                self._url("/Sys_JCWS/JKDA/Do_Query_Handler.ashx"),
                params={
                    "action": "B0105",
                    "PAGENO": "1",
                    "PERSONID": person_id,
                    "n": str(int(time.time() * 1000)),
                },
                timeout=self._timeout,
            )
        except requests.RequestException:
            return []
        if resp.status_code != 200:
            return []

        out: List[Dict] = []
        body = resp.text.split("@@")[0]
        for row_m in re.finditer(
            r'<row\s+id="([^"]+)"([^>]*)>(.*?)</row>', body, re.DOTALL
        ):
            cc = row_m.group(1)
            attrs = row_m.group(2)
            cells = [_strip_html(t) for t in re.findall(
                r"<cell[^>]*>(.*?)</cell>", row_m.group(3), re.DOTALL
            )]

            def safe(idx: int) -> str:
                return cells[idx] if idx < len(cells) else ""

            voided = False
            voided_m = re.search(r'B0105_13="([^"]+)"', attrs)
            if voided_m and voided_m.group(1) == "1":
                voided = True

            out.append({
                "contract_code": cc,
                "status_text": ("作废" if voided else safe(1)) or safe(1),
                "voided": voided,
                "agreement_start": safe(2),
                "agreement_end": safe(3),
                "doctor": safe(4),
            })
        return out

    # ---- 发起签约 ----

    def _csrf_header(self) -> Dict[str, str]:
        for c in self.session.cookies:
            if c.name == "csrf_token":
                return {"csrf_token": c.value}
        return {}

    def _load_teams(self, html: str) -> List[Dict]:
        """从签约表单页面提取团队列表（zNodes数组）。"""
        import json as _json
        m = re.search(
            r'\$\("#QYTD"\)\.drawMultipleTree\(\{[^z]*zNodes:\s*(\[.*?\])\s*,',
            html, re.DOTALL,
        )
        if m:
            try:
                return _json.loads(m.group(1))
            except Exception:
                pass
        return []

    def _load_service_packs(self, fwlx: str = "0") -> Tuple[str, str]:
        """获取服务包列表，返回 (guids逗号分隔, 中文名逗号分隔)。

        fwlx: 人群类型代码 (0=所有, 1=一般人群, 2=高血压, 3=糖尿病, ...)
        """
        import json as _json
        try:
            resp = self.session.get(
                self._url("/Sys_JCWS/B0105/Do_B0105_Handler.ashx"),
                params={"ACTION": "8", "B0110_02": "2", "B0110_07": fwlx},
                timeout=self._timeout,
            )
            data = _json.loads(resp.text)
            items = data.get("B0110", data) if isinstance(data, dict) else data
            if isinstance(items, dict):
                items = items.get("B0110", [])
            guids = ",".join(it["GUID"] for it in items)
            names = ",".join(it.get("B0110_01", it.get("B0110_03", "")) for it in items)
            return guids, names
        except Exception:
            return "", ""

    def _find_team(
        self, teams: List[Dict], team_name: str = "", team_id: str = ""
    ) -> Tuple[str, str]:
        """在团队列表中匹配，返回 (team_guid, team_name)。"""
        clean = [
            t for t in teams
            if isinstance(t, dict) and t.get("id") and t.get("name")
        ]
        if team_id:
            for t in clean:
                if t["id"] == team_id:
                    return t["id"], t["name"]
        if team_name:
            for t in clean:
                if team_name in t["name"] or t["name"] in team_name:
                    return t["id"], t["name"]
        if clean:
            return clean[0]["id"], clean[0]["name"]
        return "", ""

    def initiate_signing(
        self,
        person_id: str,
        team_name: str = "",
        team_id: str = "",
        doctor_name: str = "",
        service_type: str = "0",
        signing_date: str = "",
        fwb_list: str = "",
        fwb_mc_list: str = "",
        agreement_start: str = "",
        agreement_end: str = "",
        period: str = "1",
    ) -> SignResult:
        if not self.logged_in:
            return SignResult(False, person_id, error="未登录", step="initiate")
        if self.qr_pending:
            return SignResult(
                False, person_id,
                error="登录不完整: 需要二维码验证", step="initiate",
            )

        t0 = time.time()
        try:
            ts = str(int(time.time() * 1000))
            today = time.strftime("%Y%m%d")
            start_date = agreement_start or today
            if agreement_end:
                end_date = agreement_end
            else:
                yrs = int(period) if period.isdigit() else 1
                end_date = str(int(start_date[:4]) + yrs) + start_date[4:]

            enc_guid = PH3Crypto.crptosEn(person_id + "|" + ts, self.token_en)
            sign = PH3Crypto.crptosTH(enc_guid + self.token_th)

            form_page_url = self._url("/Sys_JCWS/B0105/Pg_Insert_B0105.aspx")

            resp = self.session.get(
                form_page_url,
                params={"GUID": enc_guid, "sign": sign},
                timeout=self._timeout,
            )
            if resp.status_code != 200:
                return SignResult(
                    False, person_id,
                    error="表单加载失败 HTTP %d" % resp.status_code,
                    step="initiate", elapsed=time.time() - t0,
                )

            html = resp.text

            patient_name = ""
            nm = re.search(
                r'name=["\']XM["\'][^>]*value=["\']([^"\']+)', html, re.I
            )
            if nm:
                patient_name = nm.group(1)

            form_data: Dict[str, str] = {}
            for m in re.finditer(r"<input\b([^>]+)>", html, re.I):
                attrs_str = m.group(1)
                tp = re.search(r'type=["\']([^"\']+)', attrs_str, re.I)
                ftype = tp.group(1).lower() if tp else "text"
                if ftype in ("checkbox", "radio", "submit", "reset", "button"):
                    continue
                n = re.search(r'name=["\']([^"\']+)', attrs_str, re.I)
                v = re.search(r'value=["\']([^"\']*)', attrs_str, re.I)
                if n:
                    form_data[n.group(1)] = v.group(1) if v else ""

            teams = self._load_teams(html)
            tid, tname = self._find_team(
                teams,
                team_name=team_name or self.team_name,
                team_id=team_id,
            )

            if not fwb_list or not fwb_mc_list:
                fwb_list, fwb_mc_list = self._load_service_packs(service_type)

            form_data.update({
                "QYLX": "2",
                "QYLX_INPUT": "2",
                "FWDH": "",
                "QYTD": tid,
                "QYTDMC": tname,
                "QYYS": doctor_name or self.doctor_name or form_data.get("SBR", ""),
                "QYRQ": signing_date or today,
                "FWLX": service_type,
                "XYKSRQ": start_date,
                "QYZQ": period,
                "QYZQ_INPUT": period,
                "XYJSRQ": end_date,
                "YFJE": "0",
                "BZJE": "0",
                "ZJJE": "0",
                "FWBLIST": fwb_list,
                "FWBMCLIST": fwb_mc_list,
                "ACTION": "1",
                "SBDW": self.org_code or form_data.get("XGDW", ""),
            })
            form_data.pop("btnSave", None)
            form_data.pop("btnReset", None)

            handler_url = self._url("/Sys_JCWS/B0105/Do_B0105_Handler.ashx")

            submit = self.session.post(
                handler_url,
                data=form_data,
                headers=self._csrf_header(),
                timeout=self._timeout,
            )
            elapsed = time.time() - t0

            if submit.status_code != 200:
                return SignResult(
                    False, person_id, patient_name,
                    error="提交失败 HTTP %d" % submit.status_code,
                    step="initiate", elapsed=elapsed,
                )

            text = submit.text.strip()

            import json as _json
            try:
                obj = _json.loads(text)
                if not isinstance(obj, dict):
                    raise ValueError("non-dict json")
                if obj.get("opType") in (0, "0"):
                    cc = (
                        obj.get("type", "")
                        or obj.get("CONTRACT_CODE", "")
                        or obj.get("contract_code", "")
                    )
                    return SignResult(
                        True, person_id, patient_name,
                        contract_code=cc, step="initiate", elapsed=elapsed,
                    )
                return SignResult(
                    False, person_id, patient_name,
                    error=obj.get("msg", "服务器返回: opType=%s" % obj.get("opType")),
                    step="initiate", elapsed=elapsed,
                )
            except Exception:
                pass

            cc_m = re.search(
                r'[Cc]ontract.?[Cc]ode["\s]*[=:]["\s]*([a-f0-9-]{36})',
                text, re.IGNORECASE,
            )
            cc = cc_m.group(1) if cc_m else ""
            is_error = any(kw in text for kw in ("操作失败", "错误", "异常"))

            if is_error and not cc:
                err_m = re.search(r"(操作失败[^<]{0,80}|错误[^<]{0,80})", text)
                return SignResult(
                    False, person_id, patient_name,
                    error=err_m.group(1) if err_m else "表单返回异常",
                    step="initiate", elapsed=elapsed,
                )

            # 非 JSON 响应: 只有真正抓到 36 位合同号才算成功。
            # 之前: 没拿到 cc 也返回 success=True (误报) —— 现在改为失败,
            # 避免把"未知/HTML/空响应"当成发起成功 (上游会据此继续 confirm).
            if not cc:
                return SignResult(
                    False, person_id, patient_name,
                    error="发起返回非预期响应(无 opType / 无合同号), 无法确认是否成功",
                    step="initiate", elapsed=elapsed,
                )

            return SignResult(
                True, person_id, patient_name,
                contract_code=cc, step="initiate", elapsed=elapsed,
            )

        except Exception as e:
            return SignResult(
                False, person_id, error=str(e),
                step="initiate", elapsed=time.time() - t0,
            )

    # ---- 家庭归属反查 ----

    def find_family_guid(
        self, person_id: str, member_name: str = "",
    ) -> Tuple[str, str]:
        """根据 PERSONID + 成员姓名反查所属家庭 GUID。

        实现：先按 ``CYXM=member_name`` 过滤 ``Pg_View_B0103`` 的 ``action=4`` 列表，
        再对每条家庭记录调用 ``action=5`` 拉取成员，匹配 PERSONID。

        返回 (family_guid, head_personid)；找不到时返回 ("", "")。
        """
        if not self.logged_in or not person_id or not member_name:
            return "", ""
        try:
            ts = str(int(time.time() * 1000))
            enc = PH3Crypto.crptosEn("1|" + (self.org_code or "") + ts, self.token_en)
            sign = PH3Crypto.crptosTH(enc + self.token_th)
            resp = self.session.post(
                self._url("/Sys_JCWS/B0103/Do_B0103_Handler.ashx"),
                params={
                    "action": "4", "PAGENO": enc, "sign": sign,
                    "ORGCODE": self.org_code or "",
                    "ADDRCODE": self.org_code or "", "TABCODE": "0",
                },
                data={
                    "HZXM": "", "CYXM": member_name,
                    "B0103_04_BEGIN": "", "B0103_04_END": "",
                    "B0103_06": "", "B0103_11": "",
                    "TABCODE": "0", "PAGEINDEX": "1",
                },
                timeout=self._timeout,
            )
        except requests.RequestException:
            return "", ""
        body = (resp.text or "").split("@@")[0]
        for m in re.finditer(r'<row id="([^"]+)"([^>]*)>', body):
            family_guid = m.group(1)
            head = re.search(r'PERSONID="([^"]+)"', m.group(2))
            head_pid = head.group(1) if head else ""
            try:
                ev, sg, ts2 = PH3Crypto.open_url_handle(
                    family_guid, self.token_en, self.token_th,
                )
                rr = self.session.get(
                    self._url("/Sys_JCWS/B0103/Do_B0103_Handler.ashx"),
                    params={
                        "action": "5", "PAGENO": "1",
                        "ORGCODE": self.org_code or "",
                        "ADDRCODE": self.org_code or "",
                        "TABCODE": "0",
                        "GUID": ev, "sign": sg, "n": ts2,
                    },
                    timeout=self._timeout,
                )
            except requests.RequestException:
                continue
            mb = (rr.text or "").split("@@")[0]
            if re.search(r'PERSONID="' + re.escape(person_id) + r'"', mb):
                return family_guid, head_pid
        return "", ""

    # ---- 家庭批量发起（ACTION=10） ----

    def family_batch_initiate(
        self,
        person_ids: List[str],
        family_guid: str = "",
        team_name: str = "",
        team_id: str = "",
        doctor_name: str = "",
        service_type: str = "0",
        signing_date: str = "",
        agreement_start: str = "",
        agreement_end: str = "",
        period: str = "1",
        contact_phone: str = "",
    ) -> Tuple[bool, str, List[Dict]]:
        """批量发起家庭签约（``Do_B0105_Handler.ashx`` ``ACTION=10``）。

        来源：B0103 家庭档案页面 ``Pg_Insert_Jtysqy.aspx`` 的 JS 实现。
        服务端实现批量插入家庭医生签约记录，单条业务逻辑等价于 ``ACTION=1``，
        即批量产生 ``STATUS=5`` (医生申请)，**不会直接落库为 STATUS=0**。

        相对一对一 ``initiate_signing`` 的优势：
          - 一次 HTTP 调用提交多人，吞吐量大幅提升；
          - 避免逐个加载 ``Pg_Insert_B0105.aspx`` 表单页。

        参数：
          person_ids: 人员 PERSONID 列表（同家庭/同批次）
          family_guid: 所属家庭档案 GUID（用于 JTID 字段）；可为空
          contact_phone: 服务电话（YSLXDH），服务端要求非空，否则提交失败

        返回：(success, message, created_contracts)
          created_contracts: 成功时回填每位居民对应的合同号 (PERSONID, contract_code)。
        """
        import json as _json
        if not self.logged_in:
            return False, "未登录", []
        if self.qr_pending:
            return False, "登录不完整: 需要二维码验证", []
        if not person_ids:
            return False, "person_ids 为空", []

        t0 = time.time()
        today = time.strftime("%Y%m%d")
        start_date = agreement_start or today
        if agreement_end:
            end_date = agreement_end
        else:
            yrs = int(period) if str(period).isdigit() else 1
            end_date = str(int(start_date[:4]) + yrs) + start_date[4:]

        ts = str(int(time.time() * 1000))
        sample_pid = person_ids[0]
        enc_guid = PH3Crypto.crptosEn(sample_pid + "|" + ts, self.token_en)
        sign = PH3Crypto.crptosTH(enc_guid + self.token_th)
        try:
            html = self.session.get(
                self._url("/Sys_JCWS/B0105/Pg_Insert_B0105.aspx"),
                params={"GUID": enc_guid, "sign": sign},
                timeout=self._timeout,
            ).text
        except requests.RequestException as e:
            return False, "团队/服务包加载失败: %s" % e, []

        teams = self._load_teams(html)
        tid, tname = self._find_team(
            teams, team_name=team_name or self.team_name, team_id=team_id,
        )
        if not tid and teams:
            tid, tname = teams[0].get("id", ""), teams[0].get("name", "")
        fwb_ids, fwb_names = self._load_service_packs(service_type)

        before_codes: Dict[str, set] = {}
        for pid in person_ids:
            try:
                lst = self.list_personal_b0105(pid)
                before_codes[pid] = {x.get("contract_code", "") for x in lst}
            except Exception:
                before_codes[pid] = set()

        rows = []
        for pid in person_ids:
            rows.append({
                "PERSONID": pid,
                "B0105_03": tname,
                "B0105_04": doctor_name or self.doctor_name or "",
                "B0105_05": signing_date or today,
                "B0105_07": start_date,
                "B0105_09": end_date,
                "B0105_08": str(period),
                "B0105_03_GUID": tid,
                "B0105_06_GUID": fwb_ids,
                "B0105_06": fwb_names,
                "JTID": family_guid,
                "B0105_13": "5",
                "B0105_10": "0",
                "B0105_11": "0",
                "B0105_12": "0",
                "B0105_01": "2",
                # contact_phone (YSLXDH) 服务端非空校验; 调用方未提供时
                # 历史上一直退回到 "13800000000" 占位符 — 这会污染真实数据,
                # 此处保留兼容但发出告警, 让上层调用者尽快迁移到真实电话.
                "B0105_02": contact_phone or "13800000000",
            })
        if not contact_phone:
            logger.warning(
                "family_batch_initiate: contact_phone is empty, "
                "falling back to placeholder '13800000000' — please "
                "configure a real 服务电话 to avoid polluting production data."
            )

        try:
            resp = self.session.post(
                self._url("/Sys_JCWS/B0105/Do_B0105_Handler.ashx"),
                data={"ACTION": "10", "JSON": _json.dumps(rows, ensure_ascii=False)},
                headers=self._csrf_header(),
                timeout=self._timeout,
            )
        except requests.RequestException as e:
            return False, "提交失败: %s" % e, []

        if resp.status_code != 200:
            return False, "HTTP %d" % resp.status_code, []

        try:
            obj = _json.loads(resp.text.strip())
        except Exception:
            return False, "服务器返回异常: %s" % resp.text[:160], []

        if obj.get("opType") != 0:
            return False, obj.get("msg", "ACTION=10 提交失败"), []

        created: List[Dict] = []
        for pid in person_ids:
            try:
                lst = self.list_personal_b0105(pid)
            except Exception:
                lst = []
            for x in lst:
                cc = x.get("contract_code", "")
                if cc and cc not in before_codes.get(pid, set()):
                    created.append({
                        "person_id": pid,
                        "contract_code": cc,
                        "status_text": x.get("status_text", ""),
                    })
                    break

        elapsed = time.time() - t0
        # 之前: 即便 created 为空也返回 success=True. 修复: 必须真的创建出来才算成功.
        n_created = len(created)
        n_requested = len(person_ids)
        if n_created == 0:
            return (
                False,
                "服务器接受了请求 (opType=0) 但创建后查证未发现新合同号 (%d 人, %.1fs)"
                % (n_requested, elapsed),
                created,
            )
        if n_created < n_requested:
            return (
                False,  # 部分失败也按失败计, 让 UI 不再把它统计为成功签约.
                "家庭批量部分失败: 仅 %d/%d 创建成功 (%.1fs)"
                % (n_created, n_requested, elapsed),
                created,
            )
        return (
            True,
            "家庭批量发起成功 (%d 人, %.1fs)" % (n_created, elapsed),
            created,
        )

    # ---- 确认签约 ----

    def confirm_signing(
        self, person_id: str, contract_code: str, name: str = ""
    ) -> SignResult:
        """确认居民申请的签约（仅适用于 status=6 的合同）。

        对 status=5（医生申请）调用 ACTION=9 时，服务端会拒绝（常见提示：该类型不能处理）；
        与界面「确认」弹窗 Pg_Queren_Status 使用同一入口，但业务上只处理待审核的「居民端」申请。
        """
        if not self.logged_in:
            return SignResult(False, person_id, name, error="未登录", step="confirm")
        if self.qr_pending:
            return SignResult(
                False, person_id, name,
                error="登录不完整: 需要二维码验证", step="confirm",
            )

        t0 = time.time()
        try:
            resp = self.session.post(
                self._url("/Sys_JCWS/B0105/Do_B0105_Handler.ashx"),
                params={"ACTION": "9"},
                data={
                    "STATUS": "1",
                    "REMARK": "",
                    "GUID": contract_code,
                    "PERSONID": person_id,
                },
                headers=self._csrf_header(),
                timeout=self._timeout,
            )
            elapsed = time.time() - t0

            if resp.status_code != 200:
                return SignResult(
                    False, person_id, name,
                    error="HTTP %d" % resp.status_code,
                    step="confirm", elapsed=elapsed,
                )

            body = resp.text.strip()
            import json as _json
            try:
                obj = _json.loads(body)
                if isinstance(obj, dict) and obj.get("opType") in (0, "0"):
                    return SignResult(
                        True, person_id, name,
                        contract_code=contract_code,
                        step="confirm", elapsed=elapsed,
                    )
                return SignResult(
                    False, person_id, name,
                    contract_code=contract_code,
                    error=obj.get("msg", "确认失败"),
                    step="confirm", elapsed=elapsed,
                )
            except Exception:
                ok = body == "0"
                if ok:
                    return SignResult(
                        True, person_id, name,
                        contract_code=contract_code,
                        step="confirm", elapsed=elapsed,
                    )
                return SignResult(
                    False, person_id, name,
                    contract_code=contract_code,
                    error="服务器返回: %s" % body[:120],
                    step="confirm", elapsed=elapsed,
                )
        except Exception as e:
            return SignResult(
                False, person_id, name,
                error=str(e), step="confirm",
                elapsed=time.time() - t0,
            )

    # ---- 删除签约 ----

    @staticmethod
    def _opType_zero(text: str) -> bool:
        """严格解析 JSON 后判断 opType==0; 之前的 substring 匹配会被
        HTML 错误页里碰巧出现的 '"opType":0' 误报为成功。"""
        import json as _json
        try:
            obj = _json.loads((text or "").strip())
        except Exception:
            return False
        return isinstance(obj, dict) and obj.get("opType") in (0, "0")

    def delete_signing(self, contract_code: str) -> bool:
        """删除一条签约记录（ACTION=3），适用于status=5/6。"""
        try:
            resp = self.session.get(
                self._url("/Sys_JCWS/B0105/Do_B0105_Handler.ashx"),
                params={
                    "ACTION": "3",
                    "GUID": contract_code,
                    "etc": str(int(time.time() * 1000)),
                },
                timeout=self._timeout,
            )
            return self._opType_zero(resp.text)
        except Exception:
            return False

    def void_signing(self, contract_code: str) -> bool:
        """作废一条已签约的记录（ACTION=11），仅适用于status=0（已签约）。"""
        try:
            resp = self.session.get(
                self._url("/Sys_JCWS/B0105/Do_B0105_Handler.ashx"),
                params={
                    "ACTION": "11",
                    "GUID": contract_code,
                    "etc": str(int(time.time() * 1000)),
                },
                headers=self._csrf_header(),
                timeout=self._timeout,
            )
            return self._opType_zero(resp.text)
        except Exception:
            return False

    # ---- 档案修改 (B0101 ACTION=2) ----

    def load_archive(self, person_id: str) -> Tuple[bool, Dict, str]:
        """Load the archive edit form for a person, return all form fields.

        Returns (success, fields_dict, error_message).
        """
        if not self.logged_in:
            return False, {}, "未登录"
        if self.qr_pending:
            return False, {}, "登录不完整: 需要二维码验证"

        try:
            ts = str(int(time.time() * 1000))
            enc_guid = PH3Crypto.crptosEn(person_id + "|" + ts, self.token_en)
            sign = PH3Crypto.crptosTH(enc_guid + self.token_th)

            resp = self.session.get(
                self._url("/Sys_JCWS/B0101/Pg_Edit_B0101.aspx"),
                params={"GUID": enc_guid, "sign": sign},
                timeout=self._timeout,
            )
            if resp.status_code != 200:
                return False, {}, "加载失败 HTTP %d" % resp.status_code

            html = resp.text
            fields: Dict[str, str] = {}

            for m in re.finditer(r"<input\b([^>]+)>", html, re.I):
                attrs = m.group(1)
                tp = re.search(r'type=["\']([^"\']+)', attrs, re.I)
                ftype = tp.group(1).lower() if tp else "text"
                if ftype in ("checkbox", "radio", "submit", "reset", "button"):
                    continue
                n = re.search(r'name=["\']([^"\']+)', attrs, re.I)
                v = re.search(r'value=["\']([^"\']*)', attrs, re.I)
                if n:
                    fields[n.group(1)] = v.group(1) if v else ""

            for m in re.finditer(
                r'<select[^>]+name=["\']([^"\']+)["\'][^>]*>(.*?)</select>',
                html, re.DOTALL | re.I,
            ):
                name = m.group(1)
                opts_html = m.group(2)
                sel = re.search(
                    r'<option[^>]+selected[^>]*value=["\']([^"\']*)', opts_html, re.I,
                )
                if not sel:
                    sel = re.search(
                        r'<option[^>]*value=["\']([^"\']*)[^>]*selected',
                        opts_html, re.I,
                    )
                fields[name] = sel.group(1) if sel else ""

            for m in re.finditer(
                r'<textarea[^>]+name=["\']([^"\']+)["\'][^>]*>(.*?)</textarea>',
                html, re.DOTALL | re.I,
            ):
                fields[m.group(1)] = m.group(2).strip()

            if "GUID" not in fields:
                fields["GUID"] = person_id

            return True, fields, ""

        except Exception as e:
            return False, {}, str(e)

    def modify_archive(self, person_id: str, updates: Dict[str, str]) -> Tuple[bool, str]:
        """Modify a patient's archive (B0101 ACTION=2).

        Loads the edit form, applies *updates*, and submits.
        Typical use: ``modify_archive(pid, {"SFZH": "...", "CSRQ": "..."})``

        Returns (success, message).
        """
        ok, fields, err = self.load_archive(person_id)
        if not ok:
            return False, "加载档案失败: %s" % err

        fields.update(updates)
        fields["ACTION"] = "2"
        if not fields.get("GUID"):
            fields["GUID"] = person_id

        for key in ("btnSave", "btnReset", "btn1", "btn2"):
            fields.pop(key, None)

        try:
            import json as _json
            resp = self.session.post(
                self._url("/Sys_JCWS/B0101/Do_B0101_Handler.ashx"),
                data=fields,
                headers=self._csrf_header(),
                timeout=self._timeout,
            )
            if resp.status_code != 200:
                return False, "提交失败 HTTP %d" % resp.status_code

            text = resp.text.strip()
            try:
                obj = _json.loads(text)
            except Exception:
                # 之前: "成功" 子串或 text=="0" 都视为成功 — 容易把 HTML 错误页
                # 误判. 现在: 仅在严格 JSON 且 opType==0 时算成功.
                if len(text) < 200:
                    return False, "修改失败 (非JSON响应): %s" % text
                return False, "修改失败 (未知响应)"
            if obj.get("opType") == 0:
                return True, "修改成功"
            return False, obj.get(
                "msg", "修改失败: opType=%s" % obj.get("opType"),
            )

        except Exception as e:
            return False, "修改异常: %s" % str(e)

    # ---- 状态校验 + 档案推进 (对标竞品 checkSignStatus / updateDanganInfo) ----

    def check_sign_status_by_sfzh(
        self, sfzh: str, name: str = "", org_code: str = ""
    ) -> Tuple[str, str, str, str]:
        """按身份证号查询某居民的真实签约状态（只读）。

        对标竞品 ``ggws_session.checkSignStatus``：竞品用
        ``action=4 + POST SFZH/ISDAZT=0/PAGEINDEX=1`` 查询并读取状态文本。
        本实现复用 :meth:`query_patients` 的网格查询（同一 ``Do_B0105_Handler.ashx``
        ``action=4`` 接口，``_DEFAULT_QUERY_FORM`` 已含 ``SFZH``/``ISDAZT=0``）。

        返回 ``(status_code, status_text, person_id, contract_code)``。
        其中 ``status_code`` 取值见 :data:`_STATUS_MAP`（``0`` 已签约 / ``5`` 医生申请
        / ``6`` 居民申请 …）。查不到或失败统一返回 ``("", "", "", "")``，
        调用方据此判断"无法确认"，**不得**把无法确认当成功。
        """
        sfzh = (sfzh or "").strip()
        if not sfzh:
            return "", "", "", ""
        if not self.logged_in or self.qr_pending:
            return "", "", "", ""

        filters: Dict[str, str] = {"SFZH": sfzh}
        if name and name.strip():
            filters["XM"] = name.strip()

        try:
            patients, _ = self.query_patients(
                org_code=org_code, extra_filters=filters
            )
        except Exception as e:
            logger.warning("查询签约状态失败: %s", e)
            return "", "", "", ""

        if not patients:
            return "", "", "", ""

        chosen = None
        for p in patients:
            if (p.id_card or "").strip() == sfzh:
                chosen = p
                break
        if chosen is None:
            # 无精确身份证匹配时: 只有"唯一一条且其身份证被脱敏(含 *)"才退而
            # 取之 —— 否则宁可返回空(无法确认), 也绝不报告别人的状态(防止误判).
            if len(patients) == 1 and "*" in (patients[0].id_card or ""):
                chosen = patients[0]
            else:
                return "", "", "", ""

        return (
            chosen.contract_status or "",
            chosen.status_text or "",
            chosen.person_id or "",
            chosen.contract_code or "",
        )

    def finalize_via_archive(
        self,
        person_id: str,
        sfzh: str = "",
        name: str = "",
        org_code: str = "",
        max_retries: int = 3,
        sleep_between: float = 3.0,
        _sleep: Optional[Callable] = None,
    ) -> SignResult:
        """把停留在"居民申请/医生申请"的签约推进到"已签约"（对标竞品 updateDanganInfo）。

        机制（来自竞品 ``ggws_session.updateDanganInfo`` 反编译）：公卫系统要求
        居民**核心档案 (B0101)** 完整后，合同才会落库为"已签约"。竞品的做法是
        重新加载并 POST 一次 B0101 档案（内容不变，``ACTION=2``）触发服务端
        重新校验/落库，然后回查状态，循环到"已签约"或重试用尽（``sleep(3)`` 间隔）。

        流程::

            for _ in range(max_retries):
                查状态 -> 已签约? 直接返回成功
                modify_archive(person_id, {})   # 重新提交档案
                sleep(sleep_between)
            最终回查 -> 已签约? 成功 : 失败(诚实报告真实状态)

        必须提供 ``sfzh`` 才能确认结果；没有 ``sfzh`` 时无法核实，返回
        ``success=False`` 并注明"无法确认"，避免误报。

        返回 :class:`SignResult`。``_sleep`` 仅用于测试注入。
        """
        _sleep = _sleep or time.sleep
        if not self.logged_in:
            return SignResult(False, person_id, name, error="未登录", step="finalize")
        if self.qr_pending:
            return SignResult(
                False, person_id, name,
                error="登录不完整: 需要二维码验证", step="finalize",
            )

        retries = max(1, int(max_retries))
        last_text = ""
        last_cc = ""

        for attempt in range(retries):
            if sfzh:
                code, text, pid, cc = self.check_sign_status_by_sfzh(
                    sfzh, name, org_code
                )
                if text:
                    last_text = text
                if cc:
                    last_cc = cc
                if code == "0":
                    return SignResult(
                        True, person_id or pid, name,
                        contract_code=cc or last_cc, step="finalize_verified",
                    )
                if pid and not person_id:
                    person_id = pid

            if not person_id:
                return SignResult(
                    False, person_id, name,
                    error="缺少 person_id, 无法提交档案", step="finalize",
                )

            ok, msg = self.modify_archive(person_id, {})
            if not ok and not last_text:
                last_text = msg  # 仅作诊断, 不致命: 继续重试

            if attempt < retries - 1:
                _sleep(sleep_between)

        if sfzh:
            code, text, pid, cc = self.check_sign_status_by_sfzh(sfzh, name, org_code)
            if code == "0":
                return SignResult(
                    True, person_id or pid, name,
                    contract_code=cc or last_cc, step="finalize_verified",
                )
            return SignResult(
                False, person_id, name, contract_code=last_cc,
                error="档案已重提交但仍未落库为已签约 (当前: %s)"
                % (text or last_text or "未知状态"),
                step="finalize",
            )

        return SignResult(
            False, person_id, name,
            error="已提交档案但缺少身份证号, 无法确认是否落库为已签约",
            step="finalize",
        )

    def _verify_and_finalize(
        self,
        r: SignResult,
        person_id: str,
        sfzh: str = "",
        name: str = "",
        verify_final: bool = False,
        finalize_archive: bool = False,
        finalize_retries: int = 3,
    ) -> SignResult:
        """对一次签约结果做真实状态校验, 可选触发档案推进。

        - ``verify_final`` 且有 ``sfzh``: 回查真实状态。
            * 真实=已签约 -> 标记 success, step="verified_signed"。
            * 真实=医生/居民申请 且 ``finalize_archive`` -> 走档案推进。
            * 否则若 confirm 自称成功但真实未落库 -> **诚实改判 success=False**。
        - 查不到状态(code="") -> 无法确认, **保持原结果不动**(不误报也不误杀)。
        """
        if not verify_final or not (sfzh or "").strip():
            return r

        code, text, vpid, vcc = self.check_sign_status_by_sfzh(sfzh, name)

        if code == "0":
            r.success = True
            r.step = "verified_signed"
            r.error = ""
            if vcc:
                r.contract_code = vcc
            return r

        if finalize_archive and code in ("5", "6"):
            rf = self.finalize_via_archive(
                vpid or person_id, sfzh=sfzh, name=name,
                max_retries=finalize_retries,
            )
            if rf.success:
                r.success = True
                r.step = "finalized_via_archive"
                r.error = ""
                r.contract_code = rf.contract_code or r.contract_code
            else:
                r.success = False
                r.step = "verify_failed"
                r.error = rf.error or (
                    "确认后仍未签约 (状态: %s)" % (text or code or "未知")
                )
            return r

        # 已知的"未落库"状态: confirm 自称成功也要诚实改判
        if r.success and code in ("1", "4", "5", "6"):
            r.success = False
            r.step = "verify_failed"
            r.error = "确认成功但实际状态为 %s, 未落库为已签约" % (text or code)
        elif r.success and code == "":
            # 要求校验却查不到真实状态: 保留 success(不误杀真实成功), 但把
            # step 标成 unverified 让调用方/UI 看见"未经证实", 不静默当已核实.
            r.step = "unverified"

        # code == "" 且 r 本就失败: 保持原结果
        return r

    # ---- 完整签约 (发起+确认) ----

    def sign_one(
        self,
        person_id: str,
        name: str = "",
        team_name: str = "",
        team_id: str = "",
        doctor_name: str = "",
        delay: float = 0.3,
        contract_status: str = "",
        contract_code: str = "",
        auto_void: bool = False,
        auto_delete_doctor: bool = False,
        auto_delete_resident: bool = False,
        service_type: str = "0",
        agreement_start: str = "",
        agreement_end: str = "",
        period: str = "1",
        sfzh: str = "",
        verify_final: bool = False,
        finalize_archive: bool = False,
        finalize_retries: int = 3,
    ) -> SignResult:
        """签约一位居民。

        根据当前签约状态和选项自动选择操作：
        - auto_void: 若已签约(status=0)，先作废再重新签约
        - auto_delete_doctor: 若医生申请(status=5)，先删除再重新签约
        - auto_delete_resident: 若居民申请(status=6)，先删除再重新签约
        - status=6 (居民申请): 直接确认 → 已签约
        - status=1 (未签约) 或无状态: 发起签约
        - status=5 (医生申请): 已发起，尝试确认

        校验/落库选项（对标竞品）：
        - verify_final + sfzh: 签约后回查**真实状态**，把"自称成功实则停留在
          5/6"的误报诚实改判为失败 (step="verify_failed")。
        - finalize_archive: 真实状态仍为 5/6 时，重提交核心档案 (B0101) 把合同
          推进到"已签约" (对标竞品 updateDanganInfo)；成功则 step="finalized_via_archive"。
        """
        t0 = time.time()

        if contract_status == "0" and contract_code and auto_void:
            ok = self.void_signing(contract_code)
            if not ok:
                return SignResult(
                    False, person_id, name,
                    contract_code=contract_code,
                    error="作废已有签约失败",
                    step="void", elapsed=time.time() - t0,
                )
            contract_status = "1"
            contract_code = ""

        if contract_status == "5" and contract_code and auto_delete_doctor:
            ok = self.delete_signing(contract_code)
            if not ok:
                return SignResult(
                    False, person_id, name,
                    contract_code=contract_code,
                    error="删除医生申请失败",
                    step="delete", elapsed=time.time() - t0,
                )
            contract_status = "1"
            contract_code = ""

        if contract_status == "6" and contract_code and auto_delete_resident:
            ok = self.delete_signing(contract_code)
            if not ok:
                return SignResult(
                    False, person_id, name,
                    contract_code=contract_code,
                    error="删除居民申请失败",
                    step="delete", elapsed=time.time() - t0,
                )
            contract_status = "1"
            contract_code = ""

        if contract_status == "6" and contract_code:
            r = self.confirm_signing(person_id, contract_code, name)
            r = self._verify_and_finalize(
                r, person_id, sfzh=sfzh, name=r.name or name,
                verify_final=verify_final, finalize_archive=finalize_archive,
                finalize_retries=finalize_retries,
            )
            r.elapsed = time.time() - t0
            return r

        if contract_status == "5" and contract_code:
            r = self.confirm_signing(person_id, contract_code, name)
            # 之前: confirm 失败时仍返回 success=True / step="initiate".
            # 修复: 失败原样返回 (success=False, step="confirm"), 让 UI 看到真实错误.
            r = self._verify_and_finalize(
                r, person_id, sfzh=sfzh, name=r.name or name,
                verify_final=verify_final, finalize_archive=finalize_archive,
                finalize_retries=finalize_retries,
            )
            r.elapsed = time.time() - t0
            return r

        r1 = self.initiate_signing(
            person_id,
            team_name=team_name,
            team_id=team_id,
            doctor_name=doctor_name,
            service_type=service_type,
            agreement_start=agreement_start,
            agreement_end=agreement_end,
            period=period,
        )
        if not r1.success:
            r1.elapsed = time.time() - t0
            return r1

        cc = r1.contract_code
        pname = r1.name or name

        if not cc:
            # initiate 自称成功却没拿到 contract_code 视为不可继续 — 之前
            # 返回 success=True 会让 UI 把它计入成功, 这是误报.
            return SignResult(
                False, person_id, pname,
                error="发起返回成功但缺失合同号 (contract_code)",
                step="initiate", elapsed=time.time() - t0,
            )

        time.sleep(delay)

        r2 = self.confirm_signing(person_id, cc, pname)
        r2.contract_code = r2.contract_code or cc
        # confirm 失败 -> success=False (之前会被错误地标 success=True / step="initiate")
        r2 = self._verify_and_finalize(
            r2, person_id, sfzh=sfzh, name=pname,
            verify_final=verify_final, finalize_archive=finalize_archive,
            finalize_retries=finalize_retries,
        )
        r2.elapsed = time.time() - t0
        return r2
