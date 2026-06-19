# -*- coding: utf-8 -*-
"""
OpenID 抓包代理 — 内置 MITM 代理，自动提取健康卡 OpenID

工作流程:
  1. 生成 CA 证书（首次运行）
  2. 手机安装并信任 CA 证书
  3. 手机设置 WiFi 代理指向本机
  4. 手机打开"我的健康卡"小程序
  5. 代理自动抓取 OpenID
"""
import os
import re
import ssl
import sys
import socket
import select
import threading
import time
import logging
from typing import Optional, Callable, Set
from urllib.parse import urlparse, parse_qs

logger = logging.getLogger(__name__)

TARGET_HOSTS = {
    "jkkyljl.hnhfpc.gov.cn",
    "jkkgzh.hnhfpc.gov.cn",
    "jkkzc.hnhfpc.gov.cn",
    "ggws.hnhfpc.gov.cn",
    "ggwsfw.hnhfpc.gov.cn",
    "sjfx.hnhfpc.gov.cn",
}

TUNNEL_HOSTS = {
    "health.tengmed.com",
    "h5-health.tengmed.com",
    "wechat.wecity.qq.com",
    "card.wecity.qq.com",
    "open.weixin.qq.com",
    "api.weixin.qq.com",
    "res.wx.qq.com",
    "mp.weixin.qq.com",
}

# 任意子域名都拦截 (公卫3.0 / 健康卡 平台一律走 *.hnhfpc.gov.cn).
# 竞品软件用 Playwright 驱动的浏览器登录 ggws 网页, 真正"造居民申请(6)"
# 的写请求就发往这些域名. 用后缀匹配可覆盖以后新增的子域名.
INTERCEPT_HOST_SUFFIXES = (
    ".hnhfpc.gov.cn",
)

# "全程录制"模式下, 我们想看 **每一条** 发往公卫域名的请求+响应原文,
# 而不仅仅是下面 6 个已知签约端点. 这些关键词只用来在实时日志里"高亮"
# 可能与"医生申请(5)→居民申请(6)"切换相关的流, 不影响落盘 (落盘是全量).
FLOW_HIGHLIGHT_KEYWORDS = (
    "居民申请", "医生申请", "用户申请", "拒绝签约",
    "QYZT", "SQZT", "CONTRACT_STATE", "APPLICANT", "SQLY",
    "B0107", "B0105", "B0101", "ACTION=10", "ACTION=6", "ACTION=5",
)

# 家医签约抓包: 用户在公卫3.0网页里点 [家医签约] 按钮时, 我们要捕获 POST.
# 可疑端点 (基于 js_native.pyc 反编译 + 已知接口表):
#   /Sys_JCWS/B0105/Do_B0105_Handler.ashx  ← 居民档案签约相关
#   /Sys_JCWS/B0107/Do_B0107_Handler.ashx  ← 团队/医生签约管理
#   /Sys_JCWS/B0103/Do_B0103_Handler.ashx  ← 家庭档案/成员
#   /Sys_JCWS/JKDA/Do_Query_Handler.ashx   ← 健康档案查询 (排除, 这是 read-only)
#
# 我们捕获以下写操作的 POST (JKDA / 纯查询 GET 不抓):
#   B0105/B0107/B0103 → 家医签约相关
#   B0101 ACTION=2     → 档案修改 (★ 年龄绕行就是改这里的 SFZH/CSRQ, 必抓)
#   jkxbservice.ashx   → 健康卡 insertJtysqy(建居民申请) 等签约写
#   Wx_jmjkk/Handler   → 健康卡绑卡注册
SIGN_CAPTURE_PATH_PATTERNS = (
    re.compile(rb"/Sys_JCWS/B0105/Do_B0105_Handler\.ashx", re.IGNORECASE),
    re.compile(rb"/Sys_JCWS/B0107/Do_B0107_Handler\.ashx", re.IGNORECASE),
    re.compile(rb"/Sys_JCWS/B0103/Do_B0103_Handler\.ashx", re.IGNORECASE),
    re.compile(rb"/Sys_JCWS/B0101/Do_B0101_Handler\.ashx", re.IGNORECASE),
    re.compile(rb"/httpapi/jkxbservice\.ashx", re.IGNORECASE),
    re.compile(rb"/gzc/Wx_jmjkk/Handler\.ashx", re.IGNORECASE),
)


def classify_write(path: str, action: str, body_form: dict) -> dict:
    """对一条被捕获的写请求做分类, 重点识别"年龄绕行"(B0101 改龄)。

    返回一个 dict, 至少含 ``type``; 当判定为档案改龄且把出生年改到
    未成年/老年区间时, 置 ``age_bypass_suspected=True`` 并附 ``implied_age``。
    纯函数, 便于单测。
    """
    import datetime
    p = (path or "").upper()
    act = str(action or "")
    form = body_form or {}

    def g(*keys):
        for k in keys:
            for kk in (k, k.upper(), k.lower()):
                if kk in form and form.get(kk) not in (None, ""):
                    return str(form.get(kk))
        return ""

    if "B0101" in p and act == "2":
        sfzh = g("SFZH")
        csrq = g("CSRQ")
        kind = {
            "type": "档案修改(B0101 ACTION=2)",
            "sfzh_tail": sfzh[-4:] if len(sfzh) >= 4 else "",
            "csrq": csrq,
        }
        birth_year = None
        if len(sfzh) >= 14 and sfzh[6:10].isdigit():
            birth_year = int(sfzh[6:10])
        elif len(csrq) >= 4 and csrq[:4].isdigit():
            birth_year = int(csrq[:4])
        if birth_year:
            age = datetime.date.today().year - birth_year
            kind["birth_year"] = birth_year
            kind["implied_age"] = age
            if age < 18 or age > 60:
                kind["age_bypass_suspected"] = True
        return kind
    if "JKXBSERVICE" in p:
        return {"type": "健康卡签约写(jkxbservice)", "action": act}
    if "WX_JMJKK/HANDLER" in p:
        return {"type": "健康卡绑卡注册", "action": act}
    if "B0105" in p:
        return {"type": "家医签约(B0105)", "action": act}
    if "B0107" in p:
        return {"type": "团队/医生签约(B0107)", "action": act}
    if "B0103" in p:
        return {"type": "家庭档案(B0103)", "action": act}
    return {"type": "其它写操作", "action": act}

OPENID_PATTERN = re.compile(
    rb'[?&](?:[Oo]penid|openId|OPENID)=([a-zA-Z0-9_-]{20,})', re.IGNORECASE
)

OPENID_JSON_PATTERN = re.compile(
    rb'"(?:openid|openId|OPENID)"\s*:\s*"([a-zA-Z0-9_-]{20,})"'
)

OPENID_HEADER_PATTERN = re.compile(
    rb'^openId:\s*(@?[a-zA-Z0-9_-]{15,})', re.MULTILINE
)

WECHATCODE_URL_PATTERN = re.compile(
    rb'wechatCode\.aspx\?wechatCode=([A-Fa-f0-9]{20,})', re.IGNORECASE
)

WECHATCODE_COOKIE_PATTERN = re.compile(
    rb'Set-Cookie:\s*Wechatcode=([A-Fa-f0-9]{20,})', re.IGNORECASE
)

WECHATCODE_REDIRECT_PATTERN = re.compile(
    rb'Wechat_code=([A-Fa-f0-9]{20,})', re.IGNORECASE
)


def get_local_ip() -> str:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def _get_macos_network_service() -> str:
    """Find the active network service name (usually 'Wi-Fi')."""
    try:
        import subprocess
        r = subprocess.run(["networksetup", "-listallnetworkservices"],
                           capture_output=True, text=True)
        for line in r.stdout.splitlines():
            s = line.strip()
            if s.startswith("*"):
                continue
            if "wi-fi" in s.lower() or "wifi" in s.lower():
                return s
        for line in r.stdout.splitlines():
            s = line.strip()
            if s.startswith("*") or s.startswith("An asterisk"):
                continue
            if "ethernet" in s.lower() or "thunderbolt" in s.lower():
                return s
    except Exception:
        pass
    return "Wi-Fi"


def set_system_proxy(host: str, port: int) -> bool:
    """Set system proxy (auto-detects macOS/Windows)."""
    if sys.platform == "darwin":
        return _set_macos_proxy(host, port)
    elif sys.platform == "win32":
        return set_windows_proxy(host, port)
    return False


def clear_system_proxy() -> bool:
    """Clear system proxy (auto-detects macOS/Windows)."""
    if sys.platform == "darwin":
        return _clear_macos_proxy()
    elif sys.platform == "win32":
        return clear_windows_proxy()
    return False


def install_ca_to_system(ca_cert_path: str) -> bool:
    """Install CA certificate (auto-detects macOS/Windows)."""
    if sys.platform == "darwin":
        return _install_ca_to_macos(ca_cert_path)
    elif sys.platform == "win32":
        return install_ca_to_windows(ca_cert_path)
    return False


def _set_macos_proxy(host: str, port: int) -> bool:
    try:
        import subprocess
        svc = _get_macos_network_service()
        p = str(port)
        subprocess.run(["networksetup", "-setwebproxy", svc, host, p], capture_output=True)
        subprocess.run(["networksetup", "-setsecurewebproxy", svc, host, p], capture_output=True)
        return True
    except Exception:
        return False


def _clear_macos_proxy() -> bool:
    try:
        import subprocess
        svc = _get_macos_network_service()
        subprocess.run(["networksetup", "-setwebproxystate", svc, "off"], capture_output=True)
        subprocess.run(["networksetup", "-setsecurewebproxystate", svc, "off"], capture_output=True)
        return True
    except Exception:
        return False


def _install_ca_to_macos(ca_cert_path: str) -> bool:
    if not os.path.exists(ca_cert_path):
        return False
    try:
        import subprocess
        r = subprocess.run([
            "security", "add-trusted-cert",
            "-r", "trustRoot",
            "-k", os.path.expanduser("~/Library/Keychains/login.keychain-db"),
            ca_cert_path,
        ], capture_output=True, text=True)
        return r.returncode == 0
    except Exception:
        return False


def set_windows_proxy(host: str, port: int) -> bool:
    """Set Windows system proxy (IE/WinHTTP) and return True on success."""
    if sys.platform != "win32":
        return False
    try:
        import subprocess
        proxy_str = "%s:%d" % (host, port)
        subprocess.run([
            "reg", "add",
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings",
            "/v", "ProxyServer", "/t", "REG_SZ", "/d", proxy_str, "/f",
        ], check=True, capture_output=True)
        subprocess.run([
            "reg", "add",
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings",
            "/v", "ProxyEnable", "/t", "REG_DWORD", "/d", "1", "/f",
        ], check=True, capture_output=True)
        _refresh_proxy_settings()
        return True
    except Exception:
        return False


def clear_windows_proxy() -> bool:
    """Remove Windows system proxy setting."""
    if sys.platform != "win32":
        return False
    try:
        import subprocess
        subprocess.run([
            "reg", "add",
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings",
            "/v", "ProxyEnable", "/t", "REG_DWORD", "/d", "0", "/f",
        ], check=True, capture_output=True)
        _refresh_proxy_settings()
        return True
    except Exception:
        return False


def _refresh_proxy_settings():
    """Notify Windows that proxy settings changed (so apps pick it up)."""
    try:
        import ctypes
        import ctypes.wintypes
        INTERNET_OPTION_REFRESH = 37
        INTERNET_OPTION_SETTINGS_CHANGED = 39
        wininet = ctypes.windll.wininet
        wininet.InternetSetOptionW(None, INTERNET_OPTION_SETTINGS_CHANGED, None, 0)
        wininet.InternetSetOptionW(None, INTERNET_OPTION_REFRESH, None, 0)
    except Exception:
        pass


def install_ca_to_windows(ca_cert_path: str) -> bool:
    """Install CA certificate into the Windows user trust store."""
    if sys.platform != "win32":
        return False
    if not os.path.exists(ca_cert_path):
        return False
    try:
        import subprocess
        from cryptography.hazmat.primitives.serialization import Encoding
        from cryptography import x509 as x509_mod

        with open(ca_cert_path, "rb") as f:
            cert_data = f.read()

        cert_obj = x509_mod.load_pem_x509_certificate(cert_data)
        der_path = ca_cert_path.replace(".pem", ".crt")
        with open(der_path, "wb") as f:
            f.write(cert_obj.public_bytes(Encoding.DER))

        result = subprocess.run(
            ["certutil", "-addstore", "-user", "Root", der_path],
            capture_output=True, text=True,
        )
        return result.returncode == 0
    except Exception:
        return False


def remove_ca_from_windows() -> bool:
    """Remove the GulfSign CA from the Windows user trust store."""
    if sys.platform != "win32":
        return False
    try:
        import subprocess
        result = subprocess.run(
            ["certutil", "-delstore", "-user", "Root", "GulfSign CA"],
            capture_output=True, text=True,
        )
        return result.returncode == 0
    except Exception:
        return False


# 让用 certifi 默认校验的 Python (requests/urllib3) 信任我们的 MITM 证书:
# 设置用户级环境变量指向合并证书包。仅对**之后启动**的进程生效, 所以设置后
# 必须重启对方软件。这些变量会持久化, 故停止抓包时务必清除。
_CA_ENV_VARS = (
    "REQUESTS_CA_BUNDLE",  # requests
    "SSL_CERT_FILE",       # Python ssl / OpenSSL
    "CURL_CA_BUNDLE",      # curl / 部分库
    "NODE_EXTRA_CA_CERTS", # node (若对方用 electron/node)
)


def set_requests_ca_env(bundle_path: str) -> bool:
    """设置用户级 CA 包环境变量 (Windows). 返回是否成功。"""
    if sys.platform != "win32":
        for k in _CA_ENV_VARS:
            os.environ[k] = bundle_path
        return True
    if not bundle_path or not os.path.exists(bundle_path):
        return False
    try:
        import subprocess
        ok = True
        for k in _CA_ENV_VARS:
            os.environ[k] = bundle_path
            r = subprocess.run(
                ["setx", k, bundle_path], capture_output=True, text=True,
            )
            ok = ok and (r.returncode == 0)
        _broadcast_env_change()
        return ok
    except Exception:
        return False


def clear_requests_ca_env() -> bool:
    """清除之前设置的 CA 包环境变量 (Windows), 还原系统。"""
    if sys.platform != "win32":
        for k in _CA_ENV_VARS:
            os.environ.pop(k, None)
        return True
    try:
        import subprocess
        for k in _CA_ENV_VARS:
            os.environ.pop(k, None)
            subprocess.run(
                ["reg", "delete", r"HKCU\Environment", "/v", k, "/f"],
                capture_output=True, text=True,
            )
        _broadcast_env_change()
        return True
    except Exception:
        return False


def _broadcast_env_change():
    """通知系统环境变量已变更 (新进程才会拿到, 已运行的不受影响)。"""
    try:
        import ctypes
        HWND_BROADCAST = 0xFFFF
        WM_SETTINGCHANGE = 0x001A
        SMTO_ABORTIFHUNG = 0x0002
        res = ctypes.c_ulong()
        ctypes.windll.user32.SendMessageTimeoutW(
            HWND_BROADCAST, WM_SETTINGCHANGE, 0, "Environment",
            SMTO_ABORTIFHUNG, 3000, ctypes.byref(res),
        )
    except Exception:
        pass


class CertManager:
    """Generate and manage CA + per-host certificates for MITM."""

    def __init__(self, cert_dir: str):
        self.cert_dir = cert_dir
        os.makedirs(cert_dir, exist_ok=True)
        self.ca_cert_path = os.path.join(cert_dir, "GulfSign_CA.pem")
        self.ca_key_path = os.path.join(cert_dir, "GulfSign_CA.key")
        self._ca_cert = None
        self._ca_key = None
        self._host_cache = {}

    def ensure_ca(self) -> bool:
        try:
            from cryptography import x509
            from cryptography.x509.oid import NameOID
            from cryptography.hazmat.primitives import hashes, serialization
            from cryptography.hazmat.primitives.asymmetric import rsa
            import datetime

            if os.path.exists(self.ca_cert_path) and os.path.exists(self.ca_key_path):
                with open(self.ca_key_path, "rb") as f:
                    self._ca_key = serialization.load_pem_private_key(f.read(), None)
                with open(self.ca_cert_path, "rb") as f:
                    self._ca_cert = x509.load_pem_x509_certificate(f.read())
                if self._ca_cert.not_valid_after_utc.replace(tzinfo=None) > datetime.datetime.utcnow():
                    return True

            self._ca_key = rsa.generate_private_key(65537, 2048)
            subject = issuer = x509.Name([
                x509.NameAttribute(NameOID.COUNTRY_NAME, "CN"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "GulfSign Helper"),
                x509.NameAttribute(NameOID.COMMON_NAME, "GulfSign CA"),
            ])
            now = datetime.datetime.utcnow()
            ca_ski = x509.SubjectKeyIdentifier.from_public_key(
                self._ca_key.public_key()
            )
            self._ca_cert = (
                x509.CertificateBuilder()
                .subject_name(subject)
                .issuer_name(issuer)
                .public_key(self._ca_key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(now)
                .not_valid_after(now + datetime.timedelta(days=3650))
                .add_extension(x509.BasicConstraints(ca=True, path_length=None), True)
                .add_extension(
                    x509.KeyUsage(
                        digital_signature=True, key_cert_sign=True, crl_sign=True,
                        content_commitment=False, key_encipherment=False,
                        data_encipherment=False, key_agreement=False,
                        encipher_only=False, decipher_only=False,
                    ), True,
                )
                .add_extension(ca_ski, False)
                .sign(self._ca_key, hashes.SHA256())
            )

            with open(self.ca_key_path, "wb") as f:
                f.write(self._ca_key.private_bytes(
                    serialization.Encoding.PEM,
                    serialization.PrivateFormat.TraditionalOpenSSL,
                    serialization.NoEncryption(),
                ))
            with open(self.ca_cert_path, "wb") as f:
                f.write(self._ca_cert.public_bytes(serialization.Encoding.PEM))

            return True
        except Exception as e:
            logger.error("CA cert generation failed: %s", e)
            return False

    def ensure_combined_bundle(self) -> Optional[str]:
        """生成『系统可信根 + 我们的 CA』合并证书包, 路径写到
        certs/combined_ca_bundle.pem。

        把它配到对方软件进程的 REQUESTS_CA_BUNDLE / SSL_CERT_FILE 环境变量,
        即可让用 certifi 默认校验的 Python requests 信任我们的 MITM 证书,
        从而抓到它发往公卫系统的明文请求 (同时不影响它访问其它正常网站)。
        """
        try:
            if not os.path.exists(self.ca_cert_path):
                if not self.ensure_ca():
                    return None
            base_pem = b""
            try:
                import certifi
                with open(certifi.where(), "rb") as f:
                    base_pem = f.read()
            except Exception:
                try:
                    import ssl as _ssl
                    cafile = _ssl.get_default_verify_paths().cafile
                    if cafile and os.path.exists(cafile):
                        with open(cafile, "rb") as f:
                            base_pem = f.read()
                except Exception:
                    base_pem = b""
            with open(self.ca_cert_path, "rb") as f:
                our_pem = f.read()
            out_path = os.path.join(self.cert_dir, "combined_ca_bundle.pem")
            with open(out_path, "wb") as f:
                if base_pem:
                    f.write(base_pem)
                    if not base_pem.endswith(b"\n"):
                        f.write(b"\n")
                f.write(b"\n# ===== GulfSign local MITM CA =====\n")
                f.write(our_pem)
            return out_path
        except Exception as e:
            logger.error("combined bundle failed: %s", e)
            return None

    def get_host_cert(self, hostname: str) -> Optional[tuple]:
        """Return (cert_path, key_path) for a hostname, generating if needed."""
        if hostname in self._host_cache:
            return self._host_cache[hostname]

        try:
            from cryptography import x509
            from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
            from cryptography.hazmat.primitives import hashes, serialization
            from cryptography.hazmat.primitives.asymmetric import rsa
            import datetime

            if not self._ca_cert or not self._ca_key:
                return None

            key = rsa.generate_private_key(65537, 2048)
            now = datetime.datetime.utcnow()

            aki = x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(
                self._ca_cert.extensions.get_extension_for_class(
                    x509.SubjectKeyIdentifier
                ).value
            )
            ski = x509.SubjectKeyIdentifier.from_public_key(key.public_key())

            # 关键修复: Windows SChannel / Chrome 对服务器证书很严格 — 缺少
            # serverAuth EKU 或 KeyUsage 会被直接拒绝 (TLS 握手失败 → 连接重置
            # ERR_CONNECTION_RESET), 即使 CA 已被信任。OpenSSL/requests 较宽松,
            # 所以之前只在浏览器上暴露。这里补齐 EKU + KeyUsage。
            cert = (
                x509.CertificateBuilder()
                .subject_name(x509.Name([
                    x509.NameAttribute(NameOID.COMMON_NAME, hostname),
                ]))
                .issuer_name(self._ca_cert.subject)
                .public_key(key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(now - datetime.timedelta(days=1))
                .not_valid_after(now + datetime.timedelta(days=365))
                .add_extension(
                    x509.SubjectAlternativeName([x509.DNSName(hostname)]),
                    False,
                )
                .add_extension(
                    x509.BasicConstraints(ca=False, path_length=None), True,
                )
                .add_extension(
                    x509.KeyUsage(
                        digital_signature=True, key_encipherment=True,
                        content_commitment=False, data_encipherment=False,
                        key_agreement=False, key_cert_sign=False,
                        crl_sign=False, encipher_only=False, decipher_only=False,
                    ), True,
                )
                .add_extension(
                    x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
                    False,
                )
                .add_extension(aki, False)
                .add_extension(ski, False)
                .sign(self._ca_key, hashes.SHA256())
            )

            cert_path = os.path.join(self.cert_dir, "%s.pem" % hostname)
            key_path = os.path.join(self.cert_dir, "%s.key" % hostname)

            with open(cert_path, "wb") as f:
                f.write(cert.public_bytes(serialization.Encoding.PEM))
            with open(key_path, "wb") as f:
                f.write(key.private_bytes(
                    serialization.Encoding.PEM,
                    serialization.PrivateFormat.TraditionalOpenSSL,
                    serialization.NoEncryption(),
                ))

            self._host_cache[hostname] = (cert_path, key_path)
            return cert_path, key_path
        except Exception as e:
            logger.error("Host cert generation failed for %s: %s", hostname, e)
            return None


class OpenIDProxy:
    """MITM proxy that captures OpenID from health card traffic.

    Optional 二次身份: 通过传入 ``on_sign_captured`` 回调激活 "家医签约抓包"
    模式 — 当 MITM 看到 ggws.hnhfpc.gov.cn 上对 B0105/B0107/B0103 Handler 的
    POST 请求时, 把完整的 (URL, headers, body) 序列化成 JSON 落盘并回调.
    """

    def __init__(
        self,
        port: int = 8888,
        on_openid: Optional[Callable] = None,
        on_log: Optional[Callable] = None,
        on_wechatcode: Optional[Callable] = None,
        on_sign_captured: Optional[Callable] = None,
        sign_capture_dir: Optional[str] = None,
        capture_all: bool = False,
        session_dir: Optional[str] = None,
        extra_intercept_hosts: Optional[Set[str]] = None,
        on_flow: Optional[Callable] = None,
    ):
        self.port = port
        self.on_openid = on_openid
        self.on_log = on_log
        self.on_wechatcode = on_wechatcode
        # 家医签约抓包回调 — 接收 dict: {timestamp, host, method, path, query,
        # action, headers, body_text, body_form, raw_request}
        self.on_sign_captured = on_sign_captured
        # 全程录制 (capture_all): 把每一条发往公卫域名的请求+响应原文整条落盘,
        # 并通过 on_flow(dict) 回调上层 (用于实时表格/高亮). 用于"录制对方软件
        # 全过程", 找出它到底打哪个端点、用哪个字段把签约状态写成居民申请(6).
        self.capture_all = capture_all
        self.on_flow = on_flow
        self.extra_intercept_hosts = set(extra_intercept_hosts or set())
        self._running = False
        self._server_socket = None
        self._thread = None
        self._found_openids: Set[str] = set()
        self._found_wechatcodes: Set[str] = set()
        self._sign_captures: list = []
        self._flows: list = []
        self._flow_seq = 0
        self._traffic_log_lock = threading.Lock()
        self._flow_lock = threading.Lock()
        # 自适应回退: 某主机的客户端 TLS 握手反复失败 (= 客户端不信任我们的
        # CA, 例如用 certifi 的 requests) 时, 把它加入直通名单, 之后纯隧道转发,
        # 保证对方软件/网页能正常访问 (只是这条流抓不到明文)。
        self._mitm_block: Set[str] = set()
        self._mitm_fail: dict = {}
        self._adapt_lock = threading.Lock()

        base_dir = os.path.dirname(os.path.abspath(__file__))
        cert_dir = os.path.join(base_dir, "certs")
        self.cert_mgr = CertManager(cert_dir)
        self.traffic_log_path = os.path.join(base_dir, "traffic_log.txt")
        self.sign_capture_dir = sign_capture_dir or os.path.join(
            base_dir, ".dbg", "sign_captures"
        )
        # 每次会话一个独立目录: logs/竞品全程录制/<时间戳>/
        if session_dir:
            self.session_dir = session_dir
        else:
            import datetime as _dt
            self.session_dir = os.path.join(
                base_dir, "logs", "竞品全程录制",
                _dt.datetime.now().strftime("%Y%m%d_%H%M%S"),
            )
        self.flow_index_path = os.path.join(self.session_dir, "_index.jsonl")

    @property
    def ca_cert_path(self):
        return self.cert_mgr.ca_cert_path

    @property
    def found_openids(self):
        return set(self._found_openids)

    def _log(self, msg, tag=""):
        if self.on_log:
            self.on_log(msg, tag)

    def _report_openid(self, openid: str, source: str = ""):
        if openid not in self._found_openids:
            self._found_openids.add(openid)
            self._log("发现 OpenID: %s" % openid, "ok")
            if self.on_openid:
                self.on_openid(openid)

    def _log_traffic(self, hostname: str, direction: str, data: bytes):
        """Write full request/response to traffic_log.txt for analysis."""
        try:
            import datetime
            ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            text = data.decode("utf-8", errors="replace")[:200000]
            with self._traffic_log_lock:
                with open(self.traffic_log_path, "a", encoding="utf-8") as f:
                    f.write("\n" + "=" * 70 + "\n")
                    f.write("[%s] %s  %s\n" % (ts, direction, hostname))
                    f.write("-" * 70 + "\n")
                    f.write(text + "\n")
        except Exception:
            pass

        # 家医签约抓包: 仅在 REQUEST 方向, 仅对 ggws 域名, 仅 POST.
        if direction == ">>> REQUEST" and "ggws" in (hostname or "").lower():
            try:
                self._maybe_capture_sign_request(hostname, data)
            except Exception as e:
                logger.debug("sign capture skip: %s", e)

    def _maybe_capture_sign_request(self, hostname: str, data: bytes):
        """检测是否为 [家医签约] / [即时签约] / [批量签约] 等 POST,
        命中则解析 → JSON 落盘 → 回调."""
        if not data:
            return
        # 必须 POST (GET 是查询/页面加载, 跳过)
        if not data.startswith(b"POST "):
            return

        # 拆 request line / headers / body
        head_end = data.find(b"\r\n\r\n")
        if head_end < 0:
            return
        head_part = data[:head_end].decode("utf-8", errors="replace")
        body_bytes = data[head_end + 4:]

        lines = head_part.split("\r\n")
        if not lines:
            return
        # 第一行: "POST /path?query HTTP/1.1"
        try:
            _method, path_full, _ver = lines[0].split(" ", 2)
        except ValueError:
            return

        # 命中签约相关 Handler?
        path_bytes = path_full.encode("utf-8", errors="replace")
        if not any(p.search(path_bytes) for p in SIGN_CAPTURE_PATH_PATTERNS):
            return

        # 解析 headers
        headers: dict = {}
        for ln in lines[1:]:
            if ":" in ln:
                k, _, v = ln.partition(":")
                headers[k.strip()] = v.strip()

        # 拆 path / query
        from urllib.parse import urlparse, parse_qsl
        u = urlparse("http://x" + path_full)  # urlparse 需要 scheme
        path_only = u.path
        query_pairs = parse_qsl(u.query, keep_blank_values=True)
        query_dict = dict(query_pairs)
        action = (
            query_dict.get("ACTION") or query_dict.get("action") or ""
        )

        # 解析 body — 尝试 form-encoded; 失败则保留 raw
        body_text = body_bytes.decode("utf-8", errors="replace")
        body_form: dict = {}
        ct = headers.get("Content-Type", "").lower()
        if "application/x-www-form-urlencoded" in ct or (
            body_text and "=" in body_text and "<" not in body_text[:32]
        ):
            try:
                body_form = dict(parse_qsl(body_text, keep_blank_values=True))
            except Exception:
                body_form = {}

        import datetime
        import json
        ts = datetime.datetime.now()
        record = {
            "timestamp": ts.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
            "host": hostname,
            "method": "POST",
            "path": path_only,
            "query": query_dict,
            "action": action,
            "headers": headers,
            "body_text": body_text[:8000],
            "body_form": body_form,
            # raw_request 截 8KB 防止巨大 body 撑爆 JSON
            "raw_request": data[:8000].decode("utf-8", errors="replace"),
        }

        # 分类 + 年龄绕行识别
        try:
            kind = classify_write(path_only, action, body_form)
            record["_write_kind"] = kind
            if kind.get("age_bypass_suspected"):
                self._log(
                    "⚠⚠ 检测到【档案改龄·疑似年龄绕行】: 出生年→%s (约%s岁), "
                    "SFZH尾号 %s — 对方正在把此人改成免人脸年龄段!" % (
                        kind.get("birth_year"), kind.get("implied_age"),
                        kind.get("sfzh_tail") or "?",
                    ),
                    "warn",
                )
            elif kind.get("type", "").startswith("档案修改"):
                self._log(
                    "📝 检测到 B0101 档案修改 (ACTION=2) — 出生年=%s/约%s岁; "
                    "未落在免人脸区间, 暂不判定绕行" % (
                        kind.get("birth_year", "?"), kind.get("implied_age", "?"),
                    ),
                    "info",
                )
        except Exception:
            pass

        self._sign_captures.append(record)

        # 落盘到 sign_captures/sign_<ts>_<action>.json
        try:
            os.makedirs(self.sign_capture_dir, exist_ok=True)
            fn = "sign_%s_%s.json" % (
                ts.strftime("%Y%m%d_%H%M%S_%f")[:-3],
                (action or "noaction").replace("/", "_"),
            )
            fp = os.path.join(self.sign_capture_dir, fn)
            with open(fp, "w", encoding="utf-8") as f:
                json.dump(record, f, ensure_ascii=False, indent=2)
            record["_saved_to"] = fp
            self._log(
                "📡 已捕获签约请求: %s ACTION=%s → %s" % (
                    path_only, action or "?", os.path.basename(fp),
                ),
                "ok",
            )
        except Exception as e:
            self._log("签约请求保存失败: %s" % e, "warn")

        if self.on_sign_captured:
            try:
                self.on_sign_captured(record)
            except Exception:
                pass

    @property
    def sign_captures(self) -> list:
        """返回当前会话内已捕获的签约请求记录列表 (副本)."""
        return list(self._sign_captures)

    @property
    def flows(self) -> list:
        """全程录制模式下捕获的所有流 (副本)."""
        with self._flow_lock:
            return list(self._flows)

    def _record_full_flow(self, hostname: str, request_data: bytes, response: bytes):
        """全程录制: 把一条 (请求, 响应) 完整 (不截断) 写到会话目录,
        解析出 method/path/action 等元信息, 命中关键词时高亮, 并回调 on_flow.

        这是"录制对方软件全过程"的核心 — 我们不预设端点, 凡是发往公卫域名
        的写/读请求一律整条留存, 之后离线对比即可定位"造居民申请(6)"的端点。
        """
        if not request_data:
            return

        import datetime
        import json
        from urllib.parse import urlparse, parse_qsl

        # ---- 解析请求行 ----
        head_end = request_data.find(b"\r\n\r\n")
        head_part = request_data[:head_end] if head_end >= 0 else request_data
        head_text = head_part.decode("utf-8", errors="replace")
        lines = head_text.split("\r\n")
        try:
            method, path_full, _ver = lines[0].split(" ", 2)
        except (ValueError, IndexError):
            method, path_full = "?", "?"

        req_headers: dict = {}
        for ln in lines[1:]:
            if ":" in ln:
                k, _, v = ln.partition(":")
                req_headers[k.strip()] = v.strip()

        u = urlparse("http://x" + path_full) if path_full.startswith("/") else urlparse(path_full)
        path_only = u.path or path_full
        query_dict = dict(parse_qsl(u.query, keep_blank_values=True))
        action = query_dict.get("ACTION") or query_dict.get("action") or ""

        req_body = request_data[head_end + 4:] if head_end >= 0 else b""
        body_text = req_body.decode("utf-8", errors="replace")
        body_form: dict = {}
        if body_text and "=" in body_text and "<" not in body_text[:32]:
            try:
                body_form = dict(parse_qsl(body_text, keep_blank_values=True))
            except Exception:
                body_form = {}

        # ---- 响应状态码 ----
        resp_status = ""
        resp_text_full = response.decode("utf-8", errors="replace") if response else ""
        if resp_text_full[:5].upper().startswith("HTTP"):
            try:
                resp_status = resp_text_full.split(" ", 2)[1]
            except Exception:
                resp_status = ""

        # ---- 命中高亮关键词? (只看请求行/请求体/响应) ----
        scan_blob = (path_full + "\n" + body_text + "\n" + resp_text_full)
        hits = [kw for kw in FLOW_HIGHLIGHT_KEYWORDS if kw in scan_blob]
        is_write = method.upper() in ("POST", "PUT", "PATCH", "DELETE")

        with self._flow_lock:
            self._flow_seq += 1
            seq = self._flow_seq

        ts = datetime.datetime.now()
        rec = {
            "seq": seq,
            "timestamp": ts.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
            "host": hostname,
            "method": method,
            "path": path_only,
            "query": query_dict,
            "action": action,
            "resp_status": resp_status,
            "is_write": is_write,
            "highlights": hits,
            "req_bytes": len(request_data),
            "resp_bytes": len(response or b""),
        }

        # ---- 整条原文落盘 (不截断) ----
        try:
            os.makedirs(self.session_dir, exist_ok=True)
            tag = (action or method or "flow").replace("/", "_")[:24]
            fn = "%04d_%s_%s_%s.txt" % (
                seq, ts.strftime("%H%M%S"), hostname.split(".")[0], tag,
            )
            fp = os.path.join(self.session_dir, fn)
            with open(fp, "w", encoding="utf-8", errors="replace") as f:
                f.write("# ===== GULFSIGN 全程录制 流 #%d =====\n" % seq)
                f.write("# time   : %s\n" % rec["timestamp"])
                f.write("# host   : %s\n" % hostname)
                f.write("# method : %s  path: %s  ACTION: %s\n" % (method, path_only, action or "-"))
                f.write("# resp   : HTTP %s  (req %dB / resp %dB)\n" % (
                    resp_status or "?", rec["req_bytes"], rec["resp_bytes"]))
                if hits:
                    f.write("# *** 命中关键词: %s ***\n" % ", ".join(hits))
                f.write("\n" + ">" * 30 + " REQUEST " + ">" * 30 + "\n")
                f.write(request_data.decode("utf-8", errors="replace"))
                f.write("\n\n" + "<" * 30 + " RESPONSE " + "<" * 30 + "\n")
                f.write(resp_text_full)
                f.write("\n")
            rec["file"] = os.path.basename(fp)
        except Exception as e:
            logger.debug("flow file write failed: %s", e)
            rec["file"] = ""

        # ---- 追加 JSONL 索引 ----
        try:
            with self._flow_lock:
                with open(self.flow_index_path, "a", encoding="utf-8") as f:
                    f.write(json.dumps(rec, ensure_ascii=False) + "\n")
                self._flows.append(rec)
        except Exception:
            pass

        # ---- 实时日志: 写请求 / 命中高亮 重点提示 ----
        if hits:
            self._log(
                "★ 命中关键流 #%d  %s %s  ACTION=%s  [%s]" % (
                    seq, method, path_only, action or "-", ", ".join(hits),
                ),
                "warn",
            )
        elif is_write:
            self._log(
                "● 写请求 #%d  %s %s  ACTION=%s  HTTP %s" % (
                    seq, method, path_only, action or "-", resp_status or "?",
                ),
                "ok",
            )

        if self.on_flow:
            try:
                self.on_flow(rec)
            except Exception:
                pass

    def session_summary(self) -> dict:
        """返回会话统计 (流总数 / 写请求数 / 命中数 / 目录)."""
        flows = self.flows
        return {
            "total": len(flows),
            "writes": sum(1 for f in flows if f.get("is_write")),
            "highlights": sum(1 for f in flows if f.get("highlights")),
            "session_dir": self.session_dir,
        }

    def export_session_zip(self, dest_path: str) -> bool:
        """把整个会话目录打包成 zip, 方便客户一键发回来分析."""
        try:
            import zipfile
            if not os.path.isdir(self.session_dir):
                return False
            with zipfile.ZipFile(dest_path, "w", zipfile.ZIP_DEFLATED) as zf:
                for root, _dirs, files in os.walk(self.session_dir):
                    for name in files:
                        full = os.path.join(root, name)
                        rel = os.path.relpath(full, os.path.dirname(self.session_dir))
                        zf.write(full, rel)
                # 顺带把整段 traffic_log 也塞进去 (含被隧道放过的域名概览)
                if os.path.exists(self.traffic_log_path) and \
                        os.path.getsize(self.traffic_log_path) > 0:
                    zf.write(self.traffic_log_path, "traffic_log.txt")
            return True
        except Exception as e:
            logger.error("export session zip failed: %s", e)
            return False

    def start(self) -> bool:
        if self._running:
            return True

        if not self.cert_mgr.ensure_ca():
            self._log("CA证书生成失败，请确认已安装 cryptography 库", "err")
            return False

        if os.path.exists(self.traffic_log_path):
            try:
                os.remove(self.traffic_log_path)
            except Exception:
                pass

        try:
            self._server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._server_socket.bind(("0.0.0.0", self.port))
            self._server_socket.listen(50)
            self._server_socket.settimeout(1.0)
            self._running = True

            self._thread = threading.Thread(target=self._accept_loop, daemon=True)
            self._thread.start()

            ip = get_local_ip()
            self._log("代理已启动: %s:%d" % (ip, self.port), "ok")
            return True
        except OSError as e:
            self._log("启动失败: %s" % e, "err")
            return False

    def stop(self):
        self._running = False
        if self._server_socket:
            try:
                self._server_socket.close()
            except Exception:
                pass
        if self._thread:
            self._thread.join(timeout=3)
        if os.path.exists(self.traffic_log_path):
            sz = os.path.getsize(self.traffic_log_path)
            if sz > 0:
                self._log("完整流量日志已保存: traffic_log.txt (%d bytes)" % sz, "ok")
        self._log("代理已停止", "info")

    def _accept_loop(self):
        while self._running:
            try:
                client, addr = self._server_socket.accept()
                threading.Thread(
                    target=self._handle_client, args=(client,), daemon=True
                ).start()
            except socket.timeout:
                continue
            except Exception:
                if self._running:
                    continue
                break

    def _peek_request_header(self, sock) -> bytes:
        """用 MSG_PEEK 取出请求头 (到 \r\n\r\n 为止) 而**不消费**套接字数据。

        关键修复: CONNECT 之后客户端紧跟着发 TLS ClientHello, 若用普通 recv
        很可能把 ClientHello 的前几个字节一起读走 → OpenSSL 读到残缺握手 →
        握手失败 → 连接被重置 (ERR_CONNECTION_RESET)。改用 peek 找到头边界,
        只精确消费请求头, ClientHello 原封不动留在内核缓冲交给 OpenSSL。
        """
        deadline = time.time() + 12
        while time.time() < deadline:
            try:
                peek = sock.recv(65536, socket.MSG_PEEK)
            except socket.timeout:
                return b""
            except Exception:
                return b""
            if not peek:
                return b""
            idx = peek.find(b"\r\n\r\n")
            if idx >= 0:
                return peek[:idx + 4]
            if len(peek) > 60000:
                return peek
            time.sleep(0.005)
        return b""

    @staticmethod
    def _consume_exact(sock, n: int):
        """精确消费 n 个字节 (配合 _peek_request_header 用)。"""
        got = 0
        while got < n:
            try:
                chunk = sock.recv(min(65536, n - got))
            except Exception:
                return
            if not chunk:
                return
            got += len(chunk)

    def _handle_client(self, client_sock):
        try:
            client_sock.settimeout(15)
            header = self._peek_request_header(client_sock)
            if not header:
                client_sock.close()
                return

            first_line = header.split(b"\r\n")[0].decode("utf-8", errors="replace")

            if first_line.startswith("CONNECT"):
                # 只消费 CONNECT 请求头本身; TLS ClientHello 留给 OpenSSL。
                self._consume_exact(client_sock, len(header))
                self._handle_connect(client_sock, first_line, header)
            else:
                # 普通 HTTP: 直接读取 (无 TLS 握手顺序问题)。
                data = b""
                try:
                    data = client_sock.recv(65536)
                except Exception:
                    data = header
                self._handle_http(client_sock, first_line, data or header)
        except Exception:
            pass
        finally:
            try:
                client_sock.close()
            except Exception:
                pass

    def _handle_http(self, client_sock, first_line, data):
        self._scan_for_openid(data)

        parts = first_line.split()
        if len(parts) < 3:
            return

        url = parts[1]
        parsed = urlparse(url)

        if self._serve_cert_if_requested(client_sock, parsed, data):
            return

        host = parsed.hostname or ""
        port = parsed.port or 80

        try:
            remote = socket.create_connection((host, port), timeout=10)
            path = parsed.path
            if parsed.query:
                path += "?" + parsed.query

            new_first = "%s %s %s" % (parts[0], path, parts[2])
            lines = data.split(b"\r\n")
            lines[0] = new_first.encode()
            remote.sendall(b"\r\n".join(lines))

            response = b""
            while True:
                chunk = remote.recv(4096)
                if not chunk:
                    break
                response += chunk
                client_sock.sendall(chunk)

            self._scan_for_openid(response)
            remote.close()
        except Exception:
            pass

    def _serve_cert_if_requested(self, client_sock, parsed, raw_data) -> bool:
        """Serve CA certificate when phone visits http://proxy_ip:port/cert"""
        raw_url = raw_data.split(b" ")[1] if b" " in raw_data else b""
        is_proxied = raw_url.startswith(b"http://") or raw_url.startswith(b"https://")

        if is_proxied and parsed.hostname:
            local_ip = get_local_ip()
            if parsed.hostname not in ("127.0.0.1", "localhost", local_ip):
                return False

        path_clean = (parsed.path or "").rstrip("/")

        is_cert_request = path_clean in ("/cert", "/ca", "/certificate")
        is_page_request = path_clean in ("", "/") and not is_proxied

        if not is_cert_request and not is_page_request:
            return False

        ca_path = self.cert_mgr.ca_cert_path
        if not os.path.exists(ca_path):
            body = b"<html><body><h1>CA cert not generated yet.</h1></body></html>"
            header = (
                b"HTTP/1.1 500 Internal Server Error\r\n"
                b"Content-Type: text/html; charset=utf-8\r\n"
                b"Content-Length: %d\r\n"
                b"Connection: close\r\n\r\n" % len(body)
            )
            client_sock.sendall(header + body)
            return True

        if is_page_request and not is_cert_request:
            body = self._cert_landing_page().encode("utf-8")
            header = (
                b"HTTP/1.1 200 OK\r\n"
                b"Content-Type: text/html; charset=utf-8\r\n"
                b"Content-Length: %d\r\n"
                b"Connection: close\r\n\r\n" % len(body)
            )
            client_sock.sendall(header + body)
            return True

        with open(ca_path, "rb") as f:
            cert_data = f.read()

        from cryptography.hazmat.primitives.serialization import Encoding
        from cryptography import x509 as x509_mod
        cert_obj = x509_mod.load_pem_x509_certificate(cert_data)
        der_data = cert_obj.public_bytes(Encoding.DER)

        header = (
            b"HTTP/1.1 200 OK\r\n"
            b"Content-Type: application/x-x509-ca-cert\r\n"
            b"Content-Disposition: attachment; filename=\"GulfSign_CA.crt\"\r\n"
            b"Content-Length: %d\r\n"
            b"Connection: close\r\n\r\n" % len(der_data)
        )
        client_sock.sendall(header + der_data)
        self._log("CA证书已发送到手机 (.crt格式)", "ok")
        return True

    def _cert_landing_page(self) -> str:
        return """<!DOCTYPE html>
<html><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>GulfSign CA 证书安装</title>
<style>
body{font-family:-apple-system,sans-serif;max-width:600px;margin:0 auto;padding:20px;background:#f5f5f5}
h1{color:#333;font-size:22px}
.btn{display:block;text-align:center;padding:16px;background:#1677ff;color:#fff;
     border-radius:8px;text-decoration:none;font-size:18px;margin:20px 0}
.btn:active{background:#0958d9}
.steps{background:#fff;border-radius:8px;padding:16px;margin:16px 0}
.steps h3{margin:0 0 8px;color:#1677ff}
.steps p{margin:4px 0;color:#555;line-height:1.6}
.warn{background:#fff7e6;border:1px solid #ffd591;border-radius:8px;padding:12px;margin:16px 0;color:#ad6800}
</style></head><body>
<h1>GulfSign 证书安装助手</h1>
<a class="btn" href="/cert">点击下载 CA 证书</a>
<div class="steps"><h3>安卓手机安装步骤</h3>
<p>1. 点击上方按钮下载证书</p>
<p>2. 打开 <b>设置 → 安全 → 更多安全设置 → 加密与凭据 → 安装证书</b></p>
<p>3. 选择 <b>CA 证书</b></p>
<p>4. 找到下载的 GulfSign_CA.crt 文件并安装</p>
<p>5. 确认安装（可能需要输入锁屏密码）</p>
</div>
<div class="steps"><h3>苹果手机安装步骤</h3>
<p>1. 点击上方按钮下载证书</p>
<p>2. 弹出提示后点击 <b>允许</b></p>
<p>3. 打开 <b>设置 → 已下载描述文件 → GulfSign CA → 安装</b></p>
<p>4. 打开 <b>设置 → 通用 → 关于本机 → 证书信任设置</b></p>
<p>5. 开启 GulfSign CA 的完全信任</p>
</div>
<div class="warn">
<b>重要提示：</b>证书仅用于获取OpenID，使用完毕后请删除证书并关闭WiFi代理。
</div>
</body></html>"""

    def _handle_connect(self, client_sock, first_line, data):
        parts = first_line.split()
        if len(parts) < 2:
            return

        host_port = parts[1]
        if ":" in host_port:
            hostname, port_str = host_port.rsplit(":", 1)
            port = int(port_str)
        else:
            hostname = host_port
            port = 443

        client_sock.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")

        hl = (hostname or "").lower()
        with self._adapt_lock:
            blocked = hl in self._mitm_block
        should_intercept = (not blocked) and (
            any(hl == h or hl.endswith("." + h) or hl.endswith(h) for h in TARGET_HOSTS)
            or any(hl.endswith(suf) for suf in INTERCEPT_HOST_SUFFIXES)
            or any(hl == eh or hl.endswith(eh) for eh in self.extra_intercept_hosts)
        )

        if should_intercept:
            self._mitm_intercept(client_sock, hostname, port)
        else:
            self._tunnel(client_sock, hostname, port)

    def _tunnel(self, client_sock, hostname, port):
        """Plain tunnel for non-target hosts."""
        try:
            remote = socket.create_connection((hostname, port), timeout=10)
            self._relay(client_sock, remote)
            remote.close()
        except Exception:
            pass

    def _mitm_intercept(self, client_sock, hostname, port):
        """MITM intercept with HTTP keep-alive support."""
        certs = self.cert_mgr.get_host_cert(hostname)
        if not certs:
            self._tunnel(client_sock, hostname, port)
            return

        cert_path, key_path = certs

        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(cert_path, key_path)
            client_ssl = ctx.wrap_socket(client_sock, server_side=True)
        except ssl.SSLError:
            # 客户端在握手期拒绝了我们的证书 (通常是用 certifi 的 requests,
            # 不读 Windows 证书库)。ClientHello 已被 OpenSSL 消费, 无法再隧道
            # 救回这条连接 → 干净关闭。多次失败后把该主机加入直通名单, 以后
            # 纯隧道转发, 保证对方软件能正常访问 (代价: 这台主机抓不到明文)。
            self._note_mitm_failure(hostname)
            return
        except Exception:
            return

        remote_ssl = None
        try:
            remote_ctx = ssl.create_default_context()
            remote_ctx.check_hostname = False
            remote_ctx.verify_mode = ssl.CERT_NONE
            remote_raw = socket.create_connection((hostname, port), timeout=15)
            remote_ssl = remote_ctx.wrap_socket(remote_raw, server_hostname=hostname)

            client_ssl.settimeout(60)

            while True:
                # 读完整 HTTP 请求 (headers + body). 修复 v3.1.1 之前的 bug:
                # 单次 recv 只拿到 headers, body 在下一帧时被丢弃 — 直接导致
                # 抓签约请求时 body_form 为空, 重放时无法替换 person_id.
                request_data = b""
                req_hdr_end = -1
                req_cl = -1
                req_chunked = False
                try:
                    while True:
                        chunk = client_ssl.recv(65536)
                        if not chunk:
                            break
                        request_data += chunk

                        if req_hdr_end < 0 and b"\r\n\r\n" in request_data:
                            req_hdr_end = request_data.index(b"\r\n\r\n") + 4
                            hdr_lower = request_data[:req_hdr_end].lower()
                            m = re.search(rb"content-length:\s*(\d+)", hdr_lower)
                            if m:
                                req_cl = int(m.group(1))
                            req_chunked = b"transfer-encoding: chunked" in hdr_lower

                        if req_hdr_end > 0:
                            if req_cl >= 0:
                                if len(request_data) - req_hdr_end >= req_cl:
                                    break
                            elif req_chunked:
                                if b"\r\n0\r\n\r\n" in request_data[-32:]:
                                    break
                            else:
                                # 没 CL, 没 chunked — GET / 无 body 请求, headers 完整即可
                                break
                except (socket.timeout, ssl.SSLError, OSError):
                    pass

                if not request_data:
                    break

                self._scan_for_openid(request_data)
                self._log_traffic(hostname, ">>> REQUEST", request_data)

                req_line = request_data.split(b"\r\n")[0].decode("utf-8", errors="replace")
                self._log("已记录 [%s] %s" % (hostname, req_line[:80]), "info")

                try:
                    remote_ssl.sendall(request_data)
                except (OSError, ssl.SSLError):
                    break

                response = b""
                remote_ssl.settimeout(20)
                hdr_end = -1
                cl = -1

                while True:
                    try:
                        chunk = remote_ssl.recv(16384)
                        if not chunk:
                            break
                        response += chunk
                        client_ssl.sendall(chunk)

                        if hdr_end < 0 and b"\r\n\r\n" in response:
                            hdr_end = response.index(b"\r\n\r\n") + 4
                            hdr_lower = response[:hdr_end].lower()
                            m = re.search(rb"content-length:\s*(\d+)", hdr_lower)
                            if m:
                                cl = int(m.group(1))
                            else:
                                remote_ssl.settimeout(10)

                        if cl >= 0 and hdr_end > 0:
                            if len(response) - hdr_end >= cl:
                                break
                        elif hdr_end > 0:
                            if b"\r\n0\r\n\r\n" in response[-32:]:
                                break
                            remote_ssl.settimeout(10)

                    except socket.timeout:
                        break
                    except (ssl.SSLError, OSError):
                        break

                self._scan_for_openid(response)
                if response:
                    self._log_traffic(hostname, "<<< RESPONSE", response)

                # 全程录制: 把这一对 (请求, 响应) 整条落盘 + 回调上层.
                if self.capture_all:
                    try:
                        self._record_full_flow(hostname, request_data, response)
                    except Exception as e:
                        logger.debug("record flow skip: %s", e)

                resp_lower = response.lower()
                req_lower = request_data.lower()
                if b"connection: close" in resp_lower or b"connection: close" in req_lower:
                    break

        except Exception as e:
            logger.debug("MITM error for %s: %s", hostname, e)
        finally:
            if remote_ssl:
                try:
                    remote_ssl.close()
                except Exception:
                    pass
            try:
                client_ssl.close()
            except Exception:
                pass

    def _note_mitm_failure(self, hostname: str):
        """记录一次客户端握手失败; 达到阈值则该主机转直通, 避免反复重置。"""
        hl = (hostname or "").lower()
        with self._adapt_lock:
            self._mitm_fail[hl] = self._mitm_fail.get(hl, 0) + 1
            n = self._mitm_fail[hl]
            if n >= 2 and hl not in self._mitm_block:
                self._mitm_block.add(hl)
                newly_blocked = True
            else:
                newly_blocked = False
        if newly_blocked:
            self._log(
                "⚠ %s 的客户端不信任本地证书 (多半是用 certifi 的 requests)，"
                "已切换为『直通放行』以保证它能正常联网 — 该程序的这条流量将"
                "无法解密。若需抓它, 请在『竞品全程录制』里开启"
                "『让对方软件信任证书』后重启对方软件。" % hostname,
                "warn",
            )

    def _relay(self, sock1, sock2, timeout=30):
        """Relay data between two sockets."""
        socks = [sock1, sock2]
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                readable, _, _ = select.select(socks, [], [], 1.0)
            except Exception:
                break
            for s in readable:
                try:
                    data = s.recv(8192)
                    if not data:
                        return
                    other = sock2 if s is sock1 else sock1
                    other.sendall(data)
                except Exception:
                    return

    def _report_wechatcode(self, code: str, source: str = ""):
        if code not in self._found_wechatcodes:
            self._found_wechatcodes.add(code)
            self._log("★ 发现 Wechatcode: %s (来源: %s)" % (code[:16] + "...", source), "ok")
            if self.on_wechatcode:
                self.on_wechatcode(code)

    def _scan_for_openid(self, data: bytes):
        for m in OPENID_PATTERN.finditer(data):
            openid = m.group(1).decode("utf-8", errors="replace")
            if len(openid) >= 20:
                self._report_openid(openid, "url")
        for m in OPENID_JSON_PATTERN.finditer(data):
            openid = m.group(1).decode("utf-8", errors="replace")
            if len(openid) >= 20:
                self._report_openid(openid, "json")
        for m in OPENID_HEADER_PATTERN.finditer(data):
            openid = m.group(1).decode("utf-8", errors="replace")
            if len(openid) >= 15:
                self._report_openid(openid, "header")

        for m in WECHATCODE_URL_PATTERN.finditer(data):
            code = m.group(1).decode("utf-8", errors="replace")
            self._report_wechatcode(code, "url")
        for m in WECHATCODE_COOKIE_PATTERN.finditer(data):
            code = m.group(1).decode("utf-8", errors="replace")
            self._report_wechatcode(code, "cookie")
        for m in WECHATCODE_REDIRECT_PATTERN.finditer(data):
            code = m.group(1).decode("utf-8", errors="replace")
            self._report_wechatcode(code, "redirect")
