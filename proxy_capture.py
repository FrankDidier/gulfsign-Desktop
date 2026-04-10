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
    "health.tengmed.com",
    "wechat.wecity.qq.com",
}

OPENID_PATTERN = re.compile(
    rb'[?&](?:[Oo]penid|openId|OPENID)=([a-zA-Z0-9_-]{20,})', re.IGNORECASE
)

OPENID_JSON_PATTERN = re.compile(
    rb'"(?:openid|openId|OPENID)"\s*:\s*"([a-zA-Z0-9_-]{20,})"'
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

    def get_host_cert(self, hostname: str) -> Optional[tuple]:
        """Return (cert_path, key_path) for a hostname, generating if needed."""
        if hostname in self._host_cache:
            return self._host_cache[hostname]

        try:
            from cryptography import x509
            from cryptography.x509.oid import NameOID
            from cryptography.hazmat.primitives import hashes, serialization
            from cryptography.hazmat.primitives.asymmetric import rsa
            import datetime

            if not self._ca_cert or not self._ca_key:
                return None

            key = rsa.generate_private_key(65537, 2048)
            now = datetime.datetime.utcnow()

            cert = (
                x509.CertificateBuilder()
                .subject_name(x509.Name([
                    x509.NameAttribute(NameOID.COMMON_NAME, hostname),
                ]))
                .issuer_name(self._ca_cert.subject)
                .public_key(key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(now)
                .not_valid_after(now + datetime.timedelta(days=365))
                .add_extension(
                    x509.SubjectAlternativeName([x509.DNSName(hostname)]),
                    False,
                )
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
    """MITM proxy that captures OpenID from health card traffic."""

    def __init__(
        self,
        port: int = 8888,
        on_openid: Optional[Callable] = None,
        on_log: Optional[Callable] = None,
    ):
        self.port = port
        self.on_openid = on_openid
        self.on_log = on_log
        self._running = False
        self._server_socket = None
        self._thread = None
        self._found_openids: Set[str] = set()

        cert_dir = os.path.join(
            os.path.dirname(os.path.abspath(__file__)), "certs"
        )
        self.cert_mgr = CertManager(cert_dir)

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

    def start(self) -> bool:
        if self._running:
            return True

        if not self.cert_mgr.ensure_ca():
            self._log("CA证书生成失败，请确认已安装 cryptography 库", "err")
            return False

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

    def _handle_client(self, client_sock):
        try:
            client_sock.settimeout(15)
            data = client_sock.recv(8192)
            if not data:
                client_sock.close()
                return

            first_line = data.split(b"\r\n")[0].decode("utf-8", errors="replace")

            if first_line.startswith("CONNECT"):
                self._handle_connect(client_sock, first_line, data)
            else:
                self._handle_http(client_sock, first_line, data)
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
        raw_path = raw_data.split(b" ")[1] if b" " in raw_data else b""

        is_cert_request = False
        if parsed.path and parsed.path.rstrip("/") in ("/cert", "/ca", "/certificate"):
            is_cert_request = True
        if raw_path.rstrip(b"/") in (b"/cert", b"/ca", b"/certificate"):
            is_cert_request = True

        if not is_cert_request:
            return False

        ca_path = self.cert_mgr.ca_cert_path
        if not os.path.exists(ca_path):
            body = b"<html><body><h1>CA cert not generated yet. Please retry.</h1></body></html>"
            header = (
                b"HTTP/1.1 500 Internal Server Error\r\n"
                b"Content-Type: text/html\r\n"
                b"Content-Length: %d\r\n"
                b"Connection: close\r\n\r\n" % len(body)
            )
            client_sock.sendall(header + body)
            return True

        with open(ca_path, "rb") as f:
            cert_data = f.read()

        header = (
            b"HTTP/1.1 200 OK\r\n"
            b"Content-Type: application/x-x509-ca-cert\r\n"
            b"Content-Disposition: attachment; filename=\"GulfSign_CA.pem\"\r\n"
            b"Content-Length: %d\r\n"
            b"Connection: close\r\n\r\n" % len(cert_data)
        )
        client_sock.sendall(header + cert_data)
        self._log("CA证书已发送到手机", "ok")
        return True

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

        should_intercept = any(
            hostname.endswith(h) for h in TARGET_HOSTS
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
        """MITM intercept for target hosts to extract OpenID."""
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
            self._tunnel(client_sock, hostname, port)
            return
        except Exception:
            return

        try:
            request_data = client_ssl.recv(16384)
            if not request_data:
                return

            self._scan_for_openid(request_data)

            remote_ctx = ssl.create_default_context()
            remote_ctx.check_hostname = False
            remote_ctx.verify_mode = ssl.CERT_NONE

            remote_raw = socket.create_connection((hostname, port), timeout=10)
            remote_ssl = remote_ctx.wrap_socket(remote_raw, server_hostname=hostname)

            remote_ssl.sendall(request_data)

            response = b""
            while True:
                try:
                    chunk = remote_ssl.recv(8192)
                    if not chunk:
                        break
                    response += chunk
                    client_ssl.sendall(chunk)
                except (ssl.SSLError, socket.timeout):
                    break

            self._scan_for_openid(response)
            remote_ssl.close()
        except Exception as e:
            logger.debug("MITM error for %s: %s", hostname, e)
        finally:
            try:
                client_ssl.close()
            except Exception:
                pass

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

    def _scan_for_openid(self, data: bytes):
        for m in OPENID_PATTERN.finditer(data):
            openid = m.group(1).decode("utf-8", errors="replace")
            if len(openid) >= 20:
                self._report_openid(openid, "url")
        for m in OPENID_JSON_PATTERN.finditer(data):
            openid = m.group(1).decode("utf-8", errors="replace")
            if len(openid) >= 20:
                self._report_openid(openid, "json")
