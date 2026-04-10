# -*- coding: utf-8 -*-
"""
OpenID 一键抓取脚本 (独立版, 跨平台 macOS/Windows)

用法:
  python capture_openid.py

功能:
  1. 自动生成并安装CA证书 (macOS: Keychain / Windows: certutil)
  2. 自动设置系统代理 (macOS: networksetup / Windows: Registry)
  3. 启动MITM代理,拦截目标域名的HTTPS流量
  4. 在电脑版微信打开"我的健康卡"即可抓到 OpenID
  5. 所有拦截到的请求/响应完整记录到 traffic_log.txt
  6. Ctrl+C 停止并自动清理代理设置
"""
import os
import sys
import re
import ssl
import json
import socket
import select
import threading
import time
import signal
import subprocess
import datetime
import logging
from urllib.parse import urlparse

logging.basicConfig(level=logging.INFO, format="[%(asctime)s] %(message)s", datefmt="%H:%M:%S")
log = logging.getLogger("capture")

PROXY_PORT = 8888

TARGET_HOSTS = {
    "jkkyljl.hnhfpc.gov.cn",
    "jkkgzh.hnhfpc.gov.cn",
    "jkkzc.hnhfpc.gov.cn",
    "health.tengmed.com",
    "h5-health.tengmed.com",
    "wechat.wecity.qq.com",
    "card.wecity.qq.com",
}

OPENID_RE = re.compile(rb'[?&](?:[Oo]pen[Ii]d|OPENID)=([a-zA-Z0-9_-]{20,})')
OPENID_JSON_RE = re.compile(rb'"(?:openid|openId|OPENID)"\s*:\s*"([a-zA-Z0-9_-]{20,})"')
OPENID_HEADER_RE = re.compile(rb'^openId:\s*(@?[a-zA-Z0-9_-]{15,})', re.MULTILINE)
USERID_HEADER_RE = re.compile(rb'^userId:\s*([a-zA-Z0-9_-]{15,})', re.MULTILINE)

found_openids = set()
cert_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "certs")
ca_cert_path = os.path.join(cert_dir, "GulfSign_CA.pem")
ca_key_path = os.path.join(cert_dir, "GulfSign_CA.key")
traffic_log_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "traffic_log.txt")
_ca_cert = None
_ca_key = None
_host_cert_cache = {}
_running = True
_log_lock = threading.Lock()


def log_traffic(hostname, direction, data):
    """Log intercepted traffic to file for later analysis."""
    try:
        ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        text = data.decode("utf-8", errors="replace")[:4000]
        with _log_lock:
            with open(traffic_log_path, "a", encoding="utf-8") as f:
                f.write("\n" + "=" * 70 + "\n")
                f.write("[%s] %s  %s\n" % (ts, direction, hostname))
                f.write("-" * 70 + "\n")
                f.write(text + "\n")
    except Exception:
        pass


# ── Certificate Generation ──────────────────────────────────────────

def generate_ca():
    global _ca_cert, _ca_key
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    os.makedirs(cert_dir, exist_ok=True)

    if os.path.exists(ca_cert_path) and os.path.exists(ca_key_path):
        with open(ca_key_path, "rb") as f:
            _ca_key = serialization.load_pem_private_key(f.read(), None)
        with open(ca_cert_path, "rb") as f:
            _ca_cert = x509.load_pem_x509_certificate(f.read())
        log.info("CA证书已存在，复用")
        return True

    log.info("生成CA证书...")
    _ca_key = rsa.generate_private_key(65537, 2048)
    name = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "CN"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "GulfSign Helper"),
        x509.NameAttribute(NameOID.COMMON_NAME, "GulfSign CA"),
    ])
    now = datetime.datetime.utcnow()
    ski = x509.SubjectKeyIdentifier.from_public_key(_ca_key.public_key())
    _ca_cert = (
        x509.CertificateBuilder()
        .subject_name(name).issuer_name(name)
        .public_key(_ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), True)
        .add_extension(x509.KeyUsage(
            digital_signature=True, key_cert_sign=True, crl_sign=True,
            content_commitment=False, key_encipherment=False,
            data_encipherment=False, key_agreement=False,
            encipher_only=False, decipher_only=False,
        ), True)
        .add_extension(ski, False)
        .sign(_ca_key, hashes.SHA256())
    )

    with open(ca_key_path, "wb") as f:
        f.write(_ca_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        ))
    with open(ca_cert_path, "wb") as f:
        f.write(_ca_cert.public_bytes(serialization.Encoding.PEM))

    log.info("CA证书已生成: %s", ca_cert_path)
    return True


def get_host_cert(hostname):
    if hostname in _host_cert_cache:
        return _host_cert_cache[hostname]

    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    key = rsa.generate_private_key(65537, 2048)
    now = datetime.datetime.utcnow()
    aki = x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(
        _ca_cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value
    )
    ski = x509.SubjectKeyIdentifier.from_public_key(key.public_key())
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hostname)]))
        .issuer_name(_ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(hostname)]), False)
        .add_extension(aki, False)
        .add_extension(ski, False)
        .sign(_ca_key, hashes.SHA256())
    )

    cert_path = os.path.join(cert_dir, "%s.pem" % hostname)
    key_path = os.path.join(cert_dir, "%s.key" % hostname)
    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    with open(key_path, "wb") as f:
        f.write(key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        ))

    _host_cert_cache[hostname] = (cert_path, key_path)
    return cert_path, key_path


# ── System Proxy & Cert (cross-platform) ────────────────────────────

_wifi_service = None

def _get_macos_network_service():
    """Find the active network service name (usually 'Wi-Fi')."""
    global _wifi_service
    if _wifi_service:
        return _wifi_service
    try:
        r = subprocess.run(["networksetup", "-listallnetworkservices"],
                           capture_output=True, text=True)
        for line in r.stdout.splitlines():
            line = line.strip()
            if line.startswith("*"):
                continue
            if "wi-fi" in line.lower() or "wifi" in line.lower():
                _wifi_service = line
                return line
        for line in r.stdout.splitlines():
            line = line.strip()
            if line.startswith("*") or line.startswith("An asterisk"):
                continue
            if "ethernet" in line.lower() or "thunderbolt" in line.lower():
                _wifi_service = line
                return line
    except Exception:
        pass
    _wifi_service = "Wi-Fi"
    return "Wi-Fi"


def install_ca():
    if sys.platform == "darwin":
        return _install_ca_macos()
    elif sys.platform == "win32":
        return _install_ca_windows()
    log.warning("Unsupported OS for auto cert install")
    return False


def _install_ca_macos():
    log.info("安装CA证书到macOS Keychain... (需要输入密码)")
    r = subprocess.run([
        "security", "add-trusted-cert",
        "-r", "trustRoot",
        "-k", os.path.expanduser("~/Library/Keychains/login.keychain-db"),
        ca_cert_path,
    ], capture_output=True, text=True)
    if r.returncode == 0:
        log.info("CA证书安装成功 (macOS Keychain)")
        return True
    log.warning("CA证书安装结果: rc=%d %s", r.returncode, r.stderr.strip() or r.stdout.strip())
    log.info("如果失败,请双击 %s 手动安装并信任", ca_cert_path)
    return False


def _install_ca_windows():
    from cryptography.hazmat.primitives.serialization import Encoding
    from cryptography import x509 as x509_mod

    der_path = ca_cert_path.replace(".pem", ".crt")
    with open(ca_cert_path, "rb") as f:
        cert_data = f.read()
    cert_obj = x509_mod.load_pem_x509_certificate(cert_data)
    with open(der_path, "wb") as f:
        f.write(cert_obj.public_bytes(Encoding.DER))

    log.info("安装CA证书到Windows信任存储... (可能弹出确认框，请点\"是\")")
    r = subprocess.run(["certutil", "-addstore", "-user", "Root", der_path],
                       capture_output=True, text=True)
    if r.returncode == 0:
        log.info("CA证书安装成功")
        return True
    log.warning("CA证书安装可能失败: %s", r.stderr.strip() or r.stdout.strip())
    return False


def set_proxy():
    if sys.platform == "darwin":
        _set_proxy_macos()
    elif sys.platform == "win32":
        _set_proxy_windows()


def clear_proxy():
    if sys.platform == "darwin":
        _clear_proxy_macos()
    elif sys.platform == "win32":
        _clear_proxy_windows()


def _set_proxy_macos():
    svc = _get_macos_network_service()
    port = str(PROXY_PORT)
    subprocess.run(["networksetup", "-setwebproxy", svc, "127.0.0.1", port], capture_output=True)
    subprocess.run(["networksetup", "-setsecurewebproxy", svc, "127.0.0.1", port], capture_output=True)
    log.info("macOS系统代理已设置: %s -> 127.0.0.1:%s", svc, port)


def _clear_proxy_macos():
    svc = _get_macos_network_service()
    subprocess.run(["networksetup", "-setwebproxystate", svc, "off"], capture_output=True)
    subprocess.run(["networksetup", "-setsecurewebproxystate", svc, "off"], capture_output=True)
    log.info("macOS系统代理已清除: %s", svc)


def _set_proxy_windows():
    proxy = "127.0.0.1:%d" % PROXY_PORT
    subprocess.run([
        "reg", "add",
        r"HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings",
        "/v", "ProxyServer", "/t", "REG_SZ", "/d", proxy, "/f",
    ], capture_output=True)
    subprocess.run([
        "reg", "add",
        r"HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings",
        "/v", "ProxyEnable", "/t", "REG_DWORD", "/d", "1", "/f",
    ], capture_output=True)
    _refresh_proxy_windows()
    log.info("Windows系统代理已设置: %s", proxy)


def _clear_proxy_windows():
    subprocess.run([
        "reg", "add",
        r"HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings",
        "/v", "ProxyEnable", "/t", "REG_DWORD", "/d", "0", "/f",
    ], capture_output=True)
    _refresh_proxy_windows()
    log.info("Windows系统代理已清除")


def _refresh_proxy_windows():
    try:
        import ctypes
        inet = ctypes.windll.wininet
        inet.InternetSetOptionW(None, 39, None, 0)
        inet.InternetSetOptionW(None, 37, None, 0)
    except Exception:
        pass


# ── OpenID Scanner ──────────────────────────────────────────────────

found_userids = set()

def scan_openid(data):
    for pattern in (OPENID_RE, OPENID_JSON_RE, OPENID_HEADER_RE):
        for m in pattern.finditer(data):
            oid = m.group(1).decode("utf-8", errors="replace")
            if len(oid) >= 15 and oid not in found_openids:
                found_openids.add(oid)
                print()
                print("=" * 60)
                print("  *** 发现 OpenID: %s ***" % oid)
                print("=" * 60)
                print()
    for m in USERID_HEADER_RE.finditer(data):
        uid = m.group(1).decode("utf-8", errors="replace")
        if uid not in found_userids:
            found_userids.add(uid)
            log.info("发现 userId: %s", uid)


# ── Proxy Server ────────────────────────────────────────────────────

def handle_client(client_sock):
    try:
        client_sock.settimeout(15)
        data = client_sock.recv(8192)
        if not data:
            client_sock.close()
            return

        first_line = data.split(b"\r\n")[0].decode("utf-8", errors="replace")

        if first_line.startswith("CONNECT"):
            handle_connect(client_sock, first_line)
        else:
            scan_openid(data)
            handle_http(client_sock, first_line, data)
    except Exception:
        pass
    finally:
        try:
            client_sock.close()
        except Exception:
            pass


def handle_http(client_sock, first_line, data):
    parts = first_line.split()
    if len(parts) < 3:
        return

    url = parts[1]
    parsed = urlparse(url)

    if serve_cert(client_sock, parsed, data):
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

        while True:
            chunk = remote.recv(4096)
            if not chunk:
                break
            scan_openid(chunk)
            client_sock.sendall(chunk)
        remote.close()
    except Exception:
        pass


def serve_cert(client_sock, parsed, raw_data):
    raw_url = raw_data.split(b" ")[1] if b" " in raw_data else b""
    is_proxied = raw_url.startswith(b"http://")
    if is_proxied and parsed.hostname:
        local_ip = get_local_ip()
        if parsed.hostname not in ("127.0.0.1", "localhost", local_ip):
            return False

    path = (parsed.path or "").rstrip("/")
    if path in ("/cert", "/ca"):
        from cryptography.hazmat.primitives.serialization import Encoding
        from cryptography import x509 as x509_mod
        with open(ca_cert_path, "rb") as f:
            pem = f.read()
        der = x509_mod.load_pem_x509_certificate(pem).public_bytes(Encoding.DER)
        header = (
            b"HTTP/1.1 200 OK\r\n"
            b"Content-Type: application/x-x509-ca-cert\r\n"
            b"Content-Disposition: attachment; filename=\"GulfSign_CA.crt\"\r\n"
            b"Content-Length: %d\r\n"
            b"Connection: close\r\n\r\n" % len(der)
        )
        client_sock.sendall(header + der)
        log.info("CA证书已发送")
        return True
    return False


def handle_connect(client_sock, first_line):
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

    should_intercept = any(hostname.endswith(h) for h in TARGET_HOSTS)

    if should_intercept:
        mitm_intercept(client_sock, hostname, port)
    else:
        tunnel(client_sock, hostname, port)


def tunnel(client_sock, hostname, port):
    try:
        remote = socket.create_connection((hostname, port), timeout=10)
        relay(client_sock, remote)
        remote.close()
    except Exception:
        pass


def mitm_intercept(client_sock, hostname, port):
    certs = get_host_cert(hostname)
    if not certs:
        tunnel(client_sock, hostname, port)
        return

    cert_path, key_path = certs
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(cert_path, key_path)
        client_ssl = ctx.wrap_socket(client_sock, server_side=True)
    except ssl.SSLError as e:
        log.debug("MITM TLS握手失败 %s: %s (客户端可能未信任CA证书)", hostname, e)
        tunnel(client_sock, hostname, port)
        return
    except Exception:
        return

    try:
        request_data = client_ssl.recv(16384)
        if not request_data:
            return

        scan_openid(request_data)
        log_traffic(hostname, ">>> REQUEST", request_data)

        req_line = request_data.split(b"\r\n")[0].decode("utf-8", errors="replace")
        log.info("拦截 [%s] %s", hostname, req_line[:80])

        remote_ctx = ssl.create_default_context()
        remote_ctx.check_hostname = False
        remote_ctx.verify_mode = ssl.CERT_NONE

        remote_raw = socket.create_connection((hostname, port), timeout=10)
        remote_ssl = remote_ctx.wrap_socket(remote_raw, server_hostname=hostname)
        remote_ssl.sendall(request_data)

        resp_chunks = []
        while True:
            try:
                chunk = remote_ssl.recv(8192)
                if not chunk:
                    break
                resp_chunks.append(chunk)
                scan_openid(chunk)
                client_ssl.sendall(chunk)
            except (ssl.SSLError, socket.timeout):
                break

        if resp_chunks:
            log_traffic(hostname, "<<< RESPONSE", b"".join(resp_chunks))

        remote_ssl.close()
    except Exception as e:
        log.debug("MITM error %s: %s", hostname, e)
    finally:
        try:
            client_ssl.close()
        except Exception:
            pass


def relay(sock1, sock2, timeout=30):
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


def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


# ── Main ────────────────────────────────────────────────────────────

def main():
    global _running

    print()
    print("=" * 60)
    print("  OpenID 抓取 + 全流量记录工具")
    print("  Platform: %s" % sys.platform)
    print("=" * 60)
    print()

    if not generate_ca():
        print("CA证书生成失败!")
        return

    # Clear old traffic log
    if os.path.exists(traffic_log_path):
        os.remove(traffic_log_path)

    install_ca()
    set_proxy()

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        server.bind(("0.0.0.0", PROXY_PORT))
    except OSError as e:
        log.error("端口 %d 被占用: %s", PROXY_PORT, e)
        log.error("请关闭占用该端口的程序后重试")
        clear_proxy()
        return

    server.listen(50)
    server.settimeout(1.0)

    local_ip = get_local_ip()
    print()
    log.info("代理已启动: %s:%d", local_ip, PROXY_PORT)
    log.info("流量日志: %s", traffic_log_path)
    print()
    print("-" * 60)
    print("  系统代理已自动设置!")
    print("  现在请打开电脑版微信 -> 搜索\"我的健康卡\" -> 进入小程序")
    print("  所有目标域名的请求/响应会完整记录到 traffic_log.txt")
    print("-" * 60)
    print()
    print("  等待抓取... (按 Ctrl+C 停止)")
    print()

    def signal_handler(sig, frame):
        global _running
        _running = False

    signal.signal(signal.SIGINT, signal_handler)

    try:
        while _running:
            try:
                client, addr = server.accept()
                threading.Thread(target=handle_client, args=(client,), daemon=True).start()
            except socket.timeout:
                continue
            except Exception:
                if _running:
                    continue
                break
    finally:
        server.close()
        clear_proxy()

        print()
        print("=" * 60)
        if found_openids:
            print("  抓取到的 OpenID:")
            for oid in found_openids:
                print("    %s" % oid)
        else:
            print("  未抓取到OpenID")
        print()
        if os.path.exists(traffic_log_path):
            sz = os.path.getsize(traffic_log_path)
            print("  完整流量日志: %s (%d bytes)" % (traffic_log_path, sz))
        print("=" * 60)
        print()

        if found_openids:
            result_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), "captured_openids.txt")
            with open(result_file, "w") as f:
                for oid in found_openids:
                    f.write(oid + "\n")
            log.info("OpenID已保存到: %s", result_file)


if __name__ == "__main__":
    main()
