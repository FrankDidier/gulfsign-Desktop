#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
分析公卫3.0系统SSL握手失败问题
"""
import sys
import os
import time
import socket
import ssl
import urllib3
from urllib3.util.ssl_ import create_urllib3_context
import requests
from requests.adapters import HTTPAdapter

def analyze_ssl_configuration(url):
    """分析SSL配置"""
    print(f"\n🔬 分析SSL配置: {url}")
    
    # 解析主机名和端口
    from urllib.parse import urlparse
    parsed = urlparse(url)
    hostname = parsed.hostname
    port = parsed.port or 443
    
    print(f"   主机名: {hostname}")
    print(f"   端口: {port}")
    
    # 测试不同的SSL/TLS版本
    ssl_versions = []
    
    # 检查可用的SSL/TLS版本
    if hasattr(ssl, 'PROTOCOL_TLSv1_3'):
        ssl_versions.append(("TLSv1.3", ssl.PROTOCOL_TLSv1_3))
    if hasattr(ssl, 'PROTOCOL_TLSv1_2'):
        ssl_versions.append(("TLSv1.2", ssl.PROTOCOL_TLSv1_2))
    if hasattr(ssl, 'PROTOCOL_TLSv1_1'):
        ssl_versions.append(("TLSv1.1", ssl.PROTOCOL_TLSv1_1))
    if hasattr(ssl, 'PROTOCOL_TLSv1'):
        ssl_versions.append(("TLSv1", ssl.PROTOCOL_TLSv1))
    if hasattr(ssl, 'PROTOCOL_SSLv3'):
        ssl_versions.append(("SSLv3", ssl.PROTOCOL_SSLv3))
    if hasattr(ssl, 'PROTOCOL_SSLv2'):
        ssl_versions.append(("SSLv2", ssl.PROTOCOL_SSLv2))
    
    # 如果没有找到任何版本，使用默认版本
    if not ssl_versions:
        ssl_versions.append(("TLS", ssl.PROTOCOL_TLS))
    
    results = {}
    
    for version_name, ssl_protocol in ssl_versions:
        try:
            # 创建SSL上下文
            context = ssl.SSLContext(ssl_protocol)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            # 设置兼容的加密套件
            if ssl_protocol in [ssl.PROTOCOL_SSLv2, ssl.PROTOCOL_SSLv3, ssl.PROTOCOL_TLSv1]:
                context.set_ciphers('DEFAULT:@SECLEVEL=0')
            else:
                context.set_ciphers('DEFAULT:@SECLEVEL=1')
            
            # 创建socket连接
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            
            # 包装为SSL socket
            ssl_sock = context.wrap_socket(sock, server_hostname=hostname)
            
            start_time = time.time()
            ssl_sock.connect((hostname, port))
            connect_time = int((time.time() - start_time) * 1000)
            
            # 获取SSL信息
            cipher = ssl_sock.cipher()
            ssl_version = ssl_sock.version()
            
            print(f"   ✅ {version_name}: 支持")
            print(f"      SSL版本: {ssl_version}")
            print(f"      加密套件: {cipher[0]}")
            print(f"      连接时间: {connect_time}ms")
            
            results[version_name] = {
                "supported": True,
                "ssl_version": ssl_version,
                "cipher": cipher[0],
                "connect_time": connect_time
            }
            
            ssl_sock.close()
            sock.close()
            
        except Exception as e:
            print(f"   ❌ {version_name}: 不支持 ({str(e)})")
            results[version_name] = {
                "supported": False,
                "error": str(e)
            }
    
    return results

def test_custom_ssl_adapter(url):
    """测试自定义SSL适配器"""
    print(f"\n🔬 测试自定义SSL适配器: {url}")
    
    class CustomSSLAdapter(HTTPAdapter):
        """自定义SSL适配器，支持更广泛的SSL/TLS配置"""
        
        def init_poolmanager(self, *args, **kwargs):
            # 创建自定义SSL上下文
            ctx = create_urllib3_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            
            # 尝试多种加密套件配置
            cipher_configs = [
                'DEFAULT:@SECLEVEL=0',  # 最低安全级别
                'ALL:@SECLEVEL=0',      # 所有加密套件
                'COMPLEMENTOFALL',      # 补充所有
                'RSA',                  # RSA加密
                'ECDHE',                # ECDHE密钥交换
            ]
            
            for cipher_config in cipher_configs:
                try:
                    ctx.set_ciphers(cipher_config)
                    kwargs['ssl_context'] = ctx
                    return super().init_poolmanager(*args, **kwargs)
                except Exception:
                    continue
            
            # 如果所有配置都失败，使用默认配置
            return super().init_poolmanager(*args, **kwargs)
    
    try:
        session = requests.Session()
        session.mount("https://", CustomSSLAdapter())
        session.verify = False
        
        start_time = time.time()
        response = session.get(url, timeout=15)
        response_time = int((time.time() - start_time) * 1000)
        
        print(f"   ✅ 连接成功")
        print(f"      状态码: {response.status_code}")
        print(f"      响应时间: {response_time}ms")
        
        # 检查响应内容
        if response.status_code == 200:
            content = response.text[:500]  # 只取前500字符
            is_ggws = "ggws" in content.lower() or "公卫" in content
            
            print(f"      系统类型: {'公卫3.0系统' if is_ggws else '未知系统'}")
            print(f"      内容预览: {content[:100]}...")
        
        return True, response.status_code, response_time
        
    except Exception as e:
        print(f"   ❌ 连接失败: {str(e)}")
        return False, 0, 0

def test_direct_socket_connection(url):
    """测试直接socket连接"""
    print(f"\n🔬 测试直接socket连接: {url}")
    
    from urllib.parse import urlparse
    parsed = urlparse(url)
    hostname = parsed.hostname
    port = parsed.port or 443
    
    try:
        # 创建原始socket连接
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        
        start_time = time.time()
        sock.connect((hostname, port))
        connect_time = int((time.time() - start_time) * 1000)
        
        print(f"   ✅ TCP连接成功")
        print(f"      连接时间: {connect_time}ms")
        
        # 尝试发送HTTP请求
        http_request = f"GET / HTTP/1.1\r\nHost: {hostname}\r\nConnection: close\r\n\r\n"
        sock.send(http_request.encode())
        
        # 接收响应
        response_data = b""
        while True:
            try:
                chunk = sock.recv(1024)
                if not chunk:
                    break
                response_data += chunk
            except socket.timeout:
                break
        
        if response_data:
            response_text = response_data.decode('utf-8', errors='ignore')
            print(f"   ✅ 收到HTTP响应")
            print(f"      响应长度: {len(response_data)} 字节")
            
            # 解析状态码
            lines = response_text.split('\r\n')
            if lines and 'HTTP' in lines[0]:
                status_line = lines[0]
                print(f"      状态行: {status_line}")
        
        sock.close()
        return True, connect_time
        
    except Exception as e:
        print(f"   ❌ 连接失败: {str(e)}")
        return False, 0

def analyze_redirect_chain(url):
    """分析重定向链"""
    print(f"\n🔬 分析重定向链: {url}")
    
    try:
        session = requests.Session()
        session.max_redirects = 5  # 限制重定向次数
        
        start_time = time.time()
        response = session.get(url, timeout=15, allow_redirects=True)
        response_time = int((time.time() - start_time) * 1000)
        
        print(f"   ✅ 最终状态码: {response.status_code}")
        print(f"      最终URL: {response.url}")
        print(f"      响应时间: {response_time}ms")
        
        # 检查重定向历史
        if response.history:
            print(f"   🔄 重定向历史:")
            for i, resp in enumerate(response.history, 1):
                print(f"      {i}. {resp.status_code} -> {resp.url}")
        
        # 检查响应头
        print(f"   📋 响应头:")
        for header, value in response.headers.items():
            if header.lower() in ['server', 'content-type', 'location', 'set-cookie']:
                print(f"      {header}: {value}")
        
        return True, response.status_code, response.url
        
    except Exception as e:
        print(f"   ❌ 分析失败: {str(e)}")
        return False, 0, ""

def main():
    """主分析函数"""
    print("=" * 70)
    print("🔬 公卫3.0系统SSL握手失败问题深度分析")
    print("=" * 70)
    
    target_url = "https://ggws.hnhfpc.gov.cn"
    
    print(f"\n🎯 分析目标: {target_url}")
    print(f"   问题描述: SSLv3握手失败 (SSLV3_ALERT_HANDSHAKE_FAILURE)")
    print(f"   可能原因:")
    print(f"     1. 服务器使用特殊的SSL/TLS配置")
    print(f"     2. 需要特定的加密套件")
    print(f"     3. 服务器证书问题")
    print(f"     4. 网络中间件干扰")
    
    # 1. 分析SSL配置
    ssl_results = analyze_ssl_configuration(target_url)
    
    # 2. 测试自定义SSL适配器
    adapter_success, adapter_code, adapter_time = test_custom_ssl_adapter(target_url)
    
    # 3. 测试直接socket连接
    socket_success, socket_time = test_direct_socket_connection(target_url)
    
    # 4. 分析重定向链
    redirect_success, redirect_code, final_url = analyze_redirect_chain(target_url)
    
    # 打印总结
    print(f"\n{'='*70}")
    print("📊 分析总结")
    print(f"{'='*70}")
    
    print(f"\n🔍 SSL/TLS支持情况:")
    supported_versions = [v for v, r in ssl_results.items() if r.get("supported")]
    unsupported_versions = [v for v, r in ssl_results.items() if not r.get("supported")]
    
    if supported_versions:
        print(f"   ✅ 支持的版本: {', '.join(supported_versions)}")
    if unsupported_versions:
        print(f"   ❌ 不支持的版本: {', '.join(unsupported_versions)}")
    
    print(f"\n🔧 测试结果:")
    print(f"   1. 自定义SSL适配器: {'✅ 成功' if adapter_success else '❌ 失败'}")
    print(f"   2. 直接socket连接: {'✅ 成功' if socket_success else '❌ 失败'}")
    print(f"   3. 重定向分析: {'✅ 成功' if redirect_success else '❌ 失败'}")
    
    print(f"\n💡 问题诊断:")
    
    # 检查SSLv3支持
    if "SSLv3" in unsupported_versions:
        print(f"   • SSLv3握手失败: 服务器可能已禁用SSLv3或使用特殊配置")
    
    # 检查重定向
    if redirect_success and final_url != target_url:
        print(f"   • 存在重定向: {target_url} -> {final_url}")
        print(f"     可能需要处理SSO认证流程")
    
    # 检查连接性
    if socket_success and not adapter_success:
        print(f"   • TCP连接正常但SSL握手失败")
        print(f"     可能是SSL/TLS配置不匹配或证书问题")
    
    print(f"\n🔧 修复建议:")
    print(f"   1. 使用网页登录方式 (方式1)")
    print(f"      - 直接打开浏览器登录，避免SSL握手问题")
    print(f"      - 登录成功后同步配置信息")
    print(f"   2. 检查网络环境")
    print(f"      - 确保没有防火墙或代理干扰")
    print(f"      - 尝试不同的网络环境")
    print(f"   3. 联系系统管理员")
    print(f"      - 确认服务器SSL/TLS配置")
    print(f"      - 检查证书有效性")
    
    print(f"\n{'='*70}")
    print("📋 结论: 建议客户使用网页登录方式 (方式1)")
    print(f"{'='*70}")
    
    return True

if __name__ == "__main__":
    main()