#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
测试SSL/TLS连接修复
"""
import sys
import os
import time
import requests
import ssl
import urllib3
from urllib3.util.ssl_ import create_urllib3_context

# 添加当前目录到路径
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def test_standard_https(url):
    """测试标准HTTPS连接"""
    print(f"\n🔍 测试1: 标准HTTPS连接")
    print(f"   目标: {url}")
    
    try:
        start_time = time.time()
        response = requests.get(url, timeout=10, verify=True)
        response_time = int((time.time() - start_time) * 1000)
        
        print(f"   ✅ 连接成功")
        print(f"   📊 状态码: {response.status_code}")
        print(f"   ⏱️  响应时间: {response_time}ms")
        
        # 检查是否是公卫系统
        is_ggws = "ggws" in response.text.lower() or "公卫" in response.text
        print(f"   🏥 系统类型: {'公卫3.0系统' if is_ggws else '未知系统'}")
        
        # 显示服务器信息
        if 'Server' in response.headers:
            print(f"   🖥️  服务器: {response.headers['Server']}")
        
        return True, response.status_code, response_time
        
    except Exception as e:
        print(f"   ❌ 连接失败: {str(e)}")
        return False, 0, 0

def test_no_verify_https(url):
    """测试跳过证书验证的HTTPS连接"""
    print(f"\n🔍 测试2: 跳过证书验证")
    print(f"   目标: {url}")
    
    try:
        start_time = time.time()
        response = requests.get(url, timeout=10, verify=False)
        response_time = int((time.time() - start_time) * 1000)
        
        print(f"   ✅ 连接成功")
        print(f"   📊 状态码: {response.status_code}")
        print(f"   ⏱️  响应时间: {response_time}ms")
        
        # 检查是否是公卫系统
        is_ggws = "ggws" in response.text.lower() or "公卫" in response.text
        print(f"   🏥 系统类型: {'公卫3.0系统' if is_ggws else '未知系统'}")
        
        return True, response.status_code, response_time
        
    except Exception as e:
        print(f"   ❌ 连接失败: {str(e)}")
        return False, 0, 0

def test_compatible_ssl(url):
    """测试兼容SSL/TLS连接"""
    print(f"\n🔍 测试3: 兼容SSL/TLS连接")
    print(f"   目标: {url}")
    
    try:
        # 创建自定义SSL上下文，支持较旧的协议
        ssl_context = ssl.create_default_context()
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE
        ssl_context.set_ciphers('DEFAULT:@SECLEVEL=1')  # 降低安全级别以支持较旧的加密套件
        
        # 使用urllib3
        http = urllib3.PoolManager(
            ssl_context=ssl_context,
            retries=urllib3.Retry(total=3, backoff_factor=0.5),
            timeout=urllib3.Timeout(connect=5.0, read=10.0)
        )
        
        start_time = time.time()
        response = http.request('GET', url)
        response_time = int((time.time() - start_time) * 1000)
        
        print(f"   ✅ 连接成功")
        print(f"   📊 状态码: {response.status}")
        print(f"   ⏱️  响应时间: {response_time}ms")
        
        # 检查是否是公卫系统
        response_text = response.data.decode('utf-8', errors='ignore')
        is_ggws = "ggws" in response_text.lower() or "公卫" in response_text
        print(f"   🏥 系统类型: {'公卫3.0系统' if is_ggws else '未知系统'}")
        
        return True, response.status, response_time
        
    except Exception as e:
        print(f"   ❌ 连接失败: {str(e)}")
        return False, 0, 0

def test_network_connectivity():
    """测试网络连接性"""
    print(f"\n🔍 测试网络连接性")
    
    # 测试百度连接
    try:
        import socket
        start_time = time.time()
        socket.create_connection(("www.baidu.com", 443), timeout=5)
        response_time = int((time.time() - start_time) * 1000)
        print(f"   ✅ 网络连接正常 (响应时间: {response_time}ms)")
        return True, response_time
    except Exception as e:
        print(f"   ❌ 网络连接失败: {str(e)}")
        return False, 0

def test_dns_resolution():
    """测试DNS解析"""
    print(f"\n🔍 测试DNS解析")
    
    try:
        import socket
        start_time = time.time()
        socket.gethostbyname("ggws.hnhfpc.gov.cn")
        dns_time = int((time.time() - start_time) * 1000)
        print(f"   ✅ DNS解析成功 (耗时: {dns_time}ms)")
        return True, dns_time
    except Exception as e:
        print(f"   ❌ DNS解析失败: {str(e)}")
        return False, 0

def main():
    """主测试函数"""
    print("=" * 60)
    print("🔬 SSL/TLS连接修复测试")
    print("=" * 60)
    
    # 测试目标URL
    test_urls = [
        "https://ggws.hnhfpc.gov.cn",
        "https://www.baidu.com"
    ]
    
    results = {}
    
    # 测试网络连接性
    net_success, net_time = test_network_connectivity()
    results["network"] = {"success": net_success, "time": net_time}
    
    # 测试DNS解析
    dns_success, dns_time = test_dns_resolution()
    results["dns"] = {"success": dns_success, "time": dns_time}
    
    # 测试每个URL
    for url in test_urls:
        print(f"\n{'='*60}")
        print(f"🌐 测试URL: {url}")
        print(f"{'='*60}")
        
        url_results = {}
        
        # 测试标准HTTPS
        success1, code1, time1 = test_standard_https(url)
        url_results["standard"] = {"success": success1, "code": code1, "time": time1}
        
        # 测试跳过证书验证
        success2, code2, time2 = test_no_verify_https(url)
        url_results["no_verify"] = {"success": success2, "code": code2, "time": time2}
        
        # 测试兼容SSL
        success3, code3, time3 = test_compatible_ssl(url)
        url_results["compatible"] = {"success": success3, "code": code3, "time": time3}
        
        results[url] = url_results
    
    # 打印总结
    print(f"\n{'='*60}")
    print("📊 测试总结")
    print(f"{'='*60}")
    
    total_tests = 0
    passed_tests = 0
    
    # 网络连接测试
    if results["network"]["success"]:
        print(f"✅ 网络连接: 正常 ({results['network']['time']}ms)")
        passed_tests += 1
    else:
        print(f"❌ 网络连接: 失败")
    total_tests += 1
    
    # DNS解析测试
    if results["dns"]["success"]:
        print(f"✅ DNS解析: 正常 ({results['dns']['time']}ms)")
        passed_tests += 1
    else:
        print(f"❌ DNS解析: 失败")
    total_tests += 1
    
    # 每个URL的测试结果
    for url in test_urls:
        url_results = results[url]
        print(f"\n🌐 {url}:")
        
        # 标准HTTPS
        if url_results["standard"]["success"]:
            print(f"  ✅ 标准HTTPS: HTTP {url_results['standard']['code']} ({url_results['standard']['time']}ms)")
            passed_tests += 1
        else:
            print(f"  ❌ 标准HTTPS: 失败")
        total_tests += 1
        
        # 跳过证书验证
        if url_results["no_verify"]["success"]:
            print(f"  ✅ 跳过验证: HTTP {url_results['no_verify']['code']} ({url_results['no_verify']['time']}ms)")
            passed_tests += 1
        else:
            print(f"  ❌ 跳过验证: 失败")
        total_tests += 1
        
        # 兼容SSL
        if url_results["compatible"]["success"]:
            print(f"  ✅ 兼容SSL: HTTP {url_results['compatible']['code']} ({url_results['compatible']['time']}ms)")
            passed_tests += 1
        else:
            print(f"  ❌ 兼容SSL: 失败")
        total_tests += 1
    
    # 总体结果
    print(f"\n{'='*60}")
    print(f"📈 总体结果: {passed_tests}/{total_tests} 测试通过")
    
    if passed_tests == total_tests:
        print(f"🎉 所有测试通过！SSL/TLS连接修复成功。")
    else:
        print(f"⚠️  部分测试失败，需要进一步检查。")
    
    print(f"{'='*60}")
    
    return passed_tests == total_tests

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)