#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
分析SSO重定向循环问题
"""

import requests
import ssl
from requests.adapters import HTTPAdapter
from urllib3.util.ssl_ import create_urllib3_context
import logging
import time

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class CustomSSLAdapter(HTTPAdapter):
    """自定义SSL适配器，支持较旧的TLS版本"""
    def init_poolmanager(self, *args, **kwargs):
        ctx = create_urllib3_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.set_ciphers('DEFAULT:@SECLEVEL=1')
        kwargs['ssl_context'] = ctx
        return super().init_poolmanager(*args, **kwargs)

def test_sso_redirect():
    """测试SSO重定向"""
    print("🔍 测试SSO重定向循环问题")
    print("="*60)
    
    # 测试URL（从错误日志中提取）
    test_urls = [
        "https://sso.hnhfpc.gov.cn:8077/Authenticate.aspx?ReturnUrl=https%3a%2f%2fggws.hnhfpc.gov.cn%2fIndex.aspx%3fgoto%3dhttps%253a%252f%252fggws.hnhfpc.gov.cn%252fIndex.aspx%253fss%253dbd2aec13-dd5c-4a6a-92f5-ebb84a3f31bf",
        "https://ggws.hnhfpc.gov.cn/FormMain.aspx",
        "https://ggws.hnhfpc.gov.cn/Index.aspx"
    ]
    
    for i, url in enumerate(test_urls, 1):
        print(f"\n{i}. 测试URL: {url}")
        
        # 创建会话
        session = requests.Session()
        session.mount("https://", CustomSSLAdapter())
        session.verify = False
        session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        })
        
        try:
            # 设置最大重定向次数
            session.max_redirects = 5
            
            start_time = time.time()
            response = session.get(url, timeout=10, allow_redirects=True)
            elapsed = time.time() - start_time
            
            print(f"   状态码: {response.status_code}")
            print(f"   最终URL: {response.url}")
            print(f"   重定向次数: {len(response.history)}")
            print(f"   耗时: {elapsed:.2f}秒")
            
            # 显示重定向链
            if response.history:
                print("   重定向链:")
                for j, resp in enumerate(response.history):
                    print(f"     {j+1}. {resp.url} (状态码: {resp.status_code})")
            
            # 检查响应内容
            if response.status_code == 200:
                content = response.text[:500]
                print(f"   响应内容前500字符:")
                print(f"   {content}")
                
                # 检查是否有登录表单
                if "login" in content.lower() or "用户名" in content or "密码" in content:
                    print("   ✅ 检测到登录表单")
                else:
                    print("   ❌ 未检测到登录表单")
                    
                # 检查是否有Token
                if "Token" in response.url or "token" in response.url.lower():
                    print("   ✅ 检测到Token参数")
                else:
                    print("   ❌ 未检测到Token参数")
                    
                # 检查是否有SSO服务器
                if "sso.hnhfpc.gov.cn" in response.url:
                    print("   ✅ 检测到SSO服务器")
                else:
                    print("   ❌ 未检测到SSO服务器")
                    
            elif response.status_code == 302 or response.status_code == 301:
                print("   重定向响应")
                if 'Location' in response.headers:
                    print(f"   重定向到: {response.headers['Location']}")
                    
        except requests.exceptions.TooManyRedirects as e:
            print(f"   ❌ 重定向过多: {str(e)}")
            print(f"   当前重定向次数: {len(session.history) if hasattr(session, 'history') else '未知'}")
            
        except Exception as e:
            print(f"   ❌ 请求失败: {str(e)}")

def test_direct_sso_access():
    """直接访问SSO服务器"""
    print("\n🔍 直接访问SSO服务器")
    print("="*60)
    
    sso_url = "https://sso.hnhfpc.gov.cn:8077/Authenticate.aspx"
    
    # 创建会话
    session = requests.Session()
    session.mount("https://", CustomSSLAdapter())
    session.verify = False
    session.headers.update({
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Referer": "https://ggws.hnhfpc.gov.cn/"
    })
    
    try:
        # 不带参数访问
        print(f"1. 不带参数访问: {sso_url}")
        response = session.get(sso_url, timeout=10, allow_redirects=False)
        print(f"   状态码: {response.status_code}")
        print(f"   响应头: {dict(response.headers)}")
        
        # 带参数访问
        params = {
            "ReturnUrl": "https://ggws.hnhfpc.gov.cn/Index.aspx?goto=https%3a%2f%2fggws.hnhfpc.gov.cn%2fIndex.aspx%3fss%3dtest123"
        }
        print(f"\n2. 带参数访问: {sso_url}?ReturnUrl=...")
        response = session.get(sso_url, params=params, timeout=10, allow_redirects=False)
        print(f"   状态码: {response.status_code}")
        print(f"   响应头: {dict(response.headers)}")
        
        if response.status_code == 302 and 'Location' in response.headers:
            location = response.headers['Location']
            print(f"   重定向到: {location}")
            
            # 检查重定向目标
            if "ggws.hnhfpc.gov.cn" in location:
                print("   ✅ 重定向回公卫系统")
            elif "sso.hnhfpc.gov.cn" in location:
                print("   ⚠️  仍在SSO服务器内")
            else:
                print(f"   ❓ 重定向到未知目标: {location}")
                
    except Exception as e:
        print(f"   ❌ 请求失败: {str(e)}")

def test_alternative_approach():
    """测试替代方法"""
    print("\n🔍 测试替代登录方法")
    print("="*60)
    
    # 方法1: 直接访问FormMain.aspx并处理重定向
    print("1. 直接访问FormMain.aspx (禁用重定向)")
    
    session = requests.Session()
    session.mount("https://", CustomSSLAdapter())
    session.verify = False
    session.headers.update({
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    })
    
    try:
        # 禁用自动重定向
        response = session.get("https://ggws.hnhfpc.gov.cn/FormMain.aspx", 
                              timeout=10, allow_redirects=False)
        
        print(f"   状态码: {response.status_code}")
        
        if response.status_code == 302:
            location = response.headers.get('Location', '')
            print(f"   重定向到: {location}")
            
            # 检查是否是SSO服务器
            if "sso.hnhfpc.gov.cn" in location:
                print("   ⚠️  重定向到SSO服务器")
                
                # 提取Token
                import urllib.parse as urlparse
                parsed = urlparse.urlparse(location)
                query_params = urlparse.parse_qs(parsed.query)
                
                if 'Token' in query_params:
                    token = query_params['Token'][0]
                    print(f"   ✅ 找到Token: {token}")
                    
                    # 构建正确的登录URL
                    login_url = f"https://ggws.hnhfpc.gov.cn/Index.aspx?Token={token}"
                    print(f"   正确的登录URL: {login_url}")
                    
                    # 访问登录页面
                    response2 = session.get(login_url, timeout=10, allow_redirects=True)
                    print(f"   登录页面状态码: {response2.status_code}")
                    print(f"   登录页面URL: {response2.url}")
                    
                    # 检查是否有登录表单
                    if "login" in response2.text.lower() or "用户名" in response2.text:
                        print("   ✅ 登录页面加载成功")
                    else:
                        print("   ❌ 登录页面未加载")
                        
                else:
                    print("   ❌ 未找到Token参数")
                    
        elif response.status_code == 200:
            print("   ✅ 直接访问成功")
            # 检查是否有登录表单
            if "login" in response.text.lower():
                print("   ✅ 页面包含登录表单")
            else:
                print("   ❌ 页面不包含登录表单")
                
    except Exception as e:
        print(f"   ❌ 请求失败: {str(e)}")

if __name__ == "__main__":
    test_sso_redirect()
    test_direct_sso_access()
    test_alternative_approach()