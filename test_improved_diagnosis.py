#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
测试改进的诊断方法
"""
import requests
import time
import ssl
import urllib3
from urllib.parse import urlparse, urljoin, quote

def test_improved_diagnosis():
    """测试改进的诊断方法"""
    print("🔍 测试改进的诊断方法")
    print("="*60)
    
    base_url = "https://ggws.hnhfpc.gov.cn"
    
    # 创建自定义SSL适配器
    class CustomSSLAdapter(requests.adapters.HTTPAdapter):
        def init_poolmanager(self, *args, **kwargs):
            # 创建自定义SSL上下文
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            
            # 尝试多种SSL/TLS配置
            try:
                # 首先尝试TLSv1.2
                ctx.minimum_version = ssl.TLSVersion.TLSv1_2
                ctx.maximum_version = ssl.TLSVersion.TLSv1_2
            except AttributeError:
                # 回退到较旧的配置
                ctx.options |= ssl.OP_NO_SSLv2
                ctx.options |= ssl.OP_NO_SSLv3
                ctx.options |= ssl.OP_NO_TLSv1
                ctx.options |= ssl.OP_NO_TLSv1_1
            
            # 设置较宽松的加密套件
            ctx.set_ciphers('DEFAULT:@SECLEVEL=1')
            
            kwargs['ssl_context'] = ctx
            return super().init_poolmanager(*args, **kwargs)
    
    # 测试不同的连接方法
    test_methods = [
        ("标准HTTPS", {"verify": True, "timeout": 10}),
        ("跳过证书验证", {"verify": False, "timeout": 10}),
        ("自定义SSL适配器", {"verify": False, "timeout": 10, "adapter": CustomSSLAdapter()}),
        ("使用urllib3", {"verify": False, "timeout": 10, "use_urllib3": True}),
    ]
    
    for method_name, config in test_methods:
        print(f"\n测试方法: {method_name}")
        print(f"目标URL: {base_url}")
        
        try:
            if config.get("use_urllib3"):
                # 使用urllib3
                http = urllib3.PoolManager(
                    cert_reqs='CERT_NONE',
                    retries=urllib3.Retry(total=3, backoff_factor=0.5),
                    timeout=urllib3.Timeout(connect=5.0, read=10.0)
                )
                
                start_time = time.time()
                response = http.request('GET', base_url)
                response_time = int((time.time() - start_time) * 1000)
                
                print(f"   状态码: {response.status}")
                print(f"   响应时间: {response_time}ms")
                
                if response.status == 200:
                    response_text = response.data.decode('utf-8', errors='ignore')
                    print(f"   响应大小: {len(response_text)} 字符")
                    
                    # 检查内容
                    if "login" in response_text.lower():
                        print(f"   ✅ 检测到登录页面")
                    elif "sso" in response_text.lower():
                        print(f"   ⚠️  检测到SSO相关内容")
                    else:
                        print(f"   ℹ️  页面内容未知")
                
            else:
                # 使用requests
                session = requests.Session()
                
                if config.get("adapter"):
                    session.mount("https://", config["adapter"])
                
                session.verify = config.get("verify", True)
                session.headers.update({
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
                })
                
                start_time = time.time()
                response = session.get(base_url, timeout=config.get("timeout", 10))
                response_time = int((time.time() - start_time) * 1000)
                
                print(f"   状态码: {response.status_code}")
                print(f"   最终URL: {response.url}")
                print(f"   响应时间: {response_time}ms")
                
                if response.history:
                    print(f"   重定向次数: {len(response.history)}")
                    for i, resp in enumerate(response.history):
                        print(f"     {i+1}. {resp.url} → {resp.status_code}")
                
                if response.status_code == 200:
                    print(f"   响应大小: {len(response.text)} 字符")
                    
                    # 检查内容
                    if "login" in response.text.lower():
                        print(f"   ✅ 检测到登录页面")
                    elif "sso" in response.text.lower():
                        print(f"   ⚠️  检测到SSO相关内容")
                    else:
                        print(f"   ℹ️  页面内容未知")
                        
                    # 检查是否有SSO重定向
                    if "sso.hnhfpc.gov.cn" in response.url:
                        print(f"   🔄 已重定向到SSO服务器")
                        
                        # 分析SSO页面
                        sso_analysis(response.text)
                
        except requests.exceptions.SSLError as e:
            print(f"   ❌ SSL错误: {str(e)}")
        except requests.exceptions.ConnectionError as e:
            print(f"   ❌ 连接错误: {str(e)}")
        except requests.exceptions.Timeout as e:
            print(f"   ❌ 超时: {str(e)}")
        except Exception as e:
            print(f"   ❌ 其他错误: {str(e)}")

def sso_analysis(html: str):
    """分析SSO页面"""
    print(f"\n   🔍 分析SSO页面结构")
    
    import re
    
    # 查找表单
    form_patterns = [
        r'<form[^>]*action="([^"]*)"[^>]*>',
        r'<form[^>]*>.*?action="([^"]*)"',
    ]
    
    for pattern in form_patterns:
        matches = re.findall(pattern, html, re.DOTALL | re.IGNORECASE)
        if matches:
            print(f"     找到表单action: {matches[0]}")
            break
    
    # 查找输入字段
    input_pattern = r'<input[^>]*name="([^"]*)"[^>]*value="([^"]*)"[^>]*>'
    inputs = re.findall(input_pattern, html, re.IGNORECASE)
    
    if inputs:
        print(f"     找到输入字段: {len(inputs)}个")
        for name, value in inputs[:5]:  # 只显示前5个
            print(f"       {name}: {value[:50]}...")
    
    # 查找登录相关文本
    login_texts = [
        "用户名", "密码", "登录", "user", "password", "login",
        "账号", "认证", "authenticate"
    ]
    
    found_texts = []
    for text in login_texts:
        if text.lower() in html.lower():
            found_texts.append(text)
    
    if found_texts:
        print(f"     找到登录相关文本: {', '.join(found_texts)}")

def test_sso_direct_connection():
    """测试直接连接SSO服务器"""
    print("\n" + "="*60)
    print("测试直接连接SSO服务器")
    print("="*60)
    
    sso_url = "https://sso.hnhfpc.gov.cn:8077/Authenticate.aspx"
    
    # 构建ReturnUrl
    base_url = "https://ggws.hnhfpc.gov.cn"
    goto_url = quote(f"{base_url}/Index.aspx?ss=test-session-id", safe='')
    return_url = quote(f"{base_url}/Index.aspx?goto={goto_url}", safe='')
    full_sso_url = f"{sso_url}?ReturnUrl={return_url}"
    
    print(f"SSO URL: {full_sso_url[:150]}...")
    
    try:
        session = requests.Session()
        session.verify = False
        
        # 设置较宽松的User-Agent
        session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
            "Accept-Encoding": "gzip, deflate, br",
            "Connection": "keep-alive",
        })
        
        response = session.get(full_sso_url, timeout=10, allow_redirects=False)
        
        print(f"状态码: {response.status_code}")
        
        if response.status_code in [301, 302, 303, 307, 308]:
            location = response.headers.get('Location', '')
            print(f"重定向到: {location}")
            
            if location:
                # 尝试跟随重定向
                redirect_response = session.get(location, timeout=10, allow_redirects=True)
                print(f"最终状态码: {redirect_response.status_code}")
                print(f"最终URL: {redirect_response.url}")
                
                if redirect_response.status_code == 200:
                    print(f"页面标题: {extract_title(redirect_response.text)}")
        
        elif response.status_code == 200:
            print(f"页面标题: {extract_title(response.text)}")
            
            # 分析页面内容
            sso_analysis(response.text)
        
    except Exception as e:
        print(f"连接失败: {str(e)}")

def extract_title(html: str) -> str:
    """提取页面标题"""
    import re
    title_match = re.search(r'<title>([^<]+)</title>', html, re.IGNORECASE)
    if title_match:
        return title_match.group(1).strip()
    return "无标题"

def analyze_login_workflow():
    """分析登录工作流程"""
    print("\n" + "="*60)
    print("分析登录工作流程")
    print("="*60)
    
    print("当前问题分析:")
    print("1. 系统使用SSO认证: sso.hnhfpc.gov.cn:8077")
    print("2. 标准HTTPS连接失败: SSLv3握手失败")
    print("3. 需要处理重定向链")
    print("4. 需要提取正确的登录表单")
    
    print("\n建议的解决方案:")
    print("1. 使用自定义SSL适配器，支持较旧的TLS版本")
    print("2. 处理SSO重定向，提取认证令牌")
    print("3. 模拟浏览器行为，包括Cookie和Session管理")
    print("4. 实现完整的登录流程，包括表单提交和会话保持")
    
    print("\n具体步骤:")
    print("1. 访问系统首页，获取初始Cookie")
    print("2. 处理SSO重定向，获取认证页面")
    print("3. 提取表单字段和隐藏参数")
    print("4. 提交登录表单，包含账号密码")
    print("5. 处理登录后的重定向，获取主页面")
    print("6. 提取用户信息和加密令牌")
    print("7. 保持会话状态，用于后续API调用")

if __name__ == "__main__":
    test_improved_diagnosis()
    test_sso_direct_connection()
    analyze_login_workflow()