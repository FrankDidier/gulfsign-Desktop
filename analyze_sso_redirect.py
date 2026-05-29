#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
分析SSO重定向问题
"""
import requests
import time
from urllib.parse import urlparse, urljoin, quote

def analyze_sso_redirect():
    """分析SSO重定向链"""
    base_url = "https://ggws.hnhfpc.gov.cn"
    
    print("🔍 分析公卫3.0系统登录流程")
    print("="*60)
    
    # 创建会话
    session = requests.Session()
    session.verify = False
    session.headers.update({
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    })
    
    # 1. 访问首页
    print("\n1. 访问首页...")
    try:
        response = session.get(base_url, timeout=10)
        print(f"   状态码: {response.status_code}")
        print(f"   最终URL: {response.url}")
        print(f"   重定向次数: {len(response.history)}")
        
        # 显示重定向链
        if response.history:
            print("   重定向链:")
            for i, resp in enumerate(response.history):
                print(f"     {i+1}. {resp.url}")
        
        # 检查页面内容
        if "login" in response.text.lower():
            print("   ✅ 检测到登录页面")
        else:
            print("   ❌ 未检测到登录页面")
            
        # 查找登录表单
        import re
        login_patterns = [
            r'action="([^"]*login[^"]*)"',
            r'href="([^"]*login[^"]*)"',
            r'window\.location\s*=\s*["\']([^"\']*login[^"\']*)["\']',
            r'window\.open\(["\']([^"\']*login[^"\']*)["\']',
        ]
        
        for pattern in login_patterns:
            matches = re.findall(pattern, response.text, re.IGNORECASE)
            if matches:
                print(f"   找到登录URL模式: {matches[:3]}")
                
    except Exception as e:
        print(f"   ❌ 访问失败: {str(e)}")
    
    # 2. 尝试访问FormMain.aspx
    print("\n2. 尝试访问FormMain.aspx...")
    try:
        formmain_url = urljoin(base_url, "/FormMain.aspx")
        response = session.get(formmain_url, timeout=10)
        print(f"   状态码: {response.status_code}")
        print(f"   最终URL: {response.url}")
        
        if response.history:
            print("   重定向链:")
            for i, resp in enumerate(response.history):
                print(f"     {i+1}. {resp.url}")
        
        # 检查是否重定向到SSO
        if "sso.hnhfpc.gov.cn" in response.url:
            print("   ⚠️  重定向到SSO认证服务器")
            
    except Exception as e:
        print(f"   ❌ 访问失败: {str(e)}")
    
    # 3. 尝试访问登录页面
    print("\n3. 尝试访问登录页面...")
    try:
        login_url = urljoin(base_url, "/login.aspx")
        response = session.get(login_url, timeout=10)
        print(f"   状态码: {response.status_code}")
        print(f"   最终URL: {response.url}")
        
        if response.history:
            print("   重定向链:")
            for i, resp in enumerate(response.history):
                print(f"     {i+1}. {resp.url}")
        
        # 检查页面标题
        title_match = re.search(r'<title>([^<]+)</title>', response.text, re.IGNORECASE)
        if title_match:
            print(f"   页面标题: {title_match.group(1)}")
            
    except Exception as e:
        print(f"   ❌ 访问失败: {str(e)}")
    
    # 4. 分析SSO认证URL
    print("\n4. 分析SSO认证URL结构...")
    sso_url = "https://sso.hnhfpc.gov.cn:8077/Authenticate.aspx"
    
    # 构建一个典型的ReturnUrl
    return_url = quote(f"{base_url}/Index.aspx?goto={quote(f'{base_url}/Index.aspx?ss=test-session-id')}", safe='')
    full_sso_url = f"{sso_url}?ReturnUrl={return_url}"
    
    print(f"   SSO服务器: sso.hnhfpc.gov.cn:8077")
    print(f"   ReturnUrl示例: {return_url[:100]}...")
    print(f"   完整SSO URL: {full_sso_url[:150]}...")
    
    # 5. 测试SSO连接
    print("\n5. 测试SSO服务器连接...")
    try:
        # 先测试不带参数的连接
        response = session.get(sso_url, timeout=10, allow_redirects=False)
        print(f"   状态码: {response.status_code}")
        
        if response.status_code in [301, 302, 303, 307, 308]:
            location = response.headers.get('Location', '')
            print(f"   重定向到: {location}")
            
            # 测试重定向目标
            if location:
                redirect_response = session.get(location, timeout=10, allow_redirects=False)
                print(f"   重定向目标状态码: {redirect_response.status_code}")
        
    except Exception as e:
        print(f"   ❌ SSO连接失败: {str(e)}")
    
    # 6. 检查实际的登录流程
    print("\n6. 检查实际登录流程...")
    print("   根据错误信息，系统尝试访问:")
    print("   https://sso.hnhfpc.gov.cn:8077/Authenticate.aspx?ReturnUrl=...")
    print("\n   可能的解决方案:")
    print("   1. 直接使用SSO认证URL进行登录")
    print("   2. 修改PH3Client的登录逻辑以支持SSO重定向")
    print("   3. 使用浏览器自动登录方式")
    print("   4. 获取正确的登录API端点")
    
    return session

def test_direct_login():
    """测试直接登录"""
    print("\n" + "="*60)
    print("测试直接登录方法")
    print("="*60)
    
    account = "431122012"
    password = "wei1147609775@"
    
    # 方法1: 尝试使用PH3Client
    try:
        from ph3_api import PH3Client
        client = PH3Client()
        success, message = client.login("https://ggws.hnhfpc.gov.cn", account, password)
        print(f"\nPH3Client登录结果:")
        print(f"   成功: {success}")
        print(f"   消息: {message}")
        
        if success:
            print(f"   机构代码: {client.org_code}")
            print(f"   医生姓名: {client.doctor_name}")
            print(f"   团队名称: {client.team_name}")
    except Exception as e:
        print(f"   ❌ PH3Client登录失败: {str(e)}")
    
    # 方法2: 尝试模拟浏览器登录
    print("\n模拟浏览器登录流程...")
    session = requests.Session()
    session.verify = False
    
    # 尝试获取登录页面
    try:
        login_page = session.get("https://ggws.hnhfpc.gov.cn/login.aspx", timeout=10)
        print(f"   登录页面状态码: {login_page.status_code}")
        print(f"   登录页面URL: {login_page.url}")
        
        # 检查是否重定向到SSO
        if "sso.hnhfpc.gov.cn" in login_page.url:
            print("   ⚠️  登录页面重定向到SSO")
            
            # 尝试访问SSO页面
            sso_response = session.get(login_page.url, timeout=10)
            print(f"   SSO页面状态码: {sso_response.status_code}")
            
            # 提取表单数据
            import re
            form_data = {}
            
            # 查找表单字段
            input_pattern = r'<input[^>]*name="([^"]*)"[^>]*value="([^"]*)"'
            inputs = re.findall(input_pattern, sso_response.text)
            
            if inputs:
                print(f"   找到表单字段: {inputs}")
                for name, value in inputs:
                    form_data[name] = value
                
                # 添加账号密码
                form_data['username'] = account
                form_data['password'] = password
                
                # 查找表单action
                action_pattern = r'<form[^>]*action="([^"]*)"'
                action_match = re.search(action_pattern, sso_response.text)
                
                if action_match:
                    form_action = action_match.group(1)
                    print(f"   表单action: {form_action}")
                    
                    # 提交表单
                    submit_url = urljoin(sso_response.url, form_action)
                    print(f"   提交URL: {submit_url}")
                    
                    # 尝试提交
                    submit_response = session.post(submit_url, data=form_data, timeout=10)
                    print(f"   提交状态码: {submit_response.status_code}")
                    print(f"   提交后URL: {submit_response.url}")
                    
    except Exception as e:
        print(f"   ❌ 模拟登录失败: {str(e)}")

if __name__ == "__main__":
    print("开始分析SSO重定向问题...")
    analyze_sso_redirect()
    test_direct_login()