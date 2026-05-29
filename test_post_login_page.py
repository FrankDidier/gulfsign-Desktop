#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
测试登录后的页面
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import requests
import ssl
from requests.adapters import HTTPAdapter
from urllib3.util.ssl_ import create_urllib3_context
import re

class CustomSSLAdapter(HTTPAdapter):
    """自定义SSL适配器，支持较旧的TLS版本"""
    def init_poolmanager(self, *args, **kwargs):
        ctx = create_urllib3_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.set_ciphers('DEFAULT:@SECLEVEL=1')
        kwargs['ssl_context'] = ctx
        return super().init_poolmanager(*args, **kwargs)

def test_post_login_page():
    """测试登录后的页面"""
    print("🔍 测试登录后的页面内容")
    print("="*60)
    
    account = "431122012"
    password = "wei1147609775@"
    base_url = "https://ggws.hnhfpc.gov.cn"
    
    # 创建会话
    session = requests.Session()
    session.mount("https://", CustomSSLAdapter())
    session.verify = False
    session.headers.update({
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    })
    
    try:
        # 1. 访问FormMain.aspx（触发SSO重定向）
        print(f"1. 访问 {base_url}/FormMain.aspx")
        response = session.get(f"{base_url}/FormMain.aspx", timeout=10, allow_redirects=True)
        
        print(f"   状态码: {response.status_code}")
        print(f"   最终URL: {response.url}")
        
        # 检查是否有Token
        if "Token" in response.url:
            print("   ✅ 检测到Token参数")
            import urllib.parse as urlparse
            parsed = urlparse.urlparse(response.url)
            query_params = urlparse.parse_qs(parsed.query)
            if 'Token' in query_params:
                token = query_params['Token'][0]
                print(f"   Token值: {token}")
        
        # 2. 提取en/th tokens
        print(f"\n2. 提取加密令牌...")
        
        en_patterns = [
            r"""en\s*:\s*['"]([A-Fa-f0-9]{32})['"]""",
            r"""en\s*=\s*['"]([A-Fa-f0-9]{32})['"]""",
            r"""var\s+en\s*=\s*['"]([A-Fa-f0-9]{32})['"]""",
            r"""crptosEn\s*:\s*['"]([A-Fa-f0-9]{32})['"]""",
            r"""crptosEn\s*=\s*['"]([A-Fa-f0-9]{32})['"]""",
        ]
        
        en_token = None
        for pattern in en_patterns:
            en_m = re.search(pattern, response.text)
            if en_m:
                en_token = en_m.group(1)
                print(f"   ✅ 检测到en token: {en_token}")
                break
        
        th_patterns = [
            r"""th\s*:\s*['"]([A-Fa-f0-9]{64})['"]""",
            r"""th\s*=\s*['"]([A-Fa-f0-9]{64})['"]""",
            r"""var\s+th\s*=\s*['"]([A-Fa-f0-9]{64})['"]""",
            r"""crptosTH\s*:\s*['"]([A-Fa-f0-9]{64})['"]""",
            r"""crptosTH\s*=\s*['"]([A-Fa-f0-9]{64})['"]""",
        ]
        
        th_token = None
        for pattern in th_patterns:
            th_m = re.search(pattern, response.text)
            if th_m:
                th_token = th_m.group(1)
                print(f"   ✅ 检测到th token: {th_token}")
                break
        
        if not en_token or not th_token:
            print("   ❌ 未检测到加密令牌")
            return False
        
        # 3. 执行登录
        print(f"\n3. 执行登录...")
        
        import time as _t
        ts = str(int(_t.time() * 1000))
        
        # 导入PH3Crypto
        from ph3_api import PH3Crypto
        
        enc_pwd = PH3Crypto.crptosEn(password + "|" + ts, en_token)
        sign_pwd = PH3Crypto.crptosTH(enc_pwd + th_token)
        
        login_url = f"{base_url}/ashx/LoginHandler.ashx"
        params = {
            "action": "LOGIN",
            "YONGHUMING": account,
            "MIMA": enc_pwd,
            "SIGN": sign_pwd,
            "t": ts,
            "YANZHENGMA": "",
            "TYPE": "1",
        }
        
        login_resp = session.post(
            login_url,
            params=params,
            headers={
                "Referer": response.url,
                "X-Requested-With": "XMLHttpRequest",
            },
            timeout=10,
        )
        
        print(f"   登录响应状态码: {login_resp.status_code}")
        print(f"   登录响应内容: {login_resp.text[:200]}...")
        
        # 解析登录响应
        import json as _json
        try:
            obj = _json.loads(login_resp.text)
            op = obj.get("opType")
            msg = obj.get("msg", "")
            
            print(f"   登录结果: opType={op}, msg={msg}")
            
            if op != 0:
                print("   ❌ 登录失败")
                return False
            
            print("   ✅ 登录成功")
            
        except Exception as e:
            print(f"   ❌ 解析登录响应失败: {str(e)}")
            return False
        
        # 4. 访问FormMain.aspx获取用户信息
        print(f"\n4. 访问FormMain.aspx获取用户信息...")
        main_resp = session.get(f"{base_url}/FormMain.aspx", timeout=10)
        
        print(f"   状态码: {main_resp.status_code}")
        print(f"   最终URL: {main_resp.url}")
        
        # 保存响应内容
        with open("post_login_content.html", "w", encoding="utf-8") as f:
            f.write(main_resp.text)
        print("   响应内容已保存到 post_login_content.html")
        
        # 检查是否有用户信息
        print(f"\n5. 检查用户信息...")
        
        # 尝试多种机构代码模式
        org_patterns = [
            r"""(?:ORGCODE|orgcode|OrgCode)\s*[=:]\s*['"](\d{15,})['"]""",
            r"""orgCode\s*:\s*['"](\d{15,})['"]""",
            r"""orgCode\s*=\s*['"](\d{15,})['"]""",
            r"""orgcode\s*:\s*['"](\d{15,})['"]""",
            r"""orgcode\s*=\s*['"](\d{15,})['"]""",
            r"""ORGCODE\s*:\s*['"](\d{15,})['"]""",
            r"""ORGCODE\s*=\s*['"](\d{15,})['"]""",
            r"""var\s+orgCode\s*=\s*['"](\d{15,})['"]""",
            r"""var\s+ORGCODE\s*=\s*['"](\d{15,})['"]""",
        ]
        
        org_code = None
        for pattern in org_patterns:
            org_m = re.search(pattern, main_resp.text, re.IGNORECASE)
            if org_m:
                org_code = org_m.group(1)
                print(f"   ✅ 检测到机构代码: {org_code}")
                break
        
        if not org_code:
            print("   ❌ 未检测到机构代码")
            
            # 显示部分HTML内容查找模式
            print("   尝试查找其他模式...")
            
            # 查找所有可能的变量赋值
            var_patterns = [
                r"""(\w+)\s*[=:]\s*['"]([^'"]+)['"]""",
                r"""var\s+(\w+)\s*=\s*['"]([^'"]+)['"]""",
            ]
            
            found_vars = []
            for pattern in var_patterns:
                matches = re.findall(pattern, main_resp.text[:5000])
                for var_name, var_value in matches:
                    if var_name.lower() in ['orgcode', 'org', 'jgdm', 'jgcode']:
                        print(f"   发现机构相关变量: {var_name} = {var_value}")
                        found_vars.append((var_name, var_value))
            
            if not found_vars:
                print("   未找到机构相关变量")
        
        # 检查医生姓名
        name_patterns = [
            r"""(?:UserName|XINGMING|xm)\s*[=:]\s*['"]([^'"]+)['"]""",
            r"""userName\s*:\s*['"]([^'"]+)['"]""",
            r"""userName\s*=\s*['"]([^'"]+)['"]""",
            r"""XINGMING\s*:\s*['"]([^'"]+)['"]""",
            r"""XINGMING\s*=\s*['"]([^'"]+)['"]""",
            r"""xm\s*:\s*['"]([^'"]+)['"]""",
            r"""xm\s*=\s*['"]([^'"]+)['"]""",
            r"""var\s+userName\s*=\s*['"]([^'"]+)['"]""",
            r"""var\s+XINGMING\s*=\s*['"]([^'"]+)['"]""",
        ]
        
        doctor_name = None
        for pattern in name_patterns:
            name_m = re.search(pattern, main_resp.text, re.IGNORECASE)
            if name_m:
                doctor_name = name_m.group(1).strip()
                print(f"   ✅ 检测到医生姓名: {doctor_name}")
                break
        
        if not doctor_name:
            print("   ❌ 未检测到医生姓名")
        
        # 显示部分响应内容
        print(f"\n6. 响应内容预览 (前1000字符):")
        print("-"*60)
        print(main_resp.text[:1000])
        print("-"*60)
        
        return True
        
    except Exception as e:
        print(f"❌ 测试失败: {str(e)}")
        return False

if __name__ == "__main__":
    success = test_post_login_page()
    
    print("\n" + "="*60)
    if success:
        print("✅ 测试完成")
    else:
        print("❌ 测试失败")