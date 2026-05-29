#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
测试实际响应内容
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import requests
import ssl
from requests.adapters import HTTPAdapter
from urllib3.util.ssl_ import create_urllib3_context

class CustomSSLAdapter(HTTPAdapter):
    """自定义SSL适配器，支持较旧的TLS版本"""
    def init_poolmanager(self, *args, **kwargs):
        ctx = create_urllib3_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.set_ciphers('DEFAULT:@SECLEVEL=1')
        kwargs['ssl_context'] = ctx
        return super().init_poolmanager(*args, **kwargs)

def test_actual_response():
    """测试实际响应"""
    print("🔍 测试实际响应内容")
    print("="*60)
    
    base_url = "https://ggws.hnhfpc.gov.cn"
    
    # 创建会话
    session = requests.Session()
    session.mount("https://", CustomSSLAdapter())
    session.verify = False
    session.headers.update({
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    })
    
    try:
        # 尝试访问FormMain.aspx
        print(f"1. 访问 {base_url}/FormMain.aspx")
        response = session.get(f"{base_url}/FormMain.aspx", timeout=10, allow_redirects=True)
        
        print(f"   状态码: {response.status_code}")
        print(f"   最终URL: {response.url}")
        print(f"   重定向次数: {len(response.history)}")
        
        if response.history:
            print("   重定向链:")
            for i, resp in enumerate(response.history):
                print(f"     {i+1}. {resp.url}")
        
        # 检查响应内容
        print(f"\n2. 响应内容分析")
        print(f"   内容长度: {len(response.text)} 字符")
        
        # 保存响应内容到文件
        with open("response_content.html", "w", encoding="utf-8") as f:
            f.write(response.text)
        print("   响应内容已保存到 response_content.html")
        
        # 检查是否有Token
        if "Token" in response.url:
            print("   ✅ 检测到Token参数")
            # 解析Token
            import urllib.parse as urlparse
            parsed = urlparse.urlparse(response.url)
            query_params = urlparse.parse_qs(parsed.query)
            if 'Token' in query_params:
                token = query_params['Token'][0]
                print(f"   Token值: {token}")
        
        # 检查是否有公卫系统特征
        if "ggws" in response.text.lower() or "公卫" in response.text:
            print("   ✅ 检测到公卫系统特征")
        else:
            print("   ⚠️  未检测到公卫系统特征")
        
        # 检查是否有加密Token
        import re
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
        
        if not en_token:
            print("   ❌ 未检测到en token")
        
        # 检查机构代码
        org_patterns = [
            r"""(?:ORGCODE|orgcode|OrgCode)\s*[=:]\s*['"](\d{15,})['"]""",
            r"""orgCode\s*:\s*['"](\d{15,})['"]""",
            r"""orgCode\s*=\s*['"](\d{15,})['"]""",
        ]
        
        org_code = None
        for pattern in org_patterns:
            org_m = re.search(pattern, response.text, re.IGNORECASE)
            if org_m:
                org_code = org_m.group(1)
                print(f"   ✅ 检测到机构代码: {org_code}")
                break
        
        if not org_code:
            print("   ❌ 未检测到机构代码")
            
            # 尝试其他模式
            other_patterns = [
                r"""orgCode\s*['"]?\s*:\s*['"]?(\d{15,})""",
                r"""orgcode\s*['"]?\s*:\s*['"]?(\d{15,})""",
                r"""ORGCODE\s*['"]?\s*:\s*['"]?(\d{15,})""",
            ]
            
            for pattern in other_patterns:
                org_m = re.search(pattern, response.text)
                if org_m:
                    org_code = org_m.group(1)
                    print(f"   ✅ 检测到机构代码(其他模式): {org_code}")
                    break
        
        # 显示部分响应内容
        print(f"\n3. 响应内容预览 (前1000字符):")
        print("-"*60)
        print(response.text[:1000])
        print("-"*60)
        
    except Exception as e:
        print(f"❌ 访问失败: {str(e)}")

if __name__ == "__main__":
    test_actual_response()