#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
测试用户信息提取
"""
import re
import requests
import time
from ph3_api import PH3Client, PH3Crypto

def test_user_info_extraction():
    """测试用户信息提取"""
    print("🔍 测试用户信息提取")
    print("="*60)
    
    account = "431122012"
    password = "wei1147609775@"
    
    # 创建客户端
    client = PH3Client()
    
    # 执行登录
    print(f"\n1. 执行登录...")
    print(f"   账号: {account}")
    print(f"   密码: {password}")
    
    success, message = client.login("https://ggws.hnhfpc.gov.cn", account, password)
    
    print(f"   登录结果: {success}")
    print(f"   登录消息: {message}")
    
    if not success:
        print("   ❌ 登录失败，无法继续测试")
        return
    
    print(f"\n2. 检查提取的用户信息...")
    print(f"   机构代码: {client.org_code}")
    print(f"   医生姓名: {client.doctor_name}")
    print(f"   团队名称: {client.team_name}")
    print(f"   是否已登录: {client.logged_in}")
    
    # 如果机构代码为空，尝试获取机构树
    if not client.org_code:
        print(f"\n3. 尝试获取机构树...")
        orgs = client.get_org_tree("0")
        
        if orgs:
            print(f"   找到机构节点: {len(orgs)}个")
            for i, (org_id, org_name) in enumerate(orgs[:5]):
                print(f"     {i+1}. {org_id} - {org_name}")
            
            # 尝试向下钻取
            print(f"\n4. 尝试向下钻取机构树...")
            client._drill_org_tree(orgs)
            
            print(f"   钻取后机构代码: {client.org_code}")
        else:
            print("   ❌ 未找到机构节点")
    
    # 测试查询功能
    print(f"\n5. 测试查询功能...")
    try:
        # 尝试查询签约列表
        patients = client.query_signed_list(
            org_code=client.org_code or "",
            page_no=1,
            page_size=10
        )
        
        if patients:
            print(f"   查询成功，找到 {len(patients)} 个患者")
            for i, patient in enumerate(patients[:3]):
                print(f"     {i+1}. {patient.name} ({patient.id_card})")
        else:
            print("   ⚠️  查询成功但未找到患者数据")
            
    except Exception as e:
        print(f"   ❌ 查询失败: {str(e)}")
    
    # 检查会话状态
    print(f"\n6. 检查会话状态...")
    if hasattr(client, 'session') and client.session:
        # 尝试访问一个需要登录的页面
        try:
            test_response = client.session.get(client._url("/FormMain.aspx"), timeout=5)
            print(f"   会话状态测试: 状态码 {test_response.status_code}")
            
            # 检查是否被重定向到登录页面
            if "login" in test_response.url.lower():
                print("   ⚠️  会话已过期或被重定向到登录页面")
            else:
                print("   ✅ 会话状态正常")
                
        except Exception as e:
            print(f"   ❌ 会话测试失败: {str(e)}")
    
    print(f"\n7. 分析可能的提取问题...")
    print("   可能的问题:")
    print("   1. 正则表达式不匹配实际的HTML结构")
    print("   2. 用户信息存储在不同的变量名中")
    print("   3. 需要从不同的API端点获取用户信息")
    print("   4. 登录成功后需要额外的初始化步骤")
    
    # 建议的解决方案
    print(f"\n8. 建议的解决方案:")
    print("   1. 修改 _extract_user_info 方法中的正则表达式")
    print("   2. 添加更多可能的变量名模式")
    print("   3. 从登录响应中提取用户信息")
    print("   4. 调用额外的API来获取用户信息")

def analyze_html_pattern():
    """分析HTML模式"""
    print("\n" + "="*60)
    print("分析HTML模式")
    print("="*60)
    
    # 测试不同的正则表达式模式
    test_html = """
    <script>
        var en = '0123456789ABCDEF0123456789ABCDEF';
        var th = '0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF';
        var ORGCODE = '430726000001';
        var UserName = '测试医生';
        var xm = '测试医生';
        var XINGMING = '测试医生';
        var orgcode = '430726000001';
        var OrgCode = '430726000001';
    </script>
    """
    
    patterns = [
        (r"""en\s*:\s*['"]([A-Fa-f0-9]{32})['"]""", "en token"),
        (r"""th\s*:\s*['"]([A-Fa-f0-9]{64})['"]""", "th token"),
        (r"""(?:ORGCODE|orgcode|OrgCode)\s*[=:]\s*['"](\d{15,})['"]""", "机构代码"),
        (r"""(?:UserName|XINGMING|xm)\s*[=:]\s*['"]([^'"]+)['"]""", "医生姓名"),
    ]
    
    for pattern, description in patterns:
        matches = re.findall(pattern, test_html, re.IGNORECASE)
        print(f"\n{description} 模式: {pattern}")
        print(f"   匹配结果: {matches}")

if __name__ == "__main__":
    test_user_info_extraction()
    analyze_html_pattern()