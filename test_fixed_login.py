#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
测试修复后的登录
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from ph3_api import PH3Client
import json

def test_fixed_login():
    """测试修复后的登录"""
    print("🔍 测试修复后的PH3Client登录")
    print("="*60)
    
    account = "431122012"
    password = "wei1147609775@"
    base_url = "https://ggws.hnhfpc.gov.cn"
    
    print(f"账号: {account}")
    print(f"密码: {password}")
    print(f"系统地址: {base_url}")
    
    # 创建客户端
    client = PH3Client()
    
    # 执行登录
    print(f"\n1. 执行登录...")
    success, message = client.login(base_url, account, password)
    
    print(f"   登录结果: {success}")
    print(f"   登录消息: {message}")
    
    if not success:
        print("   ❌ 登录失败")
        return False
    
    print(f"\n2. 检查提取的用户信息...")
    print(f"   机构代码: {client.org_code}")
    print(f"   医生姓名: {client.doctor_name}")
    print(f"   团队名称: {client.team_name}")
    print(f"   是否已登录: {client.logged_in}")
    
    # 检查加密令牌
    print(f"\n3. 检查加密令牌...")
    print(f"   en token: {client.token_en}")
    print(f"   th token: {client.token_th}")
    
    if client.token_en and client.token_th:
        print("   ✅ 加密令牌提取成功")
    else:
        print("   ❌ 加密令牌提取失败")
        return False
    
    # 检查机构代码
    if client.org_code:
        print(f"   ✅ 机构代码提取成功: {client.org_code}")
    else:
        print("   ❌ 机构代码未提取")
        
        # 尝试获取机构树
        print(f"\n4. 尝试获取机构树...")
        orgs = client.get_org_tree("0")
        
        if orgs:
            print(f"   找到机构节点: {len(orgs)}个")
            for i, (org_id, org_name) in enumerate(orgs[:3]):
                print(f"     {i+1}. {org_id} - {org_name}")
            
            # 尝试向下钻取
            print(f"\n5. 尝试向下钻取机构树...")
            client._drill_org_tree(orgs)
            
            print(f"   钻取后机构代码: {client.org_code}")
        else:
            print("   ❌ 未找到机构节点")
    
    # 测试查询功能
    print(f"\n6. 测试查询功能...")
    try:
        # 尝试查询签约列表
        patients = client.query_signed_list(
            org_code=client.org_code or "",
            page_no=1,
            page_size=10
        )
        
        if patients:
            print(f"   ✅ 查询成功，找到 {len(patients)} 个患者")
            for i, patient in enumerate(patients[:3]):
                print(f"     {i+1}. {patient.name} ({patient.id_card})")
        else:
            print("   ⚠️  查询成功但未找到患者")
    except Exception as e:
        print(f"   ❌ 查询失败: {str(e)}")
    
    return True

if __name__ == "__main__":
    success = test_fixed_login()
    
    print("\n" + "="*60)
    if success:
        print("✅ 测试通过：登录功能正常工作")
    else:
        print("❌ 测试失败：登录功能有问题")