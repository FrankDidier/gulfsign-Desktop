#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
综合测试修复
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from ph3_api import PH3Client
import json

def test_ph3client_login():
    """测试PH3Client登录"""
    print("🔍 测试PH3Client登录和用户信息提取")
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
        print("   ❌ 登录失败，无法继续测试")
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
    
    # 检查机构代码
    if client.org_code:
        print(f"   ✅ 机构代码提取成功: {client.org_code}")
        
        # 尝试获取机构树
        print(f"\n4. 尝试获取机构树...")
        orgs = client.get_org_tree("0")
        
        if orgs:
            print(f"   找到机构节点: {len(orgs)}个")
            for i, (org_id, org_name) in enumerate(orgs[:3]):
                print(f"     {i+1}. {org_id} - {org_name}")
        else:
            print("   ⚠️  未找到机构节点")
    else:
        print("   ❌ 机构代码未提取")
        
        # 尝试手动获取机构树
        print(f"\n4. 尝试手动获取机构树...")
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
            print(f"   查询成功，找到 {len(patients)} 个患者")
            for i, patient in enumerate(patients[:3]):
                print(f"     {i+1}. {patient.name} ({patient.id_card})")
            return True
        else:
            print("   ⚠️  查询成功但未找到患者数据")
            return True
            
    except Exception as e:
        print(f"   ❌ 查询失败: {str(e)}")
        return False

def test_config_save():
    """测试配置保存"""
    print("\n" + "="*60)
    print("测试配置保存")
    print("="*60)
    
    config_file = "gulfsign_config.json"
    
    # 读取当前配置
    if os.path.exists(config_file):
        with open(config_file, 'r', encoding='utf-8') as f:
            config = json.load(f)
        
        print("当前配置:")
        print(json.dumps(config, indent=2, ensure_ascii=False))
        
        # 检查关键字段
        missing_fields = []
        if not config.get("username"):
            missing_fields.append("username")
        if not config.get("ggws_base_url"):
            missing_fields.append("ggws_base_url")
        if not config.get("password"):
            print("   ⚠️  密码字段为空")
        
        if missing_fields:
            print(f"   ❌ 缺失字段: {', '.join(missing_fields)}")
            return False
        else:
            print("   ✅ 配置完整")
            return True
    else:
        print("   ❌ 配置文件不存在")
        return False

def test_app_startup():
    """测试应用程序启动"""
    print("\n" + "="*60)
    print("测试应用程序启动")
    print("="*60)
    
    try:
        # 尝试导入并创建应用实例
        from app import GulfSignApp
        import tkinter as tk
        
        print("1. 导入模块成功")
        
        # 创建根窗口
        root = tk.Tk()
        root.withdraw()  # 隐藏主窗口
        
        print("2. 创建Tkinter根窗口成功")
        
        # 创建应用实例
        app = GulfSignApp(root)
        
        print("3. 创建GulfSignApp实例成功")
        
        # 检查UI变量
        print("4. 检查UI变量...")
        variables = [
            ("var_url", app.var_url),
            ("var_account", app.var_account),
            ("var_password", app.var_password),
            ("var_org", app.var_org),
            ("var_doctor", app.var_doctor),
            ("var_team", app.var_team),
        ]
        
        all_vars_ok = True
        for name, var in variables:
            if hasattr(var, 'get'):
                print(f"   ✅ {name}: 存在")
            else:
                print(f"   ❌ {name}: 不存在")
                all_vars_ok = False
        
        if all_vars_ok:
            print("   ✅ 所有UI变量初始化成功")
        else:
            print("   ❌ 部分UI变量初始化失败")
        
        # 检查配置
        print("5. 检查配置...")
        if hasattr(app, '_cfg') and app._cfg:
            print(f"   ✅ 配置加载成功，账号: {app._cfg.get('username', '未设置')}")
        else:
            print("   ❌ 配置加载失败")
        
        # 清理
        root.destroy()
        
        return all_vars_ok
        
    except Exception as e:
        print(f"   ❌ 应用程序启动测试失败: {str(e)}")
        return False

def main():
    """主测试函数"""
    print("开始综合测试修复...")
    
    # 测试1: PH3Client登录
    login_success = test_ph3client_login()
    
    # 测试2: 配置保存
    config_success = test_config_save()
    
    # 测试3: 应用程序启动
    app_success = test_app_startup()
    
    # 总结
    print("\n" + "="*60)
    print("测试总结")
    print("="*60)
    
    print(f"1. PH3Client登录测试: {'✅ 通过' if login_success else '❌ 失败'}")
    print(f"2. 配置保存测试: {'✅ 通过' if config_success else '❌ 失败'}")
    print(f"3. 应用程序启动测试: {'✅ 通过' if app_success else '❌ 失败'}")
    
    overall_success = login_success and config_success and app_success
    
    print(f"\n总体结果: {'✅ 所有测试通过' if overall_success else '❌ 部分测试失败'}")
    
    if not overall_success:
        print("\n需要进一步修复的问题:")
        if not login_success:
            print("   - PH3Client登录或用户信息提取失败")
        if not config_success:
            print("   - 配置保存或完整性检查失败")
        if not app_success:
            print("   - 应用程序启动或UI变量初始化失败")
    
    return overall_success

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)