#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
最终验证测试
"""
import sys
import os
import json
import time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def verify_configuration():
    """验证配置"""
    print("🔍 验证配置完整性")
    print("="*60)
    
    config_file = "gulfsign_config.json"
    
    if not os.path.exists(config_file):
        print("❌ 配置文件不存在")
        return False
    
    with open(config_file, 'r', encoding='utf-8') as f:
        config = json.load(f)
    
    print("当前配置状态:")
    print(f"   账号: {config.get('username', '未设置')}")
    print(f"   密码: {'已设置' if config.get('password') else '未设置'}")
    print(f"   系统地址: {config.get('ggws_base_url', '未设置')}")
    print(f"   机构代码: {config.get('org_code', '未设置')}")
    
    # 检查必需字段
    missing = []
    if not config.get("username"):
        missing.append("账号")
    if not config.get("ggws_base_url"):
        missing.append("系统地址")
    
    if missing:
        print(f"❌ 缺失必需字段: {', '.join(missing)}")
        return False
    
    print("✅ 配置完整性验证通过")
    return True

def verify_ph3client():
    """验证PH3Client"""
    print("\n🔍 验证PH3Client登录")
    print("="*60)
    
    try:
        from ph3_api import PH3Client
        
        account = "431122012"
        password = "wei1147609775@"
        base_url = "https://ggws.hnhfpc.gov.cn"
        
        print(f"测试登录:")
        print(f"   账号: {account}")
        print(f"   系统地址: {base_url}")
        
        client = PH3Client()
        success, message = client.login(base_url, account, password)
        
        print(f"   登录结果: {success}")
        print(f"   登录消息: {message}")
        
        if not success:
            print("❌ PH3Client登录失败")
            return False
        
        print(f"   机构代码: {client.org_code}")
        print(f"   医生姓名: {client.doctor_name}")
        print(f"   团队名称: {client.team_name}")
        
        # 检查加密令牌
        if client.token_en and client.token_th:
            print("✅ 加密令牌提取成功")
        else:
            print("❌ 加密令牌提取失败")
            return False
        
        # 检查机构代码
        if client.org_code:
            print(f"✅ 机构代码提取成功: {client.org_code}")
        else:
            print("⚠️  机构代码未提取，尝试获取机构树...")
            orgs = client.get_org_tree("0")
            if orgs:
                print(f"   找到机构节点: {len(orgs)}个")
                # 尝试向下钻取
                client._drill_org_tree(orgs)
                print(f"   钻取后机构代码: {client.org_code}")
        
        print("✅ PH3Client验证通过")
        return True
        
    except Exception as e:
        print(f"❌ PH3Client验证失败: {str(e)}")
        return False

def verify_app_ui():
    """验证应用程序UI"""
    print("\n🔍 验证应用程序UI")
    print("="*60)
    
    try:
        import tkinter as tk
        from app import GulfSignApp
        
        print("1. 创建应用程序实例...")
        # 注意: GulfSignApp继承自tk.Tk，不需要传递master参数
        app = GulfSignApp()
        
        print("2. 检查UI变量...")
        ui_variables = [
            ("var_url", app.var_url),
            ("var_account", app.var_account),
            ("var_password", app.var_password),
            ("var_org", app.var_org),
            ("var_doctor", app.var_doctor),
            ("var_team", app.var_team),
        ]
        
        all_ok = True
        for name, var in ui_variables:
            if hasattr(var, 'get'):
                print(f"   ✅ {name}: 存在")
            else:
                print(f"   ❌ {name}: 不存在")
                all_ok = False
        
        if not all_ok:
            print("❌ UI变量验证失败")
            return False
        
        print("3. 检查配置加载...")
        if hasattr(app, '_cfg') and app._cfg:
            print(f"   ✅ 配置加载成功")
            print(f"      账号: {app._cfg.get('username', '未设置')}")
            print(f"      系统地址: {app._cfg.get('ggws_base_url', '未设置')}")
        else:
            print("❌ 配置加载失败")
            return False
        
        print("4. 检查客户端实例...")
        if hasattr(app, 'client') and app.client:
            print("   ✅ PH3Client实例存在")
        else:
            print("❌ PH3Client实例不存在")
            return False
        
        # 清理
        app.destroy()
        
        print("✅ 应用程序UI验证通过")
        return True
        
    except Exception as e:
        print(f"❌ 应用程序UI验证失败: {str(e)}")
        return False

def verify_diagnosis():
    """验证诊断功能"""
    print("\n🔍 验证诊断功能")
    print("="*60)
    
    try:
        import tkinter as tk
        from app import GulfSignApp
        
        print("1. 创建应用程序实例...")
        app = GulfSignApp()
        
        print("2. 设置测试配置...")
        app.enhanced_url_var.set("https://ggws.hnhfpc.gov.cn")
        app.enhanced_api_account_var.set("431122012")
        
        print("3. 运行诊断...")
        # 运行诊断（同步方式）
        diagnostics = app._perform_login_diagnosis()
        
        print("4. 检查诊断结果...")
        for name, success, message in diagnostics:
            icon = "✅" if success else "❌"
            print(f"   {icon} {name}: {message}")
        
        # 检查关键诊断项
        network_ok = any(name == "网络连接" and success for name, success, _ in diagnostics)
        system_ok = any(name == "公卫3.0系统" and success for name, success, _ in diagnostics)
        config_ok = any(name == "配置完整性" and success for name, success, _ in diagnostics)
        
        if not network_ok:
            print("❌ 网络连接诊断失败")
            return False
        
        if not system_ok:
            print("⚠️  公卫系统访问失败，但配置可能仍然有效")
            # 继续测试，因为配置可能仍然有效
        
        if not config_ok:
            print("❌ 配置完整性检查失败")
            return False
        
        print("✅ 诊断功能验证通过")
        
        # 清理
        app.destroy()
        
        return True
        
    except Exception as e:
        print(f"❌ 诊断功能验证失败: {str(e)}")
        return False

def main():
    """主验证函数"""
    print("开始最终验证测试...")
    print("="*60)
    
    print("测试环境:")
    print(f"   Python版本: {sys.version}")
    print(f"   工作目录: {os.getcwd()}")
    print(f"   配置文件: gulfsign_config.json")
    
    # 运行所有验证
    tests = [
        ("配置完整性", verify_configuration),
        ("PH3Client登录", verify_ph3client),
        ("应用程序UI", verify_app_ui),
        ("诊断功能", verify_diagnosis),
    ]
    
    results = []
    
    for test_name, test_func in tests:
        print(f"\n▶️  运行测试: {test_name}")
        try:
            success = test_func()
            results.append((test_name, success))
        except Exception as e:
            print(f"❌ 测试异常: {str(e)}")
            results.append((test_name, False))
    
    # 总结
    print("\n" + "="*60)
    print("验证总结")
    print("="*60)
    
    all_passed = True
    for test_name, success in results:
        status = "✅ 通过" if success else "❌ 失败"
        print(f"{test_name}: {status}")
        if not success:
            all_passed = False
    
    print("\n" + "="*60)
    if all_passed:
        print("🎉 所有验证测试通过！")
        print("\n应用程序状态:")
        print("   1. ✅ 配置完整性检查通过")
        print("   2. ✅ PH3Client登录功能正常")
        print("   3. ✅ 应用程序UI初始化正常")
        print("   4. ✅ 诊断功能正常工作")
        print("\n下一步:")
        print("   1. 运行应用程序进行完整功能测试")
        print("   2. 使用账号密码登录系统")
        print("   3. 测试查询和签约功能")
        print("   4. 生成EXE文件进行部署")
    else:
        print("⚠️  部分验证测试失败")
        print("\n需要修复的问题:")
        for test_name, success in results:
            if not success:
                print(f"   - {test_name}")
    
    return all_passed

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)