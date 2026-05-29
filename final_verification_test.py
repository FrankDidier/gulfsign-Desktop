#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
最终验证测试
验证配置是否正确保存到文件系统
"""
import os
import sys
import json
import time
import shutil

def verify_config_save():
    """验证配置保存到文件系统"""
    print("=" * 70)
    print("最终验证测试 - 配置保存到文件系统")
    print("=" * 70)
    
    config_path = "gulfsign_config.json"
    backup_path = "gulfsign_config.json.backup"
    
    # 1. 备份原始配置文件
    print("\n1. 备份原始配置文件...")
    if os.path.exists(config_path):
        shutil.copy2(config_path, backup_path)
        print(f"   ✅ 已备份到: {backup_path}")
        
        with open(config_path, 'r', encoding='utf-8') as f:
            original_config = json.load(f)
        
        print(f"   原始配置:")
        print(f"   - username: {original_config.get('username')}")
        print(f"   - password: {'已设置' if original_config.get('password') else '未设置'}")
        print(f"   - ggws_base_url: {original_config.get('ggws_base_url')}")
    else:
        print(f"   ❌ 配置文件不存在: {config_path}")
        return False
    
    # 2. 创建测试配置
    print("\n2. 创建测试配置...")
    test_config = {
        "username": "test_final_verification",
        "password": "test_password_final",
        "ggws_base_url": "https://test.final.verification.gov.cn",
        "org_code": "test_org_001",
        "doctor": "测试医生",
        "team": "测试团队",
        "delay": "1.0",
        "pop_type": "一般人群",
        "agree_start": "2026-05-29",
        "agree_end": "2027-05-28",
        "max_count": "5",
        "hc_openid": "",
        "hc_orgcode": "",
        "hc_team": "",
        "hc_doctor": "",
        "hc_start": "",
        "hc_end": "",
        "license_server_url": "http://test.server:5004",
        "max_workers": 10,
        "batch_size": 3
    }
    
    # 3. 保存测试配置
    print("\n3. 保存测试配置到文件...")
    with open(config_path, 'w', encoding='utf-8') as f:
        json.dump(test_config, f, ensure_ascii=False, indent=2)
    
    print("   ✅ 测试配置已保存")
    
    # 4. 验证文件存在且内容正确
    print("\n4. 验证文件存在且内容正确...")
    time.sleep(0.5)  # 确保文件已写入
    
    if not os.path.exists(config_path):
        print("   ❌ 配置文件不存在")
        return False
    
    with open(config_path, 'r', encoding='utf-8') as f:
        saved_config = json.load(f)
    
    print(f"   读取的配置:")
    print(f"   - username: {saved_config.get('username')}")
    print(f"   - password: {'已设置' if saved_config.get('password') else '未设置'}")
    print(f"   - ggws_base_url: {saved_config.get('ggws_base_url')}")
    
    # 验证关键字段
    verification_passed = True
    required_fields = ['username', 'password', 'ggws_base_url']
    
    for field in required_fields:
        expected = test_config.get(field)
        actual = saved_config.get(field)
        
        if field == 'password':
            # 密码应该被加密保存（以ENC:开头）
            if actual and actual.startswith('ENC:'):
                print(f"   ✅ {field}: 已正确加密保存")
            else:
                print(f"   ❌ {field}: 未正确加密保存")
                verification_passed = False
        else:
            if actual == expected:
                print(f"   ✅ {field}: 正确保存 ({actual})")
            else:
                print(f"   ❌ {field}: 保存不正确 (期望: {expected}, 实际: {actual})")
                verification_passed = False
    
    # 5. 测试ConfigManager
    print("\n5. 测试ConfigManager加载配置...")
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    
    try:
        from config_manager import ConfigManager
        
        config_manager = ConfigManager()
        loaded_config = config_manager.load()
        
        print(f"   ConfigManager加载的配置:")
        print(f"   - username: {loaded_config.get('username')}")
        print(f"   - ggws_base_url: {loaded_config.get('ggws_base_url')}")
        
        # 验证ConfigManager可以正确加载
        if (loaded_config.get('username') == test_config['username'] and
            loaded_config.get('ggws_base_url') == test_config['ggws_base_url']):
            print("   ✅ ConfigManager加载验证通过!")
        else:
            print("   ❌ ConfigManager加载验证失败!")
            verification_passed = False
            
    except Exception as e:
        print(f"   ❌ ConfigManager测试失败: {str(e)}")
        verification_passed = False
    
    # 6. 恢复原始配置
    print("\n6. 恢复原始配置...")
    if os.path.exists(backup_path):
        shutil.copy2(backup_path, config_path)
        os.remove(backup_path)
        print("   ✅ 已恢复原始配置")
        
        # 验证恢复
        with open(config_path, 'r', encoding='utf-8') as f:
            restored_config = json.load(f)
        
        if restored_config.get('username') == original_config.get('username'):
            print("   ✅ 配置恢复验证通过!")
        else:
            print(f"   ⚠️  配置恢复不一致 (原始: {original_config.get('username')}, 恢复: {restored_config.get('username')})")
    
    print("\n" + "=" * 70)
    print("最终验证测试完成!")
    print("=" * 70)
    
    return verification_passed

def check_file_permissions():
    """检查文件权限"""
    print("\n" + "=" * 70)
    print("文件权限检查")
    print("=" * 70)
    
    config_path = "gulfsign_config.json"
    
    if os.path.exists(config_path):
        # 检查文件权限
        stat_info = os.stat(config_path)
        
        print(f"配置文件: {config_path}")
        print(f"文件大小: {stat_info.st_size} 字节")
        print(f"最后修改: {time.ctime(stat_info.st_mtime)}")
        print(f"权限: {oct(stat_info.st_mode)[-3:]}")
        
        # 检查是否可写
        if os.access(config_path, os.W_OK):
            print("✅ 文件可写")
            return True
        else:
            print("❌ 文件不可写")
            return False
    else:
        print(f"❌ 文件不存在: {config_path}")
        return False

def verify_client_account():
    """验证客户账号配置"""
    print("\n" + "=" * 70)
    print("客户账号配置验证")
    print("=" * 70)
    
    config_path = "gulfsign_config.json"
    
    if not os.path.exists(config_path):
        print(f"❌ 配置文件不存在: {config_path}")
        return False
    
    with open(config_path, 'r', encoding='utf-8') as f:
        config = json.load(f)
    
    client_account = "431122012"
    client_url = "https://ggws.hnhfpc.gov.cn"
    
    print(f"验证客户配置:")
    print(f"- 期望账号: {client_account}")
    print(f"- 实际账号: {config.get('username')}")
    print(f"- 期望系统地址: {client_url}")
    print(f"- 实际系统地址: {config.get('ggws_base_url')}")
    
    account_ok = config.get('username') == client_account
    url_ok = config.get('ggws_base_url') == client_url
    password_ok = bool(config.get('password'))
    
    if account_ok:
        print("✅ 账号配置正确")
    else:
        print(f"❌ 账号配置不正确 (期望: {client_account}, 实际: {config.get('username')})")
    
    if url_ok:
        print("✅ 系统地址配置正确")
    else:
        print(f"❌ 系统地址配置不正确 (期望: {client_url}, 实际: {config.get('ggws_base_url')})")
    
    if password_ok:
        print("✅ 密码已设置")
    else:
        print("❌ 密码未设置")
    
    return account_ok and url_ok and password_ok

if __name__ == "__main__":
    print("最终验证测试套件")
    print("=" * 70)
    
    all_tests_passed = True
    
    # 运行所有测试
    print("\n运行测试 1/3: 文件权限检查")
    if check_file_permissions():
        print("✅ 文件权限检查通过")
    else:
        print("❌ 文件权限检查失败")
        all_tests_passed = False
    
    print("\n运行测试 2/3: 客户账号配置验证")
    if verify_client_account():
        print("✅ 客户账号配置验证通过")
    else:
        print("❌ 客户账号配置验证失败")
        all_tests_passed = False
    
    print("\n运行测试 3/3: 配置保存到文件系统验证")
    if verify_config_save():
        print("✅ 配置保存到文件系统验证通过")
    else:
        print("❌ 配置保存到文件系统验证失败")
        all_tests_passed = False
    
    print("\n" + "=" * 70)
    print("最终验证测试套件完成!")
    print("=" * 70)
    
    if all_tests_passed:
        print("\n🎉 所有验证测试通过!")
        print("\n应用程序配置系统验证结果:")
        print("1. ✅ 文件权限正确 - 应用程序可以写入配置文件")
        print("2. ✅ 客户账号配置正确 - 账号 431122012 和系统地址 https://ggws.hnhfpc.gov.cn 已正确配置")
        print("3. ✅ 配置保存机制正确 - 配置可以正确保存到文件系统并恢复")
        print("\n应用程序现在应该能够:")
        print("- 正确保存用户输入的账号、密码和系统地址")
        print("- 在登录成功后立即保存配置")
        print("- 在应用程序重新启动时正确恢复配置")
        print("- 避免出现 '缺失：账号' 和无效URL的问题")
    else:
        print("\n❌ 部分验证测试失败!")
        print("请检查配置保存逻辑和文件权限。")
    
    sys.exit(0 if all_tests_passed else 1)