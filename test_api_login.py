#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
测试API登录功能
"""
import os
import sys
import logging

# 设置日志
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# 添加模块路径
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "GulfSign_Client_Package/core_modules"))

from ph3_api import PH3Client

def test_api_login():
    """测试API登录"""
    print("=== 测试API登录功能 ===")
    
    # 创建PH3Client实例
    client = PH3Client()
    
    print(f"1. 初始状态:")
    print(f"   - base_url: {repr(client.base_url)}")
    print(f"   - logged_in: {client.logged_in}")
    
    # 从配置文件读取配置
    config_file = "gulfsign_config.json"
    if os.path.exists(config_file):
        import json
        with open(config_file, 'r', encoding='utf-8') as f:
            config = json.load(f)
        
        username = config.get('username', '')
        base_url = config.get('ggws_base_url', '')
        password = config.get('password', '')
        
        print(f"\n2. 从配置文件读取:")
        print(f"   - username: {repr(username)}")
        print(f"   - base_url: {repr(base_url)}")
        print(f"   - password: {repr(password)}")
        
        if not base_url:
            print("   ⚠ 警告: base_url 为空")
            return
        
        if not username:
            print("   ⚠ 警告: username 为空")
            return
        
        if not password:
            print("   ⚠ 警告: password 为空 (用户需要输入密码)")
            # 模拟用户输入密码
            password = input("请输入密码进行测试: ")
        
        print(f"\n3. 尝试登录:")
        print(f"   - URL: {base_url}")
        print(f"   - 账号: {username}")
        
        try:
            # 尝试登录
            success, message = client.login(base_url, username, password)
            
            print(f"   - 登录结果: {success}")
            print(f"   - 消息: {message}")
            
            if success:
                print(f"\n4. 登录成功后的状态:")
                print(f"   - base_url: {repr(client.base_url)}")
                print(f"   - logged_in: {client.logged_in}")
                print(f"   - org_code: {repr(client.org_code)}")
                print(f"   - doctor_name: {repr(client.doctor_name)}")
                print(f"   - team_name: {repr(client.team_name)}")
                
                # 测试API调用
                print(f"\n5. 测试API调用:")
                try:
                    patients, total = client.query_patients(status="0", page=1)
                    print(f"   - 查询成功")
                    print(f"   - 患者数量: {len(patients)}")
                    print(f"   - 总数: {total}")
                except Exception as e:
                    print(f"   - 查询失败: {e}")
            else:
                print(f"\n4. 登录失败原因分析:")
                print(f"   - 可能原因: {message}")
                
        except Exception as e:
            print(f"   - 登录过程异常: {e}")
            import traceback
            traceback.print_exc()
    
    else:
        print(f"配置文件不存在: {config_file}")
    
    print(f"\n=== 测试完成 ===")

if __name__ == "__main__":
    test_api_login()