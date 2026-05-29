#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
调试配置加载问题
"""
import os
import sys
import json
import logging

# 设置日志
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# 添加模块路径
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "GulfSign_Client_Package/core_modules"))

from config_manager import ConfigManager

def debug_config_load():
    """调试配置加载"""
    print("=== 调试配置加载 ===")
    
    # 检查配置文件是否存在
    config_file = "gulfsign_config.json"
    if os.path.exists(config_file):
        print(f"1. 配置文件存在: {config_file}")
        
        # 读取原始文件内容
        with open(config_file, 'r', encoding='utf-8') as f:
            raw_content = json.load(f)
            
        print(f"2. 原始文件内容:")
        print(f"   - username: {repr(raw_content.get('username'))}")
        print(f"   - ggws_base_url: {repr(raw_content.get('ggws_base_url'))}")
        print(f"   - password: {repr(raw_content.get('password'))}")
        print(f"   - auth: {raw_content.get('auth')}")
        
        # 检查是否有字段看起来像加密的
        print(f"\n3. 检查加密字段:")
        for key, value in raw_content.items():
            if isinstance(value, str) and value:
                # 检查是否以 ENC: 开头
                if value.startswith('ENC:'):
                    print(f"   - {key}: 以 ENC: 开头 (加密)")
                else:
                    # 检查是否是有效的 base64
                    try:
                        import base64
                        # 移除可能的填充
                        value_to_test = value.replace('=', '')
                        if len(value_to_test) % 4 == 1:
                            print(f"   - {key}: 可能是无效的base64 (长度{len(value)}字符)")
                    except:
                        pass
    else:
        print(f"配置文件不存在: {config_file}")
        return
    
    print(f"\n4. 测试 ConfigManager 加载:")
    try:
        config_manager = ConfigManager()
        loaded_config = config_manager.load()
        
        print(f"   - 加载成功")
        print(f"   - username: {repr(loaded_config.get('username'))}")
        print(f"   - ggws_base_url: {repr(loaded_config.get('ggws_base_url'))}")
        print(f"   - password: {repr(loaded_config.get('password'))}")
        
    except Exception as e:
        print(f"   - 加载失败: {e}")
        import traceback
        traceback.print_exc()
    
    print(f"\n5. 测试直接解密:")
    try:
        from config_manager import ConfigEncryptor
        encryptor = ConfigEncryptor()
        
        # 测试解密空字符串
        empty_result = encryptor.decrypt('')
        print(f"   - 解密空字符串: {repr(empty_result)}")
        
        # 测试解密普通字符串
        plain_result = encryptor.decrypt('test')
        print(f"   - 解密 'test': {repr(plain_result)}")
        
        # 测试解密加密字符串
        encrypted = encryptor.encrypt('secret')
        print(f"   - 加密 'secret': {repr(encrypted)}")
        decrypted = encryptor.decrypt(encrypted)
        print(f"   - 解密加密字符串: {repr(decrypted)}")
        
    except Exception as e:
        print(f"   - 解密测试失败: {e}")
        import traceback
        traceback.print_exc()
    
    print(f"\n=== 调试完成 ===")

if __name__ == "__main__":
    debug_config_load()