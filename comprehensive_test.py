#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
综合测试脚本 - 验证所有组件功能正常
"""

import os
import sys
import json
import time
import tempfile
import shutil
from pathlib import Path
import logging

# 添加当前目录到路径
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# 设置日志
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

def test_config_migration():
    """测试配置迁移功能"""
    print("\n" + "="*80)
    print("测试 1: 配置迁移功能")
    print("="*80)
    
    from config_manager import ConfigManager
    
    # 创建临时目录进行测试
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_dir = Path(temp_dir)
        
        # 1. 创建旧格式配置文件
        old_config = {
            "url": "https://ggws.hnhfpc.gov.cn",
            "account": "test_user_old",
            "org_code": "431122012345678",
            "doctor": "测试医生_旧",
            "team": "测试团队_旧",
            "delay": "0.8",
            "pop_type": "老年人",
            "agree_start": "2026-01-01",
            "agree_end": "2026-12-31",
            "max_count": "100",
            "hc_openid": "test_openid_old",
            "hc_orgcode": "test_orgcode_old",
            "hc_team": "健康卡团队_旧",
            "hc_doctor": "健康卡医生_旧",
            "hc_start": "2026-01-01",
            "hc_end": "2026-12-31"
        }
        
        old_config_file = temp_dir / "gulfsign_config.json"
        with open(old_config_file, 'w', encoding='utf-8') as f:
            json.dump(old_config, f, ensure_ascii=False, indent=2)
        
        print(f"✓ 创建旧格式配置文件: {old_config_file}")
        
        # 2. 使用ConfigManager加载配置
        manager = ConfigManager(config_dir=temp_dir)
        config = manager.load()
        
        # 3. 验证迁移结果
        print("\n验证迁移结果:")
        
        # 检查字段映射
        test_cases = [
            ("account -> username", "test_user_old", config.get('username')),
            ("org_code -> org_code", "431122012345678", config.get('org_code')),
            ("doctor -> doctor_name", "测试医生_旧", config.get('doctor_name')),
            ("team -> doctor_team", "测试团队_旧", config.get('doctor_team')),
            ("url -> ggws_base_url", "https://ggws.hnhfpc.gov.cn", config.get('ggws_base_url')),
            ("delay -> request_delay", 0.8, config.get('request_delay')),
            ("pop_type -> population_type", "老年人", config.get('population_type')),
            ("agree_start -> contract_date", "2026-01-01", config.get('contract_date')),
            ("agree_end -> contract_end_date", "2026-12-31", config.get('contract_end_date')),
            ("max_count -> max_contracts", "100", config.get('max_contracts')),
            ("hc_openid -> health_card_openid", "test_openid_old", config.get('health_card_openid')),
            ("hc_orgcode -> health_card_orgcode", "test_orgcode_old", config.get('health_card_orgcode')),
            ("hc_team -> health_card_team", "健康卡团队_旧", config.get('health_card_team')),
            ("hc_doctor -> health_card_doctor", "健康卡医生_旧", config.get('health_card_doctor')),
            ("hc_start -> health_card_start_date", "2026-01-01", config.get('health_card_start_date')),
            ("hc_end -> health_card_end_date", "2026-12-31", config.get('health_card_end_date'))
        ]
        
        all_passed = True
        for test_name, expected, actual in test_cases:
            if expected == actual:
                print(f"  ✓ {test_name}: {actual}")
            else:
                print(f"  ✗ {test_name}: 期望 '{expected}', 实际 '{actual}'")
                all_passed = False
        
        # 4. 测试保存功能
        print("\n测试配置保存功能:")
        config['username'] = 'updated_user'
        config['password'] = 'updated_password'
        
        if manager.save(config):
            print(f"  ✓ 配置保存成功")
            
            # 重新加载验证
            reloaded_config = manager.load()
            if reloaded_config.get('username') == 'updated_user':
                print(f"  ✓ 重新加载验证通过")
            else:
                print(f"  ✗ 重新加载验证失败")
                all_passed = False
        else:
            print(f"  ✗ 配置保存失败")
            all_passed = False
        
        # 5. 测试加密功能
        print("\n测试配置加密功能:")
        encrypted_config = manager.encryptor.encrypt_dict(config)
        
        # 检查密码字段是否被加密
        if encrypted_config.get('password', '').startswith('ENC:'):
            print(f"  ✓ 密码字段已加密")
            
            # 测试解密
            decrypted_config = manager.encryptor.decrypt_dict(encrypted_config)
            if decrypted_config.get('password') == 'updated_password':
                print(f"  ✓ 密码字段解密成功")
            else:
                print(f"  ✗ 密码字段解密失败")
                all_passed = False
        else:
            print(f"  ✗ 密码字段未加密")
            all_passed = False
        
        if all_passed:
            print(f"\n✅ 配置迁移测试全部通过!")
        else:
            print(f"\n❌ 配置迁移测试有失败!")
        
        return all_passed

def test_license_client():
    """测试许可证客户端功能"""
    print("\n" + "="*80)
    print("测试 2: 许可证客户端功能")
    print("="*80)
    
    from license_client import LicenseClient, LicenseConfig, LicenseCrypto
    
    all_passed = True
    
    # 1. 测试LicenseCrypto类
    print("测试加密功能:")
    crypto = LicenseCrypto()
    
    # 测试AES密钥生成
    aes_key, aes_iv = crypto.generate_aes_key_iv()
    if len(aes_key) == 32 and len(aes_iv) == 16:
        print(f"  ✓ AES密钥生成成功: 密钥={len(aes_key)}字节, IV={len(aes_iv)}字节")
    else:
        print(f"  ✗ AES密钥生成失败")
        all_passed = False
    
    # 测试AES加密/解密
    test_data = b"Test data for encryption"
    encrypted = crypto.aes_encrypt(test_data, aes_key, aes_iv)
    decrypted = crypto.aes_decrypt(encrypted, aes_key, aes_iv)
    
    if test_data == decrypted:
        print(f"  ✓ AES加密/解密测试通过")
    else:
        print(f"  ✗ AES加密/解密测试失败")
        all_passed = False
    
    # 测试RSA加密（短数据）
    rsa_encrypted = crypto.rsa_encrypt_short_data(aes_key)
    if len(rsa_encrypted) > 0:
        print(f"  ✓ RSA加密测试通过")
    else:
        print(f"  ✗ RSA加密测试失败")
        all_passed = False
    
    # 2. 测试LicenseClient类
    print("\n测试许可证客户端:")
    
    # 创建测试配置
    config = LicenseConfig(
        account="test_account",
        password="test_password",
        server_url="http://127.0.0.1:9999"  # 使用不存在的服务器进行测试
    )
    
    client = LicenseClient(config)
    
    # 测试构建加密请求
    try:
        payload = {
            "account": config.account,
            "password": config.password,
            "timestamp": int(time.time() * 1000)
        }
        
        encrypted_request = client.crypto.create_encrypted_request(payload)
        
        required_fields = ['encrypted_key', 'encrypted_iv', 'encrypted_data', 'timestamp']
        missing_fields = [field for field in required_fields if field not in encrypted_request]
        
        if not missing_fields:
            print(f"  ✓ 加密请求构建成功")
            
            # 验证字段
            for field in required_fields:
                if encrypted_request[field]:
                    print(f"    ✓ {field}: 已设置")
                else:
                    print(f"    ✗ {field}: 为空")
                    all_passed = False
        else:
            print(f"  ✗ 加密请求构建失败，缺失字段: {missing_fields}")
            all_passed = False
            
    except Exception as e:
        print(f"  ✗ 加密请求构建异常: {e}")
        all_passed = False
    
    # 3. 测试服务器连接（预期失败）
    print("\n测试服务器连接:")
    import requests
    
    # 测试连接不存在的服务器（预期失败）
    try:
        response = requests.head(config.server_url, timeout=2, verify=False)
        print(f"  ⚠️  服务器连接测试: 返回HTTP {response.status_code}")
    except requests.exceptions.ConnectionError:
        print(f"  ✓ 服务器连接测试: 预期连接失败（服务器不存在）")
    except Exception as e:
        print(f"  ⚠️  服务器连接测试异常: {e}")
    
    if all_passed:
        print(f"\n✅ 许可证客户端测试全部通过!")
    else:
        print(f"\n❌ 许可证客户端测试有失败!")
    
    return all_passed

def test_batch_processor():
    """测试批量处理器功能"""
    print("\n" + "="*80)
    print("测试 3: 批量处理器功能")
    print("="*80)
    
    from batch_processor import BatchProcessor, SuccessLogger
    
    all_passed = True
    
    # 创建临时目录进行测试
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_dir = Path(temp_dir)
        
        # 1. 测试SuccessLogger类
        print("测试成功日志记录器:")
        
        logger = SuccessLogger(
            log_dir=str(temp_dir / "logs"),
            success_log_dir=str(temp_dir / "logs" / "成功")
        )
        
        # 测试日志记录
        test_account = "test_account_123"
        test_result = {
            "id_card": "430102199001011234",
            "name": "测试用户",
            "age": 35,
            "gender": "男",
            "contract_code": "TEST202605240001",
            "status": "5",
            "agreement": "2026-05-24 至 2027-05-23",
            "doctor": "测试医生"
        }
        
        try:
            log_file = logger.log_success(
                account=test_account,
                result_data=test_result,
                additional_info={"source": "test_batch_processor"}
            )
            
            if Path(log_file).exists():
                print(f"  ✓ 成功日志创建: {log_file}")
                
                # 验证文件内容
                import pandas as pd
                df = pd.read_excel(log_file)
                
                if len(df) > 0:
                    print(f"  ✓ 日志文件包含 {len(df)} 条记录")
                    
                    # 检查关键字段
                    if 'account' in df.columns and df.iloc[0]['account'] == test_account:
                        print(f"  ✓ 账号字段正确: {df.iloc[0]['account']}")
                    else:
                        print(f"  ✗ 账号字段不正确")
                        all_passed = False
                else:
                    print(f"  ✗ 日志文件为空")
                    all_passed = False
            else:
                print(f"  ✗ 日志文件不存在")
                all_passed = False
                
        except Exception as e:
            print(f"  ✗ 日志记录失败: {e}")
            all_passed = False
        
        # 2. 测试BatchProcessor类
        print("\n测试批量处理器:")
        
        processor = BatchProcessor(
            max_workers=2,  # 使用较小的线程数进行测试
            batch_size=1,
            log_dir=str(temp_dir / "logs"),
            success_log_dir=str(temp_dir / "logs" / "成功")
        )
        
        # 创建模拟处理函数
        def mock_process_func(task_data):
            """模拟处理函数"""
            # 模拟处理延迟
            time.sleep(0.1)
            
            # 返回模拟结果
            return {
                "success": True,
                "result": f"Processed: {task_data.get('id', 'unknown')}",
                "timestamp": time.time()
            }
        
        # 添加测试任务
        test_tasks = [
            {"id": "task_1", "name": "任务1", "data": "测试数据1"},
            {"id": "task_2", "name": "任务2", "data": "测试数据2"},
            {"id": "task_3", "name": "任务3", "data": "测试数据3"}
        ]
        
        task_ids = processor.add_tasks(test_tasks)
        
        if len(task_ids) == 3:
            print(f"  ✓ 成功添加 {len(task_ids)} 个任务")
        else:
            print(f"  ✗ 任务添加失败，期望3个，实际{len(task_ids)}个")
            all_passed = False
        
        # 测试处理任务
        print("\n测试批量处理:")
        
        try:
            results = processor.process_tasks(
                process_func=mock_process_func,
                progress_callback=lambda p: print(f"    进度: {p.completion_percentage:.1f}%")
            )
            
            if len(results) == 3:
                print(f"  ✓ 成功处理 {len(results)} 个任务")
                
                # 检查结果
                success_count = sum(1 for r in results if r.success)
                if success_count == 3:
                    print(f"  ✓ 所有任务处理成功")
                else:
                    print(f"  ✗ 任务处理失败: {success_count}/3 成功")
                    all_passed = False
            else:
                print(f"  ✗ 任务处理数量不正确，期望3个，实际{len(results)}个")
                all_passed = False
                
        except Exception as e:
            print(f"  ✗ 批量处理失败: {e}")
            all_passed = False
        
        # 3. 测试进度跟踪
        print("\n测试进度跟踪:")
        
        with processor.progress_lock:
            progress = processor.progress
            
            print(f"  总任务数: {progress.total_tasks}")
            print(f"  已完成任务: {progress.completed_tasks}")
            print(f"  成功任务: {progress.successful_tasks}")
            print(f"  失败任务: {progress.failed_tasks}")
            print(f"  完成百分比: {progress.completion_percentage:.1f}%")
            print(f"  成功率: {progress.success_rate:.1f}%")
            print(f"  耗时: {progress.elapsed_time:.2f}秒")
            
            if progress.completed_tasks == progress.total_tasks:
                print(f"  ✓ 进度跟踪正确")
            else:
                print(f"  ✗ 进度跟踪不正确")
                all_passed = False
    
    if all_passed:
        print(f"\n✅ 批量处理器测试全部通过!")
    else:
        print(f"\n❌ 批量处理器测试有失败!")
    
    return all_passed

def test_excel_logging():
    """测试Excel日志功能"""
    print("\n" + "="*80)
    print("测试 4: Excel日志功能")
    print("="*80)
    
    from batch_processor import SuccessLogger
    
    all_passed = True
    
    # 创建临时目录进行测试
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_dir = Path(temp_dir)
        
        # 创建日志记录器
        logger = SuccessLogger(
            log_dir=str(temp_dir / "logs"),
            success_log_dir=str(temp_dir / "logs" / "成功")
        )
        
        print("测试单个日志记录:")
        
        # 测试数据
        test_account = "doctor_li"
        test_result = {
            "id_card": "430102198001011234",
            "name": "李医生",
            "age": 44,
            "gender": "男",
            "contract_code": "CONTRACT20260524001",
            "status": "5",
            "agreement": "2026-05-24 至 2027-05-23",
            "doctor": "主任医师",
            "sign_time": "2026-05-24 10:30:00"
        }
        
        # 记录日志
        try:
            log_file = logger.log_success(
                account=test_account,
                result_data=test_result
            )
            
            if Path(log_file).exists():
                print(f"  ✓ 单个日志创建成功: {log_file}")
                
                # 验证文件内容
                import pandas as pd
                df = pd.read_excel(log_file)
                
                expected_columns = ['account', 'timestamp', 'success_time', 
                                   'id_card', 'name', 'age', 'gender', 
                                   'contract_code', 'status', 'agreement', 
                                   'doctor', 'sign_time']
                
                # 检查列
                missing_columns = [col for col in expected_columns if col not in df.columns]
                if not missing_columns:
                    print(f"  ✓ 日志文件包含所有预期列")
                else:
                    print(f"  ✗ 日志文件缺失列: {missing_columns}")
                    all_passed = False
                
                # 检查数据
                if len(df) == 1:
                    print(f"  ✓ 日志文件包含1条记录")
                    
                    # 验证账号
                    if df.iloc[0]['account'] == test_account:
                        print(f"  ✓ 账号正确: {df.iloc[0]['account']}")
                    else:
                        print(f"  ✗ 账号不正确: {df.iloc[0]['account']}")
                        all_passed = False
                else:
                    print(f"  ✗ 日志文件记录数不正确: {len(df)}")
                    all_passed = False
                    
            else:
                print(f"  ✗ 日志文件不存在")
                all_passed = False
                
        except Exception as e:
            print(f"  ✗ 单个日志记录失败: {e}")
            all_passed = False
        
        print("\n测试批量日志记录:")
        
        # 测试批量记录
        accounts = ["patient_wang", "patient_li", "patient_zhang"]
        
        for i, account in enumerate(accounts):
            result_data = {
                "id_card": f"430102199{i}011234",
                "name": f"患者{i+1}",
                "age": 30 + i,
                "gender": "男" if i % 2 == 0 else "女",
                "contract_code": f"CONTRACT20260524{i+1:03d}",
                "status": "5",
                "agreement": f"2026-05-24 至 2027-05-23",
                "doctor": "家庭医生",
                "visit_date": f"2026-05-2{i+1}"
            }
            
            try:
                log_file = logger.log_success(
                    account=account,
                    result_data=result_data,
                    additional_info={"batch_id": "test_batch_001"}
                )
                
                if Path(log_file).exists():
                    print(f"  ✓ 日志 {i+1}/{len(accounts)} 创建成功: {account}")
                else:
                    print(f"  ✗ 日志 {i+1}/{len(accounts)} 创建失败: {account}")
                    all_passed = False
                    
            except Exception as e:
                print(f"  ✗ 日志 {i+1}/{len(accounts)} 记录异常: {e}")
                all_passed = False
        
        print("\n测试日志读取功能:")
        
        # 测试读取日志
        try:
            logs = logger.get_success_logs(account=test_account)
            
            if logs:
                print(f"  ✓ 成功读取 {len(logs)} 条日志记录")
                
                # 验证读取的数据
                first_log = logs[0]
                if first_log.get('account') == test_account:
                    print(f"  ✓ 读取的账号正确: {first_log.get('account')}")
                else:
                    print(f"  ✗ 读取的账号不正确")
                    all_passed = False
            else:
                print(f"  ✗ 未读取到日志记录")
                all_passed = False
                
        except Exception as e:
            print(f"  ✗ 日志读取失败: {e}")
            all_passed = False
        
        print("\n测试日志文件结构:")
        
        # 检查目录结构
        log_dir = temp_dir / "logs"
        success_dir = log_dir / "成功"
        date_dir = success_dir / time.strftime("%Y%m%d")
        
        if date_dir.exists():
            print(f"  ✓ 日期目录创建正确: {date_dir}")
            
            # 检查文件数量
            excel_files = list(date_dir.glob("*.xlsx"))
            print(f"  ✓ 创建了 {len(excel_files)} 个Excel日志文件")
        else:
            print(f"  ✗ 日期目录不存在")
            all_passed = False
    
    if all_passed:
        print(f"\n✅ Excel日志功能测试全部通过!")
    else:
        print(f"\n❌ Excel日志功能测试有失败!")
    
    return all_passed

def test_application_integration():
    """测试应用程序集成 (使用临时目录，避免覆盖真实配置)"""
    print("\n" + "="*80)
    print("测试 5: 应用程序集成测试")
    print("="*80)
    
    all_passed = True
    
    print("测试应用程序启动:")
    
    # 测试应用程序导入
    try:
        # 尝试导入所有关键模块
        from config_manager import ConfigManager
        from license_client import LicenseClient, LicenseConfig
        from batch_processor import BatchProcessor, SuccessLogger
        from app import GulfSignApp, load_config, save_config
        
        print(f"  ✓ 所有关键模块导入成功")
        
        with tempfile.TemporaryDirectory() as integration_tmp:
            integration_tmp = Path(integration_tmp)

            print(f"\n测试配置函数 (临时目录: {integration_tmp}):")

            test_config = {
                "username": "test_integration",
                "password": "test_password_integration",
                "doctor_name": "集成测试医生",
                "doctor_team": "集成测试团队",
                "contract_date": "2026-06-01",
                "contract_years": "2",
                "del_doctor": True,
                "del_resident": True,
                "del_valid": False,
                "license_account": "license_test",
                "license_password": "license_password_test"
            }

            try:
                isolated_mgr = ConfigManager(config_dir=integration_tmp)
                isolated_mgr.save(test_config)
                print(f"  ✓ 配置保存函数正常")
            except Exception as e:
                print(f"  ✗ 配置保存函数异常: {e}")
                all_passed = False

            try:
                loaded_config = isolated_mgr.load()
                if loaded_config:
                    print(f"  ✓ 配置加载函数正常")
                    if loaded_config.get('username') == test_config['username']:
                        print(f"  ✓ 配置数据正确")
                    else:
                        print(f"  ✗ 配置数据不正确")
                        all_passed = False
                else:
                    print(f"  ✗ 配置加载返回空")
                    all_passed = False
            except Exception as e:
                print(f"  ✗ 配置加载函数异常: {e}")
                all_passed = False

            print(f"\n测试组件初始化:")

            try:
                config_manager = ConfigManager(config_dir=integration_tmp)
                print(f"  ✓ ConfigManager初始化成功")
            except Exception as e:
                print(f"  ✗ ConfigManager初始化失败: {e}")
                all_passed = False

            try:
                license_config = LicenseConfig(
                    account="test_integration_account",
                    password="test_integration_password"
                )
                license_client = LicenseClient(license_config)
                print(f"  ✓ LicenseClient初始化成功")
            except Exception as e:
                print(f"  ✗ LicenseClient初始化失败: {e}")
                all_passed = False

            try:
                batch_processor = BatchProcessor(
                    max_workers=1, batch_size=1,
                    log_dir=str(integration_tmp / "logs"),
                    success_log_dir=str(integration_tmp / "logs" / "成功"),
                )
                print(f"  ✓ BatchProcessor初始化成功")
            except Exception as e:
                print(f"  ✗ BatchProcessor初始化失败: {e}")
                all_passed = False

            try:
                success_logger = SuccessLogger(
                    log_dir=str(integration_tmp / "logs"),
                    success_log_dir=str(integration_tmp / "logs" / "成功"),
                )
                print(f"  ✓ SuccessLogger初始化成功")
            except Exception as e:
                print(f"  ✗ SuccessLogger初始化失败: {e}")
                all_passed = False

            print(f"\n测试组件交互:")

            try:
                test_config2 = {
                    "username": "interaction_test",
                    "license_account": "interaction_test",
                    "license_password": "interaction_password"
                }
                isolated_mgr.save(test_config2, validate=False)
                loaded_config = isolated_mgr.load()
                license_config = LicenseConfig(
                    account=loaded_config.get('license_account', ''),
                    password=loaded_config.get('license_password', '')
                )
                license_client = LicenseClient(license_config)
                print(f"  ✓ 配置管理器与许可证客户端交互成功")
            except Exception as e:
                print(f"  ✗ 配置管理器与许可证客户端交互失败: {e}")
                all_passed = False
        
            try:
                processor = BatchProcessor(
                    max_workers=1, batch_size=1,
                    log_dir=str(integration_tmp / "logs"),
                    success_log_dir=str(integration_tmp / "logs" / "成功"),
                )
                processor.add_task({"test": "integration"})

                def mock_process(data):
                    return {"success": True, "result": "processed"}

                results = processor.process_tasks(mock_process)

                if results and results[0].success:
                    print(f"  ✓ 批量处理器与任务处理交互成功")
                else:
                    print(f"  ✗ 批量处理器与任务处理交互失败")
                    all_passed = False

            except Exception as e:
                print(f"  ✗ 批量处理器与任务处理交互失败: {e}")
                all_passed = False
        
    except ImportError as e:
        print(f"  ✗ 模块导入失败: {e}")
        all_passed = False
    except Exception as e:
        print(f"  ✗ 应用程序集成测试异常: {e}")
        all_passed = False
    
    if all_passed:
        print(f"\n✅ 应用程序集成测试全部通过!")
    else:
        print(f"\n❌ 应用程序集成测试有失败!")
    
    return all_passed

def run_all_tests():
    """运行所有测试"""
    print("="*80)
    print("开始综合测试 - 验证所有组件功能正常")
    print("="*80)
    
    test_results = []
    
    # 运行所有测试
    test_results.append(("配置迁移", test_config_migration()))
    test_results.append(("许可证客户端", test_license_client()))
    test_results.append(("批量处理器", test_batch_processor()))
    test_results.append(("Excel日志", test_excel_logging()))
    test_results.append(("应用程序集成", test_application_integration()))
    
    # 打印测试总结
    print("\n" + "="*80)
    print("测试总结")
    print("="*80)
    
    all_passed = True
    for test_name, passed in test_results:
        status = "✅ 通过" if passed else "❌ 失败"
        print(f"{test_name}: {status}")
        if not passed:
            all_passed = False
    
    print("\n" + "="*80)
    if all_passed:
        print("🎉 所有测试通过! 应用程序功能完整，无静默失败。")
    else:
        print("⚠️  部分测试失败，需要进一步检查。")
    print("="*80)
    
    return all_passed

if __name__ == "__main__":
    run_all_tests()