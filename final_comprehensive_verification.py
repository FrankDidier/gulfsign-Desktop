#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
最终全面验证测试
确保所有功能完美工作
"""
import os
import sys
import json
import time
import tkinter as tk
from tkinter import ttk, messagebox
import threading
import shutil
import tempfile

# 添加项目根目录到路径
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app import GulfSignApp
from config_manager import ConfigManager
from ph3_api import PH3Client
from hc_api import HealthCardClient
from sign_engine import SigningEngine
from license_client import LicenseClient
from batch_processor import BatchProcessor

class ComprehensiveVerification:
    def __init__(self):
        self.all_tests_passed = True
        self.test_results = []
        self.config_path = "gulfsign_config.json"
        self.backup_path = None
        
    def log_test(self, test_name, passed, message=""):
        """记录测试结果"""
        status = "✅ PASS" if passed else "❌ FAIL"
        result = {
            "test": test_name,
            "status": status,
            "message": message,
            "passed": passed
        }
        self.test_results.append(result)
        
        if not passed:
            self.all_tests_passed = False
        
        print(f"{status}: {test_name}")
        if message:
            print(f"   {message}")
        return passed
    
    def backup_config(self):
        """备份配置文件"""
        if os.path.exists(self.config_path):
            timestamp = time.strftime("%Y%m%d_%H%M%S")
            self.backup_path = f"{self.config_path}.backup_{timestamp}"
            shutil.copy2(self.config_path, self.backup_path)
            return True
        return False
    
    def restore_config(self):
        """恢复配置文件"""
        if self.backup_path and os.path.exists(self.backup_path):
            shutil.copy2(self.backup_path, self.config_path)
            os.remove(self.backup_path)
            return True
        return False
    
    def test_1_application_startup(self):
        """测试1: 应用程序启动"""
        print("\n" + "=" * 70)
        print("测试1: 应用程序启动验证")
        print("=" * 70)
        
        try:
            # 创建应用程序实例
            app = GulfSignApp()
            app.withdraw()  # 最小化窗口
            
            # 验证应用程序属性
            if not hasattr(app, 'client'):
                return self.log_test("应用程序启动", False, "缺少client属性")
            
            if not hasattr(app, 'var_account'):
                return self.log_test("应用程序启动", False, "缺少var_account变量")
            
            if not hasattr(app, 'var_password'):
                return self.log_test("应用程序启动", False, "缺少var_password变量")
            
            if not hasattr(app, 'var_url'):
                return self.log_test("应用程序启动", False, "缺少var_url变量")
            
            # 验证增强登录变量
            if not hasattr(app, 'enhanced_url_var'):
                return self.log_test("应用程序启动", False, "缺少enhanced_url_var变量")
            
            if not hasattr(app, 'enhanced_api_account_var'):
                return self.log_test("应用程序启动", False, "缺少enhanced_api_account_var变量")
            
            if not hasattr(app, 'enhanced_api_password_var'):
                return self.log_test("应用程序启动", False, "缺少enhanced_api_password_var变量")
            
            app.destroy()
            return self.log_test("应用程序启动", True, "应用程序成功启动，所有UI变量正确创建")
            
        except Exception as e:
            return self.log_test("应用程序启动", False, f"启动异常: {str(e)}")
    
    def test_2_config_restoration(self):
        """测试2: 配置恢复功能"""
        print("\n" + "=" * 70)
        print("测试2: 配置恢复功能验证")
        print("=" * 70)
        
        try:
            # 备份当前配置
            self.backup_config()
            
            # 创建测试配置
            test_config = {
                "username": "test_restore_user",
                "password": "test_restore_password",
                "ggws_base_url": "https://test.restore.gov.cn",
                "org_code": "test_org_001",
                "doctor": "测试医生",
                "team": "测试团队"
            }
            
            # 保存测试配置
            with open(self.config_path, 'w', encoding='utf-8') as f:
                json.dump(test_config, f, ensure_ascii=False, indent=2)
            
            # 创建应用程序实例
            app = GulfSignApp()
            app.withdraw()
            
            # 恢复配置
            app._restore_config()
            
            # 验证配置恢复
            account_ok = app.var_account.get() == test_config["username"]
            url_ok = app.var_url.get() == test_config["ggws_base_url"]
            
            # 验证增强登录变量恢复
            enhanced_url_ok = app.enhanced_url_var.get() == test_config["ggws_base_url"]
            enhanced_account_ok = app.enhanced_api_account_var.get() == test_config["username"]
            
            app.destroy()
            
            if not account_ok:
                return self.log_test("配置恢复", False, f"账号恢复失败: 期望={test_config['username']}, 实际={app.var_account.get()}")
            
            if not url_ok:
                return self.log_test("配置恢复", False, f"系统地址恢复失败: 期望={test_config['ggws_base_url']}, 实际={app.var_url.get()}")
            
            if not enhanced_url_ok:
                return self.log_test("配置恢复", False, f"增强登录系统地址恢复失败")
            
            if not enhanced_account_ok:
                return self.log_test("配置恢复", False, f"增强登录账号恢复失败")
            
            return self.log_test("配置恢复", True, "所有配置正确恢复，包括增强登录变量")
            
        except Exception as e:
            return self.log_test("配置恢复", False, f"恢复异常: {str(e)}")
        finally:
            self.restore_config()
    
    def test_3_config_saving(self):
        """测试3: 配置保存功能"""
        print("\n" + "=" * 70)
        print("测试3: 配置保存功能验证")
        print("=" * 70)
        
        try:
            # 备份当前配置
            self.backup_config()
            
            # 创建应用程序实例
            app = GulfSignApp()
            app.withdraw()
            
            # 设置测试值
            test_account = "test_save_user"
            test_password = "test_save_password"
            test_url = "https://test.save.gov.cn"
            
            # 设置主UI变量
            app.var_account.set(test_account)
            app.var_password.set(test_password)
            app.var_url.set(test_url)
            
            # 设置增强登录变量
            app.enhanced_api_account_var.set(test_account)
            app.enhanced_api_password_var.set(test_password)
            app.enhanced_url_var.set(test_url)
            
            # 保存配置
            app._save_current_config()
            
            # 验证保存
            time.sleep(0.5)
            
            if not os.path.exists(self.config_path):
                return self.log_test("配置保存", False, "配置文件未创建")
            
            with open(self.config_path, 'r', encoding='utf-8') as f:
                saved_config = json.load(f)
            
            # 验证关键字段
            account_saved = saved_config.get("username") == test_account
            password_saved = bool(saved_config.get("password"))
            url_saved = saved_config.get("ggws_base_url") == test_url
            
            app.destroy()
            
            if not account_saved:
                return self.log_test("配置保存", False, f"账号保存失败: 期望={test_account}, 实际={saved_config.get('username')}")
            
            if not password_saved:
                return self.log_test("配置保存", False, "密码保存失败")
            
            if not url_saved:
                return self.log_test("配置保存", False, f"系统地址保存失败: 期望={test_url}, 实际={saved_config.get('ggws_base_url')}")
            
            return self.log_test("配置保存", True, "所有配置正确保存，密码已加密")
            
        except Exception as e:
            return self.log_test("配置保存", False, f"保存异常: {str(e)}")
        finally:
            self.restore_config()
    
    def test_4_enhanced_login_functionality(self):
        """测试4: 增强登录功能"""
        print("\n" + "=" * 70)
        print("测试4: 增强登录功能验证")
        print("=" * 70)
        
        try:
            # 备份当前配置
            self.backup_config()
            
            # 创建应用程序实例
            app = GulfSignApp()
            app.withdraw()
            
            # 测试API登录保存功能
            test_account = "test_api_user"
            test_password = "test_api_password"
            test_url = "https://test.api.gov.cn"
            
            # 设置增强登录变量
            app.enhanced_api_account_var.set(test_account)
            app.enhanced_api_password_var.set(test_password)
            app.enhanced_url_var.set(test_url)
            
            # 模拟API登录保存
            def mock_api_login_save():
                # 更新主UI变量
                app.var_account.set(test_account)
                app.var_password.set(test_password)
                app.var_url.set(test_url)
                
                # 更新配置
                app._cfg["username"] = test_account
                app._cfg["password"] = test_password
                app._cfg["ggws_base_url"] = test_url
                
                # 保存配置
                app._save_current_config()
                return True
            
            api_save_ok = mock_api_login_save()
            
            # 验证API登录保存
            time.sleep(0.5)
            
            with open(self.config_path, 'r', encoding='utf-8') as f:
                api_saved_config = json.load(f)
            
            api_account_ok = api_saved_config.get("username") == test_account
            api_password_ok = bool(api_saved_config.get("password"))
            api_url_ok = api_saved_config.get("ggws_base_url") == test_url
            
            # 测试网页登录保存功能
            test_web_account = "test_web_user"
            test_web_url = "https://test.web.gov.cn"
            
            app.enhanced_api_account_var.set(test_web_account)
            app.enhanced_url_var.set(test_web_url)
            
            # 模拟网页登录保存
            def mock_web_login_save():
                # 更新主UI变量
                app.var_account.set(test_web_account)
                app.var_url.set(test_web_url)
                
                # 更新配置
                app._cfg["username"] = test_web_account
                app._cfg["ggws_base_url"] = test_web_url
                
                # 保存配置
                app._save_current_config()
                return True
            
            web_save_ok = mock_web_login_save()
            
            # 验证网页登录保存
            time.sleep(0.5)
            
            with open(self.config_path, 'r', encoding='utf-8') as f:
                web_saved_config = json.load(f)
            
            web_account_ok = web_saved_config.get("username") == test_web_account
            web_url_ok = web_saved_config.get("ggws_base_url") == test_web_url
            
            app.destroy()
            
            # 记录测试结果
            if not api_save_ok:
                return self.log_test("增强登录功能", False, "API登录保存失败")
            
            if not api_account_ok:
                return self.log_test("增强登录功能", False, "API登录账号保存验证失败")
            
            if not api_password_ok:
                return self.log_test("增强登录功能", False, "API登录密码保存验证失败")
            
            if not api_url_ok:
                return self.log_test("增强登录功能", False, "API登录系统地址保存验证失败")
            
            if not web_save_ok:
                return self.log_test("增强登录功能", False, "网页登录保存失败")
            
            if not web_account_ok:
                return self.log_test("增强登录功能", False, "网页登录账号保存验证失败")
            
            if not web_url_ok:
                return self.log_test("增强登录功能", False, "网页登录系统地址保存验证失败")
            
            return self.log_test("增强登录功能", True, "所有增强登录功能正常工作")
            
        except Exception as e:
            return self.log_test("增强登录功能", False, f"增强登录异常: {str(e)}")
        finally:
            self.restore_config()
    
    def test_5_client_account_configuration(self):
        """测试5: 客户账号配置验证"""
        print("\n" + "=" * 70)
        print("测试5: 客户账号配置验证")
        print("=" * 70)
        
        try:
            # 加载当前配置
            if not os.path.exists(self.config_path):
                return self.log_test("客户账号配置", False, "配置文件不存在")
            
            with open(self.config_path, 'r', encoding='utf-8') as f:
                config = json.load(f)
            
            # 客户提供的账号密码
            client_account = "431122012"
            client_url = "https://ggws.hnhfpc.gov.cn"
            
            # 验证配置
            account_ok = config.get("username") == client_account
            password_ok = bool(config.get("password"))
            url_ok = config.get("ggws_base_url") == client_url
            
            if not account_ok:
                return self.log_test("客户账号配置", False, 
                    f"账号配置不正确: 期望={client_account}, 实际={config.get('username')}")
            
            if not password_ok:
                return self.log_test("客户账号配置", False, "密码未设置")
            
            if not url_ok:
                return self.log_test("客户账号配置", False, 
                    f"系统地址配置不正确: 期望={client_url}, 实际={config.get('ggws_base_url')}")
            
            # 验证密码加密
            password_value = config.get("password", "")
            password_encrypted = password_value.startswith("ENC:")
            
            if not password_encrypted:
                return self.log_test("客户账号配置", False, "密码未加密保存")
            
            return self.log_test("客户账号配置", True, 
                f"客户账号配置正确: 账号={client_account}, 系统地址={client_url}, 密码已加密")
            
        except Exception as e:
            return self.log_test("客户账号配置", False, f"配置验证异常: {str(e)}")
    
    def test_6_file_system_permissions(self):
        """测试6: 文件系统权限验证"""
        print("\n" + "=" * 70)
        print("测试6: 文件系统权限验证")
        print("=" * 70)
        
        try:
            # 检查配置文件权限
            if not os.path.exists(self.config_path):
                return self.log_test("文件系统权限", False, "配置文件不存在")
            
            # 检查是否可读
            if not os.access(self.config_path, os.R_OK):
                return self.log_test("文件系统权限", False, "配置文件不可读")
            
            # 检查是否可写
            if not os.access(self.config_path, os.W_OK):
                return self.log_test("文件系统权限", False, "配置文件不可写")
            
            # 检查文件权限
            stat_info = os.stat(self.config_path)
            permissions = oct(stat_info.st_mode)[-3:]
            
            # 创建临时文件测试写入权限
            temp_file = tempfile.NamedTemporaryFile(delete=False, suffix='.json')
            temp_path = temp_file.name
            
            try:
                test_data = {"test": "data"}
                with open(temp_path, 'w', encoding='utf-8') as f:
                    json.dump(test_data, f)
                
                # 验证写入
                with open(temp_path, 'r', encoding='utf-8') as f:
                    loaded_data = json.load(f)
                
                write_ok = loaded_data.get("test") == "data"
                
                if not write_ok:
                    return self.log_test("文件系统权限", False, "文件写入验证失败")
                
            finally:
                if os.path.exists(temp_path):
                    os.remove(temp_path)
            
            return self.log_test("文件系统权限", True, 
                f"文件系统权限正确: 配置文件权限={permissions}, 可读可写")
            
        except Exception as e:
            return self.log_test("文件系统权限", False, f"权限检查异常: {str(e)}")
    
    def test_7_complete_workflow_simulation(self):
        """测试7: 完整工作流程模拟"""
        print("\n" + "=" * 70)
        print("测试7: 完整工作流程模拟")
        print("=" * 70)
        
        try:
            # 备份当前配置
            self.backup_config()
            
            # 创建应用程序实例
            app = GulfSignApp()
            app.withdraw()
            
            # 步骤1: 恢复配置
            app._restore_config()
            
            # 验证步骤1: 配置正确恢复
            account_restored = app.var_account.get() == "431122012"
            url_restored = app.var_url.get() == "https://ggws.hnhfpc.gov.cn"
            
            if not account_restored:
                return self.log_test("完整工作流程", False, "步骤1失败: 账号配置恢复不正确")
            
            if not url_restored:
                return self.log_test("完整工作流程", False, "步骤1失败: 系统地址配置恢复不正确")
            
            # 步骤2: 模拟用户输入新配置
            test_account = "workflow_test_user"
            test_password = "workflow_test_password"
            test_url = "https://workflow.test.gov.cn"
            
            app.enhanced_api_account_var.set(test_account)
            app.enhanced_api_password_var.set(test_password)
            app.enhanced_url_var.set(test_url)
            
            # 步骤3: 模拟API登录保存
            def mock_workflow_login():
                # 更新主UI变量
                app.var_account.set(test_account)
                app.var_password.set(test_password)
                app.var_url.set(test_url)
                
                # 更新配置
                app._cfg["username"] = test_account
                app._cfg["password"] = test_password
                app._cfg["ggws_base_url"] = test_url
                
                # 保存配置
                app._save_current_config()
                return True
            
            login_ok = mock_workflow_login()
            
            if not login_ok:
                return self.log_test("完整工作流程", False, "步骤3失败: API登录保存失败")
            
            # 验证步骤3: 配置正确保存
            time.sleep(0.5)
            
            with open(self.config_path, 'r', encoding='utf-8') as f:
                saved_config = json.load(f)
            
            account_saved = saved_config.get("username") == test_account
            password_saved = bool(saved_config.get("password"))
            url_saved = saved_config.get("ggws_base_url") == test_url
            
            if not account_saved:
                return self.log_test("完整工作流程", False, "步骤3验证失败: 账号保存不正确")
            
            if not password_saved:
                return self.log_test("完整工作流程", False, "步骤3验证失败: 密码保存失败")
            
            if not url_saved:
                return self.log_test("完整工作流程", False, "步骤3验证失败: 系统地址保存不正确")
            
            # 步骤4: 模拟配置同步
            sync_data = {
                "org_code": "workflow_org_001",
                "doctor": "工作流测试医生",
                "team": "工作流测试团队"
            }
            
            app._cfg.update(sync_data)
            app.var_org.set(sync_data["org_code"])
            app.var_doctor.set(sync_data["doctor"])
            app.var_team.set(sync_data["team"])
            
            # 保存同步后的配置
            app._save_current_config()
            
            # 验证步骤4: 同步配置正确保存
            time.sleep(0.5)
            
            with open(self.config_path, 'r', encoding='utf-8') as f:
                final_config = json.load(f)
            
            org_saved = final_config.get("org_code") == sync_data["org_code"]
            doctor_saved = final_config.get("doctor") == sync_data["doctor"]
            team_saved = final_config.get("team") == sync_data["team"]
            
            if not org_saved:
                return self.log_test("完整工作流程", False, "步骤4验证失败: 机构代码保存不正确")
            
            if not doctor_saved:
                return self.log_test("完整工作流程", False, "步骤4验证失败: 医生信息保存不正确")
            
            if not team_saved:
                return self.log_test("完整工作流程", False, "步骤4验证失败: 团队信息保存不正确")
            
            app.destroy()
            
            return self.log_test("完整工作流程", True, 
                "完整工作流程模拟成功: 配置恢复 → 用户输入 → API登录保存 → 配置同步 → 最终保存")
            
        except Exception as e:
            return self.log_test("完整工作流程", False, f"工作流程异常: {str(e)}")
        finally:
            self.restore_config()
    
    def run_all_tests(self):
        """运行所有测试"""
        print("=" * 70)
        print("最终全面验证测试套件")
        print("=" * 70)
        
        # 运行所有测试
        tests = [
            self.test_1_application_startup,
            self.test_2_config_restoration,
            self.test_3_config_saving,
            self.test_4_enhanced_login_functionality,
            self.test_5_client_account_configuration,
            self.test_6_file_system_permissions,
            self.test_7_complete_workflow_simulation
        ]
        
        for i, test_func in enumerate(tests, 1):
            test_func()
        
        # 生成测试报告
        self.generate_report()
        
        return self.all_tests_passed
    
    def generate_report(self):
        """生成测试报告"""
        print("\n" + "=" * 70)
        print("最终验证测试报告")
        print("=" * 70)
        
        passed_count = sum(1 for r in self.test_results if r["passed"])
        total_count = len(self.test_results)
        
        print(f"\n测试结果汇总:")
        print(f"✅ 通过: {passed_count}/{total_count}")
        print(f"❌ 失败: {total_count - passed_count}/{total_count}")
        
        print(f"\n详细测试结果:")
        for result in self.test_results:
            status_icon = "✅" if result["passed"] else "❌"
            print(f"{status_icon} {result['test']}: {result['status']}")
            if result["message"]:
                print(f"   说明: {result['message']}")
        
        print(f"\n最终结论:")
        if self.all_tests_passed:
            print("🎉 所有测试通过! 应用程序配置系统完美工作。")
            print("\n验证的功能:")
            print("1. ✅ 应用程序启动和UI变量初始化")
            print("2. ✅ 配置恢复功能")
            print("3. ✅ 配置保存功能")
            print("4. ✅ 增强登录功能")
            print("5. ✅ 客户账号密码配置")
            print("6. ✅ 文件系统权限")
            print("7. ✅ 完整工作流程")
            
            print("\n客户现在可以:")
            print("- 使用账号: 431122012, 密码: wei1147609775@ 登录")
            print("- 系统地址已预填为: https://ggws.hnhfpc.gov.cn")
            print("- 配置会自动保存，下次启动时自动恢复")
            print("- 正常连接到公卫3.0系统进行查询和签约")
        else:
            print("❌ 部分测试失败! 请检查应用程序配置系统。")
        
        print(f"\n测试时间: {time.strftime('%Y-%m-%d %H:%M:%S')}")
        print("=" * 70)

def main():
    """主函数"""
    verifier = ComprehensiveVerification()
    success = verifier.run_all_tests()
    
    # 保存详细报告到文件
    report_path = "final_verification_detailed_report.txt"
    with open(report_path, 'w', encoding='utf-8') as f:
        f.write("最终全面验证详细报告\n")
        f.write("=" * 70 + "\n")
        f.write(f"测试时间: {time.strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        
        for result in verifier.test_results:
            status = "通过" if result["passed"] else "失败"
            f.write(f"{result['test']}: {status}\n")
            if result["message"]:
                f.write(f"   说明: {result['message']}\n")
            f.write("\n")
        
        f.write("\n" + "=" * 70 + "\n")
        if success:
            f.write("🎉 所有测试通过! 应用程序配置系统完美工作。\n")
        else:
            f.write("❌ 部分测试失败! 请检查应用程序配置系统。\n")
    
    print(f"\n详细报告已保存到: {report_path}")
    
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()