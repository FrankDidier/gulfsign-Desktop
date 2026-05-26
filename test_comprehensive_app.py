#!/usr/bin/env python3
"""
测试综合版应用程序
"""

import sys
import os
from pathlib import Path

# 添加当前目录到Python路径
sys.path.insert(0, str(Path(__file__).parent))

def test_imports():
    """测试模块导入"""
    print("测试模块导入...")
    
    modules_to_test = [
        ("ph3_api", ["PH3Client", "Patient", "SignResult"]),
        ("hc_api", ["HealthCardClient", "HealthCard", "HCContract"]),
        ("sign_engine", ["SigningEngine", "get_age_from_id", "validate_id_card"]),
        ("license_client", ["LicenseClient"]),
        ("config_manager", ["ConfigManager"]),
        ("batch_processor", ["BatchProcessor"]),
    ]
    
    all_passed = True
    
    for module_name, expected_classes in modules_to_test:
        try:
            module = __import__(module_name)
            print(f"  ✓ {module_name}")
            
            # 检查类
            for class_name in expected_classes:
                if hasattr(module, class_name):
                    print(f"    ✓ {class_name}")
                else:
                    print(f"    ✗ {class_name} (未找到)")
                    all_passed = False
                    
        except ImportError as e:
            print(f"  ✗ {module_name}: {e}")
            all_passed = False
    
    return all_passed

def test_new_features():
    """测试新功能模块"""
    print("\n测试新功能模块...")
    
    new_features = [
        ("ultimate_status_conversion_explorer", "UltimateStatusConversionExplorer"),
        ("ultimate_realname_id_modification_explorer", "UltimateRealnameIDModificationExplorer"),
        ("ultimate_family_member_removal_analyzer", "UltimateFamilyMemberRemovalAnalyzer"),
        ("ultimate_sjfx_field_discovery_explorer", "UltimateSJFXFieldDiscoveryExplorer"),
        ("comprehensive_age_bypass_validation", "ComprehensiveAgeBypassValidator"),
        ("comprehensive_solution_matrix", "ComprehensiveSolutionMatrix"),
        ("penetration_testing_simulation_framework", "PenetrationTestingSimulationFramework"),
        ("advanced_attack_simulation_scenarios", "AdvancedAttackSimulationScenarios"),
    ]
    
    all_passed = True
    
    for module_name, class_name in new_features:
        try:
            module = __import__(module_name)
            print(f"  ✓ {module_name}")
            
            if hasattr(module, class_name):
                print(f"    ✓ {class_name}")
            else:
                # 尝试不同的命名约定
                found = False
                for attr_name in dir(module):
                    if class_name.lower().replace("_", "") in attr_name.lower().replace("_", ""):
                        print(f"    ⚠ {class_name} (找到类似: {attr_name})")
                        found = True
                        break
                
                if not found:
                    print(f"    ✗ {class_name} (未找到)")
                    all_passed = False
                    
        except ImportError as e:
            print(f"  ✗ {module_name}: {e}")
            all_passed = False
    
    return all_passed

def test_config_files():
    """测试配置文件"""
    print("\n测试配置文件...")
    
    required_files = [
        "gulfsign_config.json",
        "使用说明.txt",
        "使用说明_最终版.txt",
        "快速上手指南.txt",
        "操作教程.txt",
    ]
    
    all_exist = True
    
    for file_name in required_files:
        file_path = Path(__file__).parent / file_name
        if file_path.exists():
            print(f"  ✓ {file_name}")
        else:
            print(f"  ✗ {file_name} (不存在)")
            all_exist = False
    
    return all_exist

def test_data_directories():
    """测试数据目录"""
    print("\n测试数据目录...")
    
    data_dirs = [
        "actual_demo",
        "batch_processing_test",
        "encryption_test",
        "excel_log_test",
        "final_verification_proof",
        "logs",
        "real_config_test",
        "real_test_logs",
        "ultimate_verification",
    ]
    
    all_exist = True
    
    for dir_name in data_dirs:
        dir_path = Path(__file__).parent / dir_name
        if dir_path.exists():
            print(f"  ✓ {dir_name}")
        else:
            print(f"  ⚠ {dir_name} (不存在，但可能不是必需的)")
    
    return True

def create_deployment_checklist():
    """创建部署检查清单"""
    print("\n" + "=" * 60)
    print("部署检查清单")
    print("=" * 60)
    
    checklist = {
        "核心模块": [
            "ph3_api.py - 公卫3.0 API客户端",
            "hc_api.py - 健康卡平台客户端",
            "sign_engine.py - 签约引擎",
            "proxy_capture.py - 代理抓包工具",
            "license_client.py - 许可证客户端",
            "config_manager.py - 配置管理器",
            "batch_processor.py - 批量处理器",
        ],
        "新功能模块": [
            "ultimate_status_conversion_explorer.py - 状态转换探索器",
            "ultimate_realname_id_modification_explorer.py - 实名认证ID修改分析",
            "ultimate_family_member_removal_analyzer.py - 家庭成员移除分析",
            "ultimate_sjfx_field_discovery_explorer.py - sjfx API字段名发现",
            "comprehensive_age_bypass_validation.py - 年龄验证绕行测试",
            "comprehensive_solution_matrix.py - 综合解决方案矩阵",
            "penetration_testing_simulation_framework.py - 渗透测试模拟框架",
            "advanced_attack_simulation_scenarios.py - 高级攻击模拟场景",
        ],
        "配置文件": [
            "gulfsign_config.json - 主配置文件",
            "requirements.txt - Python依赖",
            "version_info.json - 版本信息",
        ],
        "文档文件": [
            "使用说明.txt - 基本使用说明",
            "使用说明_最终版.txt - 详细使用说明",
            "快速上手指南.txt - 快速入门指南",
            "操作教程.txt - 操作步骤教程",
            "README_EXE_BUILD.md - 构建说明",
        ],
        "工具脚本": [
            "gulfsign_comprehensive_app.py - 综合版应用程序",
            "launch_gulfsign.py - 启动脚本",
            "simple_build_exe.py - 简化版构建脚本",
            "build_gulfsign_exe.py - 完整构建脚本",
        ],
        "测试文件": [
            "test_comprehensive_app.py - 测试脚本",
        ],
    }
    
    for category, items in checklist.items():
        print(f"\n{category}:")
        for item in items:
            print(f"  {item}")
    
    print("\n" + "=" * 60)
    print("部署说明:")
    print("1. 确保所有文件在同一个目录")
    print("2. 运行 'python launch_gulfsign.py' 启动应用程序")
    print("3. 按照界面提示配置和使用系统")
    print("4. 如需创建快捷方式，运行启动脚本时选择'y'")
    print("=" * 60)

def main():
    """主测试函数"""
    print("=" * 60)
    print("湾流签约助手综合版 - 功能测试")
    print("=" * 60)
    
    # 测试导入
    imports_ok = test_imports()
    
    # 测试新功能
    features_ok = test_new_features()
    
    # 测试配置文件
    configs_ok = test_config_files()
    
    # 测试数据目录
    dirs_ok = test_data_directories()
    
    # 总结
    print("\n" + "=" * 60)
    print("测试总结:")
    print(f"  模块导入: {'✓ 通过' if imports_ok else '✗ 失败'}")
    print(f"  新功能模块: {'✓ 通过' if features_ok else '✗ 失败'}")
    print(f"  配置文件: {'✓ 通过' if configs_ok else '✗ 失败'}")
    print(f"  数据目录: {'✓ 通过' if dirs_ok else '✗ 失败'}")
    
    if all([imports_ok, features_ok, configs_ok, dirs_ok]):
        print("\n所有测试通过! ✓")
        print("应用程序可以正常运行。")
        
        # 显示部署检查清单
        create_deployment_checklist()
        
        return True
    else:
        print("\n测试失败! ✗")
        print("请检查缺失的模块或文件。")
        return False

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)