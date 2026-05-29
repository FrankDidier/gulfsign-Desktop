#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
测试应用程序启动
"""
import os
import sys

# 添加路径
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def test_app_startup():
    """测试应用程序启动"""
    print("测试应用程序启动...")
    
    try:
        # 导入应用程序
        from app import GulfSignApp
        
        print("1. 导入应用程序成功")
        
        # 创建应用程序实例
        print("2. 创建应用程序实例...")
        app = GulfSignApp()
        
        print("3. 应用程序实例创建成功")
        
        # 检查配置
        print("\n4. 检查配置状态:")
        print(f"   URL 变量值: {app.var_url.get()}")
        print(f"   账号变量值: {app.var_account.get()}")
        print(f"   机构代码变量值: {app.var_org.get()}")
        print(f"   客户端 base_url: {app.client.base_url}")
        
        # 检查配置字典
        print(f"\n5. 配置字典内容:")
        print(f"   username: {app._cfg.get('username', '未设置')}")
        print(f"   ggws_base_url: {app._cfg.get('ggws_base_url', '未设置')}")
        print(f"   org_code: {app._cfg.get('org_code', '未设置')}")
        
        # 验证
        print("\n6. 验证结果:")
        
        url_ok = app.var_url.get() == "https://ggws.hnhfpc.gov.cn"
        account_ok = app.var_account.get() == "430726000001010WS"
        org_ok = app.var_org.get() == ""  # 应该为空，因为配置文件中没有 org_code
        
        print(f"   URL 正确: {'✓' if url_ok else '✗'} (期望: https://ggws.hnhfpc.gov.cn, 实际: {app.var_url.get()})")
        print(f"   账号正确: {'✓' if account_ok else '✗'} (期望: 430726000001010WS, 实际: {app.var_account.get()})")
        print(f"   机构代码正确: {'✓' if org_ok else '✗'} (期望: 空, 实际: {app.var_org.get()})")
        
        if url_ok and account_ok:
            print("\n✓ 应用程序启动配置正确")
            return True
        else:
            print("\n✗ 应用程序启动配置有误")
            return False
            
    except Exception as e:
        print(f"\n✗ 应用程序启动失败: {e}")
        import traceback
        traceback.print_exc()
        return False

def main():
    """主函数"""
    print("湾流签约助手 - 应用程序启动测试")
    print("=" * 60)
    
    success = test_app_startup()
    
    print("\n" + "=" * 60)
    if success:
        print("✓ 测试通过")
        print("\n应用程序应该能够正确启动并加载配置")
        return 0
    else:
        print("✗ 测试失败")
        print("\n需要进一步调试应用程序启动问题")
        return 1

if __name__ == "__main__":
    # 注意：这个测试会创建Tkinter窗口，可能需要手动关闭
    sys.exit(main())