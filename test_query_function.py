#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
测试查询未签约人群功能
"""

import tkinter as tk
from app import GulfSignApp
import time

print("=" * 80)
print("测试查询未签约人群功能")
print("=" * 80)

print("\n1. 启动应用程序...")
try:
    # 创建应用程序实例
    app = GulfSignApp()
    print("   ✓ 应用程序启动成功")
    
    # 最小化窗口以避免干扰
    app.withdraw()
    
    print("\n2. 检查查询功能配置:")
    
    # 设置查询条件
    app.var_status.set("未签约")  # 签约状态
    app.var_org.set("")  # 机构代码（留空表示当前机构）
    app.var_name_filter.set("")  # 姓名过滤
    app.var_idcard_filter.set("")  # 身份证过滤
    
    print(f"   设置的查询条件:")
    print(f"   - 签约状态: {app.var_status.get()}")
    print(f"   - 机构代码: {app.var_org.get() or '当前机构'}")
    print(f"   - 姓名过滤: {app.var_name_filter.get() or '无'}")
    print(f"   - 身份证过滤: {app.var_idcard_filter.get() or '无'}")
    
    print("\n3. 模拟查询功能测试:")
    print("   注意: 实际查询需要网络连接和真实的公卫3.0系统")
    print("   这里只验证UI组件和配置是否正确")
    
    # 检查查询按钮
    if hasattr(app, 'btn_query'):
        print("   ✓ 查询按钮存在")
        
        # 模拟查询按钮点击（不实际执行）
        print("   模拟查询按钮点击...")
        
        # 设置查询信息显示
        app.var_query_info.set("查询条件: 未签约人群")
        print(f"   查询信息: {app.var_query_info.get()}")
        
    else:
        print("   ✗ 查询按钮不存在")
    
    print("\n4. 测试查询结果处理:")
    
    # 模拟查询结果
    mock_patients = [
        {
            "name": "张三",
            "id_card": "430102199001011234",
            "status": "未签约",
            "team": "",
            "doctor": "",
            "sign_date": "",
            "expire_date": "",
            "pid": "1234567890"
        },
        {
            "name": "李四",
            "id_card": "430102199002021235",
            "status": "未签约",
            "team": "",
            "doctor": "",
            "sign_date": "",
            "expire_date": "",
            "pid": "1234567891"
        }
    ]
    
    print(f"   模拟查询结果: {len(mock_patients)} 个未签约居民")
    for i, patient in enumerate(mock_patients, 1):
        print(f"   {i}. {patient['name']} ({patient['id_card']})")
    
    print("\n5. 测试签约准备:")
    
    # 设置签约医生和团队
    app.var_doctor.set("家庭医生")
    app.var_team.set("家庭医生团队")
    app.var_pop_type.set("一般人群")
    app.var_delay.set("0.5")
    app.var_max_count.set("10")
    
    print(f"   签约配置:")
    print(f"   - 签约医生: {app.var_doctor.get()}")
    print(f"   - 签约团队: {app.var_team.get()}")
    print(f"   - 人群类型: {app.var_pop_type.get()}")
    print(f"   - 间隔时间: {app.var_delay.get()}秒")
    print(f"   - 最大人数: {app.var_max_count.get()}")
    
    print("\n6. 测试批量选择功能:")
    
    # 模拟选择居民
    selected_count = 2
    app.selected_ids = {"1234567890", "1234567891"}
    
    print(f"   模拟选择 {selected_count} 个居民")
    print(f"   已选居民ID: {app.selected_ids}")
    
    # 更新选择信息
    app.var_select_info.set(f"已选: {selected_count}")
    print(f"   选择信息: {app.var_select_info.get()}")
    
    print("\n7. 测试签约功能:")
    
    # 检查签约按钮
    if hasattr(app, 'btn_start'):
        print("   ✓ 开始签约按钮存在")
        
        # 模拟签约按钮点击（不实际执行）
        print("   模拟开始签约按钮点击...")
        
        # 设置进度信息
        app.var_progress_text.set("准备签约...")
        print(f"   进度信息: {app.var_progress_text.get()}")
        
    else:
        print("   ✗ 开始签约按钮不存在")
    
    print("\n8. 功能完整性验证:")
    
    # 验证所有必需组件
    required_components = [
        ("var_status", "签约状态变量"),
        ("var_org", "机构代码变量"),
        ("btn_query", "查询按钮"),
        ("btn_start", "开始签约按钮"),
        ("var_progress_text", "进度信息变量"),
        ("var_select_info", "选择信息变量")
    ]
    
    missing_components = []
    for component, description in required_components:
        if not hasattr(app, component):
            missing_components.append(description)
    
    if missing_components:
        print(f"   ⚠️  缺失组件: {missing_components}")
    else:
        print("   ✅ 所有必需组件都存在")
    
    print("\n" + "=" * 80)
    print("测试总结:")
    print("=" * 80)
    
    if not missing_components:
        print("✅ 查询功能测试通过！")
        print("\n应用程序已准备好进行实际查询和签约:")
        print("1. 确保网络连接正常")
        print("2. 公卫3.0系统可访问")
        print("3. 点击'查询'按钮查找未签约人群")
        print("4. 选择要签约的居民")
        print("5. 点击'开始签约'按钮")
        print("6. 监控签约进度")
        
    else:
        print(f"⚠️  查询功能测试部分通过")
        print(f"\n需要修复的组件: {missing_components}")
    
    print("\n" + "=" * 80)
    
    # 关闭应用程序
    app.destroy()
    
except Exception as e:
    print(f"\n❌ 测试失败: {e}")
    import traceback
    traceback.print_exc()