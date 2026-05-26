湾流签约助手客户端版 v3.1.0
========================================

概述
----
湾流签约助手是一款专业的家庭医生签约自动化工具，帮助医疗机构高效完成批量签约工作。

版本信息
--------
- 版本号: 3.1.0
- 构建日期: 2026-05-25 07:02:38
- 平台: 跨平台 (Windows/Linux/macOS)

系统要求
--------
- Python 3.8或更高版本
- 网络连接 (访问公卫3.0和健康卡平台)
- 适当的系统权限

目录结构
--------
GulfSign_Client_Package/
├── core_modules/          # 核心模块
│   ├── app.py            # 主应用程序
│   ├── ph3_api.py        # 公卫3.0 API客户端
│   ├── hc_api.py         # 健康卡平台客户端
│   ├── sign_engine.py    # 签约引擎
│   ├── proxy_capture.py  # 代理抓包工具
│   ├── license_client.py # 许可证客户端
│   ├── config_manager.py # 配置管理器
│   ├── batch_processor.py # 批量处理器
│   ├── gulfsign_config.json # 配置文件
│   └── requirements.txt  # Python依赖
├── new_features/         # 新功能模块
│   ├── ultimate_status_conversion_explorer.py
│   ├── ultimate_realname_id_modification_explorer.py
│   ├── ultimate_family_member_removal_analyzer.py
│   ├── ultimate_sjfx_field_discovery_explorer.py
│   ├── comprehensive_age_bypass_validation.py
│   ├── comprehensive_solution_matrix.py
│   ├── penetration_testing_simulation_framework.py
│   └── advanced_attack_simulation_scenarios.py
├── documentation/        # 文档
│   ├── 使用说明.txt
│   ├── 使用说明_最终版.txt
│   ├── 快速上手指南.txt
│   ├── 操作教程.txt
│   ├── README_EXE_BUILD.md
│   ├── sqli_exploitation_benefits_analysis.md
│   └── final_deployment_summary.md
├── tools/               # 工具脚本
│   ├── launch_gulfsign.py
│   ├── simple_build_exe.py
│   ├── build_gulfsign_exe.py
│   ├── build_windows_exe.py
│   └── test_comprehensive_app.py
├── data/               # 数据目录
│   ├── actual_demo/
│   ├── batch_processing_test/
│   ├── encryption_test/
│   ├── excel_log_test/
│   ├── final_verification_proof/
│   ├── logs/
│   ├── real_config_test/
│   ├── real_test_logs/
│   └── ultimate_verification/
├── logs/               # 日志目录
├── 启动程序.bat        # Windows启动脚本
├── 启动程序.sh         # Linux/Mac启动脚本
└── README.txt         # 本文件

快速开始
--------

Windows系统:
1. 双击运行 "启动程序.bat"
2. 按照提示安装依赖
3. 应用程序自动启动

Linux/Mac系统:
1. 打开终端
2. 运行: chmod +x 启动程序.sh
3. 运行: ./启动程序.sh
4. 按照提示安装依赖
5. 应用程序自动启动

手动启动:
1. 安装依赖: pip install -r core_modules/requirements.txt
2. 运行程序: python core_modules/app.py

功能特性
--------

1. 自动化签约系统
   - 支持批量处理
   - 自动创建居民申请
   - 自动确认签约

2. 年龄验证绕行
   - 智能身份证号生成
   - 年龄计算和验证
   - 绕行方案评估

3. 批量处理引擎
   - 生产者-消费者模式
   - 20个工作线程
   - 高效并发处理

4. 高级分析工具
   - 状态转换探索
   - 实名认证ID修改分析
   - 家庭成员移除分析
   - sjfx API字段名发现

5. 安全评估工具
   - 渗透测试模拟
   - 高级攻击模拟
   - 全面安全评估

6. 日志记录系统
   - Excel格式日志
   - 详细操作记录
   - 错误追踪

使用步骤
--------

1. 首次运行
   - 输入机构代码
   - 输入账号和密码
   - 测试系统连接
   - 保存配置

2. 导入数据
   - 准备患者数据 (JSON格式)
   - 导入数据文件
   - 验证数据完整性

3. 批量签约
   - 配置签约参数
   - 开始批量处理
   - 监控处理进度

4. 查看结果
   - 查看签约结果
   - 导出Excel日志
   - 生成统计报告

配置文件
--------
程序会自动创建以下文件:
- gulfsign_config.json - 主配置文件
- logs/ - 日志目录
- excel_logs/ - Excel日志目录

故障排除
--------

1. 登录失败
   - 检查网络连接
   - 验证账号密码
   - 确认系统状态

2. 签约失败
   - 检查患者数据完整性
   - 验证系统状态
   - 查看错误日志

3. 依赖安装失败
   - 检查Python版本
   - 检查网络连接
   - 尝试手动安装

技术支持
--------
- 详细文档: 请参考 documentation/ 目录
- 问题反馈: 查看 logs/ 目录中的日志文件
- 版本更新: 定期检查新版本

免责声明
--------
本工具仅用于合法的家庭医生签约自动化，使用者需遵守相关法律法规和系统使用协议。

========================================
构建时间: 2026-05-25 07:02:38
版权所有: 湾流医疗技术团队
