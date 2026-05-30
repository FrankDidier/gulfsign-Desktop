#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
收集二维码验证问题的运行时证据
"""

import os
import sys
import json
import logging
import time
from datetime import datetime
from pathlib import Path

# 添加当前目录到路径
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def collect_qr_verification_evidence():
    """收集二维码验证问题的证据"""
    print("🔍 收集二维码验证问题的运行时证据")
    print("="*80)
    
    evidence_file = f"qr_verification_evidence_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    
    try:
        # 导入必要的模块
        from ph3_api import PH3Client
        
        # 创建客户端
        client = PH3Client()
        
        # 使用实际账号
        account = "431122012"
        password = "wei1147609775@"
        base_url = "https://ggws.hnhfpc.gov.cn"
        
        print(f"\n1. 准备登录测试...")
        print(f"   账号: {account}")
        print(f"   系统地址: {base_url}")
        
        # 收集证据
        evidence = {
            "timestamp": datetime.now().isoformat(),
            "test_config": {
                "account": account,
                "base_url": base_url,
                "password_provided": bool(password)
            },
            "login_attempt": {},
            "qr_verification_analysis": {},
            "session_state": {},
            "extraction_attempts": {},
            "recommendations": []
        }
        
        print(f"\n2. 执行登录...")
        start_time = time.time()
        success, message = client.login(base_url, account, password)
        elapsed_time = time.time() - start_time
        
        evidence["login_attempt"] = {
            "success": success,
            "message": message,
            "elapsed_time": elapsed_time,
            "logged_in": client.logged_in,
            "doctor_name": client.doctor_name,
            "org_code": client.org_code,
            "team_name": client.team_name
        }
        
        print(f"   登录结果: {'✅ 成功' if success else '❌ 失败'}")
        print(f"   登录消息: {message}")
        print(f"   耗时: {elapsed_time:.2f}秒")
        print(f"   登录状态: {'✅ 已登录' if client.logged_in else '❌ 未登录'}")
        print(f"   医生姓名: {client.doctor_name or '未提取'}")
        print(f"   机构代码: {client.org_code or '未提取'}")
        print(f"   团队名称: {client.team_name or '未提取'}")
        
        # 分析二维码验证需求
        print(f"\n3. 分析二维码验证需求...")
        
        # 检查消息中是否包含二维码验证提示
        requires_qr = False
        qr_analysis = {
            "msg_contains_qr": "二维码" in message or "QR" in message.upper(),
            "msg_contains_verification": "验证" in message,
            "msg_value": None,
            "requires_qr_detected": False
        }
        
        # 尝试从消息中提取msg值
        import re
        msg_match = re.search(r'msg[=:]\s*(\d+)', message)
        if msg_match:
            qr_analysis["msg_value"] = msg_match.group(1)
            msg_int = int(msg_match.group(1))
            qr_analysis["requires_qr_detected"] = msg_int <= 4
            requires_qr = msg_int <= 4
        
        evidence["qr_verification_analysis"] = qr_analysis
        
        print(f"   消息包含'二维码': {qr_analysis['msg_contains_qr']}")
        print(f"   消息包含'验证': {qr_analysis['msg_contains_verification']}")
        print(f"   提取的msg值: {qr_analysis['msg_value'] or '未找到'}")
        print(f"   需要二维码验证: {qr_analysis['requires_qr_detected']}")
        
        # 检查会话状态
        print(f"\n4. 检查会话状态...")
        session_state = {
            "has_session": hasattr(client, 'session') and client.session is not None,
            "cookies_count": 0,
            "has_auth_cookie": False,
            "session_valid": False
        }
        
        if session_state["has_session"]:
            cookies = client.session.cookies
            session_state["cookies_count"] = len(cookies)
            
            # 检查是否有认证相关的cookie
            auth_cookies = [c for c in cookies if any(keyword in c.name.lower() 
                                                     for keyword in ['auth', 'token', 'session', 'login'])]
            session_state["has_auth_cookie"] = len(auth_cookies) > 0
            
            # 测试会话是否有效
            try:
                test_response = client.session.get(f"{base_url}/FormMain.aspx", timeout=5)
                session_state["session_valid"] = test_response.status_code == 200
                session_state["test_url"] = test_response.url
                session_state["test_status_code"] = test_response.status_code
                
                # 检查是否被重定向到登录页面
                session_state["redirected_to_login"] = "login" in test_response.url.lower() or "authenticate" in test_response.url.lower()
                
            except Exception as e:
                session_state["test_error"] = str(e)
        
        evidence["session_state"] = session_state
        
        print(f"   有会话对象: {session_state['has_session']}")
        print(f"   Cookie数量: {session_state['cookies_count']}")
        print(f"   有认证Cookie: {session_state['has_auth_cookie']}")
        print(f"   会话有效: {session_state['session_valid']}")
        if 'test_url' in session_state:
            print(f"   测试URL: {session_state['test_url']}")
        if 'redirected_to_login' in session_state:
            print(f"   重定向到登录页: {session_state['redirected_to_login']}")
        
        # 尝试提取机构信息
        print(f"\n5. 尝试提取机构信息...")
        
        extraction_attempts = {
            "direct_extraction": {
                "org_code": client.org_code,
                "doctor_name": client.doctor_name,
                "team_name": client.team_name
            },
            "org_tree_attempt": {
                "attempted": False,
                "success": False,
                "orgs_found": 0,
                "drilled_org_code": None
            }
        }
        
        # 如果机构代码为空，尝试使用机构树
        if not client.org_code and client.logged_in:
            print(f"   尝试使用机构树提取...")
            extraction_attempts["org_tree_attempt"]["attempted"] = True
            
            try:
                orgs = client.get_org_tree("0")
                if orgs:
                    extraction_attempts["org_tree_attempt"]["orgs_found"] = len(orgs)
                    extraction_attempts["org_tree_attempt"]["success"] = True
                    
                    print(f"   找到机构节点: {len(orgs)}个")
                    
                    # 尝试向下钻取
                    client._drill_org_tree(orgs)
                    extraction_attempts["org_tree_attempt"]["drilled_org_code"] = client.org_code
                    
                    print(f"   钻取后机构代码: {client.org_code or '未提取'}")
                else:
                    print(f"   未找到机构节点")
                    
            except Exception as e:
                extraction_attempts["org_tree_attempt"]["error"] = str(e)
                print(f"   机构树提取失败: {str(e)}")
        
        evidence["extraction_attempts"] = extraction_attempts
        
        # 生成建议
        print(f"\n6. 生成建议...")
        
        recommendations = []
        
        if requires_qr:
            recommendations.append({
                "priority": "high",
                "title": "二维码验证是强制性的",
                "description": "系统要求二维码验证(msg<=4)，无法通过API自动完成登录流程",
                "action": "使用网页登录功能，让用户在浏览器中完成验证"
            })
        
        if not client.org_code:
            recommendations.append({
                "priority": "high",
                "title": "机构信息未提取",
                "description": "无法提取机构代码，导致所有查询功能失败",
                "action": "提供手动输入机构代码的选项，或改进提取逻辑"
            })
        
        if client.logged_in and not session_state.get("session_valid", False):
            recommendations.append({
                "priority": "medium",
                "title": "会话状态不一致",
                "description": "客户端显示已登录，但会话测试失败",
                "action": "检查会话Cookie和认证状态"
            })
        
        evidence["recommendations"] = recommendations
        
        # 打印建议
        for i, rec in enumerate(recommendations, 1):
            print(f"   {i}. [{rec['priority'].upper()}] {rec['title']}")
            print(f"      描述: {rec['description']}")
            print(f"      建议: {rec['action']}")
        
        # 保存证据
        print(f"\n7. 保存证据到文件...")
        with open(evidence_file, 'w', encoding='utf-8') as f:
            json.dump(evidence, f, ensure_ascii=False, indent=2)
        
        print(f"   ✅ 证据已保存到: {evidence_file}")
        
        # 总结
        print(f"\n" + "="*80)
        print("证据收集总结:")
        print(f"   登录成功: {success}")
        print(f"   需要二维码验证: {requires_qr}")
        print(f"   机构代码提取: {bool(client.org_code)}")
        print(f"   会话状态有效: {session_state.get('session_valid', False)}")
        
        if requires_qr:
            print(f"\n⚠️  关键发现: 二维码验证是强制性的")
            print(f"   系统返回msg={qr_analysis['msg_value']}，表示需要二维码验证")
            print(f"   这阻止了完整的登录流程，导致无法提取机构信息")
        
        return True, evidence_file
        
    except Exception as e:
        print(f"❌ 证据收集失败: {str(e)}")
        import traceback
        traceback.print_exc()
        return False, str(e)

def analyze_evidence(evidence_file):
    """分析收集到的证据"""
    print(f"\n📊 分析证据文件: {evidence_file}")
    print("="*80)
    
    try:
        with open(evidence_file, 'r', encoding='utf-8') as f:
            evidence = json.load(f)
        
        # 分析登录尝试
        login_attempt = evidence.get("login_attempt", {})
        qr_analysis = evidence.get("qr_verification_analysis", {})
        session_state = evidence.get("session_state", {})
        extraction_attempts = evidence.get("extraction_attempts", {})
        
        print(f"\n1. 登录尝试分析:")
        print(f"   成功: {login_attempt.get('success', False)}")
        print(f"   消息: {login_attempt.get('message', 'N/A')}")
        print(f"   登录状态: {login_attempt.get('logged_in', False)}")
        print(f"   医生姓名: {login_attempt.get('doctor_name', 'N/A')}")
        print(f"   机构代码: {login_attempt.get('org_code', 'N/A')}")
        
        print(f"\n2. 二维码验证分析:")
        print(f"   需要二维码验证: {qr_analysis.get('requires_qr_detected', False)}")
        print(f"   msg值: {qr_analysis.get('msg_value', 'N/A')}")
        
        print(f"\n3. 会话状态分析:")
        print(f"   有会话对象: {session_state.get('has_session', False)}")
        print(f"   Cookie数量: {session_state.get('cookies_count', 0)}")
        print(f"   会话有效: {session_state.get('session_valid', False)}")
        if session_state.get('redirected_to_login'):
            print(f"   ⚠️  会话被重定向到登录页面")
        
        print(f"\n4. 提取尝试分析:")
        direct_extraction = extraction_attempts.get("direct_extraction", {})
        org_tree_attempt = extraction_attempts.get("org_tree_attempt", {})
        
        print(f"   直接提取机构代码: {direct_extraction.get('org_code', 'N/A')}")
        print(f"   机构树尝试: {'✅ 成功' if org_tree_attempt.get('success') else '❌ 失败'}")
        if org_tree_attempt.get('drilled_org_code'):
            print(f"   钻取后机构代码: {org_tree_attempt.get('drilled_org_code')}")
        
        print(f"\n5. 根本原因分析:")
        
        requires_qr = qr_analysis.get('requires_qr_detected', False)
        has_org_code = bool(login_attempt.get('org_code'))
        session_valid = session_state.get('session_valid', False)
        
        if requires_qr:
            print(f"   ✅ 根本原因: 二维码验证要求")
            print(f"      系统返回msg={qr_analysis.get('msg_value')}，表示需要二维码验证")
            print(f"      这阻止了访问主页面，因此无法提取机构信息")
            
        elif not has_org_code:
            print(f"   ⚠️  可能原因: 机构信息提取失败")
            print(f"      即使登录成功，也无法从页面中提取机构代码")
            print(f"      可能需要改进提取模式或从其他API获取")
            
        elif not session_valid:
            print(f"   ⚠️  可能原因: 会话状态问题")
            print(f"      客户端显示已登录，但会话测试失败")
            print(f"      可能需要重新建立会话或检查认证Cookie")
        
        print(f"\n6. 建议:")
        recommendations = evidence.get("recommendations", [])
        for i, rec in enumerate(recommendations, 1):
            print(f"   {i}. [{rec['priority'].upper()}] {rec['title']}")
            print(f"      {rec['action']}")
        
        return True
        
    except Exception as e:
        print(f"❌ 证据分析失败: {str(e)}")
        return False

if __name__ == "__main__":
    print("二维码验证问题证据收集和分析")
    print("="*80)
    
    # 收集证据
    success, result = collect_qr_verification_evidence()
    
    if success and isinstance(result, str) and result.endswith('.json'):
        # 分析证据
        analyze_evidence(result)
        
        print(f"\n" + "="*80)
        print("✅ 证据收集和分析完成")
        print(f"   证据文件: {result}")
        print(f"   下一步: 根据分析结果实施修复方案")
    else:
        print(f"\n❌ 证据收集失败: {result}")