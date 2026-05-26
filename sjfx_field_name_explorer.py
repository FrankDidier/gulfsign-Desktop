#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
sjfx API 字段名穷举探索器

目标：探索 sjfx.hnhfpc.gov.cn/jkkListApi/healthCardApplication API 的字段名
方法：穷举所有可能的字段名变体，包括中文、英文、拼音、缩写等
"""

import json
import time
import requests
import logging
from typing import List, Dict, Tuple, Optional
from dataclasses import dataclass, field
from concurrent.futures import ThreadPoolExecutor, as_completed

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# 已知的字段名模式
KNOWN_FIELD_PATTERNS = {
    # b0105 系列字段
    "b0105_01": "签约类型",
    "b0105_02": "联系电话",
    "b0105_03": "团队名称",
    "b0105_03_guid": "团队GUID",
    "b0105_04": "医生姓名",
    "b0105_05": "签约开始日期",
    "b0105_06": "服务包名称",
    "b0105_06_guid": "服务包GUID",
    "b0105_07": "签约日期",
    "b0105_08": "签约年限",
    "b0105_09": "签约结束日期",
    "b0105_10": "签约状态",
    "b0105_11": "确认状态",
    "b0105_12": "审核状态",
    "b0105_13": "合同状态",
    
    # 中文字段名
    "jgbm": "机构编码",
    "jgmc": "机构名称",
    "qyzfbs": "签约状态标识",
    "qyys": "签约医生",
    "xyksrq": "协议开始日期",
    "xyjsrq": "协议结束日期",
    "qytdmc": "签约团队名称",
    "qytdbm": "签约团队编码",
    "sfzh": "身份证号",
    "xm": "姓名",
    "xb": "性别",
    "nl": "年龄",
    "lxdh": "联系电话",
    "jtdz": "家庭地址",
    "qyksrq": "签约开始日期",
    "qyjsrq": "签约结束日期",
    "qylx": "签约类型",
    "fwbmc": "服务包名称",
    "fwbguid": "服务包GUID",
    "qyzt": "签约状态",
    "qrzt": "确认状态",
    "shzt": "审核状态",
    "htzt": "合同状态",
    
    # 英文字段名
    "orgcode": "机构代码",
    "orgname": "机构名称",
    "personid": "人员ID",
    "healthcardid": "健康卡ID",
    "name": "姓名",
    "idcard": "身份证号",
    "gender": "性别",
    "age": "年龄",
    "phone": "电话",
    "address": "地址",
    "startdate": "开始日期",
    "enddate": "结束日期",
    "contracttype": "合同类型",
    "packagename": "服务包名称",
    "packageguid": "服务包GUID",
    "status": "状态",
    "confirmstatus": "确认状态",
    "auditstatus": "审核状态",
    "contractstatus": "合同状态",
    
    # 拼音字段名
    "qianyue": "签约",
    "qianyueleixing": "签约类型",
    "lianxidianhua": "联系电话",
    "tuanduimingcheng": "团队名称",
    "tuandui_guid": "团队GUID",
    "yishengxingming": "医生姓名",
    "qianyuekaishiriqi": "签约开始日期",
    "fuwubaomingcheng": "服务包名称",
    "fuwubao_guid": "服务包GUID",
    "qianyueriqi": "签约日期",
    "qianyuenianxian": "签约年限",
    "qianyuejieshuriqi": "签约结束日期",
    "qianyuezhuangtai": "签约状态",
    "querenzhuangtai": "确认状态",
    "shenhezhuangtai": "审核状态",
    "hetongzhuangtai": "合同状态",
}

# 字段名变体生成器
def generate_field_variants(base_field: str) -> List[str]:
    """生成字段名的所有可能变体"""
    variants = []
    
    # 原始字段
    variants.append(base_field)
    
    # 大小写变体
    variants.append(base_field.lower())
    variants.append(base_field.upper())
    variants.append(base_field.capitalize())
    
    # 下划线变体
    if "_" in base_field:
        variants.append(base_field.replace("_", ""))
        variants.append(base_field.replace("_", "-"))
        variants.append(base_field.replace("_", "").lower())
        variants.append(base_field.replace("_", "").upper())
    
    # 数字变体
    if any(char.isdigit() for char in base_field):
        # 保持数字不变
        pass
    
    return list(set(variants))

# API 测试客户端
class SjfxApiExplorer:
    def __init__(self, base_url: str = "https://sjfx.hnhfpc.gov.cn"):
        self.base_url = base_url
        self.session = requests.Session()
        self.session.trust_env = False
        self.session.verify = False
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Content-Type": "application/json",
            "Accept": "application/json",
        })
        
    def test_field_names(self, endpoint: str, test_data: Dict, field_candidates: List[str]) -> Dict[str, Dict]:
        """测试字段名候选列表"""
        results = {}
        
        for field_name in field_candidates:
            # 创建测试请求
            test_payload = test_data.copy()
            
            # 为字段设置测试值
            if field_name.startswith("b0105_"):
                # b0105 字段的特殊处理
                if field_name.endswith("_01"):
                    test_payload[field_name] = "2"  # 签约类型
                elif field_name.endswith("_02"):
                    test_payload[field_name] = "13800138000"  # 联系电话
                elif field_name.endswith("_13"):
                    test_payload[field_name] = "5"  # 合同状态
                else:
                    test_payload[field_name] = "test_value"
            elif "date" in field_name.lower() or "rq" in field_name:
                test_payload[field_name] = "2024-01-01"
            elif "phone" in field_name.lower() or "dh" in field_name:
                test_payload[field_name] = "13800138000"
            elif "id" in field_name.lower() or "guid" in field_name:
                test_payload[field_name] = "test_guid_123"
            else:
                test_payload[field_name] = "test_value"
            
            try:
                # 发送测试请求
                url = f"{self.base_url}/{endpoint}"
                response = self.session.post(
                    url,
                    json=test_payload,
                    timeout=10
                )
                
                # 分析响应
                result = {
                    "field_name": field_name,
                    "status_code": response.status_code,
                    "response_time": response.elapsed.total_seconds(),
                    "response_headers": dict(response.headers),
                }
                
                try:
                    result["response_body"] = response.json()
                except:
                    result["response_body"] = response.text[:500]
                
                # 判断字段是否有效
                if response.status_code == 200:
                    # 检查响应中是否包含字段相关的错误信息
                    response_text = str(result["response_body"]).lower()
                    if "invalid" in response_text or "error" in response_text or "字段" in response_text:
                        result["is_valid"] = False
                        result["error_type"] = "field_validation_error"
                    else:
                        result["is_valid"] = True
                elif response.status_code == 400:
                    # 400 错误可能表示字段名错误
                    result["is_valid"] = False
                    result["error_type"] = "bad_request"
                else:
                    result["is_valid"] = False
                    result["error_type"] = f"http_{response.status_code}"
                
                results[field_name] = result
                
            except Exception as e:
                results[field_name] = {
                    "field_name": field_name,
                    "error": str(e),
                    "is_valid": False,
                    "error_type": "request_exception"
                }
            
            # 避免请求过快
            time.sleep(0.1)
        
        return results
    
    def explore_common_patterns(self) -> Dict[str, List[str]]:
        """探索常见的字段名模式"""
        patterns = {
            "b0105_series": [],
            "chinese_fields": [],
            "english_fields": [],
            "pinyin_fields": [],
            "abbreviation_fields": [],
        }
        
        # b0105 系列
        for i in range(1, 20):
            patterns["b0105_series"].append(f"b0105_{i:02d}")
            patterns["b0105_series"].append(f"B0105_{i:02d}")
            patterns["b0105_series"].append(f"b0105_{i}")
            patterns["b0105_series"].append(f"B0105_{i}")
        
        # 添加已知的带后缀的字段
        patterns["b0105_series"].extend([
            "b0105_03_guid", "b0105_06_guid",
            "b0105_03_GUID", "b0105_06_GUID",
        ])
        
        # 中文字段
        chinese_candidates = [
            "机构编码", "机构名称", "签约状态", "签约医生",
            "开始日期", "结束日期", "身份证号", "姓名",
            "性别", "年龄", "电话", "地址",
            "团队名称", "团队编码", "服务包", "合同编号",
            "确认状态", "审核状态", "操作人", "操作时间",
        ]
        
        # 转换为可能的字段名格式
        for chinese in chinese_candidates:
            # 拼音缩写
            patterns["chinese_fields"].append(chinese)
            # 首字母缩写
            if len(chinese) <= 4:
                patterns["abbreviation_fields"].append(chinese)
        
        # 英文字段
        english_candidates = [
            "orgCode", "orgName", "contractStatus", "doctorName",
            "startDate", "endDate", "idCard", "name",
            "gender", "age", "phone", "address",
            "teamName", "teamCode", "package", "contractNo",
            "confirmStatus", "auditStatus", "operator", "operateTime",
            "personId", "healthCardId", "openId", "token",
            "action", "type", "value", "data",
            "result", "message", "code", "success",
        ]
        
        patterns["english_fields"].extend(english_candidates)
        
        # 拼音字段
        pinyin_candidates = [
            "qianyue", "qianyueleixing", "lianxidianhua",
            "tuanduimingcheng", "yishengxingming", "qianyuekaishiriqi",
            "fuwubaomingcheng", "qianyueriqi", "qianyuenianxian",
            "qianyuejieshuriqi", "qianyuezhuangtai", "querenzhuangtai",
            "shenhezhuangtai", "hetongzhuangtai", "shenfenzhenghao",
            "xingming", "xingbie", "nianling", "dianhua", "dizhi",
        ]
        
        patterns["pinyin_fields"].extend(pinyin_candidates)
        
        # 缩写字段
        abbreviation_candidates = [
            "jg", "mc", "zt", "ys", "rq", "sfz", "xm", "xb",
            "nl", "dh", "dz", "td", "fw", "ht", "qr", "sh",
            "cz", "sj", "bm", "lx", "kh", "bh", "id", "no",
        ]
        
        patterns["abbreviation_fields"].extend(abbreviation_candidates)
        
        return patterns

def main():
    """主函数"""
    print("=" * 80)
    print("sjfx API 字段名穷举探索器")
    print("=" * 80)
    
    # 初始化探索器
    explorer = SjfxApiExplorer()
    
    # 生成字段名候选
    print("\n1. 生成字段名候选列表...")
    patterns = explorer.explore_common_patterns()
    
    total_candidates = sum(len(v) for v in patterns.values())
    print(f"   生成 {total_candidates} 个字段名候选")
    
    # 准备测试数据
    test_data = {
        "action": "create",
        "openid": "test_openid_123",
        "token": "test_token_456",
        "orgcode": "430726000001010",
        "personid": "test_person_789",
        "healthcardid": "test_healthcard_012",
    }
    
    # 测试端点
    endpoint = "jkkListApi/healthCardApplication"
    
    # 分批测试
    batch_results = {}
    valid_fields = []
    
    print("\n2. 开始字段名测试...")
    print("   端点:", f"{explorer.base_url}/{endpoint}")
    
    for pattern_name, candidates in patterns.items():
        print(f"\n   测试模式: {pattern_name} ({len(candidates)} 个字段)")
        
        # 测试前10个作为示例
        sample_candidates = candidates[:10]
        
        results = explorer.test_field_names(endpoint, test_data, sample_candidates)
        batch_results[pattern_name] = results
        
        # 统计有效字段
        for field_name, result in results.items():
            if result.get("is_valid"):
                valid_fields.append({
                    "field": field_name,
                    "pattern": pattern_name,
                    "response": result.get("response_body", {}),
                })
                print(f"     ✅ 有效字段: {field_name}")
            else:
                error_type = result.get("error_type", "unknown")
                print(f"     ❌ 无效字段: {field_name} ({error_type})")
    
    # 保存结果
    output_file = "sjfx_field_exploration_results.json"
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump({
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "endpoint": endpoint,
            "test_data": test_data,
            "patterns_tested": list(patterns.keys()),
            "total_candidates": total_candidates,
            "valid_fields": valid_fields,
            "detailed_results": batch_results,
        }, f, ensure_ascii=False, indent=2)
    
    print("\n" + "=" * 80)
    print("探索完成!")
    print(f"发现 {len(valid_fields)} 个有效字段")
    print(f"结果已保存到: {output_file}")
    
    if valid_fields:
        print("\n有效字段列表:")
        for vf in valid_fields:
            print(f"  • {vf['field']} ({vf['pattern']})")
    else:
        print("\n⚠️  未发现有效字段")
        print("可能原因:")
        print("  1. API 端点需要认证")
        print("  2. 字段名模式不正确")
        print("  3. 服务器暂时不可用")
        print("  4. 需要特定的请求参数")
    
    print("\n建议下一步:")
    print("  1. 检查 API 认证要求")
    print("  2. 分析服务器响应模式")
    print("  3. 尝试不同的请求方法 (GET/POST)")
    print("  4. 查看网络流量捕获")
    print("=" * 80)

if __name__ == "__main__":
    main()