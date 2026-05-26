#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
高级 sjfx API 字段名解码器

使用多种技术尝试解码未知字段名：
1. 模式匹配（基于已知字段名模式）
2. 字典攻击（常见字段名组合）
3. 响应分析（分析服务器错误响应）
4. 模糊测试（随机字段名生成）
5. 智能猜测（基于业务逻辑）
"""

import json
import time
import random
import string
import hashlib
import requests
import logging
from typing import List, Dict, Tuple, Optional, Set
from dataclasses import dataclass, field
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import defaultdict, Counter

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# 已知的字段名数据库
FIELD_NAME_DATABASE = {
    # 基础字段
    "id": ["ID", "Id", "id", "iD"],
    "name": ["NAME", "Name", "name", "nAME"],
    "type": ["TYPE", "Type", "type", "tYPE"],
    "status": ["STATUS", "Status", "status", "sTATUS"],
    "code": ["CODE", "Code", "code", "cODE"],
    "value": ["VALUE", "Value", "value", "vALUE"],
    
    # 签约相关字段
    "contract": ["CONTRACT", "Contract", "contract", "cONTRACT"],
    "sign": ["SIGN", "Sign", "sign", "sIGN"],
    "doctor": ["DOCTOR", "Doctor", "doctor", "dOCTOR"],
    "patient": ["PATIENT", "Patient", "patient", "pATIENT"],
    "team": ["TEAM", "Team", "team", "tEAM"],
    "package": ["PACKAGE", "Package", "package", "pACKAGE"],
    
    # 日期时间字段
    "date": ["DATE", "Date", "date", "dATE"],
    "time": ["TIME", "Time", "time", "tIME"],
    "year": ["YEAR", "Year", "year", "yEAR"],
    "month": ["MONTH", "Month", "month", "mONTH"],
    "day": ["DAY", "Day", "day", "dAY"],
    
    # 业务字段
    "start": ["START", "Start", "start", "sTART"],
    "end": ["END", "End", "end", "eND"],
    "create": ["CREATE", "Create", "create", "cREATE"],
    "update": ["UPDATE", "Update", "update", "uPDATE"],
    "delete": ["DELETE", "Delete", "delete", "dELETE"],
    "confirm": ["CONFIRM", "Confirm", "confirm", "cONFIRM"],
    "audit": ["AUDIT", "Audit", "audit", "aUDIT"],
    
    # 数字后缀
    "01": ["01", "1", "001"],
    "02": ["02", "2", "002"],
    "03": ["03", "3", "003"],
    "04": ["04", "4", "004"],
    "05": ["05", "5", "005"],
    "06": ["06", "6", "006"],
    "07": ["07", "7", "007"],
    "08": ["08", "8", "008"],
    "09": ["09", "9", "009"],
    "10": ["10", "010"],
    "11": ["11", "011"],
    "12": ["12", "012"],
    "13": ["13", "013"],
    "14": ["14", "014"],
    "15": ["15", "015"],
    
    # 分隔符
    "underscore": ["_", "-", "", "."],
    "prefix": ["b", "B", "f", "F", "a", "A"],
}

# 常见的中文字段名映射
CHINESE_FIELD_MAPPING = {
    "签约": ["qianyue", "sign", "contract"],
    "医生": ["yisheng", "doctor", "physician"],
    "患者": ["huanzhe", "patient", "client"],
    "团队": ["tuandui", "team", "group"],
    "服务": ["fuwu", "service", "package"],
    "状态": ["zhuangtai", "status", "state"],
    "日期": ["riqi", "date", "time"],
    "开始": ["kaishi", "start", "begin"],
    "结束": ["jieshu", "end", "finish"],
    "确认": ["queren", "confirm", "acknowledge"],
    "审核": ["shenhe", "audit", "review"],
    "合同": ["hetong", "contract", "agreement"],
    "身份证": ["shenfenzheng", "idcard", "identity"],
    "电话": ["dianhua", "phone", "telephone"],
    "地址": ["dizhi", "address", "location"],
}

@dataclass
class FieldDiscoveryResult:
    """字段发现结果"""
    field_name: str
    confidence: float  # 0.0-1.0
    evidence: List[str]
    test_response: Optional[Dict] = None
    suggested_value: Optional[str] = None
    
    def to_dict(self) -> Dict:
        return {
            "field_name": self.field_name,
            "confidence": self.confidence,
            "evidence": self.evidence,
            "has_test_response": self.test_response is not None,
            "suggested_value": self.suggested_value,
        }

class AdvancedSjfxFieldDecoder:
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
        
        # 学习到的字段名模式
        self.learned_patterns = defaultdict(Counter)
        self.discovered_fields = []
        
    def generate_field_candidates(self, technique: str = "all") -> List[str]:
        """生成字段名候选"""
        candidates = set()
        
        if technique in ["all", "pattern"]:
            # 模式匹配：基于已知的 b0105_xx 模式
            for prefix in ["b", "B", "f", "F"]:
                for i in range(1, 20):
                    for sep in ["_", "-", ""]:
                        candidates.add(f"{prefix}0105{sep}{i:02d}")
                        candidates.add(f"{prefix}0105{sep}{i}")
                        
                        # 带后缀的变体
                        for suffix in ["", "_guid", "_GUID", "_id", "_ID"]:
                            candidates.add(f"{prefix}0105{sep}{i:02d}{suffix}")
        
        if technique in ["all", "dictionary"]:
            # 字典攻击：常见字段名组合
            common_fields = [
                # 基础组合
                "contractNo", "contractType", "contractStatus",
                "doctorId", "doctorName", "doctorCode",
                "patientId", "patientName", "patientCard",
                "teamId", "teamName", "teamCode",
                "packageId", "packageName", "packageType",
                
                # 日期组合
                "signDate", "startDate", "endDate",
                "createTime", "updateTime", "confirmTime",
                
                # 状态组合
                "auditStatus", "confirmStatus", "reviewStatus",
                "processStatus", "completeStatus",
                
                # 业务组合
                "orgCode", "orgName", "deptCode",
                "healthCardId", "personId", "familyId",
                "openId", "token", "sessionId",
            ]
            
            candidates.update(common_fields)
            
            # 添加小写和大写变体
            for field in common_fields.copy():
                candidates.add(field.lower())
                candidates.add(field.upper())
        
        if technique in ["all", "chinese"]:
            # 中文字段名
            chinese_fields = [
                "签约编号", "签约类型", "签约状态",
                "医生编码", "医生姓名", "医生工号",
                "患者编号", "患者姓名", "患者卡号",
                "团队编码", "团队名称", "团队编号",
                "服务包编码", "服务包名称", "服务包类型",
                "签约日期", "开始日期", "结束日期",
                "创建时间", "更新时间", "确认时间",
                "审核状态", "确认状态", "处理状态",
                "机构编码", "机构名称", "科室编码",
                "健康卡号", "人员编号", "家庭编号",
            ]
            
            candidates.update(chinese_fields)
        
        if technique in ["all", "fuzzy"]:
            # 模糊测试：随机字段名
            random.seed(int(time.time()))
            for _ in range(50):
                # 随机长度 3-15
                length = random.randint(3, 15)
                field = ''.join(random.choices(string.ascii_lowercase, k=length))
                candidates.add(field)
                
                # 带数字的变体
                if random.random() > 0.7:
                    field_with_num = f"{field}_{random.randint(1, 20):02d}"
                    candidates.add(field_with_num)
        
        return list(candidates)
    
    def test_field_candidate(self, endpoint: str, field_name: str, 
                           test_payload: Dict) -> Tuple[bool, Dict]:
        """测试单个字段名候选"""
        # 创建测试负载
        payload = test_payload.copy()
        
        # 根据字段名类型设置合适的测试值
        test_value = self._get_suggested_value(field_name)
        payload[field_name] = test_value
        
        try:
            url = f"{self.base_url}/{endpoint}"
            start_time = time.time()
            
            response = self.session.post(
                url,
                json=payload,
                timeout=15
            )
            
            elapsed = time.time() - start_time
            
            # 分析响应
            result = {
                "field_name": field_name,
                "status_code": response.status_code,
                "response_time": elapsed,
                "test_value": test_value,
            }
            
            # 尝试解析响应体
            try:
                result["response_body"] = response.json()
            except:
                result["response_body"] = response.text[:1000]
            
            # 判断字段是否有效
            is_valid = self._analyze_response(field_name, response, result)
            result["is_valid"] = is_valid
            
            return is_valid, result
            
        except Exception as e:
            return False, {
                "field_name": field_name,
                "error": str(e),
                "is_valid": False,
            }
    
    def _get_suggested_value(self, field_name: str) -> str:
        """根据字段名获取建议的测试值"""
        field_lower = field_name.lower()
        
        # 日期相关字段
        if any(keyword in field_lower for keyword in ["date", "rq", "time", "sj"]):
            return "2024-01-01"
        
        # 电话相关字段
        if any(keyword in field_lower for keyword in ["phone", "dh", "tel", "mobile"]):
            return "13800138000"
        
        # ID相关字段
        if any(keyword in field_lower for keyword in ["id", "guid", "code", "bm"]):
            if "person" in field_lower:
                return "test_person_123"
            elif "contract" in field_lower or "ht" in field_lower:
                return "test_contract_456"
            elif "doctor" in field_lower or "ys" in field_lower:
                return "test_doctor_789"
            else:
                return "test_id_001"
        
        # 状态相关字段
        if any(keyword in field_lower for keyword in ["status", "zt", "state"]):
            if "confirm" in field_lower or "qr" in field_lower:
                return "1"
            elif "audit" in field_lower or "sh" in field_lower:
                return "2"
            else:
                return "5"
        
        # 姓名相关字段
        if any(keyword in field_lower for keyword in ["name", "xm", "mc"]):
            return "测试姓名"
        
        # 数字字段
        if any(keyword in field_lower for keyword in ["age", "nl", "year", "nx"]):
            return "30"
        
        # 默认值
        return "test_value"
    
    def _analyze_response(self, field_name: str, response: requests.Response, 
                         result: Dict) -> bool:
        """分析响应，判断字段名是否有效"""
        status_code = response.status_code
        response_text = str(result.get("response_body", "")).lower()
        
        # 成功响应 (200) 且没有字段错误
        if status_code == 200:
            # 检查响应中是否包含字段验证错误
            error_keywords = [
                "invalid", "error", "字段", "field", "参数",
                "missing", "required", "必须", "缺少",
            ]
            
            if any(keyword in response_text for keyword in error_keywords):
                # 响应包含错误信息，字段可能无效
                return False
            else:
                # 响应看起来正常，字段可能有效
                return True
        
        # 400 错误：可能是字段名错误
        elif status_code == 400:
            # 检查是否是字段相关的错误
            if "field" in response_text or "字段" in response_text:
                return False
            else:
                # 可能是其他类型的 400 错误
                return True
        
        # 其他状态码
        else:
            return False
    
    def discover_fields(self, endpoint: str, max_candidates: int = 100) -> List[FieldDiscoveryResult]:
        """发现有效的字段名"""
        print(f"\n开始字段名发现...")
        print(f"端点: {self.base_url}/{endpoint}")
        print(f"最大候选数: {max_candidates}")
        
        # 生成候选字段名
        candidates = self.generate_field_candidates("all")
        if len(candidates) > max_candidates:
            candidates = random.sample(candidates, max_candidates)
        
        print(f"生成 {len(candidates)} 个候选字段名")
        
        # 准备测试数据
        test_payload = {
            "action": "test",
            "openid": "test_openid_" + hashlib.md5(str(time.time()).encode()).hexdigest()[:8],
            "token": "test_token_" + hashlib.md5(str(time.time()).encode()).hexdigest()[:8],
            "timestamp": str(int(time.time())),
        }
        
        # 并发测试
        results = []
        valid_fields = []
        
        with ThreadPoolExecutor(max_workers=10) as executor:
            future_to_field = {
                executor.submit(self.test_field_candidate, endpoint, field, test_payload): field
                for field in candidates
            }
            
            for i, future in enumerate(as_completed(future_to_field), 1):
                field_name = future_to_field[future]
                
                try:
                    is_valid, test_result = future.result()
                    
                    if is_valid:
                        valid_fields.append(field_name)
                        
                        # 创建发现结果
                        result = FieldDiscoveryResult(
                            field_name=field_name,
                            confidence=0.7,  # 基础置信度
                            evidence=["API 测试通过"],
                            test_response=test_result,
                            suggested_value=self._get_suggested_value(field_name),
                        )
                        results.append(result)
                        
                        print(f"  [{i}/{len(candidates)}] ✅ 发现有效字段: {field_name}")
                    else:
                        print(f"  [{i}/{len(candidates)}] ❌ 无效字段: {field_name}")
                
                except Exception as e:
                    print(f"  [{i}/{len(candidates)}] ⚠️  测试失败: {field_name} - {str(e)[:50]}")
        
        print(f"\n发现完成!")
        print(f"有效字段数: {len(valid_fields)}")
        
        # 保存结果
        self._save_discovery_results(endpoint, results)
        
        return results
    
    def _save_discovery_results(self, endpoint: str, results: List[FieldDiscoveryResult]):
        """保存发现结果"""
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        output_file = f"sjfx_field_discovery_{timestamp}.json"
        
        data = {
            "timestamp": timestamp,
            "endpoint": endpoint,
            "base_url": self.base_url,
            "total_fields_discovered": len(results),
            "fields": [r.to_dict() for r in results],
            "detailed_results": [
                {
                    "field_name": r.field_name,
                    "test_response": r.test_response,
                }
                for r in results if r.test_response
            ],
        }
        
        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        
        print(f"结果已保存到: {output_file}")
    
    def analyze_existing_traffic(self, capture_file: str) -> List[str]:
        """分析现有的网络流量捕获"""
        print(f"\n分析网络流量捕获: {capture_file}")
        
        try:
            with open(capture_file, "r", encoding="utf-8") as f:
                data = json.load(f)
            
            discovered_fields = []
            
            # 分析请求数据
            if isinstance(data, dict):
                for key, value in data.items():
                    if isinstance(value, (str, int, float, bool)):
                        discovered_fields.append(key)
                    elif isinstance(value, dict):
                        discovered_fields.extend(self._extract_fields_from_dict(value))
            
            print(f"从流量中提取到 {len(discovered_fields)} 个字段名")
            return discovered_fields
            
        except Exception as e:
            print(f"分析失败: {str(e)}")
            return []
    
    def _extract_fields_from_dict(self, data: Dict) -> List[str]:
        """从字典中提取字段名"""
        fields = []
        
        for key, value in data.items():
            fields.append(key)
            
            if isinstance(value, dict):
                fields.extend(self._extract_fields_from_dict(value))
            elif isinstance(value, list) and value and isinstance(value[0], dict):
                for item in value[:3]:  # 只检查前几个
                    fields.extend(self._extract_fields_from_dict(item))
        
        return list(set(fields))

def main():
    """主函数"""
    print("=" * 80)
    print("高级 sjfx API 字段名解码器")
    print("=" * 80)
    
    # 初始化解码器
    decoder = AdvancedSjfxFieldDecoder()
    
    # 配置
    endpoint = "jkkListApi/healthCardApplication"
    max_candidates = 50  # 减少测试数量以加快速度
    
    # 选项菜单
    print("\n选择解码方法:")
    print("  1. 自动字段名发现 (推荐)")
    print("  2. 分析现有流量捕获")
    print("  3. 智能模式匹配")
    print("  4. 所有方法组合")
    
    choice = input("\n请输入选择 (1-4, 默认 1): ").strip() or "1"
    
    results = []
    
    if choice in ["1", "4"]:
        # 自动字段名发现
        print("\n" + "-" * 40)
        print("执行自动字段名发现...")
        discovery_results = decoder.discover_fields(endpoint, max_candidates)
        results.extend(discovery_results)
    
    if choice in ["2", "4"]:
        # 分析现有流量捕获
        print("\n" + "-" * 40)
        print("分析现有流量捕获...")
        
        # 查找可能的捕获文件
        import os
        capture_files = []
        for file in os.listdir("."):
            if "capture" in file.lower() or "traffic" in file.lower():
                if file.endswith(".json"):
                    capture_files.append(file)
        
        if capture_files:
            print(f"找到 {len(capture_files)} 个捕获文件:")
            for i, file in enumerate(capture_files, 1):
                print(f"  {i}. {file}")
            
            file_choice = input("\n选择要分析的文件 (编号): ").strip()
            if file_choice.isdigit():
                idx = int(file_choice) - 1
                if 0 <= idx < len(capture_files):
                    traffic_fields = decoder.analyze_existing_traffic(capture_files[idx])
                    print(f"从流量中发现的字段: {traffic_fields}")
        else:
            print("未找到流量捕获文件")
    
    if choice in ["3", "4"]:
        # 智能模式匹配
        print("\n" + "-" * 40)
        print("执行智能模式匹配...")
        
        # 基于业务逻辑生成智能猜测
        smart_guesses = [
            # 签约核心字段
            "signType", "signStatus", "signDate",
            "contractNo", "contractType", "contractStatus",
            
            # 人员字段
            "patientId", "patientName", "patientCardNo",
            "doctorId", "doctorName", "doctorCode",
            
            # 团队字段
            "teamId", "teamName", "teamCode",
            
            # 服务包字段
            "packageId", "packageName", "packageType",
            
            # 日期字段
            "startDate", "endDate", "validDate",
            
            # 状态字段
            "confirmStatus", "auditStatus", "reviewStatus",
            
            # 系统字段
            "createBy", "createTime", "updateBy", "updateTime",
        ]
        
        print(f"生成 {len(smart_guesses)} 个智能猜测字段")
        print("字段列表:", smart_guesses)
    
    # 总结
    print("\n" + "=" * 80)
    print("解码完成!")
    
    if results:
        print(f"\n发现的有效字段 ({len(results)} 个):")
        for result in results:
            print(f"  • {result.field_name} (置信度: {result.confidence:.1%})")
            
            if result.evidence:
                print(f"    证据: {', '.join(result.evidence[:2])}")
            
            if result.suggested_value:
                print(f"    建议值: {result.suggested_value}")
    
    print("\n建议下一步行动:")
    print("  1. 使用发现的字段进行实际 API 调用测试")
    print("  2. 验证字段的业务含义")
    print("  3. 创建完整的 API 文档")
    print("  4. 集成到现有系统中")
    print("=" * 80)

if __name__ == "__main__":
    main()