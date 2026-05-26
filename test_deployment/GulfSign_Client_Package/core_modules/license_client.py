# -*- coding: utf-8 -*-
"""
湾流签约助手 — 许可证客户端

基于反编译的 jiami.pyc 实现，提供与原始 client.exe 相同的许可证验证和配额消耗功能。
支持与 http://43.137.41.187:5004 服务器的 RSA+AES 加密通信。

核心功能:
  1. 许可证验证 (/yanzheng)
  2. 配额消耗 (/xiaohao)
  3. 加密请求/响应处理
  4. 服务器签名验证

注意: 此实现使用原始 client.exe 中提取的 RSA 公钥和服务器地址。
"""

import os
import json
import base64
import time
import logging
from typing import Dict, Optional, Tuple, Any
from dataclasses import dataclass, field

import requests
from Crypto.Cipher import AES, PKCS1_v1_5
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# 常量配置 (从原始 client.exe 提取)
# ---------------------------------------------------------------------------

# 许可证服务器配置
SERVER_URL = os.environ.get('QIANYUE_SERVER_URL', 'http://43.137.41.187:5004')
VERIFY_ENDPOINT = '/yanzheng'
CONSUME_ENDPOINT = '/xiaohao'

# RSA 公钥 (从原始 jiami.pyc 提取)
RSA_PUBLIC_KEY_PEM = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArhpc0nwDJ2pgZflesOD+
30Yyq42YdczhFTO/oi0QhC9rzMr7yDUsp+xRNw03lLmDd24fyUVosUd+TNEYTg21
TY56DRroQJjkUcWxoDcO3naEK4epDDBjFVqcyAIvVxXmyk6NhfHk4GkUCDg8o5xf
/7SSQ8KZBdo6+lXhPhvn3GRu4IJ9oSZyigiemWUxSmPhb6i2ypfCx9LEDYAk4CCu
SEwBO7w59kZ5WsGw5ndZrVkMDbYB+fHVj5xmCkt5GXOMphhSUjjQcQQJmWGrJIOS
5CSrIRn+DIov/pI0CdY2MKgSQ8fPJax5L2vTTV3HMWknlMDY08nRFpOMBP9b0Rdn
DQIDAQAB
-----END PUBLIC KEY-----"""

# 调试模式配置
DEBUG_MODE = os.environ.get('QIANYUE_DEBUG') == '1'
if DEBUG_MODE:
    SERVER_URL = os.environ.get('QIANYUE_SERVER_URL', 'http://127.0.0.1:5004')
    logger.info(f"调试模式启用，服务器地址: {SERVER_URL}")

# ---------------------------------------------------------------------------
# 数据类定义
# ---------------------------------------------------------------------------

@dataclass
class LicenseResponse:
    """许可证服务器响应"""
    success: bool
    message: str
    data: Dict[str, Any] = field(default_factory=dict)
    error_code: Optional[int] = None
    timestamp: int = field(default_factory=lambda: int(time.time() * 1000))

@dataclass
class LicenseConfig:
    """许可证配置"""
    account: str
    password: str
    server_url: str = SERVER_URL
    verify_endpoint: str = VERIFY_ENDPOINT
    consume_endpoint: str = CONSUME_ENDPOINT

# ---------------------------------------------------------------------------
# 加密工具类
# ---------------------------------------------------------------------------

class LicenseCrypto:
    """许可证加密工具类，实现与原始 client.exe 相同的加密逻辑"""
    
    def __init__(self):
        # 加载 RSA 公钥
        self.public_key = RSA.import_key(RSA_PUBLIC_KEY_PEM)
        logger.debug("RSA 公钥加载成功")
    
    def generate_aes_key_iv(self) -> Tuple[bytes, bytes]:
        """生成 AES 密钥 (256位) 和 IV (128位)"""
        aes_key = get_random_bytes(32)  # 256位
        aes_iv = get_random_bytes(16)   # 128位
        return aes_key, aes_iv
    
    def aes_encrypt(self, data: bytes, key: bytes, iv: bytes) -> bytes:
        """AES-CBC 加密数据 (PKCS#7 填充)"""
        cipher = AES.new(key, AES.MODE_CBC, iv)
        padded_data = pad(data, AES.block_size)
        encrypted = cipher.encrypt(padded_data)
        return encrypted
    
    def aes_decrypt(self, encrypted_data: bytes, key: bytes, iv: bytes) -> bytes:
        """AES-CBC 解密数据"""
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted_padded = cipher.decrypt(encrypted_data)
        decrypted = unpad(decrypted_padded, AES.block_size)
        return decrypted
    
    def rsa_encrypt_short_data(self, data: bytes) -> bytes:
        """使用 RSA 公钥加密短数据 (仅用于加密 AES 密钥)"""
        cipher = PKCS1_v1_5.new(self.public_key)
        encrypted = cipher.encrypt(data)
        return encrypted
    
    def verify_server_signature(self, data: bytes, signature: bytes) -> bool:
        """验证服务器响应的签名"""
        try:
            # 计算数据的 SHA256 哈希
            hash_obj = SHA256.new(data)
            
            # 验证签名
            verifier = pkcs1_15.new(self.public_key)
            verifier.verify(hash_obj, signature)
            return True
        except (ValueError, TypeError):
            logger.warning("服务器签名验证失败")
            return False
    
    def create_encrypted_request(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """创建加密请求包 (修复RSA长度限制问题)"""
        
        # 生成 AES 密钥和 IV
        aes_key, aes_iv = self.generate_aes_key_iv()
        
        # 将 payload 转换为 JSON 字符串并编码为 bytes
        payload_json = json.dumps(payload, ensure_ascii=False)
        payload_bytes = payload_json.encode('utf-8')
        
        # 使用 AES 加密 payload
        encrypted_payload = self.aes_encrypt(payload_bytes, aes_key, aes_iv)
        
        # 使用 RSA 加密 AES 密钥
        encrypted_aes_key = self.rsa_encrypt_short_data(aes_key)
        
        # 构建请求数据
        request_data = {
            'encrypted_key': base64.b64encode(encrypted_aes_key).decode('ascii'),
            'encrypted_iv': base64.b64encode(aes_iv).decode('ascii'),
            'encrypted_data': base64.b64encode(encrypted_payload).decode('ascii'),
            'timestamp': int(time.time() * 1000)
        }
        
        return request_data
    
    def process_server_response(self, response_data: Dict[str, Any], 
                               aes_key: bytes, aes_iv: bytes) -> Dict[str, Any]:
        """处理服务器响应的通用函数 (包含AES解密)"""
        
        try:
            # 解码加密数据
            encrypted_data = base64.b64decode(response_data.get('encrypted_data', ''))
            
            # 使用 AES 解密数据
            decrypted_bytes = self.aes_decrypt(encrypted_data, aes_key, aes_iv)
            
            # 将解密后的 bytes 转换为 JSON
            decrypted_json = decrypted_bytes.decode('utf-8')
            result = json.loads(decrypted_json)
            
            return result
            
        except Exception as e:
            logger.error(f"处理服务器响应失败: {e}")
            raise

# ---------------------------------------------------------------------------
# 许可证客户端主类
# ---------------------------------------------------------------------------

class LicenseClient:
    """许可证客户端主类"""
    
    def __init__(self, config: Optional[LicenseConfig] = None):
        """
        初始化许可证客户端
        
        Args:
            config: 许可证配置，如果为 None 则使用默认配置
        """
        self.config = config or LicenseConfig(account="", password="")
        self.crypto = LicenseCrypto()
        self.session = requests.Session()
        
        # 禁用 SSL 验证 (与原始 client.exe 行为一致)
        self.session.verify = False
        requests.packages.urllib3.disable_warnings()
        
        logger.info(f"许可证客户端初始化完成，服务器: {self.config.server_url}")
    
    def _make_request(self, endpoint: str, payload: Dict[str, Any]) -> LicenseResponse:
        """
        发送加密请求到许可证服务器
        
        Args:
            endpoint: 服务器端点
            payload: 请求数据
            
        Returns:
            LicenseResponse: 服务器响应
        """
        try:
            # 创建加密请求
            encrypted_request = self.crypto.create_encrypted_request(payload)
            
            # 发送请求
            url = f"{self.config.server_url}{endpoint}"
            headers = {
                'Content-Type': 'application/json',
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }
            
            response = self.session.post(
                url, 
                json=encrypted_request,
                headers=headers,
                timeout=30
            )
            
            # 检查 HTTP 状态码
            if response.status_code != 200:
                return LicenseResponse(
                    success=False,
                    message=f"服务器返回错误状态码: {response.status_code}",
                    error_code=response.status_code
                )
            
            # 解析响应
            response_data = response.json()
            
            # 验证服务器签名 (如果提供了签名)
            if 'signature' in response_data:
                signature = base64.b64decode(response_data['signature'])
                data_to_verify = json.dumps(response_data.get('data', {})).encode('utf-8')
                
                if not self.crypto.verify_server_signature(data_to_verify, signature):
                    return LicenseResponse(
                        success=False,
                        message="服务器签名验证失败",
                        error_code=1001
                    )
            
            # 提取响应数据
            result_data = response_data.get('data', {})
            
            return LicenseResponse(
                success=response_data.get('success', False),
                message=response_data.get('message', ''),
                data=result_data,
                error_code=response_data.get('error_code')
            )
            
        except requests.exceptions.Timeout:
            return LicenseResponse(
                success=False,
                message="请求超时",
                error_code=1002
            )
        except requests.exceptions.ConnectionError:
            return LicenseResponse(
                success=False,
                message="连接服务器失败",
                error_code=1003
            )
        except Exception as e:
            logger.error(f"请求处理异常: {e}")
            return LicenseResponse(
                success=False,
                message=f"请求处理异常: {str(e)}",
                error_code=1000
            )
    
    def verify_license(self, account: Optional[str] = None, 
                      password: Optional[str] = None) -> LicenseResponse:
        """
        验证许可证
        
        Args:
            account: 许可证账号，如果为 None 则使用配置中的账号
            password: 许可证密码，如果为 None 则使用配置中的密码
            
        Returns:
            LicenseResponse: 验证结果
        """
        account = account or self.config.account
        password = password or self.config.password
        
        if not account or not password:
            return LicenseResponse(
                success=False,
                message="许可证账号或密码不能为空",
                error_code=1004
            )
        
        # 构建验证请求数据
        payload = {
            'verson': 2,  # 注意: 原始代码中有拼写错误 'verson' 而不是 'version'
            'license_account': account,
            'license_password': password
        }
        
        logger.info(f"开始验证许可证: {account}")
        response = self._make_request(self.config.verify_endpoint, payload)
        
        if response.success:
            logger.info(f"许可证验证成功: {account}")
        else:
            logger.warning(f"许可证验证失败: {account} - {response.message}")
        
        return response
    
    def consume_quota(self, account: Optional[str] = None,
                     password: Optional[str] = None,
                     person_data: Optional[Dict[str, Any]] = None) -> LicenseResponse:
        """
        消耗配额 (每签约一个人消耗一次)
        
        Args:
            account: 许可证账号，如果为 None 则使用配置中的账号
            password: 许可证密码，如果为 None 则使用配置中的密码
            person_data: 签约人员数据
            
        Returns:
            LicenseResponse: 消耗结果
        """
        account = account or self.config.account
        password = password or self.config.password
        
        if not account or not password:
            return LicenseResponse(
                success=False,
                message="许可证账号或密码不能为空",
                error_code=1004
            )
        
        # 构建配额消耗请求数据
        payload = {
            'verson': 2,
            'license_account': account,
            'license_password': password,
            'action': 'person_confirm_contract',
            'data': person_data or {}
        }
        
        logger.info(f"开始消耗配额: {account}")
        response = self._make_request(self.config.consume_endpoint, payload)
        
        if response.success:
            logger.info(f"配额消耗成功: {account}")
        else:
            logger.warning(f"配额消耗失败: {account} - {response.message}")
        
        return response
    
    def test_connection(self) -> bool:
        """
        测试与许可证服务器的连接
        
        Returns:
            bool: 连接是否成功
        """
        try:
            url = f"{self.config.server_url}/health"
            response = self.session.get(url, timeout=10)
            return response.status_code == 200
        except:
            # 如果 /health 端点不存在，尝试连接主地址
            try:
                url = self.config.server_url
                response = self.session.get(url, timeout=10)
                return True
            except:
                return False
    
    def close(self):
        """关闭客户端"""
        self.session.close()
        logger.info("许可证客户端已关闭")

# ---------------------------------------------------------------------------
# 工具函数
# ---------------------------------------------------------------------------

def create_license_client_from_config(config_dict: Dict[str, Any]) -> LicenseClient:
    """
    从配置字典创建许可证客户端
    
    Args:
        config_dict: 配置字典，包含 account, password 等字段
        
    Returns:
        LicenseClient: 许可证客户端实例
    """
    config = LicenseConfig(
        account=config_dict.get('account', ''),
        password=config_dict.get('password', ''),
        server_url=config_dict.get('server_url', SERVER_URL)
    )
    
    return LicenseClient(config)

def load_license_config(file_path: str) -> LicenseConfig:
    """
    从文件加载许可证配置
    
    Args:
        file_path: 配置文件路径
        
    Returns:
        LicenseConfig: 许可证配置
    """
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            config_data = json.load(f)
        
        return LicenseConfig(
            account=config_data.get('license_account', ''),
            password=config_data.get('license_password', ''),
            server_url=config_data.get('license_server_url', SERVER_URL)
        )
    except Exception as e:
        logger.error(f"加载许可证配置失败: {e}")
        return LicenseConfig(account="", password="")

# ---------------------------------------------------------------------------
# 使用示例
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    # 设置日志
    logging.basicConfig(level=logging.INFO)
    
    # 示例 1: 使用默认配置
    print("=== 示例 1: 使用默认配置 ===")
    client = LicenseClient()
    
    # 测试连接
    if client.test_connection():
        print("✓ 服务器连接成功")
    else:
        print("✗ 服务器连接失败")
    
    # 示例 2: 使用自定义配置
    print("\n=== 示例 2: 使用自定义配置 ===")
    config = LicenseConfig(
        account="test_account",
        password="test_password"
    )
    client2 = LicenseClient(config)
    
    # 验证许可证 (示例，需要真实账号密码)
    # response = client2.verify_license()
    # print(f"验证结果: {response.success}, 消息: {response.message}")
    
    # 关闭客户端
    client.close()
    client2.close()
    
    print("\n许可证客户端实现完成，已集成原始 client.exe 的加密通信逻辑。")