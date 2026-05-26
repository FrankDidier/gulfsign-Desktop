# -*- coding: utf-8 -*-
"""
配置管理器 — 支持原始 client.exe 配置格式和现有 gulfsign-desktop 格式

功能:
  1. 支持两种配置格式的加载和保存
  2. 自动迁移和兼容性处理
  3. 配置验证和默认值设置
  4. 加密敏感数据存储

配置格式说明:
  - 原始格式 (sign_config.json): 用于 client.exe，包含 license 信息
  - 现有格式 (gulfsign_config.json): 用于 gulfsign-desktop
"""

import os
import sys
import json
import logging
from typing import Dict, Any, Optional, Tuple
from pathlib import Path
import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# 常量定义
# ---------------------------------------------------------------------------

# 配置文件名
ORIGINAL_CONFIG_FILE = "sign_config.json"
CURRENT_CONFIG_FILE = "gulfsign_config.json"

# 默认配置值
DEFAULT_CONFIG = {
    # 公共配置
    "username": "",
    "password": "",
    "doctor_name": "",
    "doctor_team": "",
    "contract_date": "",  # 格式: "2026-05-15"
    "contract_years": "1",
    "del_doctor": True,
    "del_resident": True,
    "del_valid": False,
    
    # 许可证配置 (原始格式)
    "auth": {
        "user": "",
        "password": ""
    },
    
    # 手动名单 (原始格式)
    "manual_list": "",
    
    # 高级配置
    "batch_size": 2,
    "max_workers": 20,
    "enable_ssl_verify": False,
    "log_level": "INFO",
    
    # 服务器配置
    "license_server_url": "http://43.137.41.187:5004",
    "ggws_base_url": "https://ggws.hnhfpc.gov.cn",
    "health_card_base_url": "https://jkkyljl.hnhfpc.gov.cn",
    
    # 功能开关
    "enable_license_check": True,
    "enable_auto_confirm": True,
    "enable_batch_processing": True,
    "enable_excel_logging": True,
    
    # 路径配置
    "log_dir": "logs",
    "success_log_dir": "logs/成功",
    "cookie_dir": "cookies",
    "config_dir": "config",
    
    # 迁移字段 (旧格式兼容)
    "request_delay": 0.5,
    "population_type": "一般人群",
    "contract_end_date": "",
    "max_contracts": "",
    "health_card_openid": "",
    "health_card_orgcode": "",
    "health_card_team": "",
    "health_card_doctor": "",
    "health_card_start_date": "",
    "health_card_end_date": ""
}

# 加密配置
ENCRYPTION_KEY = b'4847e2f10bdee3300b580df7b861d590'  # 从原始 client.exe 提取的 AES 密钥
ENCRYPTION_NONCE = b'692e7169616e797565da3f19'  # 从原始 client.exe 提取的 nonce

# ---------------------------------------------------------------------------
# 加密工具
# ---------------------------------------------------------------------------

class ConfigEncryptor:
    """配置加密工具"""
    
    def __init__(self, key: bytes = ENCRYPTION_KEY, nonce: bytes = ENCRYPTION_NONCE):
        self.key = key
        self.nonce = nonce
    
    def encrypt(self, data: str) -> str:
        """加密字符串数据"""
        try:
            cipher = AES.new(self.key, AES.MODE_GCM, nonce=self.nonce)
            ciphertext, tag = cipher.encrypt_and_digest(data.encode('utf-8'))
            encrypted = base64.b64encode(ciphertext + tag).decode('ascii')
            return f"ENC:{encrypted}"
        except Exception as e:
            logger.error(f"加密配置失败: {e}")
            return data
    
    def decrypt(self, encrypted_data: str) -> str:
        """解密字符串数据"""
        if not encrypted_data.startswith("ENC:"):
            return encrypted_data
        
        try:
            encrypted = encrypted_data[4:]  # 移除 "ENC:" 前缀
            data = base64.b64decode(encrypted)
            ciphertext = data[:-16]  # 最后16字节是tag
            tag = data[-16:]
            
            cipher = AES.new(self.key, AES.MODE_GCM, nonce=self.nonce)
            decrypted = cipher.decrypt_and_verify(ciphertext, tag)
            return decrypted.decode('utf-8')
        except Exception as e:
            logger.error(f"解密配置失败: {e}")
            return encrypted_data
    
    def encrypt_dict(self, data_dict: Dict[str, Any]) -> Dict[str, Any]:
        """加密字典中的敏感字段"""
        encrypted_dict = data_dict.copy()
        
        # 需要加密的字段
        sensitive_fields = ['password', 'license_password', 'province_password']
        
        for field in sensitive_fields:
            if field in encrypted_dict and encrypted_dict[field]:
                encrypted_dict[field] = self.encrypt(encrypted_dict[field])
        
        # 处理嵌套的 auth 字段
        if 'auth' in encrypted_dict and isinstance(encrypted_dict['auth'], dict):
            if 'password' in encrypted_dict['auth'] and encrypted_dict['auth']['password']:
                encrypted_dict['auth']['password'] = self.encrypt(encrypted_dict['auth']['password'])
        
        return encrypted_dict
    
    def decrypt_dict(self, data_dict: Dict[str, Any]) -> Dict[str, Any]:
        """解密字典中的敏感字段"""
        decrypted_dict = data_dict.copy()
        
        # 需要解密的字段
        sensitive_fields = ['password', 'license_password', 'province_password']
        
        for field in sensitive_fields:
            if field in decrypted_dict and isinstance(decrypted_dict[field], str):
                decrypted_dict[field] = self.decrypt(decrypted_dict[field])
        
        # 处理嵌套的 auth 字段
        if 'auth' in decrypted_dict and isinstance(decrypted_dict['auth'], dict):
            if 'password' in decrypted_dict['auth'] and isinstance(decrypted_dict['auth']['password'], str):
                decrypted_dict['auth']['password'] = self.decrypt(decrypted_dict['auth']['password'])
        
        return decrypted_dict

# ---------------------------------------------------------------------------
# 配置管理器主类
# ---------------------------------------------------------------------------

class ConfigManager:
    """配置管理器主类"""
    
    def __init__(self, config_dir: Optional[str] = None):
        """
        初始化配置管理器
        
        Args:
            config_dir: 配置目录，如果为 None 则使用默认目录
        """
        if config_dir:
            self.config_dir = Path(config_dir)
        else:
            # 确定配置目录
            if getattr(sys, "frozen", False):
                base_dir = Path(sys.executable).parent
            else:
                base_dir = Path(__file__).parent
            
            self.config_dir = base_dir
        
        self.encryptor = ConfigEncryptor()
        self.config_file = self.config_dir / CURRENT_CONFIG_FILE
        self.original_config_file = self.config_dir / ORIGINAL_CONFIG_FILE
        
        logger.info(f"配置管理器初始化完成，配置目录: {self.config_dir}")
    
    def _get_default_config(self) -> Dict[str, Any]:
        """获取默认配置"""
        return DEFAULT_CONFIG.copy()
    
    def _merge_configs(self, base: Dict[str, Any], 
                      override: Dict[str, Any]) -> Dict[str, Any]:
        """深度合并两个配置字典"""
        result = base.copy()
        
        for key, value in override.items():
            if key in result and isinstance(result[key], dict) and isinstance(value, dict):
                result[key] = self._merge_configs(result[key], value)
            else:
                result[key] = value
        
        return result
    
    def _migrate_original_config(self, original_config: Dict[str, Any]) -> Dict[str, Any]:
        """迁移原始配置到新格式"""
        migrated = self._get_default_config()
        
        # 映射字段
        field_mapping = {
            'username': 'username',
            'password': 'password',
            'doctor_name': 'doctor_name',
            'doctor_team': 'doctor_team',
            'contract_date': 'contract_date',
            'contract_years': 'contract_years',
            'del_doctor': 'del_doctor',
            'del_resident': 'del_resident',
            'del_valid': 'del_valid'
        }
        
        # 复制直接映射的字段
        for orig_key, new_key in field_mapping.items():
            if orig_key in original_config:
                migrated[new_key] = original_config[orig_key]
        
        # 处理许可证信息
        if 'auth' in original_config:
            auth_data = original_config['auth']
            if isinstance(auth_data, dict):
                migrated['auth'] = auth_data.copy()
                
                # 提取许可证账号到顶级字段
                if 'user' in auth_data:
                    migrated['license_account'] = auth_data['user']
                if 'password' in auth_data:
                    migrated['license_password'] = auth_data['password']
        
        # 处理手动名单
        if 'manual_list' in original_config:
            migrated['manual_list'] = original_config['manual_list']
        
        logger.info("原始配置迁移完成")
        return migrated
    
    def _migrate_old_gulfsign_config(self, old_config: Dict[str, Any]) -> Dict[str, Any]:
        """迁移旧版 gulfsign-desktop 配置到新格式"""
        migrated = self._get_default_config()
        
        # 映射旧格式字段到新格式
        field_mapping = {
            'account': 'username',
            'org_code': 'password',
            'doctor': 'doctor_name',
            'team': 'doctor_team',
            'url': 'ggws_base_url',
            'delay': 'request_delay',
            'pop_type': 'population_type',
            'agree_start': 'contract_date',
            'agree_end': 'contract_end_date',
            'max_count': 'max_contracts',
            'hc_openid': 'health_card_openid',
            'hc_orgcode': 'health_card_orgcode',
            'hc_team': 'health_card_team',
            'hc_doctor': 'health_card_doctor',
            'hc_start': 'health_card_start_date',
            'hc_end': 'health_card_end_date'
        }
        
        # 复制映射的字段
        for old_key, new_key in field_mapping.items():
            if old_key in old_config and old_config[old_key]:
                migrated[new_key] = old_config[old_key]
        
        # 特殊处理日期字段
        if 'agree_start' in old_config and old_config['agree_start']:
            migrated['contract_date'] = old_config['agree_start']
        
        # 特殊处理延迟字段
        if 'delay' in old_config and old_config['delay']:
            try:
                # 将字符串延迟转换为浮点数
                delay_float = float(old_config['delay'])
                migrated['request_delay'] = delay_float
            except ValueError:
                migrated['request_delay'] = 0.5  # 默认值
        
        logger.info("旧版 gulfsign-desktop 配置迁移完成")
        return migrated
    
    def _validate_config(self, config: Dict[str, Any]) -> Tuple[bool, str]:
        """验证配置有效性"""
        
        # 检查必需字段
        required_fields = ['username', 'password']
        for field in required_fields:
            if not config.get(field):
                return False, f"必需字段 '{field}' 不能为空"
        
        # 检查日期格式
        if config.get('contract_date'):
            try:
                from datetime import datetime
                datetime.strptime(config['contract_date'], '%Y-%m-%d')
            except ValueError:
                return False, "合同日期格式错误，应为 YYYY-MM-DD"
        
        # 检查数字字段
        numeric_fields = ['contract_years', 'batch_size', 'max_workers']
        for field in numeric_fields:
            if field in config:
                try:
                    int(config[field])
                except ValueError:
                    return False, f"字段 '{field}' 必须为数字"
        
        return True, "配置验证通过"
    
    def load(self) -> Dict[str, Any]:
        """
        加载配置
        
        加载顺序:
          1. 现有配置文件 (gulfsign_config.json)
          2. 原始配置文件 (sign_config.json) - 如果存在则迁移
          3. 默认配置
        
        Returns:
            Dict[str, Any]: 合并后的配置
        """
        config = self._get_default_config()
        
        # 1. 尝试加载现有配置文件
        if self.config_file.exists():
            try:
                with open(self.config_file, 'r', encoding='utf-8') as f:
                    loaded_config = json.load(f)
                
                # 解密敏感数据
                loaded_config = self.encryptor.decrypt_dict(loaded_config)
                
                # 检查是否为旧格式配置 (包含 'account' 字段但不包含 'username' 字段)
                if 'account' in loaded_config and 'username' not in loaded_config:
                    logger.info(f"检测到旧格式配置文件，开始迁移: {self.config_file}")
                    # 迁移旧格式配置
                    migrated_config = self._migrate_old_gulfsign_config(loaded_config)
                    # 合并迁移后的配置
                    config = self._merge_configs(config, migrated_config)
                    logger.info(f"旧格式配置文件迁移成功: {self.config_file}")
                    
                    # 保存迁移后的配置（跳过验证，因为必填字段可能为空）
                    self.save(config, validate=False)
                    logger.info(f"迁移后的配置已保存: {self.config_file}")
                else:
                    # 合并配置 (新格式)
                    config = self._merge_configs(config, loaded_config)
                    logger.info(f"现有配置文件加载成功: {self.config_file}")
                
            except Exception as e:
                logger.error(f"加载现有配置文件失败: {e}")
        
        # 2. 尝试加载并迁移原始配置文件
        if self.original_config_file.exists():
            try:
                with open(self.original_config_file, 'r', encoding='utf-8') as f:
                    original_config = json.load(f)
                
                # 迁移原始配置
                migrated_config = self._migrate_original_config(original_config)
                
                # 合并配置 (原始配置优先级较低)
                config = self._merge_configs(config, migrated_config)
                logger.info(f"原始配置文件迁移成功: {self.original_config_file}")
                
            except Exception as e:
                logger.error(f"加载原始配置文件失败: {e}")
        
        # 验证配置
        is_valid, message = self._validate_config(config)
        if not is_valid:
            logger.warning(f"配置验证警告: {message}")
        
        logger.info("配置加载完成")
        return config
    
    def save(self, config: Dict[str, Any], validate: bool = True) -> bool:
        """
        保存配置
        
        Args:
            config: 配置字典
            validate: 是否验证配置，默认为 True
            
        Returns:
            bool: 保存是否成功
        """
        try:
            # 验证配置（可选）
            if validate:
                is_valid, message = self._validate_config(config)
                if not is_valid:
                    logger.error(f"配置验证失败: {message}")
                    return False
            
            # 创建配置目录
            self.config_file.parent.mkdir(parents=True, exist_ok=True)
            
            # 加密敏感数据
            encrypted_config = self.encryptor.encrypt_dict(config)
            
            # 保存配置
            with open(self.config_file, 'w', encoding='utf-8') as f:
                json.dump(encrypted_config, f, ensure_ascii=False, indent=2)
            
            logger.info(f"配置保存成功: {self.config_file}")
            return True
            
        except Exception as e:
            logger.error(f"保存配置失败: {e}")
            return False
    
    def export_original_format(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """
        导出为原始配置格式
        
        Args:
            config: 当前格式的配置
            
        Returns:
            Dict[str, Any]: 原始格式的配置
        """
        original_format = {}
        
        # 映射字段到原始格式
        field_mapping = {
            'username': 'username',
            'password': 'password',
            'doctor_name': 'doctor_name',
            'doctor_team': 'doctor_team',
            'contract_date': 'contract_date',
            'contract_years': 'contract_years',
            'del_doctor': 'del_doctor',
            'del_resident': 'del_resident',
            'del_valid': 'del_valid'
        }
        
        # 复制直接映射的字段
        for new_key, orig_key in field_mapping.items():
            if new_key in config:
                original_format[orig_key] = config[new_key]
        
        # 构建 auth 字段
        auth_data = {}
        if 'license_account' in config:
            auth_data['user'] = config['license_account']
        if 'license_password' in config:
            auth_data['password'] = config['license_password']
        
        # 如果 auth 字段有数据，则添加到配置中
        if auth_data:
            original_format['auth'] = auth_data
        
        # 添加 manual_list
        if 'manual_list' in config:
            original_format['manual_list'] = config['manual_list']
        
        return original_format
    
    def save_original_format(self, config: Dict[str, Any]) -> bool:
        """
        保存为原始配置格式
        
        Args:
            config: 当前格式的配置
            
        Returns:
            bool: 保存是否成功
        """
        try:
            # 导出为原始格式
            original_config = self.export_original_format(config)
            
            # 保存文件
            with open(self.original_config_file, 'w', encoding='utf-8') as f:
                json.dump(original_config, f, ensure_ascii=False, indent=2)
            
            logger.info(f"原始格式配置保存成功: {self.original_config_file}")
            return True
            
        except Exception as e:
            logger.error(f"保存原始格式配置失败: {e}")
            return False
    
    def get_license_config(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """
        提取许可证配置
        
        Args:
            config: 完整配置
            
        Returns:
            Dict[str, Any]: 许可证配置
        """
        license_config = {
            'account': config.get('license_account', ''),
            'password': config.get('license_password', ''),
            'server_url': config.get('license_server_url', 'http://43.137.41.187:5004')
        }
        
        # 如果 auth 字段中有数据，优先使用
        if 'auth' in config and isinstance(config['auth'], dict):
            auth_data = config['auth']
            if 'user' in auth_data and not license_config['account']:
                license_config['account'] = auth_data['user']
            if 'password' in auth_data and not license_config['password']:
                license_config['password'] = auth_data['password']
        
        return license_config
    
    def update_field(self, config: Dict[str, Any], 
                    field_path: str, value: Any) -> Dict[str, Any]:
        """
        更新配置字段
        
        Args:
            config: 当前配置
            field_path: 字段路径，支持点号分隔 (如 "auth.user")
            value: 新值
            
        Returns:
            Dict[str, Any]: 更新后的配置
        """
        updated_config = config.copy()
        
        # 分割字段路径
        parts = field_path.split('.')
        current = updated_config
        
        # 遍历到最后一个部分
        for i, part in enumerate(parts[:-1]):
            if part not in current:
                current[part] = {}
            current = current[part]
        
        # 设置值
        current[parts[-1]] = value
        
        return updated_config

# ---------------------------------------------------------------------------
# 工具函数
# ---------------------------------------------------------------------------

def get_config_dir() -> Path:
    """获取配置目录"""
    if getattr(sys, "frozen", False):
        base_dir = Path(sys.executable).parent
    else:
        base_dir = Path(__file__).parent.parent
    
    return base_dir

def load_config() -> Dict[str, Any]:
    """加载配置 (兼容现有代码)"""
    manager = ConfigManager()
    return manager.load()

def save_config(config: Dict[str, Any]) -> bool:
    """保存配置 (兼容现有代码)"""
    manager = ConfigManager()
    return manager.save(config)

# ---------------------------------------------------------------------------
# 使用示例
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    # 设置日志
    logging.basicConfig(level=logging.INFO)
    
    print("=== 配置管理器示例 ===")
    
    # 创建配置管理器
    manager = ConfigManager()
    
    # 加载配置
    config = manager.load()
    print(f"✓ 配置加载成功，用户名: {config.get('username', '未设置')}")
    
    # 更新配置
    config['username'] = "test_user"
    config['password'] = "test_password"
    config['license_account'] = "license_test"
    config['license_password'] = "license_password"
    
    # 保存配置
    if manager.save(config):
        print("✓ 配置保存成功")
    
    # 导出为原始格式
    original_config = manager.export_original_format(config)
    print(f"✓ 原始格式导出成功，auth.user: {original_config.get('auth', {}).get('user', '未设置')}")
    
    # 获取许可证配置
    license_config = manager.get_license_config(config)
    print(f"✓ 许可证配置提取成功，账号: {license_config.get('account', '未设置')}")
    
    print("\n配置管理器实现完成，支持原始 client.exe 配置格式和现有格式。")