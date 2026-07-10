"""
Configuration Module for MemCrypt Lab
Handles all configuration settings and constants
"""

import os
from typing import Dict, Any, List
from dataclasses import dataclass
from enum import Enum

class AttackType(Enum):
    """Enumeration of available attack types"""
    STACK_SMASH = "stack_smashing"
    FORMAT_STRING = "format_string"
    HEAP_UAF = "heap_uaf"
    CODE_INJECT = "code_injection"

class CryptoAlgorithm(Enum):
    """Enumeration of cryptographic algorithms"""
    AES_128 = "aes128"
    AES_256 = "aes256"
    RSA_2048 = "rsa2048"

class HashAlgorithm(Enum):
    """Enumeration of hash algorithms"""
    MD5 = "md5"
    SHA1 = "sha1"
    SHA256 = "sha256"

@dataclass
class AttackConfig:
    """Configuration for attack simulations"""
    stack_buffer_sizes: List[int] = None
    format_depth_range: tuple = (1, 20)
    heap_chunk_sizes: List[int] = None
    rwx_region_sizes: List[int] = None
    
    def __post_init__(self):
        if self.stack_buffer_sizes is None:
            self.stack_buffer_sizes = [8, 16, 32, 64, 128, 256]
        if self.heap_chunk_sizes is None:
            self.heap_chunk_sizes = [8, 16, 32, 64, 128, 256]
        if self.rwx_region_sizes is None:
            self.rwx_region_sizes = [1, 4, 8, 16, 32, 64]

@dataclass
class CryptoConfig:
    """Configuration for cryptographic operations"""
    aes_key_sizes: Dict[str, int] = None
    rsa_key_size: int = 2048
    gcm_iv_length: int = 12
    supported_hash_algorithms: List[str] = None
    
    def __post_init__(self):
        if self.aes_key_sizes is None:
            self.aes_key_sizes = {"aes128": 128, "aes256": 256}
        if self.supported_hash_algorithms is None:
            self.supported_hash_algorithms = ["md5", "sha1", "sha256"]

class Config:
    """Main configuration class"""
    
    def __init__(self):
        self.attack_config = AttackConfig()
        self.crypto_config = CryptoConfig()
        self.log_level = "INFO"
        self.output_format = "json"
        self.enable_simulation_mode = True
        
    def get_attack_parameters(self, attack_type: AttackType) -> Dict[str, Any]:
        """Get parameters for specific attack type"""
        parameters = {
            AttackType.STACK_SMASH: {
                "buffer_sizes": self.attack_config.stack_buffer_sizes,
                "default_buffer": 64,
                "overflow_offset": 4  # bytes for return address
            },
            AttackType.FORMAT_STRING: {
                "depth_range": self.attack_config.format_depth_range,
                "default_depth": 8,
                "got_offset_default": 4
            },
            AttackType.HEAP_UAF: {
                "chunk_sizes": self.attack_config.heap_chunk_sizes,
                "default_chunk_size": 64,
                "delay_range": (0, 500)
            },
            AttackType.CODE_INJECT: {
                "regions": ["Stack", "Heap", "BSS"],
                "region_sizes": self.attack_config.rwx_region_sizes,
                "default_size": 4
            }
        }
        return parameters.get(attack_type, {})
    
    def get_crypto_settings(self) -> Dict[str, Any]:
        """Get cryptographic settings"""
        return {
            "aes_modes": ["GCM"],
            "rsa_padding": "OAEP",
            "hash_algorithms": self.crypto_config.supported_hash_algorithms,
            "iv_length": self.crypto_config.gcm_iv_length
        }

# Global configuration instance
config = Config()