"""
Cryptographic Engine Module for MemCrypt Lab
Handles key generation, encryption, decryption, and hashing
"""

import hashlib
import base64
import os
import random
import struct
from typing import Dict, Any, Optional, Tuple, Union
from dataclasses import dataclass
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes

from config import config, CryptoAlgorithm, HashAlgorithm
from logger import logger

@dataclass
class KeyInfo:
    """Represents cryptographic key information"""
    algorithm: CryptoAlgorithm
    key_data: Union[str, bytes]
    key_size: int
    public_key: Optional[bytes] = None
    private_key: Optional[bytes] = None
    
class AESEngine:
    """AES encryption/decryption engine"""
    
    def __init__(self, key_size: int = 256):
        self.key_size = key_size
        self.key: Optional[bytes] = None
        self.key_info: Optional[KeyInfo] = None
        
    def generate_key(self) -> KeyInfo:
        """Generate a new AES key"""
        key_bytes = get_random_bytes(self.key_size // 8)
        self.key = key_bytes
        
        self.key_info = KeyInfo(
            algorithm=CryptoAlgorithm.AES_256 if self.key_size == 256 else CryptoAlgorithm.AES_128,
            key_data=key_bytes.hex(),
            key_size=self.key_size
        )
        
        logger.info(f"AES-{self.key_size} key generated successfully")
        return self.key_info
        
    def encrypt(self, plaintext: str, key: Optional[bytes] = None) -> Dict[str, str]:
        """Encrypt plaintext using AES-GCM"""
        if key is None:
            key = self.key
            
        if key is None:
            raise ValueError("No key available. Generate a key first.")
            
        # Generate random IV
        iv = get_random_bytes(12)
        
        # Create cipher
        cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
        
        # Encrypt
        plaintext_bytes = plaintext.encode('utf-8')
        ciphertext, tag = cipher.encrypt_and_digest(plaintext_bytes)
        
        result = {
            "iv": iv.hex(),
            "ciphertext": ciphertext.hex(),
            "tag": tag.hex()
        }
        
        logger.info(f"AES encryption completed: {len(plaintext)} bytes → {len(ciphertext)} bytes")
        return result
        
    def decrypt(self, ciphertext_hex: str, iv_hex: str, tag_hex: str, key: Optional[bytes] = None) -> str:
        """Decrypt ciphertext using AES-GCM"""
        if key is None:
            key = self.key
            
        if key is None:
            raise ValueError("No key available for decryption")
            
        # Convert hex to bytes
        ciphertext = bytes.fromhex(ciphertext_hex)
        iv = bytes.fromhex(iv_hex)
        tag = bytes.fromhex(tag_hex)
        
        # Create cipher
        cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
        
        # Decrypt
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        
        result = plaintext.decode('utf-8')
        logger.info(f"AES decryption completed: {len(ciphertext)} bytes → {len(result)} bytes")
        return result

class RSAEngine:
    """RSA encryption/decryption engine"""
    
    def __init__(self, key_size: int = 2048):
        self.key_size = key_size
        self.private_key: Optional[RSA.RsaKey] = None
        self.public_key: Optional[RSA.RsaKey] = None
        self.key_info: Optional[KeyInfo] = None
        
    def generate_keypair(self) -> KeyInfo:
        """Generate RSA key pair"""
        logger.info(f"Generating RSA-{self.key_size} key pair...")
        
        key = RSA.generate(self.key_size)
        self.private_key = key
        self.public_key = key.publickey()
        
        # Export keys
        private_bytes = key.export_key('DER')
        public_bytes = self.public_key.export_key('DER')
        
        self.key_info = KeyInfo(
            algorithm=CryptoAlgorithm.RSA_2048,
            key_data=public_bytes.hex(),
            key_size=self.key_size,
            public_key=public_bytes,
            private_key=private_bytes
        )
        
        logger.info(f"RSA-{self.key_size} key pair generated successfully")
        return self.key_info
        
    def encrypt(self, plaintext: str, public_key: Optional[RSA.RsaKey] = None) -> str:
        """Encrypt plaintext using RSA-OAEP"""
        if public_key is None:
            public_key = self.public_key
            
        if public_key is None:
            raise ValueError("No public key available")
            
        cipher = PKCS1_OAEP.new(public_key)
        plaintext_bytes = plaintext.encode('utf-8')
        
        # RSA can only encrypt data up to key size - padding
        max_chunk_size = self.key_size // 8 - 42  # OAEP padding overhead
        encrypted_chunks = []
        
        for i in range(0, len(plaintext_bytes), max_chunk_size):
            chunk = plaintext_bytes[i:i + max_chunk_size]
            encrypted_chunk = cipher.encrypt(chunk)
            encrypted_chunks.append(encrypted_chunk)
            
        ciphertext = b''.join(encrypted_chunks)
        result = ciphertext.hex()
        
        logger.info(f"RSA encryption completed: {len(plaintext)} bytes → {len(ciphertext)} bytes")
        return result
        
    def decrypt(self, ciphertext_hex: str, private_key: Optional[RSA.RsaKey] = None) -> str:
        """Decrypt ciphertext using RSA-OAEP"""
        if private_key is None:
            private_key = self.private_key
            
        if private_key is None:
            raise ValueError("No private key available")
            
        cipher = PKCS1_OAEP.new(private_key)
        ciphertext = bytes.fromhex(ciphertext_hex)
        
        # Decrypt in chunks
        chunk_size = self.key_size // 8
        decrypted_chunks = []
        
        for i in range(0, len(ciphertext), chunk_size):
            chunk = ciphertext[i:i + chunk_size]
            decrypted_chunk = cipher.decrypt(chunk)
            decrypted_chunks.append(decrypted_chunk)
            
        plaintext = b''.join(decrypted_chunks).decode('utf-8')
        
        logger.info(f"RSA decryption completed: {len(ciphertext)} bytes → {len(plaintext)} bytes")
        return plaintext

class HashEngine:
    """Hash generation engine"""
    
    @staticmethod
    def md5(data: str) -> str:
        """Generate MD5 hash (for educational purposes only)"""
        hash_obj = hashlib.md5(data.encode('utf-8'))
        result = hash_obj.hexdigest()
        logger.info(f"MD5 hash generated: {len(data)} bytes → {len(result)} chars")
        return result
        
    @staticmethod
    def sha1(data: str) -> str:
        """Generate SHA-1 hash"""
        hash_obj = hashlib.sha1(data.encode('utf-8'))
        result = hash_obj.hexdigest()
        logger.info(f"SHA-1 hash generated: {len(data)} bytes → {len(result)} chars")
        return result
        
    @staticmethod
    def sha256(data: str) -> str:
        """Generate SHA-256 hash"""
        hash_obj = hashlib.sha256(data.encode('utf-8'))
        result = hash_obj.hexdigest()
        logger.info(f"SHA-256 hash generated: {len(data)} bytes → {len(result)} chars")
        return result
        
    def generate_hash(self, data: str, algorithm: HashAlgorithm) -> str:
        """Generate hash using specified algorithm"""
        if algorithm == HashAlgorithm.MD5:
            return self.md5(data)
        elif algorithm == HashAlgorithm.SHA1:
            return self.sha1(data)
        elif algorithm == HashAlgorithm.SHA256:
            return self.sha256(data)
        else:
            raise ValueError(f"Unsupported hash algorithm: {algorithm}")

class CryptoEngine:
    """Main cryptographic engine class"""
    
    def __init__(self):
        self.aes_engine = AESEngine()
        self.rsa_engine = RSAEngine()
        self.hash_engine = HashEngine()
        self.current_algorithm: Optional[CryptoAlgorithm] = None
        self.last_encryption_result: Optional[Dict[str, str]] = None
        
    def generate_key(self, algorithm: str) -> KeyInfo:
        """Generate key for specified algorithm"""
        if algorithm == "aes128":
            self.aes_engine = AESEngine(128)
            self.current_algorithm = CryptoAlgorithm.AES_128
            return self.aes_engine.generate_key()
        elif algorithm == "aes256":
            self.aes_engine = AESEngine(256)
            self.current_algorithm = CryptoAlgorithm.AES_256
            return self.aes_engine.generate_key()
        elif algorithm == "rsa2048":
            self.current_algorithm = CryptoAlgorithm.RSA_2048
            return self.rsa_engine.generate_keypair()
        else:
            raise ValueError(f"Unsupported algorithm: {algorithm}")
            
    def encrypt(self, plaintext: str) -> Dict[str, str]:
        """Encrypt plaintext using current algorithm"""
        if self.current_algorithm in [CryptoAlgorithm.AES_128, CryptoAlgorithm.AES_256]:
            result = self.aes_engine.encrypt(plaintext)
            self.last_encryption_result = result
            return result
        elif self.current_algorithm == CryptoAlgorithm.RSA_2048:
            ciphertext = self.rsa_engine.encrypt(plaintext)
            result = {"ciphertext": ciphertext}
            self.last_encryption_result = result
            return result
        else:
            raise ValueError("No algorithm selected. Generate a key first.")
            
    def decrypt(self, ciphertext_data: Dict[str, str]) -> str:
        """Decrypt ciphertext using current algorithm"""
        if self.current_algorithm in [CryptoAlgorithm.AES_128, CryptoAlgorithm.AES_256]:
            return self.aes_engine.decrypt(
                ciphertext_data["ciphertext"],
                ciphertext_data["iv"],
                ciphertext_data["tag"]
            )
        elif self.current_algorithm == CryptoAlgorithm.RSA_2048:
            return self.rsa_engine.decrypt(ciphertext_data["ciphertext"])
        else:
            raise ValueError("No algorithm selected or invalid algorithm")
            
    def hash(self, data: str, algorithm: str) -> str:
        """Generate hash of data using specified algorithm"""
        hash_algo_map = {
            "md5": HashAlgorithm.MD5,
            "sha1": HashAlgorithm.SHA1,
            "sha256": HashAlgorithm.SHA256
        }
        
        algo = hash_algo_map.get(algorithm)
        if algo is None:
            raise ValueError(f"Unsupported hash algorithm: {algorithm}")
            
        return self.hash_engine.generate_hash(data, algo)