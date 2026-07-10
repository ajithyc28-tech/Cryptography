"""
Attack Simulation Module for MemCrypt Lab
Implements various memory-based attack simulations
"""

import random
import time
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass
from enum import Enum

from config import config, AttackType
from logger import logger

class MemoryRegion(Enum):
    """Memory region types"""
    STACK = "Stack"
    HEAP = "Heap"
    BSS = "BSS"

@dataclass
class AttackResult:
    """Represents the result of an attack simulation"""
    success: bool
    attack_type: AttackType
    parameters: Dict[str, Any]
    result_data: Dict[str, Any]
    mitigation: str
    
class StackSmashingAttack:
    """Simulates stack buffer overflow attacks"""
    
    def __init__(self):
        self.attack_type = AttackType.STACK_SMASH
        
    def execute(self, buffer_size: int, overflow_amount: int) -> AttackResult:
        """Execute stack smashing attack simulation"""
        logger.attack_logger.start_attack(
            "Stack Smashing",
            {"buffer_size": buffer_size, "overflow_amount": overflow_amount}
        )
        
        # Simulate attack steps
        logger.attack_logger.log_step(f"Stack buffer of {buffer_size} bytes allocated")
        logger.attack_logger.log_step(f"Sending {buffer_size + overflow_amount} bytes payload")
        logger.attack_logger.log_step(f"Overflowing {overflow_amount} bytes past buffer boundary")
        
        # Calculate overwritten addresses
        ebp_offset = buffer_size
        ret_offset = buffer_size + 4
        fake_return = 0x41414100 + random.randint(0, 255)
        
        logger.attack_logger.log_step(f"Overwriting saved EBP at offset +{ebp_offset}")
        logger.attack_logger.log_step(f"Overwriting return address at +{ret_offset} → 0x{fake_return:x}")
        
        success = overflow_amount > buffer_size
        
        if success:
            result_data = {
                "hijacked_eip": f"0x{fake_return:x}",
                "overflow_bytes": overflow_amount,
                "buffer_size": buffer_size,
                "exploit_achieved": True
            }
            mitigation = "Fix: Use fgets() instead of gets(), enable stack canaries (-fstack-protector), enable ASLR"
            logger.attack_logger.log_step("Function returns — EIP hijacked successfully!")
        else:
            result_data = {
                "overflow_bytes": overflow_amount,
                "buffer_size": buffer_size,
                "exploit_achieved": False
            }
            mitigation = "Insufficient overflow to overwrite return address"
            logger.attack_logger.log_step("Attack failed — insufficient overflow")
            
        logger.attack_logger.end_attack(success, result_data)
        
        return AttackResult(
            success=success,
            attack_type=self.attack_type,
            parameters={"buffer_size": buffer_size, "overflow_amount": overflow_amount},
            result_data=result_data,
            mitigation=mitigation
        )

class FormatStringAttack:
    """Simulates format string vulnerabilities"""
    
    def execute(self, depth: int, target_offset: int) -> AttackResult:
        """Execute format string attack simulation"""
        logger.attack_logger.start_attack(
            "Format String Attack",
            {"depth": depth, "target_offset": target_offset}
        )
        
        logger.attack_logger.log_step(f"Vulnerable call: printf(user_input)")
        logger.attack_logger.log_step(f'Injecting "%${depth}$x.%${depth}$x..." to read stack')
        
        # Simulate stack leak
        leaked_bytes = []
        for i in range(depth):
            leaked_bytes.append(random.randint(0, 0xFFFFFFFF))
            
        logger.attack_logger.log_step(f"Leaked {depth * 4} bytes from stack")
        
        got_address = 0x08049100 + (target_offset * 4)
        logger.attack_logger.log_step(f"Crafting %n payload → write to GOT[{target_offset}] @ 0x{got_address:x}")
        
        success = True  # Format string attacks usually succeed if vulnerable
        
        if success:
            result_data = {
                "leaked_values": [f"0x{x:08x}" for x in leaked_bytes[:5]],
                "got_address": f"0x{got_address:x}",
                "target_offset": target_offset,
                "exploit_achieved": True
            }
            mitigation = "Fix: Use printf('%s', input) — never pass user input as format string"
            logger.attack_logger.log_step(f"GOT entry overwritten — control flow hijacked")
        else:
            result_data = {"exploit_achieved": False}
            mitigation = "Attack failed"
            
        logger.attack_logger.end_attack(success, result_data)
        
        return AttackResult(
            success=success,
            attack_type=AttackType.FORMAT_STRING,
            parameters={"depth": depth, "target_offset": target_offset},
            result_data=result_data,
            mitigation=mitigation
        )

class HeapUAFAttack:
    """Simulates use-after-free vulnerabilities"""
    
    def execute(self, chunk_size: int, delay_ms: int) -> AttackResult:
        """Execute use-after-free attack simulation"""
        logger.attack_logger.start_attack(
            "Heap Use-After-Free",
            {"chunk_size": chunk_size, "delay_ms": delay_ms}
        )
        
        heap_address = 0x55500000 + random.randint(0, 0xFFFF)
        
        logger.attack_logger.log_step(f"malloc({chunk_size}) → chunk @ 0x{heap_address:x}")
        logger.attack_logger.log_step("Writing object data to chunk...")
        logger.attack_logger.log_step("free(ptr) — chunk returned to tcache")
        
        if delay_ms > 0:
            logger.attack_logger.log_step(f"Sleeping {delay_ms}ms (race window)...")
            time.sleep(delay_ms / 1000)  # Simulate delay
            
        logger.attack_logger.log_step(f"malloc({chunk_size}) → same chunk @ 0x{heap_address:x} (tcache hit)")
        logger.attack_logger.log_step("Overwriting vtable pointer in reused chunk")
        logger.attack_logger.log_step("Virtual call → attacker's function pointer — arbitrary code exec")
        
        success = True
        
        result_data = {
            "chunk_address": f"0x{heap_address:x}",
            "chunk_size": chunk_size,
            "delay_ms": delay_ms,
            "exploit_achieved": True
        }
        mitigation = "Fix: Set pointer to NULL after free, use smart pointers, implement heap quarantine"
        
        logger.attack_logger.end_attack(success, result_data)
        
        return AttackResult(
            success=success,
            attack_type=AttackType.HEAP_UAF,
            parameters={"chunk_size": chunk_size, "delay_ms": delay_ms},
            result_data=result_data,
            mitigation=mitigation
        )

class CodeInjectionAttack:
    """Simulates code injection via mprotect"""
    
    def execute(self, region: str, size_kb: int) -> AttackResult:
        """Execute code injection attack simulation"""
        logger.attack_logger.start_attack(
            "Code Injection via mprotect",
            {"region": region, "size_kb": size_kb}
        )
        
        base_addresses = {
            "Stack": 0x7fff0000,
            "Heap": 0x55500000,
            "BSS": 0x08049000
        }
        
        base_addr = base_addresses.get(region, 0x08049000)
        
        logger.attack_logger.log_step(f"Locating {region} base address via info leak")
        logger.attack_logger.log_step(f"{region} base @ 0x{base_addr:x}")
        logger.attack_logger.log_step(f"Calling mprotect(0x{base_addr:x}, {size_kb*1024}, PROT_READ|PROT_WRITE|PROT_EXEC)")
        logger.attack_logger.log_step(f"{region} region ({size_kb} KB) is now RWX — NX/DEP bypassed!")
        logger.attack_logger.log_step(f"Writing shellcode to 0x{base_addr:x}")
        logger.attack_logger.log_step(f"Returning to 0x{base_addr:x} — shellcode executes!")
        
        success = True
        
        result_data = {
            "region": region,
            "base_address": f"0x{base_addr:x}",
            "size_kb": size_kb,
            "rwx_created": True,
            "exploit_achieved": True
        }
        mitigation = "Fix: Enable SMEP/SMAP, implement seccomp filter on mprotect, enforce W^X at kernel level"
        
        logger.attack_logger.end_attack(success, result_data)
        
        return AttackResult(
            success=success,
            attack_type=AttackType.CODE_INJECT,
            parameters={"region": region, "size_kb": size_kb},
            result_data=result_data,
            mitigation=mitigation
        )

class AttackSimulator:
    """Main attack simulator class"""
    
    def __init__(self):
        self.stack_attack = StackSmashingAttack()
        self.format_attack = FormatStringAttack()
        self.heap_attack = HeapUAFAttack()
        self.code_attack = CodeInjectionAttack()
        
    def simulate_stack_smash(self, buffer_size: int = 64, overflow_amount: int = 76) -> AttackResult:
        """Simulate stack smashing attack"""
        logger.info(f"Launching Stack Smashing attack with buffer={buffer_size}, overflow={overflow_amount}")
        return self.stack_attack.execute(buffer_size, overflow_amount)
        
    def simulate_format_string(self, depth: int = 8, target_offset: int = 4) -> AttackResult:
        """Simulate format string attack"""
        logger.info(f"Launching Format String attack with depth={depth}, target_offset={target_offset}")
        return self.format_attack.execute(depth, target_offset)
        
    def simulate_heap_uaf(self, chunk_size: int = 64, delay_ms: int = 100) -> AttackResult:
        """Simulate heap use-after-free attack"""
        logger.info(f"Launching Heap UAF attack with chunk_size={chunk_size}, delay={delay_ms}ms")
        return self.heap_attack.execute(chunk_size, delay_ms)
        
    def simulate_code_injection(self, region: str = "Stack", size_kb: int = 4) -> AttackResult:
        """Simulate code injection attack"""
        logger.info(f"Launching Code Injection attack on {region} region ({size_kb}KB)")
        return self.code_attack.execute(region, size_kb)
        
    def get_attack_summary(self) -> Dict[str, Any]:
        """Get summary of all attacks performed"""
        return logger.attack_logger.get_attack_summary()