"""
Main Application Module for MemCrypt Lab
Entry point and CLI interface for the application
"""

import argparse
import json
import sys
from typing import Dict, Any, Optional
from colorama import init, Fore, Style

from config import config, AttackType
from logger import logger, LogLevel
from attack_simulator import AttackSimulator
from crypto_engine import CryptoEngine, KeyInfo

# Initialize colorama for cross-platform colored output
init()

class MemCryptLab:
    """Main application class for MemCrypt Lab"""
    
    def __init__(self):
        self.attack_simulator = AttackSimulator()
        self.crypto_engine = CryptoEngine()
        self.current_key: Optional[KeyInfo] = None
        
    def run(self, args: argparse.Namespace) -> None:
        """Run the application based on CLI arguments"""
        if args.attack:
            self.simulate_attack(args.attack)
        elif args.crypto:
            self.perform_crypto_operation(args.crypto)
        else:
            logger.log("No valid operation specified. Use --attack or --crypto.", LogLevel.ERROR)
            sys.exit(1)