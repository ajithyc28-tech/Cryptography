"""
Logging Module for MemCrypt Lab
Handles logging, console output, and attack simulation logs
"""

import datetime
import json
from typing import Any, Dict, List, Optional
from enum import Enum
from dataclasses import dataclass, field

class LogLevel(Enum):
    """Log level enumeration"""
    DEBUG = 0
    INFO = 1
    WARNING = 2
    ERROR = 3
    CRITICAL = 4

class LogColor:
    """ANSI color codes for terminal output"""
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

@dataclass
class LogEntry:
    """Represents a single log entry"""
    timestamp: datetime.datetime
    level: LogLevel
    message: str
    context: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert log entry to dictionary"""
        return {
            "timestamp": self.timestamp.isoformat(),
            "level": self.level.name,
            "message": self.message,
            "context": self.context
        }
    
    def format_console(self, use_colors: bool = True) -> str:
        """Format log entry for console output"""
        time_str = self.timestamp.strftime("%H:%M:%S")
        level_name = self.level.name
        
        if use_colors:
            color_map = {
                LogLevel.DEBUG: LogColor.CYAN,
                LogLevel.INFO: LogColor.GREEN,
                LogLevel.WARNING: LogColor.WARNING,
                LogLevel.ERROR: LogColor.FAIL,
                LogLevel.CRITICAL: LogColor.FAIL + LogColor.BOLD
            }
            color = color_map.get(self.level, LogColor.ENDC)
            return f"{color}[{time_str}] [{level_name}] {self.message}{LogColor.ENDC}"
        else:
            return f"[{time_str}] [{level_name}] {self.message}"

class AttackLogger:
    """Specialized logger for attack simulations"""
    
    def __init__(self):
        self.attack_logs: List[Dict[str, Any]] = []
        self.current_attack: Optional[str] = None
        
    def start_attack(self, attack_name: str, parameters: Dict[str, Any]) -> None:
        """Start logging a new attack"""
        self.current_attack = attack_name
        self.attack_logs.append({
            "attack": attack_name,
            "start_time": datetime.datetime.now().isoformat(),
            "parameters": parameters,
            "steps": [],
            "status": "running"
        })
        
    def log_step(self, step_description: str, step_data: Optional[Dict[str, Any]] = None) -> None:
        """Log a step in the current attack"""
        if self.attack_logs and self.current_attack:
            self.attack_logs[-1]["steps"].append({
                "timestamp": datetime.datetime.now().isoformat(),
                "description": step_description,
                "data": step_data or {}
            })
            
    def end_attack(self, success: bool, result: Any = None) -> None:
        """End the current attack logging"""
        if self.attack_logs and self.current_attack:
            self.attack_logs[-1]["end_time"] = datetime.datetime.now().isoformat()
            self.attack_logs[-1]["status"] = "success" if success else "failed"
            self.attack_logs[-1]["result"] = result
            self.current_attack = None
            
    def get_attack_summary(self) -> Dict[str, Any]:
        """Get summary of all attacks"""
        return {
            "total_attacks": len(self.attack_logs),
            "successful_attacks": sum(1 for log in self.attack_logs if log.get("status") == "success"),
            "failed_attacks": sum(1 for log in self.attack_logs if log.get("status") == "failed"),
            "logs": self.attack_logs
        }

class Logger:
    """Main logging class for the application"""
    
    def __init__(self, name: str = "MemCryptLab"):
        self.name = name
        self.log_level = LogLevel.INFO
        self.logs: List[LogEntry] = []
        self.attack_logger = AttackLogger()
        self.use_colors = True
        
    def set_level(self, level: LogLevel) -> None:
        """Set the logging level"""
        self.log_level = level
        
    def _log(self, level: LogLevel, message: str, context: Dict[str, Any] = None) -> None:
        """Internal logging method"""
        if level.value >= self.log_level.value:
            entry = LogEntry(
                timestamp=datetime.datetime.now(),
                level=level,
                message=message,
                context=context or {}
            )
            self.logs.append(entry)
            print(entry.format_console(self.use_colors))
            
    def debug(self, message: str, context: Dict[str, Any] = None) -> None:
        """Log debug message"""
        self._log(LogLevel.DEBUG, message, context)
        
    def info(self, message: str, context: Dict[str, Any] = None) -> None:
        """Log info message"""
        self._log(LogLevel.INFO, message, context)
        
    def warning(self, message: str, context: Dict[str, Any] = None) -> None:
        """Log warning message"""
        self._log(LogLevel.WARNING, message, context)
        
    def error(self, message: str, context: Dict[str, Any] = None) -> None:
        """Log error message"""
        self._log(LogLevel.ERROR, message, context)
        
    def critical(self, message: str, context: Dict[str, Any] = None) -> None:
        """Log critical message"""
        self._log(LogLevel.CRITICAL, message, context)
        
    def get_logs(self, level: Optional[LogLevel] = None) -> List[Dict[str, Any]]:
        """Get all logs, optionally filtered by level"""
        if level:
            return [log.to_dict() for log in self.logs if log.level == level]
        return [log.to_dict() for log in self.logs]
        
    def export_logs(self, format: str = "json") -> str:
        """Export logs in specified format"""
        if format == "json":
            return json.dumps(self.get_logs(), indent=2)
        elif format == "text":
            return "\n".join(log.format_console(False) for log in self.logs)
        else:
            raise ValueError(f"Unsupported format: {format}")
            
    def clear_logs(self) -> None:
        """Clear all logs"""
        self.logs.clear()

# Global logger instance
logger = Logger()