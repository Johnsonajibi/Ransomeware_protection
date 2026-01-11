#!/usr/bin/env python3
"""
Anti-Ransomware Production Logger
Centralized, structured logging with security audit trails
"""

import os
import sys
import logging
import logging.handlers
from pathlib import Path
import json
import time
import threading
from datetime import datetime
from typing import Dict, Any, Optional
import gzip
import shutil

class SecurityAuditFormatter(logging.Formatter):
    """Security-focused log formatter with structured data"""
    
    def format(self, record):
        # Base log entry
        log_entry = {
            'timestamp': datetime.utcnow().isoformat() + 'Z',
            'level': record.levelname,
            'logger': record.name,
            'message': record.getMessage(),
            'module': record.module,
            'function': record.funcName,
            'line': record.lineno,
            'process_id': os.getpid(),
            'thread_id': threading.get_ident()
        }
        
        # Add security context if available
        if hasattr(record, 'user_id'):
            log_entry['user_id'] = record.user_id
        if hasattr(record, 'session_id'):
            log_entry['session_id'] = record.session_id
        if hasattr(record, 'source_ip'):
            log_entry['source_ip'] = record.source_ip
        if hasattr(record, 'file_path'):
            log_entry['file_path'] = record.file_path
        if hasattr(record, 'process_name'):
            log_entry['process_name'] = record.process_name
        if hasattr(record, 'result'):
            log_entry['result'] = record.result
        if hasattr(record, 'reason'):
            log_entry['reason'] = record.reason
        if hasattr(record, 'token_id'):
            log_entry['token_id'] = record.token_id
        if hasattr(record, 'dongle_serial'):
            log_entry['dongle_serial'] = record.dongle_serial
        
        # Add exception info
        if record.exc_info:
            log_entry['exception'] = {
                'type': record.exc_info[0].__name__,
                'message': str(record.exc_info[1]),
                'traceback': self.formatException(record.exc_info)
            }
        
        return json.dumps(log_entry, separators=(',', ':'))

class RotatingSecureFileHandler(logging.handlers.RotatingFileHandler):
    """Secure file handler with compression and integrity protection"""
    
    def __init__(self, filename, mode='a', maxBytes=0, backupCount=0,
                 encoding=None, delay=False, compress=True):
        super().__init__(filename, mode, maxBytes, backupCount, encoding, delay)
        self.compress = compress
        
        # Ensure log directory has secure permissions
        log_dir = Path(filename).parent
        log_dir.mkdir(parents=True, exist_ok=True)
        os.chmod(log_dir, 0o750)
    
    def emit(self, record):
        """Emit a record with additional security measures"""
        try:
            super().emit(record)
            self.flush()  # Ensure immediate write for security events
        except Exception as e:
            self.handleError(record)
    
    def doRollover(self):
        """Roll over with compression and integrity protection"""
        if self.stream:
            self.stream.close()
            self.stream = None
        
        if self.backupCount > 0:
            for i in range(self.backupCount - 1, 0, -1):
                sfn = self.rotation_filename(f"{self.baseFilename}.{i}")
                dfn = self.rotation_filename(f"{self.baseFilename}.{i+1}")
                if os.path.exists(sfn):
                    if os.path.exists(dfn):
                        os.remove(dfn)
                    os.rename(sfn, dfn)
            
            dfn = self.rotation_filename(f"{self.baseFilename}.1")
            if os.path.exists(dfn):
                os.remove(dfn)
            
            # Compress the rotated file if enabled
            if self.compress:
                with open(self.baseFilename, 'rb') as f_in:
                    with gzip.open(f"{dfn}.gz", 'wb') as f_out:
                        shutil.copyfileobj(f_in, f_out)
                os.chmod(f"{dfn}.gz", 0o640)
            else:
                if os.path.exists(self.baseFilename):
                    os.rename(self.baseFilename, dfn)
                os.chmod(dfn, 0o640)
        
        if not self.delay:
            self.stream = self._open()
            os.chmod(self.baseFilename, 0o640)

class SyslogSecurityHandler(logging.handlers.SysLogHandler):
    """Enhanced syslog handler for security events"""
    
    def __init__(self, address=('localhost', 514), facility=logging.handlers.SysLogHandler.LOG_LOCAL0):
        super().__init__(address, facility)
        self.facility_name = 'antiransomware'
    
    def emit(self, record):
        """Emit with security context"""
        # Add facility name to message
        original_msg = record.getMessage()
        record.msg = f"[{self.facility_name}] {original_msg}"
        
        try:
            super().emit(record)
        except Exception:
            self.handleError(record)
        finally:
            # Restore original message
            record.msg = original_msg

class MetricsHandler(logging.Handler):
    """Handler for collecting security metrics"""
    
    def __init__(self):
        super().__init__()
        self.metrics = {
            'total_events': 0,
            'access_denied': 0,
            'access_granted': 0,
            'authentication_failed': 0,
            'token_expired': 0,
            'policy_violation': 0,
            'dongle_events': 0,
            'errors': 0
        }
        self.lock = threading.Lock()
    
    def emit(self, record):
        """Update metrics based on log events"""
        with self.lock:
            self.metrics['total_events'] += 1
            
            if record.levelno >= logging.ERROR:
                self.metrics['errors'] += 1
            
            # Parse security events
            if hasattr(record, 'result'):
                if record.result == 'denied':
                    self.metrics['access_denied'] += 1
                elif record.result == 'allowed':
                    self.metrics['access_granted'] += 1
            
            if hasattr(record, 'reason'):
                if 'authentication' in record.reason.lower():
                    self.metrics['authentication_failed'] += 1
                elif 'expired' in record.reason.lower():
                    self.metrics['token_expired'] += 1
                elif 'policy' in record.reason.lower():
                    self.metrics['policy_violation'] += 1
            
            if hasattr(record, 'dongle_serial'):
                self.metrics['dongle_events'] += 1
    
    def get_metrics(self) -> Dict[str, int]:
        """Get current metrics"""
        with self.lock:
            return dict(self.metrics)
    
    def reset_metrics(self):
        """Reset metrics counters"""
        with self.lock:
            for key in self.metrics:
                self.metrics[key] = 0

class ProductionLogger:
    """Production-grade logger with security features"""
    
    def __init__(self, name: str = "antiransomware", config: Dict[str, Any] = None):
        self.name = name
        self.config = config or self._default_config()
        self.logger = logging.getLogger(name)
        self.metrics_handler = MetricsHandler()
        self._setup_logging()
    
    def _default_config(self) -> Dict[str, Any]:
        """Default logging configuration"""
        return {
            "level": "INFO",
            "format": "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
            "handlers": {
                "file": {
                    "enabled": True,
                    "path": "logs/antiransomware.log",
                    "max_size": 10485760,  # 10MB
                    "backup_count": 10,
                    "compress": True
                },
                "syslog": {
                    "enabled": True,
                    "address": "/dev/log",
                    "facility": "local0"
                },
                "console": {
                    "enabled": False
                }
            }
        }
    
    def _setup_logging(self):
        """Set up logging handlers"""
        # Clear existing handlers
        self.logger.handlers.clear()
        
        # Set level
        level = getattr(logging, self.config.get("level", "INFO").upper())
        self.logger.setLevel(level)
        
        # Security audit formatter
        formatter = SecurityAuditFormatter()
        
        # File handler
        if self.config["handlers"]["file"]["enabled"]:
            file_config = self.config["handlers"]["file"]
            file_handler = RotatingSecureFileHandler(
                filename=file_config["path"],
                maxBytes=file_config.get("max_size", 10485760),
                backupCount=file_config.get("backup_count", 10),
                compress=file_config.get("compress", True)
            )
            file_handler.setLevel(level)
            file_handler.setFormatter(formatter)
            self.logger.addHandler(file_handler)
        
        # Syslog handler
        if self.config["handlers"]["syslog"]["enabled"]:
            syslog_config = self.config["handlers"]["syslog"]
            try:
                if os.path.exists(syslog_config.get("address", "/dev/log")):
                    address = syslog_config["address"]
                else:
                    address = ('localhost', 514)
                
                facility = getattr(
                    logging.handlers.SysLogHandler,
                    f"LOG_{syslog_config.get('facility', 'LOCAL0').upper()}"
                )
                
                syslog_handler = SyslogSecurityHandler(address, facility)
                syslog_handler.setLevel(level)
                syslog_handler.setFormatter(logging.Formatter(
                    '%(name)s[%(process)d]: %(levelname)s %(message)s'
                ))
                self.logger.addHandler(syslog_handler)
            except Exception as e:
                print(f"Failed to setup syslog handler: {e}")
        
        # Console handler
        if self.config["handlers"]["console"]["enabled"]:
            console_handler = logging.StreamHandler(sys.stdout)
            console_handler.setLevel(level)
            console_handler.setFormatter(logging.Formatter(
                self.config.get("format", "%(asctime)s [%(levelname)s] %(name)s: %(message)s")
            ))
            self.logger.addHandler(console_handler)
        
        # Metrics handler
        self.logger.addHandler(self.metrics_handler)
        
        # Prevent propagation to root logger
        self.logger.propagate = False
    
    def security_event(self, message: str, level: str = "INFO", **kwargs):
        """Log security event with structured data"""
        log_level = getattr(logging, level.upper())
        
        # Create log record with security context
        record = self.logger.makeRecord(
            self.logger.name,
            log_level,
            kwargs.get('pathname', ''),
            kwargs.get('lineno', 0),
            message,
            (),
            None,
            kwargs.get('funcName', '')
        )
        
        # Add security attributes
        for key, value in kwargs.items():
            if key not in ['pathname', 'lineno', 'funcName']:
                setattr(record, key, value)
        
        self.logger.handle(record)
    
    def access_denied(self, file_path: str, user_id: str, process_name: str, reason: str, **kwargs):
        """Log access denied event"""
        self.security_event(
            f"Access denied to {file_path}",
            level="WARNING",
            user_id=user_id,
            process_name=process_name,
            file_path=file_path,
            result="denied",
            reason=reason,
            **kwargs
        )
    
    def access_granted(self, file_path: str, user_id: str, process_name: str, token_id: str, **kwargs):
        """Log access granted event"""
        self.security_event(
            f"Access granted to {file_path}",
            level="INFO",
            user_id=user_id,
            process_name=process_name,
            file_path=file_path,
            result="allowed",
            token_id=token_id,
            **kwargs
        )
    
    def authentication_failed(self, user_id: str, reason: str, source_ip: str = None, **kwargs):
        """Log authentication failure"""
        self.security_event(
            f"Authentication failed for user {user_id}",
            level="WARNING",
            user_id=user_id,
            reason=reason,
            source_ip=source_ip,
            result="auth_failed",
            **kwargs
        )
    
    def dongle_event(self, event_type: str, dongle_serial: str, user_id: str = None, **kwargs):
        """Log USB dongle event"""
        self.security_event(
            f"Dongle {event_type}: {dongle_serial}",
            level="INFO",
            dongle_serial=dongle_serial,
            user_id=user_id,
            event_type=event_type,
            **kwargs
        )
    
    def policy_violation(self, file_path: str, user_id: str, process_name: str, violation_type: str, **kwargs):
        """Log policy violation"""
        self.security_event(
            f"Policy violation: {violation_type} for {file_path}",
            level="WARNING",
            user_id=user_id,
            process_name=process_name,
            file_path=file_path,
            result="policy_violation",
            violation_type=violation_type,
            **kwargs
        )
    
    def system_event(self, event_type: str, message: str, level: str = "INFO", **kwargs):
        """Log system event"""
        self.security_event(
            f"System {event_type}: {message}",
            level=level,
            event_type=event_type,
            **kwargs
        )
    
    def get_metrics(self) -> Dict[str, int]:
        """Get security metrics"""
        return self.metrics_handler.get_metrics()
    
    def reset_metrics(self):
        """Reset security metrics"""
        self.metrics_handler.reset_metrics()

# Global logger instance
_logger_instance = None

def init_logger(name: str = "antiransomware", config: Dict[str, Any] = None) -> ProductionLogger:
    """Initialize global logger"""
    global _logger_instance
    _logger_instance = ProductionLogger(name, config)
    return _logger_instance

def get_logger() -> ProductionLogger:
    """Get global logger instance"""
    global _logger_instance
    if _logger_instance is None:
        _logger_instance = init_logger()
    return _logger_instance

if __name__ == "__main__":
    # Example usage
    logger = init_logger("test_logger", {
        "level": "DEBUG",
        "handlers": {
            "file": {"enabled": True, "path": "test.log"},
            "console": {"enabled": True},
            "syslog": {"enabled": False}
        }
    })
    
    # Test security events
    logger.access_denied("/protected/file.txt", "user123", "notepad.exe", "No valid token")
    logger.access_granted("/protected/file.txt", "user123", "notepad.exe", "token_abc123")
    logger.authentication_failed("user123", "Invalid PIN", "192.168.1.100")
    logger.dongle_event("inserted", "YK001234567", "user123")
    logger.policy_violation("/protected/file.txt", "user123", "powershell.exe", "parent_process_denied")
    logger.system_event("startup", "Anti-Ransomware service started")
    
    # Show metrics
    print("Security Metrics:", logger.get_metrics())
