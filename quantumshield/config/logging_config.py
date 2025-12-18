"""
Logging Configuration for QuantumShield
"""
import logging
import logging.handlers
import sys
import json
from datetime import datetime
from pathlib import Path
from typing import Optional, Dict, Any
import traceback
from pythonjsonlogger import jsonlogger


class QuantumShieldFormatter(logging.Formatter):
    """Custom formatter with color support and structured data"""
    
    COLORS = {
        'DEBUG': '\033[36m',     # Cyan
        'INFO': '\033[32m',      # Green
        'WARNING': '\033[33m',   # Yellow
        'ERROR': '\033[31m',     # Red
        'CRITICAL': '\033[35m',  # Magenta
        'RESET': '\033[0m'
    }
    
    def __init__(self, use_colors: bool = True, include_context: bool = True):
        super().__init__()
        self.use_colors = use_colors
        self.include_context = include_context
    
    def format(self, record: logging.LogRecord) -> str:
        # Add timestamp
        timestamp = datetime.utcnow().isoformat() + 'Z'
        
        # Build base message
        level = record.levelname
        if self.use_colors:
            level_color = self.COLORS.get(level, '')
            reset = self.COLORS['RESET']
            level_str = f"{level_color}{level:8}{reset}"
        else:
            level_str = f"{level:8}"
        
        # Module info
        module_info = f"{record.name}:{record.funcName}:{record.lineno}"
        
        # Base message
        message = record.getMessage()
        
        # Build formatted string
        formatted = f"[{timestamp}] {level_str} | {module_info:50} | {message}"
        
        # Add exception info if present
        if record.exc_info:
            formatted += f"\n{''.join(traceback.format_exception(*record.exc_info))}"
        
        # Add extra context if present
        if self.include_context and hasattr(record, 'context'):
            formatted += f"\n  Context: {json.dumps(record.context, default=str)}"
        
        return formatted


class JSONFormatter(jsonlogger.JsonFormatter):
    """JSON formatter for structured logging"""
    
    def add_fields(self, log_record: Dict, record: logging.LogRecord, message_dict: Dict):
        super().add_fields(log_record, record, message_dict)
        
        log_record['timestamp'] = datetime.utcnow().isoformat() + 'Z'
        log_record['level'] = record.levelname
        log_record['logger'] = record.name
        log_record['module'] = record.module
        log_record['function'] = record.funcName
        log_record['line'] = record.lineno
        log_record['process_id'] = record.process
        log_record['thread_id'] = record.thread
        
        # Add any extra context
        if hasattr(record, 'context'):
            log_record['context'] = record.context
        
        # Add security-specific fields
        if hasattr(record, 'threat_level'):
            log_record['threat_level'] = record.threat_level
        if hasattr(record, 'source_ip'):
            log_record['source_ip'] = record.source_ip
        if hasattr(record, 'attack_type'):
            log_record['attack_type'] = record.attack_type


class SecurityEventHandler(logging.Handler):
    """Handler for security-specific events"""
    
    def __init__(self, callback=None):
        super().__init__()
        self.callback = callback
        self.security_events = []
    
    def emit(self, record: logging.LogRecord):
        if hasattr(record, 'security_event') and record.security_event:
            event = {
                'timestamp': datetime.utcnow().isoformat(),
                'level': record.levelname,
                'message': record.getMessage(),
                'threat_level': getattr(record, 'threat_level', 'unknown'),
                'source_ip': getattr(record, 'source_ip', None),
                'attack_type': getattr(record, 'attack_type', None),
                'context': getattr(record, 'context', {})
            }
            self.security_events.append(event)
            
            if self.callback:
                self.callback(event)


class ContextLogger(logging.LoggerAdapter):
    """Logger adapter that adds context to all log messages"""
    
    def __init__(self, logger: logging.Logger, context: Dict[str, Any] = None):
        super().__init__(logger, context or {})
    
    def process(self, msg: str, kwargs: Dict) -> tuple:
        # Merge extra context
        extra = kwargs.get('extra', {})
        extra['context'] = {**self.extra, **extra.get('context', {})}
        kwargs['extra'] = extra
        return msg, kwargs
    
    def security_event(self, msg: str, threat_level: str = 'medium',
                       source_ip: str = None, attack_type: str = None, **kwargs):
        """Log a security event"""
        extra = kwargs.get('extra', {})
        extra.update({
            'security_event': True,
            'threat_level': threat_level,
            'source_ip': source_ip,
            'attack_type': attack_type
        })
        kwargs['extra'] = extra
        
        if threat_level in ('high', 'critical'):
            self.error(msg, **kwargs)
        elif threat_level == 'medium':
            self.warning(msg, **kwargs)
        else:
            self.info(msg, **kwargs)


def setup_logging(
    log_level: str = "INFO",
    log_dir: Path = Path("logs"),
    app_name: str = "quantumshield",
    json_format: bool = False,
    enable_console: bool = True,
    enable_file: bool = True,
    max_bytes: int = 10 * 1024 * 1024,  # 10MB
    backup_count: int = 5,
    security_event_callback=None
) -> logging.Logger:
    """
    Configure logging for the application
    """
    # Ensure log directory exists
    log_dir = Path(log_dir)
    log_dir.mkdir(parents=True, exist_ok=True)
    
    # Get root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(getattr(logging, log_level.upper()))
    
    # Remove existing handlers
    root_logger.handlers.clear()
    
    # Create formatters
    if json_format:
        formatter = JSONFormatter()
    else:
        formatter = QuantumShieldFormatter(use_colors=enable_console)
    
    # Console handler
    if enable_console:
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setFormatter(
            QuantumShieldFormatter(use_colors=True) if not json_format else formatter
        )
        console_handler.setLevel(getattr(logging, log_level.upper()))
        root_logger.addHandler(console_handler)
    
    # File handler for application logs
    if enable_file:
        app_log_path = log_dir / "application.log"
        file_handler = logging.handlers.RotatingFileHandler(
            app_log_path,
            maxBytes=max_bytes,
            backupCount=backup_count
        )
        file_handler.setFormatter(JSONFormatter() if json_format else formatter)
        file_handler.setLevel(logging.DEBUG)
        root_logger.addHandler(file_handler)
        
        # Security events log
        security_log_path = log_dir / "security_events.log"
        security_handler = logging.handlers.RotatingFileHandler(
            security_log_path,
            maxBytes=max_bytes,
            backupCount=backup_count
        )
        security_handler.setFormatter(JSONFormatter())
        security_handler.setLevel(logging.INFO)
        security_handler.addFilter(lambda r: getattr(r, 'security_event', False))
        root_logger.addHandler(security_handler)
        
        # Performance log
        perf_log_path = log_dir / "performance.log"
        perf_handler = logging.handlers.RotatingFileHandler(
            perf_log_path,
            maxBytes=max_bytes,
            backupCount=backup_count
        )
        perf_handler.setFormatter(JSONFormatter())
        perf_handler.setLevel(logging.DEBUG)
        perf_handler.addFilter(lambda r: getattr(r, 'performance', False))
        root_logger.addHandler(perf_handler)
        
        # Error log
        error_log_path = log_dir / "errors.log"
        error_handler = logging.handlers.RotatingFileHandler(
            error_log_path,
            maxBytes=max_bytes,
            backupCount=backup_count
        )
        error_handler.setFormatter(JSONFormatter())
        error_handler.setLevel(logging.ERROR)
        root_logger.addHandler(error_handler)
    
    # Security event handler
    if security_event_callback:
        security_event_handler = SecurityEventHandler(callback=security_event_callback)
        security_event_handler.setLevel(logging.INFO)
        root_logger.addHandler(security_event_handler)
    
    # Create application logger
    app_logger = logging.getLogger(app_name)
    
    return app_logger


def get_logger(name: str, context: Dict[str, Any] = None) -> ContextLogger:
    """Get a logger with optional context"""
    logger = logging.getLogger(name)
    return ContextLogger(logger, context)


class LoggerMixin:
    """Mixin class to add logging capabilities"""
    
    @property
    def logger(self) -> ContextLogger:
        if not hasattr(self, '_logger'):
            self._logger = get_logger(
                f"{self.__class__.__module__}.{self.__class__.__name__}"
            )
        return self._logger
