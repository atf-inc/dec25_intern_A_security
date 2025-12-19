"""Command Injection Detection Module."""

import re
from typing import Dict, Any, Optional
from ..config.logging_config import get_logger

logger = get_logger(__name__)


class CommandInjectionDetector:
    """Detect OS Command Injection attacks."""
    
    def __init__(self):
        """Initialize Command Injection detector."""
        self.patterns = [
            # Chaining operators - but only when followed by commands or in suspicious context
            # Semicolon followed by command
            rb"(?i)(;\s*(cat|ls|pwd|whoami|id|uname|dir|type|ipconfig|cmd|powershell|bash|sh))",
            # Pipe followed by command
            rb"(?i)(\|\s*(cat|ls|pwd|whoami|id|uname|dir|type|ipconfig|cmd|powershell|bash|sh))",
            # Double pipe
            rb"(?i)(\|\|)",
            # Double ampersand
            rb"(?i)(&&)",
            # Backtick (command substitution)
            rb"(?i)(`)",
            # Command substitution $()
            rb"(?i)(\$\([^)]*\))",
            # Newline followed by command (multiline injection)
            rb"(?i)([\n\r]\s*(cat|ls|pwd|whoami|id|uname|dir|type|ipconfig|cmd|powershell|bash|sh))",
            # Common shell commands (Linux/Unix)
            rb"(?i)(cat\s+|ls\s+|pwd|whoami|id|uname|netcat|nc\s+|ncat|bash|sh\s+|ksh|csh|tcsh|zsh)",
            rb"(?i)(/bin/sh|/bin/bash|/usr/bin/sh|/usr/bin/bash)",
            rb"(?i)(/etc/passwd|/etc/shadow|/etc/hosts)",
            rb"(?i)(ping\s+|telnet\s+|ssh\s+|wget\s+|curl\s+)",
            # Common shell commands (Windows)
            rb"(?i)(dir(\s+|$)|type\s+|ipconfig|net\s+user|net\s+localgroup|systeminfo|whoami|calc\.exe)",
            rb"(?i)(cmd\.exe|powershell|pwsh)",
            # Windows specific paths
            rb"(?i)(c:\\windows|c:\\winnt|c:\\boot\.ini)",
            # Redirects
            rb"(?i)(>\s*|>>\s*|<\s*)",
        ]
        self.compiled_patterns = [re.compile(p) for p in self.patterns]

    def detect(self, packet: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Detect Command Injection in packet."""
        payload = packet.get("payload", b"")
        if not payload:
            return None

        for pattern in self.compiled_patterns:
            if pattern.search(payload):
                logger.warning("Command Injection detected", src_ip=packet.get("src_ip"))
                return {
                    "detected": True,
                    "threat_score": 0.95,
                    "type": "command_injection",
                }
        
        return None
