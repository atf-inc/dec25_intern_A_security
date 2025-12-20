"""SQL injection detection."""

import re
from typing import Dict, Any, Optional
import structlog
from ..config.logging_config import get_logger

logger = get_logger(__name__)


class SQLInjectionDetector:
    """Detect SQL injection attacks."""
    
    def __init__(self):
        """Initialize SQL injection detector."""
        self.patterns = [
            # Union Based
            rb"(?i)(union\s+select|union\s+all\s+select)",
            rb"(?i)(order\s+by\s+\d+)",
            rb"(?i)(null,\s*null)",
            
            # Classic CRUD Injection
            rb"(?i)(drop\s+table|drop\s+database)",
            rb"(?i)(insert\s+into)",
            rb"(?i)(delete\s+from)",
            rb"(?i)(update\s+.*set)",
            
            # Auth Bypass & Boolean Logic
            rb"(?i)(or\s+1\s*=\s*1)",
            rb"(?i)(or\s*['\"]1['\"]\s*=\s*['\"]1['\"])",
            rb"(?i)(or\s+'1'\s*=\s*'1')",
            rb"(?i)(or\s+\"1\"\s*=\s*\"1\")",
            rb"(?i)(or\s+true\s*--)",
            rb"(?i)(admin'\s+or)",
            rb"(?i)(' or ')",
            # Only match "or word = word" when it's clearly SQL injection (with quotes or in SQL context)
            rb"(?i)(or\s+['\"](\w+)['\"]\s*=\s*['\"]\2['\"])",  # or 'word' = 'word'
            rb"(?i)(or\s+['\"](\w+)['\"]\s*=\s*\2\b)",  # or 'word' = word (no quotes on right)
            rb"(?i)(or\s+(\w+)\s*=\s*['\"]\2['\"])",  # or word = 'word' (no quotes on left)
            
            # Comments & Obfuscation
            rb"(?i)(--\s|#|/\*.*\*/)",
            # Semicolon only when followed by SQL keywords (stacked queries)
            rb"(?i)(;\s*(drop|delete|insert|update|select|create|alter|exec|execute|union))",
            # Semicolon with quotes (SQL injection pattern)
            rb"(?i)(['\"]\s*;\s*['\"])",
            
            # Error Based & Information Gathering
            rb"(?i)(version\(\)|@@version|user\(\)|@@user|database\(\))",
            rb"(?i)(extractvalue|updatexml|convert|cast)",
            
            # Blind / Time Based
            rb"(?i)(sleep\(\d+\)|benchmark\(\d+,|waitfor\s+delay)",
            rb"(?i)(pg_sleep|dbms_pipe\.receive_message)",
            
            # Out of Band (OOB)
            rb"(?i)(load_file|into\s+outfile|into\s+dumpfile)",
            rb"(?i)(xp_cmdshell|xp_dirtree|utl_http|utl_inaddr)",
        ]
        self.compiled_patterns = [re.compile(p) for p in self.patterns]
    
    def detect(self, packet: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Detect SQL injection in packet."""
        payload = packet.get("payload", b"")
        
        for pattern in self.compiled_patterns:
            if pattern.search(payload):
                logger.warning("SQL injection detected", src_ip=packet.get("src_ip"))
                return {
                    "detected": True,
                    "threat_score": 0.9,
                    "type": "sql_injection",
                }
        
        return None

