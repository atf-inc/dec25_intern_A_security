"""Signature-based detection engine."""

import re
from typing import Dict, Any, List, Optional
import structlog
from ..config.logging_config import get_logger

logger = get_logger(__name__)


class SignatureEngine:
    """Signature-based threat detection using pattern matching."""
    
    def __init__(self):
        """Initialize signature engine."""
        self.signatures: List[Dict[str, Any]] = []
        self.compiled_patterns: List[re.Pattern] = []
    
    async def initialize(self) -> None:
        """Initialize and load signatures."""
        logger.info("Initializing signature engine")
        await self._load_signatures()
    
    async def _load_signatures(self) -> None:
        """Load detection signatures."""
        # Load from file or database
        # Example signatures
        self.signatures = [
            {
                "id": "SIG001",
                "name": "SQL Injection Pattern",
                "pattern": rb"(?i)(union\s+select|drop\s+table|insert\s+into)",
                "severity": "high",
                "category": "sql_injection",
            },
            {
                "id": "SIG002",
                "name": "XSS Pattern",
                "pattern": rb"(?i)(<script|javascript:|onerror=)",
                "severity": "high",
                "category": "xss",
            },
            {
                "id": "SIG003",
                "name": "Command Injection",
                "pattern": rb"(?i)(;|\||&)(\s*)(cat|ls|rm|wget|curl|nc|netcat)",
                "severity": "critical",
                "category": "command_injection",
            },
        ]
        
        # Compile patterns
        for sig in self.signatures:
            try:
                pattern = re.compile(sig["pattern"])
                self.compiled_patterns.append(pattern)
            except Exception as e:
                logger.error("Failed to compile signature", signature_id=sig["id"], error=str(e))
        
        logger.info("Loaded signatures", count=len(self.signatures))
    
    async def analyze(
        self, packet: Dict[str, Any], flow: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        """
        Analyze packet/flow for signature matches.
        
        Returns:
            Dict with threat_score, matched_signatures, and metadata
        """
        matches = []
        payload = packet.get("payload", b"")
        
        # Check payload against signatures
        for i, pattern in enumerate(self.compiled_patterns):
            if pattern.search(payload):
                sig = self.signatures[i]
                matches.append({
                    "signature_id": sig["id"],
                    "name": sig["name"],
                    "severity": sig["severity"],
                    "category": sig["category"],
                })
        
        if matches:
            # Calculate threat score based on severity
            max_severity = max(m.get("severity", "low") for m in matches)
            severity_scores = {"low": 0.3, "medium": 0.6, "high": 0.8, "critical": 1.0}
            threat_score = severity_scores.get(max_severity, 0.5)
            
            logger.warning(
                "Signature match detected",
                matches=len(matches),
                src_ip=packet.get("src_ip"),
            )
            
            return {
                "threat_score": threat_score,
                "matched_signatures": matches,
                "engine": "signature",
            }
        
        return None

