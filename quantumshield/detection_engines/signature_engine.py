from typing import Dict, List, Optional
import re
from ..core.decision_maker import ThreatIndicator, ThreatLevel

class SignatureEngine:
    """Detection engine based on known attack signatures."""
    
    def __init__(self, config: Dict = None):
        self.config = config or {}
        self.signatures = [
            (r"(?i)SELECT.*FROM", "SQL Injection"),
            (r"(?i)<script>", "XSS Attack"),
            (r"(?i)union.*select", "SQL Injection"),
            (r"(?i)/etc/passwd", "Path Traversal"),
        ]
        
    async def initialize(self):
        """Initialize the engine."""
        pass
        
    async def analyze(self, flow_data: Dict) -> List[ThreatIndicator]:
        """Analyze flow data for signatures."""
        indicators = []
        payload = flow_data.get('payload', '')
        if not isinstance(payload, str):
            try:
                payload = payload.decode('utf-8', errors='ignore')
            except:
                payload = str(payload)
                
        for pattern, name in self.signatures:
            if re.search(pattern, payload):
                indicators.append(ThreatIndicator(
                    name=f"Signature-{name}",
                    indicator_type="signature",
                    severity=ThreatLevel.HIGH,
                    confidence=1.0,
                    details=f"Matched pattern: {pattern}",
                    source="SignatureEngine"
                ))
        return indicators
