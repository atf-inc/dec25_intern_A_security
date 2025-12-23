from datetime import datetime, timezone
from typing import Optional, Dict, Any
from core.database import db
import re

class Logger:
    def __init__(self):
        self.collection_name = "logs"

    def classify_attack(self, payload: str) -> str:
        """Classify attack type based on payload patterns"""
        payload_lower = payload.lower()
        
        # SQL Injection patterns
        if re.search(r"(\bor\b|\bunion\b|\bselect\b).{0,20}(\bfrom\b|\bwhere\b|=)", payload_lower):
            return "sqli"
        if re.search(r"'.*or.*=|--|\#|\/\*", payload_lower):
            return "sqli"
            
        # XSS patterns
        if re.search(r"<script|javascript:|onerror=|onload=", payload_lower):
            return "xss"
            
        # Command Injection
        if re.search(r";|\||&&|\$\(|`", payload):
            return "command_injection"
            
        # Path Traversal
        if re.search(r"\.\./|\.\.\\|/etc/|c:\\", payload_lower):
            return "path_traversal"
            
        return "unknown"

    def classify_severity(self, attack_type: str, ml_confidence: Optional[float]) -> str:
        """Classify severity based on attack type and ML confidence"""
        confidence = ml_confidence or 0
        
        if attack_type in ("sqli", "command_injection") and confidence > 0.8:
            return "CRITICAL"
        elif attack_type in ("sqli", "xss", "command_injection"):
            return "HIGH"
        elif attack_type == "path_traversal":
            return "MEDIUM"
        return "LOW"

    async def log_interaction(
        self, 
        session_id: str, 
        ip: str, 
        request_type: str, 
        payload: str, 
        response: str,
        ml_verdict: Optional[str] = None,
        ml_confidence: Optional[float] = None,
        # New metadata fields
        http_method: Optional[str] = None,
        path: Optional[str] = None,
        query_params: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
        body_size: Optional[int] = None,
        response_time_ms: Optional[float] = None
    ):
        collection = db.get_collection(self.collection_name)
        
        # Classify attack type and severity
        attack_type = self.classify_attack(payload)
        severity = self.classify_severity(attack_type, ml_confidence)
        
        # Determine if this is a trap trigger (first request in session)
        is_trap_trigger = False
        if session_id != "BLOCKED" and request_type != "blocked_request":
            # Check if this is the first log for this session
            existing_count = await collection.count_documents({"session_id": session_id})
            is_trap_trigger = (existing_count == 0)
            
            # Update request type based on session state
            if is_trap_trigger:
                request_type = "trap_trigger"  # Initial SUSPICIOUS request
            else:
                request_type = "trapped_interaction"  # Subsequent requests from trapped IP
        
        log_entry = {
            "timestamp": datetime.now(timezone.utc),
            "session_id": session_id,
            "ip": ip,
            "type": request_type,
            "attack_type": attack_type,
            "severity": severity,
            "payload": payload,
            "response": response,
            "ml_verdict": ml_verdict,
            "ml_confidence": ml_confidence,
            "is_trap_trigger": is_trap_trigger,  # Flag for easy filtering
            # New metadata fields
            "http_method": http_method,
            "path": path,
            "query_params": query_params,
            "headers": headers,
            "body_size": body_size,
            "response_time_ms": response_time_ms
        }
        await collection.insert_one(log_entry)
        
        # Trigger Slack alert for detected attacks (DISABLED - was blocking responses)
        # Uncomment after configuring SLACK_WEBHOOK_URL in .env
        # if attack_type != "unknown":
        #     try:
        #         from alerts import alert_notifier
        #         alert_notifier.send_slack_alert({
        #             "session_id": session_id,
        #             "ip": ip,
        #             "attack_type": attack_type,
        #             "payload": payload
        #         })
        #     except Exception as e:
        #         print(f"Alert notification failed: {e}")

logger = Logger()
