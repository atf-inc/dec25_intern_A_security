from datetime import datetime, timezone
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

    async def log_interaction(self, session_id: str, ip: str, request_type: str, payload: str, response: str):
        collection = db.get_collection(self.collection_name)
        
        # Classify attack type
        attack_type = self.classify_attack(payload)
        
        log_entry = {
            "timestamp": datetime.now(timezone.utc),
            "session_id": session_id,
            "ip": ip,
            "type": request_type,
            "attack_type": attack_type,  # NEW: Attack classification
            "payload": payload,
            "response": response
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
