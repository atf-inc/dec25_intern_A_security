from datetime import datetime, timezone
import logging
import requests
from config import settings

# Configure logging
logger = logging.getLogger("slack_notifier")


class SlackNotifier:
    def __init__(self):
        self.enabled = settings.ENABLE_SLACK_ALERTS
        self.webhook_url = settings.SLACK_WEBHOOK_URL
        
        if self.enabled:
            logger.info("Slack alerts enabled")
        else:
            logger.info("Slack alerts disabled")
    
    async def send_attack_alert(
        self,
        ip: str,
        method: str,
        path: str,
        ml_verdict: str,
        ml_confidence: float,
        payload: str
    ):
        """
        Send Slack alert for high-level (MALICIOUS) attacks.
        
        Args:
            ip: Source IP address of attacker
            method: HTTP method (GET, POST, etc.)
            path: Request path
            ml_verdict: ML model verdict (MALICIOUS, SUSPICIOUS, SAFE)
            ml_confidence: Confidence score (0-1)
            payload: Request payload (truncated to 500 chars)
        """
        if not self.enabled:
            logger.debug("Slack alerts disabled, skipping notification")
            return
        
        try:
            # Get current timestamp
            timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
            
            # Truncate payload if too long
            payload_preview = payload[:500] if len(payload) > 500 else payload
            if len(payload) > 500:
                payload_preview += "... (truncated)"
            
            # Infer attack type
            attack_type = self._infer_attack_type(method, path, payload)
            
            # Determine severity color based on attack type
            severity_colors = {
                "SQL Injection": "#FF0000",           # Red - Critical
                "Cross-Site Scripting (XSS)": "#FF4500",  # Orange-Red - High
                "Command Injection": "#FF0000",       # Red - Critical
                "Path Traversal": "#FFA500",          # Orange - High
                "Unauthorized Login Attempt": "#FFD700",  # Gold - Medium
                "Malicious Request": "#808080"        # Gray - Default
            }
            color = severity_colors.get(attack_type, "#808080")
            
            # Build Slack message with rich formatting
            message = {
                "attachments": [{
                    "color": color,
                    "pretext": ":rotating_light: *MALICIOUS Attack Detected*",
                    "title": f"{attack_type} from {ip}",
                    "fields": [
                        {
                            "title": "Source IP",
                            "value": f"`{ip}`",
                            "short": True
                        },
                        {
                            "title": "Attack Type",
                            "value": attack_type,
                            "short": True
                        },
                        {
                            "title": "HTTP Method",
                            "value": method,
                            "short": True
                        },
                        {
                            "title": "Request Path",
                            "value": f"`/{path}`",
                            "short": True
                        },
                        {
                            "title": "ML Verdict",
                            "value": f":warning: {ml_verdict}",
                            "short": True
                        },
                        {
                            "title": "Confidence Score",
                            "value": f"{ml_confidence:.2%}",
                            "short": True
                        },
                        {
                            "title": "Payload Preview",
                            "value": f"```{self._escape_slack(payload_preview)}```",
                            "short": False
                        }
                    ],
                    "footer": "QuantumShield Honeypot",
                    "footer_icon": "https://platform.slack-edge.com/img/default_application_icon.png",
                    "ts": int(datetime.now(timezone.utc).timestamp())
                }]
            }
            
            # Send to Slack webhook
            response = requests.post(
                self.webhook_url,
                json=message,
                timeout=10
            )
            
            if response.status_code == 200:
                logger.info(f"Slack alert sent successfully for {ip} - {attack_type}")
            else:
                logger.warning(f"Slack alert failed with status code: {response.status_code}")
                
        except Exception as e:
            # Don't crash the application if Slack fails
            logger.error(f"Failed to send Slack alert: {str(e)}")
    
    def _infer_attack_type(self, method: str, path: str, payload: str) -> str:
        """
        Infer the type of attack based on request characteristics.
        """
        payload_lower = payload.lower()
        path_lower = path.lower()
        
        # SQL Injection patterns
        if any(pattern in payload_lower for pattern in ["' or ", "union select", "drop table", "-- ", "/*", "*/"]):
            return "SQL Injection"
        
        # XSS patterns
        if any(pattern in payload_lower for pattern in ["<script", "javascript:", "onerror=", "onload="]):
            return "Cross-Site Scripting (XSS)"
        
        # Command Injection patterns
        if any(pattern in payload_lower for pattern in ["|", ";", "&&", "`", "$(", "../"]):
            return "Command Injection"
        
        # Path Traversal
        if "../" in path_lower or "..%2f" in path_lower:
            return "Path Traversal"
        
        # Login attempts
        if "login" in path_lower or "auth" in path_lower:
            return "Unauthorized Login Attempt"
        
        # Default
        return "Malicious Request"
    
    def _escape_slack(self, text: str) -> str:
        """
        Escape special characters for Slack message formatting.
        """
        return (text
                .replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;"))


# Create singleton instance
slack_notifier = SlackNotifier()

