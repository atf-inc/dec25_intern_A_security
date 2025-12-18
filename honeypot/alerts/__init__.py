"""
Slack/Email Alert Notifier
Sends real-time notifications when attacks are detected
"""
import os
import requests
from datetime import datetime
from config import settings

class AlertNotifier:
    def __init__(self):
        self.slack_webhook = os.getenv("SLACK_WEBHOOK_URL")
        self.enabled = bool(self.slack_webhook)
        
    def send_slack_alert(self, attack_data: dict):
        """Send Slack notification for detected attack"""
        if not self.enabled:
            print("⚠️  Slack webhook not configured, skipping alert")
            return
            
        # Determine severity color
        attack_type = attack_data.get("attack_type", "unknown")
        severity_colors = {
            "sqli": "#FF0000",  # Red - Critical
            "xss": "#FFA500",   # Orange - High
            "idor": "#FFFF00",  # Yellow - Medium
            "default": "#808080" # Gray - Low
        }
        color = severity_colors.get(attack_type.lower(), severity_colors["default"])
        
        # Build Slack message
        message = {
            "attachments": [{
                "color": color,
                "title": f"🚨 {attack_type.upper()} Attack Detected",
                "fields": [
                    {
                        "title": "IP Address",
                        "value": attack_data.get("ip", "Unknown"),
                        "short": True
                    },
                    {
                        "title": "Attack Type",
                        "value": attack_type.upper(),
                        "short": True
                    },
                    {
                        "title": "Payload Snippet",
                        "value": f"`{attack_data.get('payload', '')[:100]}...`",
                        "short": False
                    },
                    {
                        "title": "Session ID",
                        "value": attack_data.get("session_id", "N/A"),
                        "short": True
                    },
                    {
                        "title": "Timestamp",
                        "value": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        "short": True
                    }
                ],
                "footer": "QuantumShield Honeypot",
                "footer_icon": "https://platform.slack-edge.com/img/default_application_icon.png"
            }]
        }
        
        try:
            response = requests.post(
                self.slack_webhook,
                json=message,
                timeout=5
            )
            if response.status_code == 200:
                print(f"✅ Slack alert sent for {attack_type} attack from {attack_data.get('ip')}")
            else:
                print(f"❌ Slack alert failed: {response.status_code}")
        except Exception as e:
            print(f"❌ Slack alert error: {e}")
    
    def send_email_alert(self, attack_data: dict):
        """Send email notification (placeholder for future implementation)"""
        # TODO: Implement SMTP email alerts
        pass

# Singleton instance
alert_notifier = AlertNotifier()
