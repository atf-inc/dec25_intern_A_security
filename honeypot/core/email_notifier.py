from datetime import datetime, timezone
import logging
from typing import Optional
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail
from config import settings

# Configure logging
logger = logging.getLogger("email_notifier")

class EmailNotifier:
    def __init__(self):
        self.enabled = settings.ENABLE_EMAIL_ALERTS
        self.from_email = settings.ALERT_FROM_EMAIL
        self.to_email = settings.ALERT_TO_EMAIL
        
        if self.enabled:
            self.client = SendGridAPIClient(settings.SENDGRID_API_KEY)
            logger.info(f"Email alerts enabled. Alerts will be sent to {self.to_email}")
        else:
            logger.info("Email alerts disabled")
    
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
        Send email alert for high-level (MALICIOUS) attacks.
        
        Args:
            ip: Source IP address of attacker
            method: HTTP method (GET, POST, etc.)
            path: Request path
            ml_verdict: ML model verdict (MALICIOUS, SUSPICIOUS, SAFE)
            ml_confidence: Confidence score (0-1)
            payload: Request payload (truncated to 500 chars)
        """
        if not self.enabled:
            logger.debug("Email alerts disabled, skipping notification")
            return
        
        try:
            # Get current timestamp
            timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
            
            # Truncate payload if too long
            payload_preview = payload[:500] if len(payload) > 500 else payload
            if len(payload) > 500:
                payload_preview += "... (truncated)"
            
            # Determine attack type based on path and method
            attack_type = self._infer_attack_type(method, path, payload)
            
            # Build HTML email content
            html_content = f"""
            <!DOCTYPE html>
            <html>
            <head>
                <style>
                    body {{
                        font-family: Arial, sans-serif;
                        line-height: 1.6;
                        color: #333;
                        max-width: 600px;
                        margin: 0 auto;
                        padding: 20px;
                    }}
                    .header {{
                        background-color: #dc3545;
                        color: white;
                        padding: 20px;
                        text-align: center;
                        border-radius: 5px 5px 0 0;
                    }}
                    .content {{
                        background-color: #f8f9fa;
                        padding: 20px;
                        border: 1px solid #dee2e6;
                        border-radius: 0 0 5px 5px;
                    }}
                    .alert-detail {{
                        background-color: white;
                        padding: 15px;
                        margin: 10px 0;
                        border-left: 4px solid #dc3545;
                        border-radius: 3px;
                    }}
                    .label {{
                        font-weight: bold;
                        color: #495057;
                    }}
                    .value {{
                        color: #212529;
                        margin-left: 10px;
                    }}
                    .danger {{
                        color: #dc3545;
                        font-weight: bold;
                    }}
                    .payload {{
                        background-color: #f1f3f5;
                        padding: 10px;
                        border-radius: 3px;
                        font-family: 'Courier New', monospace;
                        font-size: 12px;
                        word-wrap: break-word;
                        overflow-wrap: break-word;
                    }}
                    .footer {{
                        margin-top: 20px;
                        padding-top: 15px;
                        border-top: 1px solid #dee2e6;
                        font-size: 12px;
                        color: #6c757d;
                    }}
                </style>
            </head>
            <body>
                <div class="header">
                    <h1>🚨 MALICIOUS Attack Detected</h1>
                    <p>QuantumShield Security Alert</p>
                </div>
                <div class="content">
                    <div class="alert-detail">
                        <p><span class="label">Alert Time:</span><span class="value">{timestamp}</span></p>
                        <p><span class="label">Attack Type:</span><span class="value danger">{attack_type}</span></p>
                        <p><span class="label">Source IP:</span><span class="value">{ip}</span></p>
                        <p><span class="label">HTTP Method:</span><span class="value">{method}</span></p>
                        <p><span class="label">Request Path:</span><span class="value">{path}</span></p>
                        <p><span class="label">ML Verdict:</span><span class="value danger">{ml_verdict}</span></p>
                        <p><span class="label">Confidence Score:</span><span class="value">{ml_confidence:.2%}</span></p>
                    </div>
                    
                    <div class="alert-detail">
                        <p class="label">Payload Preview:</p>
                        <div class="payload">{self._escape_html(payload_preview)}</div>
                    </div>
                    
                    <div class="footer">
                        <p>This is an automated alert from QuantumShield Honeypot System.</p>
                        <p>View full details in your <a href="http://localhost:3000">security dashboard</a>.</p>
                    </div>
                </div>
            </body>
            </html>
            """
            
            # Create email message
            message = Mail(
                from_email=self.from_email,
                to_emails=self.to_email,
                subject=f"🚨 MALICIOUS Attack Detected - {attack_type} from {ip}",
                html_content=html_content
            )
            
            # Send email
            response = self.client.send(message)
            
            if response.status_code == 202:
                logger.info(f"Attack alert email sent successfully for {ip} - {attack_type}")
            else:
                logger.warning(f"Email sent with status code: {response.status_code}")
                
        except Exception as e:
            # Don't crash the application if email fails
            logger.error(f"Failed to send email alert: {str(e)}")
    
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
    
    def _escape_html(self, text: str) -> str:
        """
        Escape HTML special characters to prevent injection in email.
        """
        return (text
                .replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace('"', "&quot;")
                .replace("'", "&#x27;"))

# Create singleton instance
email_notifier = EmailNotifier()

