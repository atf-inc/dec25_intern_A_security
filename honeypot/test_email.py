"""
Test script for Email Alert functionality
Tests the SendGrid email integration for attack notifications
"""
import asyncio
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

def check_email_config():
    """Check if email configuration is properly set"""
    print("=" * 50)
    print("EMAIL CONFIGURATION CHECK")
    print("=" * 50)
    
    sendgrid_key = os.getenv("SENDGRID_API_KEY")
    from_email = os.getenv("ALERT_FROM_EMAIL")
    to_email = os.getenv("ALERT_TO_EMAIL")
    enabled = os.getenv("ENABLE_EMAIL_ALERTS", "true").lower() == "true"
    
    print(f"ENABLE_EMAIL_ALERTS: {enabled}")
    print(f"SENDGRID_API_KEY: {'Set (' + sendgrid_key[:8] + '...)' if sendgrid_key else 'Missing'}")
    print(f"ALERT_FROM_EMAIL: {from_email if from_email else 'Missing'}")
    print(f"ALERT_TO_EMAIL: {to_email if to_email else 'Missing'}")
    print()
    
    if not sendgrid_key or not from_email or not to_email:
        print("Email configuration incomplete!")
        print("\nTo configure email alerts, create a .env file with:")
        print("-" * 50)
        print("""
# Email Alert Configuration (SendGrid)
ENABLE_EMAIL_ALERTS=true
SENDGRID_API_KEY=your_sendgrid_api_key_here
ALERT_FROM_EMAIL=alerts@yourdomain.com
ALERT_TO_EMAIL=your_email@example.com

# Also need these for the app to start
GROQ_API_KEY=your_groq_api_key
""")
        print("-" * 50)
        return False
    
    return True


async def test_email_send():
    """Send a test email alert"""
    print("\n" + "=" * 50)
    print("SENDING TEST EMAIL")
    print("=" * 50)
    
    try:
        # Import here to catch config errors
        from core.email_notifier import email_notifier
        
        if not email_notifier.enabled:
            print("Email notifier is disabled!")
            print("Set ENABLE_EMAIL_ALERTS=true in your .env file")
            return False
        
        print(f"Sending test alert to: {email_notifier.to_email}")
        print("Please wait...")
        
        # Send test alert
        await email_notifier.send_attack_alert(
            ip="192.168.1.100",
            method="POST",
            path="/api/login",
            ml_verdict="MALICIOUS",
            ml_confidence=0.95,
            payload="' OR '1'='1' --; DROP TABLE users; SELECT * FROM passwords WHERE username='admin'"
        )
        
        print("\nTest email sent successfully!")
        print(f"Check your inbox at: {email_notifier.to_email}")
        print("\nNote: It may take 1-2 minutes to arrive. Also check your spam folder.")
        return True
        
    except ValueError as e:
        print(f"\nConfiguration Error: {e}")
        return False
    except Exception as e:
        print(f"\nEmail send failed: {e}")
        print("\nPossible issues:")
        print("  - Invalid SendGrid API key")
        print("  - Unverified sender email (verify at SendGrid > Sender Authentication)")
        print("  - Network connectivity issues")
        return False


def main():
    print("\nQuantumShield Honeypot - Email Alert Test")
    print("=" * 50)
    
    # First check configuration
    if not check_email_config():
        print("\nFix the configuration above and run again.")
        return
    
    # Send test email automatically
    print("\nConfiguration OK! Sending test email...")
    asyncio.run(test_email_send())


if __name__ == "__main__":
    main()

