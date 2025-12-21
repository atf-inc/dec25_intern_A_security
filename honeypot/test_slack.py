"""
Test script for Slack notifications
Run: python test_slack.py
"""
import asyncio
from core.slack_notifier import slack_notifier
from config import settings

async def test_slack_alert():
    print("=" * 50)
    print("Slack Notification Test")
    print("=" * 50)
    
    # Check configuration
    print(f"\nConfiguration:")
    print(f"  ENABLE_SLACK_ALERTS: {settings.ENABLE_SLACK_ALERTS}")
    print(f"  SLACK_WEBHOOK_URL: {'[SET]' if settings.SLACK_WEBHOOK_URL else '[NOT SET]'}")
    
    if not settings.ENABLE_SLACK_ALERTS:
        print("\n[WARNING] Slack alerts are disabled. Set ENABLE_SLACK_ALERTS=true in .env")
        return
    
    if not settings.SLACK_WEBHOOK_URL:
        print("\n[ERROR] SLACK_WEBHOOK_URL is not set in .env file!")
        return
    
    print("\nSending test alert to Slack...")
    
    # Send a test alert
    await slack_notifier.send_attack_alert(
        ip="192.168.1.100",
        method="POST",
        path="api/login",
        ml_verdict="MALICIOUS",
        ml_confidence=0.95,
        payload="username=admin&password=' OR '1'='1' --"
    )
    
    print("\n[SUCCESS] Test alert sent! Check your Slack channel.")
    print("=" * 50)

if __name__ == "__main__":
    asyncio.run(test_slack_alert())

