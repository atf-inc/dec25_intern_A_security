"""
Test script to verify that MALICIOUS (blocked) requests are logged to the database.

This script:
1. Sends a malicious SQL injection request to the honeypot
2. Waits for background task to complete
3. Queries the database to verify the attack was logged
4. Prints the logged attack details
"""

import asyncio
import httpx
import time
from core.database import db

async def test_malicious_logging():
    print("=" * 60)
    print("Testing MALICIOUS Request Logging")
    print("=" * 60)
    
    # Connect to database
    await db.connect()
    logs_collection = db.get_collection("logs")
    
    # Get initial log count
    initial_count = await logs_collection.count_documents({"ml_verdict": "MALICIOUS"})
    print(f"\n[STATS] Initial MALICIOUS logs count: {initial_count}")
    
    # Send a malicious SQL injection request
    print("\n[TEST] Sending MALICIOUS SQL injection request...")
    malicious_payload = "iPhone' OR 1=1--"
    
    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"http://localhost:8000/api/products?search={malicious_payload}",
                timeout=5.0
            )
            print(f"   Status Code: {response.status_code}")
            print(f"   Expected: 403 Forbidden")
            
            if response.status_code == 403:
                print("   [OK] Request was blocked as expected")
            else:
                print(f"   [WARN] Unexpected status code: {response.status_code}")
    
    except Exception as e:
        print(f"   [ERROR] Request failed: {e}")
    
    # Wait for background task to complete
    print("\n[WAIT] Waiting 3 seconds for background logging task...")
    await asyncio.sleep(3)
    
    # Check if attack was logged
    print("\n[CHECK] Checking database for logged attack...")
    new_count = await logs_collection.count_documents({"ml_verdict": "MALICIOUS"})
    
    if new_count > initial_count:
        print(f"   [SUCCESS] New MALICIOUS logs count: {new_count}")
        print(f"   [INCREASE] +{new_count - initial_count}")
        
        # Fetch the latest logged attack
        latest_attack = await logs_collection.find_one(
            {"ml_verdict": "MALICIOUS"},
            sort=[("timestamp", -1)]
        )
        
        if latest_attack:
            print("\n[DETAILS] Latest Logged Attack:")
            print(f"   Session ID: {latest_attack.get('session_id')}")
            print(f"   IP Address: {latest_attack.get('ip')}")
            print(f"   Request Type: {latest_attack.get('type')}")
            print(f"   Attack Type: {latest_attack.get('attack_type')}")
            print(f"   Severity: {latest_attack.get('severity')}")
            print(f"   ML Verdict: {latest_attack.get('ml_verdict')}")
            print(f"   ML Confidence: {latest_attack.get('ml_confidence'):.2%}")
            print(f"   HTTP Method: {latest_attack.get('http_method')}")
            print(f"   Path: {latest_attack.get('path')}")
            print(f"   Payload: {latest_attack.get('payload')[:100]}...")
            print(f"   Response: {latest_attack.get('response')}")
            print(f"   Timestamp: {latest_attack.get('timestamp')}")
    else:
        print(f"   [FAILED] No new logs found")
        print(f"   Expected count: {initial_count + 1}")
        print(f"   Actual count: {new_count}")
        print("\n   Possible issues:")
        print("   - Honeypot not running on port 8000")
        print("   - Background task not executing")
        print("   - Database connection issue")
    
    # Close database connection
    await db.close()
    
    print("\n" + "=" * 60)
    print("Test Complete")
    print("=" * 60)

if __name__ == "__main__":
    asyncio.run(test_malicious_logging())
