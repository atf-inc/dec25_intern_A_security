"""
Test legitimate login to see ML scores
"""

import requests
import json

# Test legitimate login
ENDPOINT = "http://localhost:8000"

# Test cases
test_cases = [
    {
        "name": "Legitimate Login (Form Data)",
        "path": "/login",
        "method": "POST",
        "data": {"username": "user1", "password": "1234"},
        "content_type": "application/x-www-form-urlencoded"
    },
    {
        "name": "Legitimate Login (JSON)",
        "path": "/api/login",
        "method": "POST",
        "json": {"username": "user1", "password": "1234"},
        "content_type": "application/json"
    },
    {
        "name": "Malicious NoSQL Injection",
        "path": "/api/login",
        "method": "POST",
        "json": {"username": {"$ne": None}, "password": {"$ne": None}},
        "content_type": "application/json"
    }
]

print("=" * 80)
print("Testing Legitimate vs Malicious Login Payloads")
print("=" * 80)

for test in test_cases:
    print(f"\n🔍 Test: {test['name']}")
    print(f"📍 Path: {test['path']}")
    
    try:
        if test.get('json'):
            print(f"📦 Payload: {json.dumps(test['json'])}")
            response = requests.post(
                ENDPOINT + test['path'],
                json=test['json'],
                timeout=10
            )
        else:
            print(f"📦 Payload: {test['data']}")
            response = requests.post(
                ENDPOINT + test['path'],
                data=test['data'],
                timeout=10
            )
        
        print(f"✅ Status: {response.status_code}")
        print(f"📝 Response (first 150 chars): {response.text[:150]}")
        
        if response.status_code == 403:
            print("⚠️  BLOCKED or HONEYPOT")
        elif response.status_code == 200:
            print("✅ FORWARDED to upstream")
        
    except Exception as e:
        print(f"❌ Error: {e}")

print("\n" + "=" * 80)
print("Check your console logs to see ML confidence scores!")
print("=" * 80)
