"""
Test whitelist bypass for legitimate credentials
"""

import requests
import json

ENDPOINT = "http://localhost:8000"

print("=" * 80)
print("Testing Whitelist Bypass for username=sam, password=sam@123")
print("=" * 80)

# Test 1: JSON format
print("\n🔍 Test 1: JSON Login (Whitelisted)")
print("📦 Payload: {\"username\": \"sam\", \"password\": \"sam@123\"}")

try:
    response = requests.post(
        f"{ENDPOINT}/api/login",
        json={"username": "sam", "password": "sam@123"},
        timeout=10
    )
    print(f"✅ Status: {response.status_code}")
    print(f"📝 Response (first 200 chars): {response.text[:200]}")
    
    if response.status_code == 200:
        print("✅ SUCCESS: Whitelisted user bypassed ML and reached upstream!")
    elif response.status_code == 403:
        print("❌ FAILED: User was blocked or sent to honeypot (whitelist not working)")
except Exception as e:
    print(f"❌ Error: {e}")

# Test 2: Form data format
print("\n🔍 Test 2: Form Login (Whitelisted)")
print("📦 Payload: username=sam&password=sam@123")

try:
    response = requests.post(
        f"{ENDPOINT}/login",
        data={"username": "sam", "password": "sam@123"},
        timeout=10
    )
    print(f"✅ Status: {response.status_code}")
    print(f"📝 Response (first 200 chars): {response.text[:200]}")
    
    if response.status_code == 200:
        print("✅ SUCCESS: Whitelisted user bypassed ML and reached upstream!")
    elif response.status_code == 403:
        print("❌ FAILED: User was blocked or sent to honeypot (whitelist not working)")
except Exception as e:
    print(f"❌ Error: {e}")

# Test 3: Non-whitelisted user (should go through ML)
print("\n🔍 Test 3: Non-Whitelisted User (Should go through ML)")
print("📦 Payload: {\"username\": \"user1\", \"password\": \"1234\"}")

try:
    response = requests.post(
        f"{ENDPOINT}/api/login",
        json={"username": "user1", "password": "1234"},
        timeout=10
    )
    print(f"✅ Status: {response.status_code}")
    print(f"📝 Response (first 200 chars): {response.text[:200]}")
    
    if response.status_code == 403:
        print("⚠️  User went through ML checks (might be blocked/honeypot)")
    elif response.status_code == 200:
        print("✅ User passed ML checks and reached upstream")
except Exception as e:
    print(f"❌ Error: {e}")

# Test 4: Malicious payload (should be blocked)
print("\n🔍 Test 4: Malicious NoSQL Injection (Should be blocked)")
print("📦 Payload: {\"username\": {\"$ne\": null}, \"password\": {\"$ne\": null}}")

try:
    response = requests.post(
        f"{ENDPOINT}/api/login",
        json={"username": {"$ne": None}, "password": {"$ne": None}},
        timeout=10
    )
    print(f"✅ Status: {response.status_code}")
    print(f"📝 Response (first 200 chars): {response.text[:200]}")
    
    if response.status_code == 403:
        print("✅ SUCCESS: Malicious payload was blocked!")
    elif response.status_code == 200:
        print("❌ FAILED: Malicious payload reached upstream!")
except Exception as e:
    print(f"❌ Error: {e}")

print("\n" + "=" * 80)
print("Check your honeypot console logs for [WHITELIST] messages!")
print("=" * 80)
