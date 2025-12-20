import requests
import json

print("Testing Honeypot Endpoint...")
print("=" * 50)

# Test 1: Direct DVWA (should work)
print("\n1. Testing DVWA directly (port 3000):")
try:
    response = requests.post(
        "http://localhost:3000/api/auth",
        json={"username": "admin' OR 1=1--", "password": "test"},
        timeout=5
    )
    print(f"   Status: {response.status_code}")
    print(f"   Response: {response.json()}")
except Exception as e:
    print(f"   ERROR: {e}")

# Test 2: Through Honeypot (might fail)
print("\n2. Testing through Honeypot (port 8000):")
try:
    response = requests.post(
        "http://localhost:8000/api/auth",
        json={"username": "admin' OR 1=1--", "password": "test"},
        timeout=5
    )
    print(f"   Status: {response.status_code}")
    print(f"   Headers: {dict(response.headers)}")
    print(f"   Response: {response.text[:200]}")
    try:
        print(f"   JSON: {response.json()}")
    except:
        print("   (Not valid JSON)")
except Exception as e:
    print(f"   ERROR: {e}")

print("\n" + "=" * 50)
print("Test complete!")
