"""
Simple test to check if honeypot is actually being triggered
"""
import requests

print("Testing honeypot detection...")

# Test malicious request
response = requests.post(
    "http://localhost:8000/api/auth",
    json={"username": "admin' OR 1=1--", "password": "test"},
    timeout=10
)

print(f"\nStatus Code: {response.status_code}")
print(f"Headers: {dict(response.headers)}")
print(f"\nResponse Text:\n{response.text}")

# Check if it's trapped
if "X-QuantumShield-Trap" in response.headers:
    print("\n✅ TRAPPED by honeypot!")
else:
    print("\n❌ NOT trapped - went to real app")
