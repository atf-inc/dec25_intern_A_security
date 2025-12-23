"""
Quick test to verify payload extraction for admin' OR 1=1--
"""

import sys
import os

# Add honeypot to path
sys.path.insert(0, os.path.dirname(__file__))

from core.ml_classifier import ml_classifier

# Test 1: URL-encoded form data
print("="*70)
print("TEST 1: URL-encoded form data")
print("="*70)
text1 = "POST /login?\nusername=admin%27+OR+1%3D1--&password=test123"
payloads1 = ml_classifier._extract_payloads(text1)
print(f"Input: {text1}")
print(f"Extracted payloads: {payloads1}")
print()

# Test 2: JSON form data
print("="*70)
print("TEST 2: JSON form data")
print("="*70)
text2 = '''POST /login?
{"username": "admin' OR 1=1--", "password": "test123"}'''
payloads2 = ml_classifier._extract_payloads(text2)
print(f"Input: {text2}")
print(f"Extracted payloads: {payloads2}")
print()

# Test 3: Simple form data
print("="*70)
print("TEST 3: Simple form data")
print("="*70)
text3 = "POST /login?\nusername=admin' OR 1=1--&password=test123"
payloads3 = ml_classifier._extract_payloads(text3)
print(f"Input: {text3}")
print(f"Extracted payloads: {payloads3}")
print()

# Test 4: Analyze the SQL injection payload
print("="*70)
print("TEST 4: ML Analysis of SQL injection payload")
print("="*70)
sqli_payload = "admin' OR 1=1--"
result = ml_classifier.predict_sqli(sqli_payload)
print(f"Payload: {sqli_payload}")
print(f"Result: {result}")
print()

# Test 5: Full request analysis
print("="*70)
print("TEST 5: Full request analysis with predict_with_confidence")
print("="*70)
from core.firewall import firewall_model

full_request = '''POST /login?
{"username": "admin' OR 1=1--", "password": "test123"}'''
result = firewall_model.predict_with_confidence(full_request)
print(f"Request: {full_request}")
print(f"Verdict: {result['verdict']}")
print(f"Confidence: {result['confidence']:.2f}")
print(f"Is Malicious: {result['is_malicious']}")
print()

if result['verdict'] == 'SUSPICIOUS':
    print("✅ SUCCESS: Would be TRAPPED and routed to honeypot")
elif result['verdict'] == 'MALICIOUS':
    print("✅ SUCCESS: Would be BLOCKED with 403")
else:
    print("❌ FAIL: Would be forwarded to upstream (NOT TRAPPED)")
