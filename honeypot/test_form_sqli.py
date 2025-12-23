"""
Test script to verify form-based SQL injection detection.

This tests that SQL injections submitted via forms (POST body) are detected
and trigger the same blocking/trapping behavior as URL-based SQL injections.
"""

import requests
import json
import time

FIREWALL_URL = "http://localhost:8000"

def test_url_sqli():
    """Test SQL injection in URL parameters (should work)"""
    print("\n" + "="*70)
    print("TEST 1: SQL Injection in URL Parameter")
    print("="*70)
    
    url = f"{FIREWALL_URL}/search?id=1' OR '1'='1"
    print(f"Request: GET {url}")
    
    try:
        response = requests.get(url, timeout=5)
        print(f"Status: {response.status_code}")
        print(f"Response: {response.text[:200]}")
        
        if response.status_code == 403:
            print("✅ BLOCKED - SQL injection detected in URL")
        else:
            print("⚠️  Not blocked - check logs")
    except Exception as e:
        print(f"❌ Error: {e}")

def test_form_sqli_urlencoded():
    """Test SQL injection in URL-encoded form data"""
    print("\n" + "="*70)
    print("TEST 2: SQL Injection in URL-Encoded Form Data")
    print("="*70)
    
    url = f"{FIREWALL_URL}/login"
    data = {
        "username": "admin' OR '1'='1",
        "password": "test123"
    }
    print(f"Request: POST {url}")
    print(f"Data: {data}")
    
    try:
        response = requests.post(
            url, 
            data=data,  # URL-encoded form data
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            timeout=5
        )
        print(f"Status: {response.status_code}")
        print(f"Response: {response.text[:200]}")
        
        if response.status_code == 403:
            print("✅ BLOCKED - SQL injection detected in form")
        else:
            print("⚠️  Not blocked - check logs")
    except Exception as e:
        print(f"❌ Error: {e}")

def test_form_sqli_json():
    """Test SQL injection in JSON form data"""
    print("\n" + "="*70)
    print("TEST 3: SQL Injection in JSON Form Data")
    print("="*70)
    
    url = f"{FIREWALL_URL}/api/login"
    data = {
        "username": "admin' OR '1'='1",
        "password": "test123"
    }
    print(f"Request: POST {url}")
    print(f"JSON: {json.dumps(data)}")
    
    try:
        response = requests.post(
            url, 
            json=data,  # JSON form data
            timeout=5
        )
        print(f"Status: {response.status_code}")
        print(f"Response: {response.text[:200]}")
        
        if response.status_code == 403:
            print("✅ BLOCKED - SQL injection detected in JSON")
        else:
            print("⚠️  Not blocked - check logs")
    except Exception as e:
        print(f"❌ Error: {e}")

def test_nested_json_sqli():
    """Test SQL injection in nested JSON data"""
    print("\n" + "="*70)
    print("TEST 4: SQL Injection in Nested JSON")
    print("="*70)
    
    url = f"{FIREWALL_URL}/api/user/update"
    data = {
        "user": {
            "profile": {
                "bio": "Hello' OR '1'='1 --",
                "name": "John Doe"
            }
        }
    }
    print(f"Request: POST {url}")
    print(f"JSON: {json.dumps(data, indent=2)}")
    
    try:
        response = requests.post(
            url, 
            json=data,
            timeout=5
        )
        print(f"Status: {response.status_code}")
        print(f"Response: {response.text[:200]}")
        
        if response.status_code == 403:
            print("✅ BLOCKED - SQL injection detected in nested JSON")
        else:
            print("⚠️  Not blocked - check logs")
    except Exception as e:
        print(f"❌ Error: {e}")

def test_safe_form():
    """Test safe form submission (should pass through)"""
    print("\n" + "="*70)
    print("TEST 5: Safe Form Submission (Control)")
    print("="*70)
    
    url = f"{FIREWALL_URL}/api/login"
    data = {
        "username": "admin",
        "password": "test123"
    }
    print(f"Request: POST {url}")
    print(f"JSON: {json.dumps(data)}")
    
    try:
        response = requests.post(
            url, 
            json=data,
            timeout=5
        )
        print(f"Status: {response.status_code}")
        print(f"Response: {response.text[:200]}")
        
        if response.status_code != 403:
            print("✅ ALLOWED - Safe request passed through")
        else:
            print("❌ FALSE POSITIVE - Safe request was blocked!")
    except Exception as e:
        print(f"❌ Error: {e}")

def check_trap_status():
    """Check if IP is trapped"""
    print("\n" + "="*70)
    print("Checking Trap Status")
    print("="*70)
    
    try:
        response = requests.get(f"{FIREWALL_URL}/debug/trap-status", timeout=5)
        if "TRAPPED" in response.text:
            print("🔒 IP is TRAPPED")
        elif "NOT TRAPPED" in response.text:
            print("🔓 IP is NOT TRAPPED")
        else:
            print("⚠️  Unknown trap status")
    except Exception as e:
        print(f"❌ Error checking trap status: {e}")

def clear_trap():
    """Clear trap for testing"""
    print("\n" + "="*70)
    print("Clearing Trap")
    print("="*70)
    
    try:
        response = requests.post(f"{FIREWALL_URL}/debug/clear-trap", timeout=5)
        print("✅ Trap cleared")
    except Exception as e:
        print(f"❌ Error clearing trap: {e}")

if __name__ == "__main__":
    print("\n" + "="*70)
    print("FORM-BASED SQL INJECTION DETECTION TEST")
    print("="*70)
    print("\nThis test verifies that SQL injections in form data are detected")
    print("and trigger the same blocking/trapping as URL-based injections.")
    print("\nMake sure the honeypot is running on http://localhost:8000")
    
    # Clear any existing trap first
    clear_trap()
    time.sleep(1)
    
    # Run tests
    test_url_sqli()
    time.sleep(1)
    
    check_trap_status()
    clear_trap()
    time.sleep(1)
    
    test_form_sqli_urlencoded()
    time.sleep(1)
    
    check_trap_status()
    clear_trap()
    time.sleep(1)
    
    test_form_sqli_json()
    time.sleep(1)
    
    check_trap_status()
    clear_trap()
    time.sleep(1)
    
    test_nested_json_sqli()
    time.sleep(1)
    
    check_trap_status()
    clear_trap()
    time.sleep(1)
    
    test_safe_form()
    time.sleep(1)
    
    check_trap_status()
    
    print("\n" + "="*70)
    print("TEST COMPLETE")
    print("="*70)
    print("\nCheck the honeypot logs for detailed payload extraction info.")
    print("All SQL injection tests should result in BLOCKED or TRAPPED status.")
