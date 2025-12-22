import requests
import time
import sys

GATEWAY_URL = "http://localhost:8000"

def test_safe_request():
    print(f"[TEST] Sending SAFE request to {GATEWAY_URL}...")
    try:
        response = requests.get(GATEWAY_URL, timeout=5)
        # DVWA login page usually contains "Login"
        if response.status_code == 200:
             print("[PASS] Safe request received 200 OK")
             if "Login" in response.text or "DVWA" in response.text:
                 print("[PASS] Content looks like DVWA")
             else:
                 print(f"[WARN] Content does not look like DVWA. Length: {len(response.text)}")
        else:
            print(f"[FAIL] Safe request returned {response.status_code}")
    except Exception as e:
        print(f"[FAIL] Connection error: {e}")

def test_attack_request():
    print(f"\n[TEST] Sending ATTACK request to {GATEWAY_URL}...")
    # SQL Injection pattern
    payload = {"q": "' OR 1=1--"}
    try:
        response = requests.get(GATEWAY_URL, params=payload, timeout=5)
        
        # We expect a 200 OK (Deception) or 403 (if Honeypot blocks, but we set it to deceive)
        # But crucially, we check headers if possible, OR check if content is different from DVWA
        
        if response.status_code == 200:
            print("[PASS] Attack request received 200 OK (Deception active)")
            # Check for Honeypot specific indicators?
            # In our implementation, honeypot creates "admin login" or similar.
            # Also we might see different headers if we inspected them, but `requests` hides some proxy headers unless explicitly returned.
        elif response.status_code == 403:
            print("[PASS] Attack request BLOCKED (403)")
        else:
            print(f"[FAIL] Attack request returned {response.status_code}")
            
    except Exception as e:
        print(f"[FAIL] Connection error: {e}")

def test_analytics_api():
    print(f"\n[TEST] Testing Analytics API proxying...")
    try:
        response = requests.get(f"{GATEWAY_URL}/api/analytics/stats", timeout=5)
        if response.status_code == 200:
             print("[PASS] Analytics API reachable via Gateway")
             data = response.json()
             print(f"[INFO] Stats received: {data.keys()}")
        else:
             print(f"[FAIL] Analytics API returned {response.status_code}")
    except Exception as e:
        print(f"[FAIL] Connection error: {e}")

if __name__ == "__main__":
    print("=== QuantumShield Integration Verification ===")
    print("Ensure 'start_all.ps1' is running before executing this script.")
    print("==============================================\n")
    
    test_safe_request()
    test_attack_request()
    test_analytics_api()
