import requests
import time

def test_scenario():
    print("--- Starting Verification ---")
    
    # 1. Test Upstream Directly
    try:
        r = requests.get("http://localhost:8001/")
        if r.status_code == 200 and "Legacy Admin Login" in r.text:
            print("✅ Upstream (Port 8001) is UP and serving Login Page.")
        else:
            print(f"❌ Upstream check failed. Status: {r.status_code}")
    except Exception as e:
        print(f"❌ Upstream unreachable: {e}")
        return

    # 2. Test Proxy Safe Access
    try:
        r = requests.get("http://localhost:8000/")
        if r.status_code == 200 and "Legacy Admin Login" in r.text:
            print("✅ Proxy (Port 8000) correctly proxies SAFE request to Upstream.")
        else:
            print(f"❌ Proxy safe check failed. Status: {r.status_code}")
            print(r.text[:200])
    except Exception as e:
        print(f"❌ Proxy unreachable: {e}")
        return

    # 3. Test Malicious Attack on Proxy (SQL Injection)
    # We use a payload we know is in the blacklist/training data
    payload = {"username": "' OR 1=1 --", "password": "anything"}
    try:
        r = requests.post("http://localhost:8000/login", data=payload)
        
        # If successfully proxied to vulnerable server, it would say "SYSTEM COMPROMISED" (because vulnerability exists)
        # If trapped by firewall, it should contain Honeypot output (or just NOT 'SYSTEM COMPROMISED')
        
        if "SYSTEM COMPROMISED" in r.text:
            print("❌ FAIL: Attack was NOT blocked! The vulnerability was triggered.")
        else:
            print("✅ SUCCESS: Attack was BLOCKED/REDIRECTED.")
            # Verify it hit the honeypot (optional, check for honeypot specific markers)
            print(f"   Response Preview: {r.text[:100]}...")
            
    except Exception as e:
        print(f"❌ Attack test failed: {e}")

    # 4. Test Attack on Upstream (Control)
    try:
        r = requests.post("http://localhost:8001/login", data=payload)
        if "SYSTEM COMPROMISED" in r.text:
            print("✅ CONTROL: Attack on Upstream (8001) SUCCEEDED as expected.")
        else:
            print("❓ CONTROL: Attack on Upstream failed? Maybe logic is wrong.")
    except:
        pass

if __name__ == "__main__":
    # Wait a bit for server to be fully up if just started
    time.sleep(2) 
    test_scenario()
