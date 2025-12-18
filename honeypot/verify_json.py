import requests
import json

def test_json_sqli():
    url = "http://localhost:8000/"
    # Payload matches the vulnerable app's structure
    payload = {
        "username": "admin' OR 1=1", 
        "password": "123"
    }
    
    headers = {"Content-Type": "application/json"}
    
    try:
        print(f"Sending JSON POST request to {url} with malicious payload...")
        response = requests.post(url, json=payload, headers=headers)
        
        print(f"Status Code: {response.status_code}")
        trap_header = response.headers.get("X-QuantumShield-Trap")
        
        if trap_header:
            print(f"SUCCESS: Trapped! Header found: {trap_header}")
        else:
            print("FAILURE: Not trapped. Request went through.")
            print(f"Response: {response.text[:200]}")
            
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    test_json_sqli()
