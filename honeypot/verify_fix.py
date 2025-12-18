import requests

def test_post_sqli():
    url = "http://localhost:8000/"
    payload = {"username": "admin' OR 1=1", "password": "123"}
    
    try:
        print(f"Sending POST request to {url} with malicious payload...")
        response = requests.post(url, data=payload)
        
        print(f"Status Code: {response.status_code}")
        trap_header = response.headers.get("X-QuantumShield-Trap")
        
        if trap_header:
            print(f"SUCCESS: Trapped! Header found: {trap_header}")
        else:
            print("FAILURE: Not trapped. Request went through.")
            print(f"Headers: {response.headers}")
            
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    test_post_sqli()
