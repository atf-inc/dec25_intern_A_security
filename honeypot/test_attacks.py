import requests

BASE_URL = "http://localhost:8000"

def test_sqli_attack():
    print("\nTesting SQL Injection Simulation...")
    # Simulating a common SQL injection payload
    payload = "UNION SELECT username, password FROM users--"
    try:
        response = requests.post(f"{BASE_URL}/api/search", data={"q": payload})
        print(f"Status: {response.status_code}")
        print(f"Response Preview: {response.text[:200]}...") 
    except Exception as e:
        print(f"Failed: {e}")

def test_sensitive_file_probe():
    print("\nTesting Sensitive File Probe...")
    # Simulating a path traversal or config file scan
    try:
        response = requests.get(f"{BASE_URL}/.env")
        print(f"Status: {response.status_code}")
        print(f"Response Preview: {response.text[:200]}...")
    except Exception as e:
        print(f"Failed: {e}")

if __name__ == "__main__":
    test_sqli_attack()
    test_sensitive_file_probe()
