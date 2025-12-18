import requests
import time

BASE_URL = "http://localhost:8000"

def test_terminal_command():
    print("Testing Terminal Command...")
    payload = {"command": "ls -la"}
    try:
        response = requests.post(f"{BASE_URL}/api/terminal", json=payload)
        print(f"Status: {response.status_code}")
        print(f"Response: {response.json()}")
    except Exception as e:
        print(f"Failed to connect: {e}")

def test_admin_login():
    print("\nTesting Admin Login Page...")
    try:
        response = requests.get(f"{BASE_URL}/admin/login")
        print(f"Status: {response.status_code}")
        print(f"Response Length: {len(response.text)}")
        print("Response Preview:", response.text[:100])
    except Exception as e:
        print(f"Failed to connect: {e}")

def test_random_probe():
    print("\nTesting Random Probe...")
    try:
        response = requests.get(f"{BASE_URL}/wp-admin/setup-config.php")
        print(f"Status: {response.status_code}")
        print("Response Preview:", response.text[:100])
    except Exception as e:
        print(f"Failed to connect: {e}")

if __name__ == "__main__":
    print("Ensure the server is running on localhost:8000")
    test_terminal_command()
    test_admin_login()
    test_random_probe()
