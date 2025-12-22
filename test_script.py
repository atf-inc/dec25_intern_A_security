
import requests
import time
import sys
import threading
from urllib.parse import quote

# Configuration
GATEWAY_URL = "http://localhost:8000"
HONEYPOT_URL = "http://localhost:8001"
DVWA_URL = "http://localhost:3000"

PASSED = 0
FAILED = 0
TOTAL_LATENCY = 0
NUM_REQUESTS = 0

RESET = "\033[0m"
RED = "\033[31m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
CYAN = "\033[36m"
BOLD = "\033[1m"


def print_header(title):
    print("\n" + "=" * 60)
    print(f"{BOLD}{CYAN}{title:^60}{RESET}")
    print("=" * 60)


def log_result(test_name, success, message, latency_ms):
    global PASSED, FAILED, TOTAL_LATENCY, NUM_REQUESTS
    
    TOTAL_LATENCY += latency_ms
    NUM_REQUESTS += 1
    
    status = f"{GREEN}PASS{RESET}" if success else f"{RED}FAIL{RESET}"
    print(f"[{status}] {test_name:<40} {latency_ms:6.2f}ms | {message}")
    
    if success:
        PASSED += 1
    else:
        FAILED += 1


def test_request(method, url, params=None, json_body=None, expected_status=None, desc=None, check_fn=None):
    start_time = time.time()
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
    }
    try:
        response = requests.request(method, url, params=params, json=json_body, headers=headers, timeout=5)
        latency = (time.time() - start_time) * 1000
        
        success = True
        msg = ""

        if expected_status and response.status_code != expected_status:
            success = False
            msg = f"Expected status {expected_status}, got {response.status_code}"
        
        if success and check_fn:
            success, error_msg = check_fn(response)
            if not success:
                msg = error_msg
        
        if success and not msg:
            msg = "Test passed"
            
        log_result(desc, success, msg, latency)
        return response
    except Exception as e:
        latency = (time.time() - start_time) * 1000
        log_result(desc, False, f"Exception: {str(e)}", latency)
        return None

# --- Verification Logic ---

def is_dvwa(response):
    if "TechShop" in response.text or "TechShop" in response.text: # DVWA title
         return True, ""
    if "login" in response.text.lower(): # Admin login
         return True, ""
    return False, "Response does not look like DVWA/TechShop"

def is_honeypot(response):
    # Check headers added by WAF or Response from Honeypot
    if "X-Request-ID" in response.headers:
        return True, ""
    if response.headers.get("Server") == "Uvicorn": # Honeypot server
        return True, ""
    # Check for Honeypot specific content (deception)
    if "Login" in response.text and "Admin" in response.text: # generated fake login
         return True, ""
    return False, "Response does not look like Honeypot (missing headers/content)"


# --- Test Suites ---

def test_efficiency():
    print_header("BASELINE & EFFICIENCY (Normal Traffic)")
    
    # 1. Normal Home Page
    test_request("GET", f"{GATEWAY_URL}/", desc="Normal Usage (Home)", 
                 expected_status=200, check_fn=is_dvwa)
    
    # 2. Normal Admin Page
    test_request("GET", f"{GATEWAY_URL}/admin", desc="Normal Usage (Admin)", 
                expected_status=200, check_fn=is_dvwa)

    # 3. Valid Product API
    test_request("GET", f"{GATEWAY_URL}/api/products", desc="Normal API Call", 
                 expected_status=200)


def test_exploits():
    print_header("ONE-SHOT EXPLOIT ATTEMPTS")

    # 1. SQL Injection (Query Param)
    payload_sqli = "' OR '1'='1"
    def check_sqli_block(res):
        is_hp, msg = is_honeypot(res)
        if not is_hp: return False, f"Was not redirected to Honeypot: {msg}"
        return True, ""
        
    test_request("GET", f"{GATEWAY_URL}/", params={"q": payload_sqli}, 
                 desc="SQL Injection (Query Param)", 
                 expected_status=200, check_fn=check_sqli_block)

    # 2. XSS (Reflected)
    payload_xss = "<script>alert(1)</script>"
    test_request("GET", f"{GATEWAY_URL}/", params={"search": payload_xss},
                 desc="XSS Attack (Reflected)",
                 expected_status=200, check_fn=check_sqli_block) # Should be blocked same way

    # 3. Path Traversal
    test_request("GET", f"{GATEWAY_URL}/?file=../../etc/passwd",
                 desc="Path Traversal",
                 expected_status=200, check_fn=check_sqli_block)
    
    # 4. Command Injection
    test_request("GET", f"{GATEWAY_URL}/?cmd=cat /etc/passwd",
                 desc="Command Injection",
                 expected_status=200, check_fn=check_sqli_block)


def test_ml_specifically():
    print_header("ML-CLASSIFIER SPECIFIC TESTS")
    
    # 1. Complex SQLi that might bypass regex but catch by ML
    payload_ml = "UNION SELECT 1, @@version -- "
    
    def check_ml_header(res):
        # We can't see internal logging easily, but we can check if it hit honeypot
        return is_honeypot(res)

    test_request("GET", f"{GATEWAY_URL}/", params={"q": payload_ml},
                 desc="ML SQLi Detection (BERT)",
                 expected_status=200, check_fn=check_ml_header)


def main():
    print(f"\n{BOLD}Starting Comprehensive Security Test...{RESET}")
    print(f"Gateway: {GATEWAY_URL}")
    print(f"Honeypot: {HONEYPOT_URL}")
    print(f"DVWA: {DVWA_URL}")
    
    # Wait for services to be ready? (Assuming they are running per user instructions)
    
    test_efficiency()
    test_exploits()
    test_ml_specifically()

    print_header("TEST RESULTS SUMMARY")
    print(f"Total Tests: {PASSED + FAILED}")
    print(f"{GREEN}Passed     : {PASSED}{RESET}")
    print(f"{RED}Failed     : {FAILED}{RESET}")
    
    if NUM_REQUESTS > 0:
        avg_latency = TOTAL_LATENCY / NUM_REQUESTS
        perf_color = GREEN if avg_latency < 500 else YELLOW if avg_latency < 1000 else RED
        print(f"Avg Latency: {perf_color}{avg_latency:.2f}ms{RESET}")
        print("\nEfficiency Note:")
        print("  < 500ms : Excellent")
        print("  < 1s    : Acceptable (considering ML overhead)")
        print("  > 1s    : Slow")

    if FAILED == 0:
        print(f"\n{BOLD}{GREEN}>>> SYSTEM AUDIT PASSED: SECURE & EFFICIENT <<<{RESET}")
    else:
        print(f"\n{BOLD}{RED}>>> SYSTEM AUDIT FAILED: VULNERABILITIES DETECTED <<<{RESET}")

if __name__ == "__main__":
    with open("test_results.txt", "w") as f:
        sys.stdout = f
        main()
        sys.stdout = sys.__stdout__
    
    # Also print to console
    with open("test_results.txt", "r") as f:
        print(f.read())
