
import requests
import time
import sys
import random
import string
import json

# Configuration
GATEWAY_URL = "http://localhost:8000"
HONEYPOT_URL = "http://localhost:8001"
# We abuse the /api/waf/process to test ML specifically
ML_API_URL = f"{GATEWAY_URL}/api/waf/process"

# Colors
RESET = "\033[0m"
BOLD = "\033[1m"
GREEN = "\033[32m"
RED = "\033[31m"
YELLOW = "\033[33m"
CYAN = "\033[36m"
MAGENTA = "\033[35m"

# Stats
stats = {
    "quantumshield": {"pass": 0, "fail": 0},
    "honeypot": {"pass": 0, "fail": 0},
    "ml_classifier": {"pass": 0, "fail": 0}
}
details = []

def print_header(title):
    print("\n" + "=" * 80)
    print(f"{BOLD}{CYAN}{title:^80}{RESET}")
    print("=" * 80)

def log_test(module, test_name, success, message):
    global stats, details
    status = f"{GREEN}PASS{RESET}" if success else f"{RED}FAIL{RESET}"
    print(f"[{status}] {module:<15} : {test_name:<40} | {message}")
    if success:
        stats[module]["pass"] += 1
    else:
        stats[module]["fail"] += 1
    details.append({"module": module, "test": test_name, "success": success, "msg": message})

# --- QUANTUMSHIELD TEST CASES (30) ---
# It should BLOCK attacks or Redirect to Honeypot
# Pass if: HTTP 200 from Honeypot OR HTTP 403 (Blocked)
# Fail if: HTTP 200 from DVWA (Content checking)

def check_qs_response(response, is_attack=True):
    # If it's an attack, we expect it to NOT be DVWA
    # If it's safe, we expect it TO BE DVWA
    
    body = response.text
    
    # Identifiers
    is_honeypot = "X-Request-ID" in response.headers or "Login System" in body or "Uvicorn" in response.headers.get("server", "")
    is_dvwa = "TechShop" in body or "Damn Vulnerable" in body or "Welcome to" in body
    is_blocked = response.status_code == 403 or "Blocked" in body
    
    if is_attack:
        # Success if Honeypot OR Blocked
        # Fail if DVWA
        if is_dvwa and not (is_honeypot or is_blocked):
            return False, "Leaked to DVWA"
        return True, "Blocked/Redirected"
    else:
        # Success if DVWA
        # Fail if Honeypot or Blocked
        if is_honeypot: return False, "False Positive (Honeypot)"
        if is_blocked: return False, "False Positive (Blocked)"
        return True, "Allowed"

def run_quantumshield_tests():
    print_header("MODULE: QUANTUMSHIELD (30 Test Cases)")
    
    # 1-10: SQL Injection
    sqli_payloads = [
         "' OR '1'='1", "UNION SELECT 1,2,3", "admin' --", "1; DROP TABLE users",
         "' OR 1=1 #", "' OR 'x'='x", "1' ORDER BY 10--", "admin'/*",
         "cn' UNION SELECT 1,user(),3--", "id=1' AND 1=1"
    ]
    for i, p in enumerate(sqli_payloads):
        try:
            r = requests.get(f"{GATEWAY_URL}/", params={"q": p}, timeout=2)
            ok, msg = check_qs_response(r, is_attack=True)
            log_test("quantumshield", f"SQLi #{i+1}", ok, msg)
        except Exception as e:
            log_test("quantumshield", f"SQLi #{i+1}", False, str(e))

    # 11-20: XSS
    xss_payloads = [
        "<script>alert(1)</script>", "<img src=x onerror=alert(1)>", 
        "javascript:alert(1)", "<svg/onload=alert(1)>", "<body>",
        "'><script>confirm(1)</script>", "<a href=javascript:alert(1)>",
        "<input onfocus=alert(1) autofocus>", "<FRAMESET><FRAME SRC=javascript:alert(1)></FRAMESET>",
        "\";alert(1)//"
    ]
    for i, p in enumerate(xss_payloads):
        try:
            r = requests.get(f"{GATEWAY_URL}/", params={"s": p}, timeout=2)
            ok, msg = check_qs_response(r, is_attack=True)
            log_test("quantumshield", f"XSS #{i+1}", ok, msg)
        except Exception as e:
            log_test("quantumshield", f"XSS #{i+1}", False, str(e))

    # 21-25: Path Traversal
    pt_payloads = [
        "../../etc/passwd", "..\\..\\windows\\win.ini", "/var/www/html/../../etc/passwd",
        "%2e%2e%2fetc%2fpasswd", "../../../boot.ini"
    ]
    for i, p in enumerate(pt_payloads):
        try:
            r = requests.get(f"{GATEWAY_URL}/", params={"file": p}, timeout=2)
            ok, msg = check_qs_response(r, is_attack=True)
            log_test("quantumshield", f"PathTrav #{i+1}", ok, msg)
        except Exception as e:
            log_test("quantumshield", f"PathTrav #{i+1}", False, str(e))

    # 26-30: Safe Traffic
    safe_payloads = [
        "apple", "search query", "item_id=10", "login", "contact-us"
    ]
    for i, p in enumerate(safe_payloads):
        try:
            r = requests.get(f"{GATEWAY_URL}/", params={"q": p}, timeout=2)
            ok, msg = check_qs_response(r, is_attack=False)
            log_test("quantumshield", f"Safe #{i+1}", ok, msg)
        except Exception as e:
            log_test("quantumshield", f"Safe #{i+1}", False, str(e))


# --- HONEYPOT TEST CASES (30) ---
# Verify it acts like a honeypot

def run_honeypot_tests():
    print_header("MODULE: HONEYPOT (30 Test Cases)")
    
    # 1-10: Fake Endpoints
    endpoints = [
        "/admin", "/login", "/wp-admin", "/backup.sql", "/config.php",
        "/environment", "/.env", "/id_rsa", "/root", "/dashboard"
    ]
    for i, ep in enumerate(endpoints):
        try:
            r = requests.get(f"{HONEYPOT_URL}{ep}", timeout=2)
            # Expecting 200 OK (Deception) not 404
            ok = r.status_code == 200
            log_test("honeypot", f"FakeEndpoint #{i+1} ({ep})", ok, f"Code: {r.status_code}")
        except Exception as e:
            log_test("honeypot", f"FakeEndpoint #{i+1}", False, str(e))

    # 11-20: Header Injection (Tracking)
    # We want to ensure it accepts requests with weird headers and logs them (returns 200)
    headers_list = [
        {"X-Forwarded-For": "1.2.3.4"}, {"User-Agent": "sqlmap"}, 
        {"Cookie": "admin=true"}, {"Authorization": "Basic YWRtaW46YWRtaW4="},
        {"Referer": "evil.com"}, {"Origin": "null"},
        {"X-Api-Key": "test"}, {"Content-Type": "application/json"},
        {"Accept": "application/xml"}, {"Connection": "close"}
    ]
    for i, h in enumerate(headers_list):
        try:
            r = requests.get(f"{HONEYPOT_URL}/", headers=h, timeout=2)
            ok = r.status_code == 200
            log_test("honeypot", f"Header #{i+1}", ok, "Accepted")
        except Exception as e:
            log_test("honeypot", f"Header #{i+1}", False, str(e))
            
    # 21-30: Post Data Deception
    # Sending credentials should return success (fake) or login page
    creds = [
        {"user":"admin", "pass":"123"}, {"u":"root", "p":"root"},
        {"email":"admin@test.com", "pass":"password"}, {"token":"12345"},
        {"api_key":"abcdef"}, {"debug":"true"}, {"cmd":"ls"},
        {"id":"1 OR 1=1"}, {"data":"<script>"}, {"file":"../../"}
    ]
    for i, d in enumerate(creds):
        try:
            r = requests.post(f"{HONEYPOT_URL}/login", json=d, timeout=2)
            # Should not crash, should return 200
            ok = r.status_code == 200
            log_test("honeypot", f"PostData #{i+1}", ok, "Handled")
        except Exception as e:
            log_test("honeypot", f"PostData #{i+1}", False, str(e))


# --- ML CLASSIFIER TEST CASES (30) ---
# Using API to test precision

def run_ml_tests():
    print_header("MODULE: ML CLASSIFIER (30 Test Cases)")
    
    # 1-15: Malicious (Obfuscated/Complex) - Should be BLOCKED (Violations > 0)
    # Note: The API returns {"allowed": False, "violations": [...]}
    malicious_inputs = [
        "UNION SELECT 1,2,3", 
        "1' OR '1'='1", 
        "<script>alert(1)</script>", 
        "../../etc/passwd",
        "; cat /etc/shadow",
        "javascript:alert(1)",
        "admin' #",
        "1=1",
        "DROP TABLE customers",
        "SELECT * FROM users WHERE id = 1 OR 1=1",
        "' OR ''='",
        "<img src=x onerror=prompt(1)>",
        "AND 1=1",
        "EXEC(1)",
        "WAITFOR DELAY '0:0:5'"
    ]
    
    for i, p in enumerate(malicious_inputs):
        try:
            body = {
                "method": "GET", 
                "uri": "/", 
                "query_params": {"q": p},
                "src_ip": "1.2.3.4"
            }
            r = requests.post(ML_API_URL, json=body, timeout=5)
            data = r.json()
            # Success if allowed=False
            ok = data.get("allowed") is False
            log_test("ml_classifier", f"Malicious #{i+1}", ok, f"Allowed: {data.get('allowed')}")
        except Exception as e:
            log_test("ml_classifier", f"Malicious #{i+1}", False, str(e))

    # 16-30: Clean Traffic - Should by ALLOWED
    clean_inputs = [
        "iPhone 13", "laptop case", "user_id=5", "page=2", "sort=desc",
        "category=electronics", "search=red shoes", "action=view",
        "email=john@example.com", "zip=90210", "city=New York",
        "about-us", "contact", "privacy-policy", "terms"
    ]
    for i, p in enumerate(clean_inputs):
        try:
            body = {
                "method": "GET", 
                "uri": "/", 
                "query_params": {"q": p},
                "src_ip": "1.2.3.4"
            }
            r = requests.post(ML_API_URL, json=body, timeout=5)
            data = r.json()
            # Success if allowed=True
            ok = data.get("allowed") is True
            log_test("ml_classifier", f"Clean #{i+1}", ok, f"Allowed: {data.get('allowed')}")
        except Exception as e:
            log_test("ml_classifier", f"Clean #{i+1}", False, str(e))


def main():
    print(f"{BOLD}Starting Comprehensive Verification (90 Tests)...{RESET}")
    print("Ensuring servers are up...")
    try:
        requests.get(GATEWAY_URL, timeout=1)
        requests.get(HONEYPOT_URL, timeout=1)
    except:
        print(f"{RED}CRITICAL: Services down. Please start the docker containers.{RESET}")
        return

    check_qs_response(requests.Response()) # Init check

    time.sleep(1)
    run_quantumshield_tests()
    time.sleep(1)
    run_honeypot_tests()
    time.sleep(1)
    run_ml_tests()

    print_header("FINAL REPORT")
    print(f"{BOLD}Summary:{RESET}")
    for mod, s in stats.items():
        total = s["pass"] + s["fail"]
        rate = (s["pass"] / total * 100) if total > 0 else 0
        color = GREEN if rate > 90 else (YELLOW if rate > 70 else RED)
        print(f"  {mod:<15}: {s['pass']}/{total} Passed ({color}{rate:.1f}%{RESET})")
        
    print(f"\n{BOLD}Note:{RESET} Failed tests in QuantumShield might be due to Heuristics being too strict or too lenient.")
    print("See details above.")
    
    # Save results to file for docs
    with open("comprehensive_test_results.txt", "w") as f:
        json.dump(details, f, indent=2)

if __name__ == "__main__":
    main()
