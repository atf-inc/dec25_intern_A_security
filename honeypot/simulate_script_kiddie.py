import requests
import time
import random
from concurrent.futures import ThreadPoolExecutor

BASE_URL = "http://localhost:8000"

# Common User-Agents used by scanning tools
USER_AGENTS = {
    "SQLMap": "sqlmap/1.5.11#stable (http://sqlmap.org)",
    "Nikto": "Mozilla/5.0 (compatible; Nikto/2.1.6; +http://cirt.net/nikto)",
    "Nmap": "Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)",
    "DirBuster": "DirBuster-1.0-RC1 (http://www.owasp.org/index.php/Category:OWASP_DirBuster_Project)",
    "Normal": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
}

# Common attack vectors
ATTACKS = [
    # SQL Injection attempts
    {"path": "/api/search?q=' OR 1=1 --", "type": "SQLi", "agent": "SQLMap"},
    {"path": "/products?id=1 UNION SELECT user, password FROM users", "type": "SQLi", "agent": "SQLMap"},
    
    # Sensitive File Probing (Nikto style)
    {"path": "/.env", "type": "File Probe", "agent": "Nikto"},
    {"path": "/wp-config.php", "type": "File Probe", "agent": "Nikto"},
    {"path": "/backup.sql", "type": "File Probe", "agent": "Nikto"},
    {"path": "/id_rsa", "type": "File Probe", "agent": "Nikto"},
    
    # Admin Interface Hunting
    {"path": "/admin", "type": "Dir Busting", "agent": "DirBuster"},
    {"path": "/administrator", "type": "Dir Busting", "agent": "DirBuster"},
    {"path": "/login.php", "type": "Dir Busting", "agent": "DirBuster"},
    
    # Command Injection
    {"path": "/api/ping?ip=127.0.0.1; cat /etc/passwd", "type": "Cmd Injection", "agent": "Nmap"},
]

def run_attack(attack):
    url = f"{BASE_URL}{attack['path']}"
    headers = {"User-Agent": USER_AGENTS[attack['agent']]}
    
    print(f"[{attack['agent']}] Attacking: {attack['path']} ...")
    try:
        response = requests.get(url, headers=headers)
        
        # Analyze response to see if the honeypot was deceptive
        status = response.status_code
        length = len(response.text)
        snippet = response.text[:50].replace('\n', ' ')
        
        print(f"   -> Response: {status} | Length: {length} | Preview: {snippet}...")
        
        if status == 200 and ("error" in response.text.lower() or "syntax" in response.text.lower()):
             print("   [SUCCESS] Honeypot feigned a vulnerability!")
        elif status == 200 and length > 0:
             print("   [SUCCESS] Honeypot returned fake content.")
             
    except Exception as e:
        print(f"   -> Connection Failed: {e}")

def start_simulation():
    print(f"--- STARTING SCRIPT KIDDIE SIMULATION AGAINST {BASE_URL} ---")
    print("Simulating parallel attacks from multiple tools...\n")
    
    # Run attacks in parallel to simulate a noisy scan
    with ThreadPoolExecutor(max_workers=2) as executor:
        executor.map(run_attack, ATTACKS)

if __name__ == "__main__":
    start_simulation()
