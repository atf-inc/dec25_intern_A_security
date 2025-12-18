
import asyncio
import aiohttp
import time
import statistics
import json
from dataclasses import dataclass
from typing import List, Dict, Any, Tuple

# Configuration
PROXY_URL = "http://localhost:8000"
CONCURRENCY = 10

# Colors for console output
class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'

@dataclass
class AttackVector:
    name: str
    category: str
    method: str
    path: str
    params: Dict[str, str] = None
    data: Any = None
    headers: Dict[str, str] = None
    description: str = ""

ATTACK_SCENARIOS = [
    # --- SQL Injection ---
    AttackVector("SQLi Union", "SQL Injection", "GET", "/", params={"q": "1' UNION SELECT user, password FROM users--"}),
    AttackVector("SQLi Blind", "SQL Injection", "GET", "/", params={"id": "1' OR SLEEP(5)--"}),
    AttackVector("SQLi Error", "SQL Injection", "GET", "/", params={"id": "1' AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT user()), 0x7e))--"}),
    AttackVector("SQLi Auth Bypass", "SQL Injection", "POST", "/login", data={"username": "admin' OR '1'='1", "password": "password"}),

    # --- XSS ---
    AttackVector("XSS Script Tag", "XSS", "GET", "/", params={"search": "<script>alert('xss')</script>"}),
    AttackVector("XSS Event Handler", "XSS", "GET", "/", params={"q": "<img src=x onerror=alert(1)>"}),
    AttackVector("XSS Javascript URI", "XSS", "GET", "/", params={"redirect": "javascript:alert(1)"}),

    # --- Command Injection ---
    AttackVector("CmdInj Linux Cat", "Command Injection", "GET", "/", params={"cmd": "; cat /etc/passwd"}),
    AttackVector("CmdInj Pipe", "Command Injection", "GET", "/", params={"ip": "127.0.0.1 | whoami"}),
    AttackVector("CmdInj Windows Dir", "Command Injection", "GET", "/", params={"file": "test.txt & dir"}),

    # --- Path Traversal ---
    AttackVector("PathTrav Std", "Path Traversal", "GET", "/", params={"file": "../../../etc/passwd"}),
    AttackVector("PathTrav Win", "Path Traversal", "GET", "/", params={"config": "..\\..\\windows\\win.ini"}),
    AttackVector("PathTrav Encoded", "Path Traversal", "GET", "/", params={"doc": "..%2f..%2f..%2fetc%2fpasswd"}),

    # --- XXE ---
    AttackVector("XXE Basic", "XXE", "POST", "/xml", data="<!DOCTYPE foo [ <!ENTITY xxe SYSTEM 'file:///etc/passwd'> ]><foo>&xxe;</foo>"),

    # --- SSRF ---
    AttackVector("SSRF AWS Meta", "SSRF", "GET", "/", params={"url": "http://169.254.169.254/latest/meta-data/"}),
    AttackVector("SSRF Localhost", "SSRF", "GET", "/", params={"webhook": "http://localhost:22"}),

    # --- Benign (False Positive Test) ---
    AttackVector("Benign Search", "Benign", "GET", "/", params={"q": "hello world"}),
    AttackVector("Benign Login", "Benign", "POST", "/login", data={"username": "user", "password": "password123"}),
    AttackVector("Benign JSON", "Benign", "POST", "/api/data", data={"id": 123, "name": "test"}, headers={"Content-Type": "application/json"}),
]

@dataclass
class TestResult:
    vector: AttackVector
    status_code: int
    latency: float
    blocked: bool
    passed: bool # Meaning the test passed (FIREWALL SUCCEEDED)

async def run_scenario(session: aiohttp.ClientSession, vector: AttackVector) -> TestResult:
    start_time = time.time()
    url = f"{PROXY_URL}{vector.path}"
    
    try:
        if vector.method == "GET":
            async with session.get(url, params=vector.params, headers=vector.headers or {}) as resp:
                status = resp.status
                await resp.read() # Read body
        elif vector.method == "POST":
            # Auto-detect JSON vs Form
            if vector.headers and "application/json" in vector.headers.get("Content-Type", ""):
                 async with session.post(url, json=vector.data, headers=vector.headers) as resp:
                    status = resp.status
                    body = await resp.read()
                    if status == 500:
                        print(f"{Colors.FAIL}500 ERROR BODY for {vector.name}: {body.decode('utf-8', errors='ignore')[:500]}{Colors.ENDC}")
            else:
                 async with session.post(url, data=vector.data, headers=vector.headers) as resp:
                    status = resp.status
                    body = await resp.read()
                    if status == 500:
                        print(f"{Colors.FAIL}500 ERROR BODY for {vector.name}: {body.decode('utf-8', errors='ignore')[:500]}{Colors.ENDC}")
        else:
             status = 0 # Unsupported
             
    except Exception as e:
        # Connection error likely means dropped connection (DPI) or proxy down
        # If proxy is down, it's a fail for the test infra, but if DPI reset connection, it's a block.
        # For this script, we assume 'ClientConnectorError' might mean connection refused (proxy down)
        # 'ServerDisconnected' might mean DPI block.
        # We'll treat exceptions as "Blocked" cautiously if they look like disconnects.
        if "ServerDisconnected" in str(e):
             status = 403 # Simulate block
        else:
             print(f"{Colors.WARNING}Error running {vector.name}: {e}{Colors.ENDC}")
             status = 599 # Generic client/network error
    
    latency = (time.time() - start_time) * 1000 # ms
    
    # Evaluation Logic
    # 403 Forbidden = Explicit Block
    # 400 Bad Request = Often WAF Block
    # 406 Not Acceptable = WAF Block
    blocked = status in [403, 400, 406, 429]
    
    # PASS condition:
    # If Malicious -> Should be Blocked (Blocked=True)
    # If Benign -> Should NOT be Blocked (Blocked=False)
    passed = False
    if vector.category == "Benign":
        passed = not blocked
    else:
        passed = blocked

    return TestResult(vector, status, latency, blocked, passed)

async def main():
    print(f"{Colors.HEADER}=== QuantumShield Firewall Performance Evaluation ==={Colors.ENDC}")
    print(f"Target: {PROXY_URL}")
    print(f"Scenarios: {len(ATTACK_SCENARIOS)}")
    
    results: List[TestResult] = []
    
    async with aiohttp.ClientSession() as session:
        # Warmup
        try:
             async with session.get(PROXY_URL) as r:
                 pass
        except:
             print(f"{Colors.FAIL}Cannot connect to proxy at {PROXY_URL}. Is full_run.py running?{Colors.ENDC}")
             # We continue anyway to show failures
        
        # Run tests
        tasks = []
        for vector in ATTACK_SCENARIOS:
            tasks.append(run_scenario(session, vector))
            
        print(f"Running tests with concurrency {CONCURRENCY}...")
        
        # Execute in batches/concurrently
        completed_count = 0
        for future in asyncio.as_completed(tasks):
            result = await future
            results.append(result)
            completed_count += 1
            if completed_count % 5 == 0:
                print(f"Progress: {completed_count}/{len(ATTACK_SCENARIOS)}")

    # Analysis
    print(f"\n{Colors.HEADER}=== Detailed Results ==={Colors.ENDC}")
    print(f"{'Name':<20} | {'Type':<15} | {'Status':<6} | {'Result':<10} | {'Latency (ms)':<10}")
    print("-" * 80)
    
    categories = {}
    
    for r in results:
        res_str = f"{Colors.OKGREEN}PASS{Colors.ENDC}" if r.passed else f"{Colors.FAIL}FAIL{Colors.ENDC}"
        print(f"{r.vector.name:<20} | {r.vector.category:<15} | {r.status_code:<6} | {res_str:<20} | {r.latency:.2f}")
        
        cat = r.vector.category
        if cat not in categories:
            categories[cat] = {"total": 0, "passed": 0, "latencies": []}
        categories[cat]["total"] += 1
        if r.passed:
            categories[cat]["passed"] += 1
        categories[cat]["latencies"].append(r.latency)

    print(f"\n{Colors.HEADER}=== Performance Metrics ==={Colors.ENDC}")
    
    overall_passed = sum(1 for r in results if r.passed)
    overall_total = len(results)
    score = (overall_passed / overall_total) * 100
    
    print(f"Overall Score: {score:.1f}%")
    print(f"Total Latency: {sum(r.latency for r in results):.2f} ms")
    print(f"Avg Latency: {statistics.mean(r.latency for r in results):.2f} ms")
    
    print(f"\n{Colors.HEADER}=== Category Breakdown ==={Colors.ENDC}")
    for cat, data in categories.items():
        cat_score = (data["passed"] / data["total"]) * 100
        avg_lat = statistics.mean(data["latencies"])
        print(f"{cat:<20}: Score {cat_score:.1f}% ({data['passed']}/{data['total']}) - Avg Latency: {avg_lat:.2f}ms")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nAborted.")
