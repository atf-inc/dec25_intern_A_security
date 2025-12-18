# Quick Start Guide

## Installation

```bash
# 1. Install dependencies
npm install

# 2. Create uploads directory
mkdir -p public/uploads

# 3. Create .env.local file (copy from .env.local.example)
# Edit .env.local and set WAF_ENABLED=false for testing without WAF
# Or set WAF_ENABLED=true to test with WAF protection

# 4. Start the application
npm run dev
```

## Testing Workflow

### Step 1: Test WITHOUT WAF (Vulnerable Mode)

1. Set `WAF_ENABLED=false` in `.env.local`
2. Start the app: `npm run dev`
3. Open http://localhost:3000
4. Navigate to each vulnerability page
5. Try the attack payloads - **they should succeed**

### Step 2: Test WITH WAF (Protected Mode)

1. Set `WAF_ENABLED=true` in `.env.local`
2. Restart the app: `npm run dev`
3. Open http://localhost:3000
4. Try the same attacks - **they should be blocked**

## Available Vulnerabilities

1. **SQL Injection** - `/vulnerable/sql-injection`
   - Try: `1 OR 1=1`, `1' OR '1'='1`

2. **XSS** - `/vulnerable/xss`
   - Try: `<script>alert('XSS')</script>`, `<img src=x onerror=alert('XSS')>`

3. **Command Injection** - `/vulnerable/command-injection`
   - Try: `localhost; ls`, `localhost && dir`

4. **Path Traversal** - `/vulnerable/path-traversal`
   - Try: `../../../etc/passwd`

5. **File Upload** - `/vulnerable/file-upload`
   - Upload a PHP web shell

6. **Authentication Bypass** - `/vulnerable/auth-bypass`
   - Try SQL injection in login

7. **SSRF** - `/vulnerable/ssrf`
   - Try: `http://localhost:22`

8. **XXE** - `/vulnerable/xxe`
   - Try external entity injection

9. **IDOR** - `/vulnerable/idor`
   - Try accessing other users' data

10. **Deserialization** - `/vulnerable/deserialization`
    - Try prototype pollution

## Automated Testing

```bash
# Install Python dependencies
cd attack-scripts
pip install -r requirements.txt

# Run attack tests
python test_all_attacks.py
```

## Expected Results

### Without WAF (WAF_ENABLED=false)
- All attacks should succeed
- You should see attack results/data
- Application is vulnerable

### With WAF (WAF_ENABLED=true)
- Attacks should be blocked
- You should see 403 Forbidden responses
- Application is protected

## Notes

- The middleware includes basic pattern matching
- For full WAF protection, integrate with QuantumShield WAF API
- See SETUP.md for advanced integration options

