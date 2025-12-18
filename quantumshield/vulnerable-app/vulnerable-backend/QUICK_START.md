# Quick Start Guide

## 1. Install Dependencies

```bash
pip install -r requirements.txt
```

## 2. Start Backend

### Without WAF (Vulnerable Mode)
```bash
python app.py
```

### With WAF (Protected Mode)
```bash
# Windows
set WAF_ENABLED=true
python app.py

# Linux/Mac
export WAF_ENABLED=true
python app.py
```

## 3. Test the API

### Option 1: Use the Frontend
1. Open `../vulnerable-frontend/index.html` in a browser
2. All vulnerabilities are testable via the web interface

### Option 2: Use Test Script
```bash
python test_attacks.py
```

### Option 3: Use curl
```bash
# SQL Injection
curl "http://localhost:8000/api/products/search?q=test' OR '1'='1"

# XSS
curl "http://localhost:8000/api/search?q=<script>alert('XSS')</script>"
```

## 4. Expected Results

### Without WAF (WAF_ENABLED=false)
- All attacks should succeed
- You'll see attack results/data
- Status codes: 200, 400, 500 (but attacks work)

### With WAF (WAF_ENABLED=true)
- Attacks should be blocked
- Status code: 403 Forbidden
- Response: `{"error": "Request blocked by WAF", ...}`

## API Endpoints Quick Reference

| Vulnerability | Endpoint | Method | Test Payload |
|--------------|----------|--------|--------------|
| SQL Injection | `/api/products/search?q=...` | GET | `test' OR '1'='1` |
| XSS | `/api/search?q=...` | GET | `<script>alert('XSS')</script>` |
| Stored XSS | `/api/reviews` | POST | `<img src=x onerror=alert('XSS')>` |
| Command Injection | `/api/admin/process` | POST | `test.txt; ls` |
| Path Traversal | `/api/admin/files?file=...` | GET | `../../../etc/passwd` |
| File Upload | `/api/admin/upload` | POST | Any file |
| Auth Bypass | `/api/login` | POST | `admin' OR '1'='1` |
| IDOR | `/api/users/{id}` | GET | Change ID |
| SSRF | `/api/orders/track?url=...` | GET | `http://localhost:22` |
| XXE | `/api/admin/import` | POST | XML with external entity |
| Deserialization | `/api/admin/import-json` | POST | `{"__proto__": {...}}` |

## Troubleshooting

**Backend won't start:**
- Check Python version: `python --version` (needs 3.8+)
- Install dependencies: `pip install -r requirements.txt`
- Check port 8000 is not in use

**WAF not working:**
- Verify `WAF_ENABLED=true` is set
- Check console for WAF initialization messages
- Make sure QuantumShield is in parent directory

**Frontend can't connect:**
- Make sure backend is running on port 8000
- Check CORS is enabled (it is by default)
- Open browser console for errors

