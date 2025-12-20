# WAF Integration Setup Guide

This guide explains how to integrate QuantumShield WAF with the ShopVuln vulnerable e-commerce platform.

## Prerequisites

1. Python 3.10+ installed
2. Node.js 18+ installed
3. QuantumShield application_layer module available

## Quick Start

### Step 1: Install Dependencies

#### For the Next.js Application:
```bash
cd vulnerable-app
npm install
```

#### For the WAF API Service:
```bash
cd vulnerable-app
pip install -r waf-api-requirements.txt
```

### Step 2: Configure Environment

1. Copy the example environment file:
```bash
cp .env.example .env.local
```

2. Edit `.env.local` and configure:
   - `WAF_ENABLED=true` - Enable WAF protection
   - `WAF_API_URL=http://localhost:8000` - WAF API service URL
   - `QUANTUMSHIELD_PATH=../quantumshield` - Path to QuantumShield

### Step 3: Start WAF API Service

In a separate terminal:
```bash
cd vulnerable-app
python waf-api-service.py
```

The WAF API service will start on `http://localhost:8000`

You can verify it's running:
```bash
curl http://localhost:8000/health
```

### Step 4: Start the Next.js Application

In another terminal:
```bash
cd vulnerable-app
npm run dev
```

The application will start on `http://localhost:3000`

## Testing

### Test Without WAF (Vulnerable Mode)

1. Set `WAF_ENABLED=false` in `.env.local`
2. Restart the Next.js app
3. Try attack payloads - they should succeed

### Test With WAF (Protected Mode)

1. Set `WAF_ENABLED=true` in `.env.local`
2. Make sure WAF API service is running
3. Restart the Next.js app
4. Try the same attack payloads - they should be blocked

## WAF API Service Options

The WAF API service supports multiple frameworks:

### Using FastAPI (Recommended)
```bash
python waf-api-service.py --host 127.0.0.1 --port 8000
```

### Using Flask
```bash
# Install Flask: pip install flask flask-cors
python waf-api-service.py
```

### Using Built-in HTTP Server
```bash
# No additional dependencies needed
python waf-api-service.py
```

## Configuration Options

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `WAF_ENABLED` | Enable/disable WAF | `false` |
| `WAF_API_URL` | WAF API service URL | `http://localhost:8000` |
| `WAF_API_ENDPOINT` | WAF API endpoint path | `/api/waf/process` |
| `WAF_API_TIMEOUT` | Request timeout (ms) | `5000` |
| `QUANTUMSHIELD_PATH` | Path to QuantumShield | `../quantumshield` |
| `WAF_RULES_DIR` | WAF rules directory | `application_layer/waf/rules` |
| `WAF_DATA_FILES_DIR` | WAF data files directory | `application_layer/waf/data_files` |
| `WAF_BLOCK_ON_VIOLATION` | Block on violation | `true` |
| `WAF_CAPTURE_REQUEST_RESPONSE` | Capture full request/response | `false` |

## Troubleshooting

### WAF API Service Not Starting

1. Check Python version: `python --version` (should be 3.10+)
2. Install dependencies: `pip install -r waf-api-requirements.txt`
3. Check QuantumShield path in `.env.local`
4. Verify QuantumShield is properly installed

### WAF Not Blocking Requests

1. Verify `WAF_ENABLED=true` in `.env.local`
2. Check WAF API service is running: `curl http://localhost:8000/health`
3. Check Next.js console for WAF logs
4. Verify middleware is intercepting requests (check `middleware.ts` config)

### Connection Timeout

1. Increase `WAF_API_TIMEOUT` in `.env.local`
2. Check WAF API service is responding: `curl http://localhost:8000/health`
3. Check firewall/network settings

## API Endpoints

### WAF API Service

- `POST /api/waf/process` - Process request through WAF
- `GET /health` - Health check
- `GET /` - Service info

### Next.js Application

All API routes are protected by WAF middleware when `WAF_ENABLED=true`:

- `/api/products` - SQL Injection, XSS
- `/api/search` - SQL Injection, Reflected XSS
- `/api/reviews` - Stored XSS
- `/api/cart` - IDOR
- `/api/wishlist` - IDOR
- `/api/compare` - SQL Injection, XSS
- `/api/recommendations` - SQL Injection, IDOR
- `/api/auth/login` - SQL Injection, Weak Auth
- `/api/csrf/transfer` - CSRF
- `/api/orders/track` - SSRF
- `/api/admin/*` - Multiple vulnerabilities
- `/api/config` - Security Misconfiguration, Path Traversal

## Testing Attack Payloads

See `README.md` for detailed attack examples for each vulnerability type.

## Production Considerations

⚠️ **WARNING**: This is a vulnerable application for testing only!

For production use:
1. Use proper authentication/authorization
2. Implement rate limiting
3. Use HTTPS
4. Sanitize all inputs
5. Use parameterized queries
6. Implement CSRF protection
7. Secure file uploads
8. Use secure session management
9. Enable security headers
10. Regular security audits
