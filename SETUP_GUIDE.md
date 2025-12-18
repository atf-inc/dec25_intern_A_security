# QuantumShield Firewall - End-to-End Setup Guide

This guide will help you set up and run the complete QuantumShield firewall with the vulnerable-app application.

## Architecture Overview

```
User Browser
    ↓
Next.js App (Port 3000) - Middleware checks requests
    ↓
Reverse Proxy (Port 8000) - Intercepts and analyzes traffic
    ↓
WAF API (Port 8081) - Processes WAF requests from middleware
    ↓
Backend Application (Port 3000) - Vulnerable app
```

## Prerequisites

1. Python 3.10+ installed
2. Node.js 18+ installed
3. All dependencies installed

## Step-by-Step Setup

### Step 1: Install Dependencies

#### Python Dependencies (QuantumShield)
```bash
cd quantumshield
pip install -r requirements.txt
```

#### Node.js Dependencies (Vulnerable App)
```bash
cd vulnerable-app
npm install
```

### Step 2: Configure Environment Variables

Create `.env.local` in the `vulnerable-app` directory:

```bash
cd vulnerable-app
```

Create `.env.local` with:
```env
WAF_ENABLED=true
WAF_API_URL=http://localhost:8000
WAF_API_ENDPOINT=/api/waf/process
WAF_API_TIMEOUT=5000
```

**Important**: The middleware will call the WAF API at `http://localhost:8000/api/waf/process`, which goes through the reverse proxy to the internal API server.

### Step 3: Start the QuantumShield Firewall

In the `quantumshield` directory:

```bash
cd quantumshield
python full_run.py
```

This will start:
- **Reverse Proxy** on port 8000 (intercepts all traffic)
- **WAF API Server** on port 8081 (internal, processes WAF requests)
- **QuantumShield Engine** (analyzes traffic)

You should see:
```
INFO: Reverse Proxy started on http://0.0.0.0:8000 -> http://localhost:3000
INFO: API server started on 0.0.0.0:8081
INFO: QuantumShield is running...
```

### Step 4: Start the Vulnerable Application

In a **new terminal**, navigate to `vulnerable-app`:

```bash
cd vulnerable-app
npm run dev
```

This starts the Next.js app on port 3000.

**Important**: The app should be accessible through the reverse proxy at `http://localhost:8000`, not directly at `http://localhost:3000`.

### Step 5: Test the Integration

1. **Access the app through the reverse proxy**: `http://localhost:8000`

2. **Test SQL Injection Attack**:
   - Navigate to: `http://localhost:8000/vulnerable/sql-injection`
   - Enter: `1 OR 1=1` in the User ID field
   - Click "Test SQL Injection"
   - **Expected**: You should see the custom message: "ohh you are trying to attack, try again because there is shubham in between"

3. **Test Login Bypass Attack**:
   - On the same page, click "Test Login Bypass"
   - **Expected**: Same custom message should appear

4. **Check Logs**:
   - In the `full_run.py` terminal, you should see:
     ```
     [ReverseProxy] WAF BLOCKED /api/vulnerable/sql-injection: 1 violation(s)
     [ReverseProxy]   - sql_injection: SQL injection pattern detected in query.id
     ```
   - In the Next.js terminal, you should see:
     ```
     [WAF] Request blocked: Malicious content detected
     [WAF] Violations: [{"type":"sql_injection","reason":"..."}]
     ```

## How It Works

### Request Flow

1. **User makes request** → `http://localhost:8000/vulnerable/sql-injection?id=1 OR 1=1`

2. **Next.js Middleware** intercepts the request:
   - Extracts query parameters, body, headers
   - Calls WAF API: `POST http://localhost:8000/api/waf/process`
   - If blocked, returns 403 with custom message

3. **Reverse Proxy** (if request passes middleware):
   - Intercepts request
   - Analyzes with WAF engine
   - If blocked, returns 403 with custom message
   - If allowed, forwards to backend

4. **WAF Engine** checks:
   - Query parameters (e.g., `?id=1 OR 1=1`)
   - Body parameters (e.g., `{"username": "admin' OR '1'='1"}`)
   - Headers
   - Path
   - Raw body

### Detection Patterns

The WAF detects:
- **SQL Injection**: `OR 1=1`, `UNION SELECT`, `DROP TABLE`, etc.
- **XSS**: `<script>`, `javascript:`, `onerror=`, etc.

## Troubleshooting

### Issue: Attacks are not being blocked

1. **Check WAF is enabled**:
   - Verify `.env.local` has `WAF_ENABLED=true`
   - Restart Next.js app after changing `.env.local`

2. **Check QuantumShield is running**:
   ```bash
   curl http://localhost:8000/health
   curl http://localhost:8081/health
   ```

3. **Check logs**:
   - Look for `[WAF]` messages in Next.js console
   - Look for `[ReverseProxy]` and `[WAF API]` messages in `full_run.py` output

4. **Verify middleware is active**:
   - Check Next.js console for: `[WAF] WAF protection enabled`
   - Check for: `[WAF] Checking request: GET /api/vulnerable/sql-injection`

### Issue: Custom message not showing

1. **Check frontend error handling**:
   - The SQL injection page should check for `response.status === 403` or `data.blocked`
   - Verify the page displays `result.message` when blocked

2. **Check middleware response**:
   - Middleware should return JSON with `{blocked: true, message: "..."}`
   - Status code should be 403

3. **Check reverse proxy response**:
   - For API requests, should return JSON with custom message
   - For browser requests, should return HTML with custom message

### Issue: Connection refused errors

1. **Check ports are not in use**:
   ```bash
   # Windows
   netstat -ano | findstr :8000
   netstat -ano | findstr :8081
   netstat -ano | findstr :3000
   
   # Linux/Mac
   lsof -i :8000
   lsof -i :8081
   lsof -i :3000
   ```

2. **Check firewall/antivirus**:
   - Windows Firewall might block ports
   - Antivirus might block Python scripts

### Issue: WAF API returns 503

1. **Check engine is initialized**:
   - Look for `Engine not initialized` in logs
   - Verify `full_run.py` started successfully

2. **Check WAF engine is enabled**:
   - Look for `WAF Engine initialized` in logs
   - Check config has `waf` section

## Testing Different Attack Types

### SQL Injection
- **GET**: `?id=1 OR 1=1`
- **POST**: `{"username": "admin' OR '1'='1"}`

### XSS
- **GET**: `?search=<script>alert('XSS')</script>`
- **POST**: `{"comment": "<script>alert('XSS')</script>"}`

### Command Injection
- **GET**: `?cmd=; ls -la`
- **POST**: `{"command": "| cat /etc/passwd"}`

## Production Considerations

⚠️ **WARNING**: This is a testing/demo setup. For production:

1. Use HTTPS
2. Add rate limiting
3. Implement proper authentication
4. Use environment-specific configurations
5. Add monitoring and alerting
6. Regular security audits
7. Update detection patterns regularly

## Support

If you encounter issues:
1. Check all logs (Next.js, QuantumShield, reverse proxy)
2. Verify all services are running
3. Check environment variables
4. Verify network connectivity between services

