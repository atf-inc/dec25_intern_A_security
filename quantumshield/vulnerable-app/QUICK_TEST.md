# Quick Test Guide

## Issues Fixed

1. **Syntax Error in Search Page** - Fixed malformed JSX comment on line 130
2. **Middleware Import** - Fixed NextRequest import
3. **Vulnerabilities Page Links** - Updated to point to correct test pages (`/vulnerable/*`)

## Testing Steps

### 1. Start Backend Services

#### Terminal 1: WAF API Service
```bash
cd vulnerable-app
python waf-api-service.py
```
Expected output:
```
INFO:     Uvicorn running on http://127.0.0.1:8000
```

#### Terminal 2: Next.js Application
```bash
cd vulnerable-app
npm run dev
```
Expected output:
```
✓ Ready in 4.9s
- Local: http://localhost:3000
```

### 2. Test Vulnerabilities Page

1. Open browser: `http://localhost:3000`
2. Navigate to: `http://localhost:3000/vulnerabilities`
3. Click on any "Test Vulnerability →" button
4. Each should open the corresponding test page

### 3. Test Individual Vulnerabilities

#### SQL Injection
- URL: `http://localhost:3000/vulnerable/sql-injection`
- Test: Enter `1 OR 1=1` in User ID field
- Click "Test SQL Injection"

#### XSS
- URL: `http://localhost:3000/vulnerable/xss`
- Test: Enter `<script>alert('XSS')</script>` in Name field
- Click "Test Reflected XSS"

#### IDOR
- URL: `http://localhost:3000/vulnerable/idor`
- Test: Change user ID to access other users' data

#### SSRF
- URL: `http://localhost:3000/vulnerable/ssrf`
- Test: Enter `http://localhost:22` in URL field

### 4. Test with WAF Enabled

1. Create/Edit `.env.local`:
```env
WAF_ENABLED=true
WAF_API_URL=http://localhost:8000
```

2. Restart Next.js app (Ctrl+C, then `npm run dev`)

3. Try the same attacks - they should be blocked with 403 response

### 5. Verify WAF Integration

Check console logs:
- Next.js: Should show `[WAF] WAF protection enabled`
- WAF API: Should show request processing logs

## Common Issues

### Issue: "WAF is disabled in configuration"
**Solution**: Check `.env.local` - set `WAF_ENABLED=true`

### Issue: "Connection refused" to WAF API
**Solution**: Make sure WAF API service is running on port 8000

### Issue: Syntax errors in pages
**Solution**: All syntax errors have been fixed. If you see new ones, check:
- Missing imports
- Malformed JSX
- Unclosed tags

### Issue: Vulnerabilities page links not working
**Solution**: All links now point to `/vulnerable/*` pages

## API Endpoints

All vulnerable endpoints are available at:
- `/api/vulnerable/sql-injection`
- `/api/vulnerable/xss`
- `/api/vulnerable/idor`
- `/api/vulnerable/ssrf`
- `/api/vulnerable/auth-bypass`
- `/api/vulnerable/command-injection`
- `/api/vulnerable/path-traversal`
- `/api/vulnerable/file-upload`
- `/api/vulnerable/xxe`
- `/api/vulnerable/deserialization`

## Frontend Test Pages

All test pages are available at:
- `/vulnerable/sql-injection`
- `/vulnerable/xss`
- `/vulnerable/idor`
- `/vulnerable/ssrf`
- `/vulnerable/auth-bypass`
- `/vulnerable/command-injection`
- `/vulnerable/path-traversal`
- `/vulnerable/file-upload`
- `/vulnerable/xxe`
- `/vulnerable/deserialization`
