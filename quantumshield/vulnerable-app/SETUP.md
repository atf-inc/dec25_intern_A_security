# Setup Guide - Vulnerable Next.js App

## Quick Start

1. **Install Dependencies**
```bash
cd vulnerable-app
npm install
```

2. **Create Environment File**
```bash
cp .env.local.example .env.local
```

3. **Create Uploads Directory**
```bash
mkdir -p public/uploads
```

4. **Start the Application**

### Without WAF (Vulnerable Mode)
```bash
# In .env.local, set WAF_ENABLED=false or leave it unset
npm run dev
```

### With WAF (Protected Mode)
```bash
# In .env.local, set WAF_ENABLED=true
npm run dev
```

5. **Access the Application**
Open http://localhost:3000 in your browser

## Testing WAF Protection

### Manual Testing

1. Start the app with `WAF_ENABLED=false`
2. Navigate to each vulnerability page
3. Try the attack payloads - they should succeed
4. Stop the app, set `WAF_ENABLED=true`
5. Restart the app
6. Try the same attacks - they should be blocked

### Automated Testing

1. Make sure the app is running
2. Install Python dependencies:
```bash
cd attack-scripts
pip install -r requirements.txt
```

3. Run the attack script:
```bash
python test_all_attacks.py
```

The script will test all vulnerabilities and show which attacks are blocked.

## WAF Integration Options

### Option 1: Basic Pattern Matching (Current)
The middleware includes basic pattern matching. This is a simplified version for demonstration.

### Option 2: Full WAF Integration (Recommended)
For full WAF protection, you should:

1. Start the QuantumShield WAF as a service/API
2. Modify `middleware.ts` to make HTTP requests to the WAF API
3. Process WAF responses and block accordingly

Example WAF API integration:
```typescript
const wafResponse = await fetch('http://localhost:8080/waf/check', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify(requestData)
})

const wafResult = await wafResponse.json()
if (!wafResult.allowed) {
  return NextResponse.json({ error: 'Blocked by WAF' }, { status: 403 })
}
```

## Troubleshooting

### WAF not blocking attacks
- Check that `WAF_ENABLED=true` in `.env.local`
- Restart the Next.js server after changing environment variables
- Check console logs for WAF initialization messages

### Module not found errors
- Make sure all dependencies are installed: `npm install`
- Check Node.js version (requires Node 18+)

### Attack scripts not working
- Make sure the app is running on http://localhost:3000
- Check that Python requests library is installed
- Verify network connectivity

## Security Notes

⚠️ **IMPORTANT**: 
- This app is intentionally vulnerable
- Never deploy to production
- Use only in isolated testing environments
- Do not use real credentials or sensitive data

