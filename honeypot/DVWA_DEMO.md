# DVWA + QuantumShield Demo

## Quick Start

Run this command in the `honeypot` folder:

```powershell
./start_dvwa_demo.ps1
```

Or use the simple version:

```powershell
./start_demo_simple.ps1
```

This will start:
1. **DVWA** on Port 3000 (Unprotected)
2. **QuantumShield Honeypot** on Port 8000 (Protected)

## Access Points

| Service | URL | Description |
|---------|-----|-------------|
| 🛡️ **Protected** | http://localhost:8000 | DVWA protected by honeypot |
| ⚠️ **Unprotected** | http://localhost:3000 | Direct DVWA access (vulnerable!) |
| 📊 **Dashboard** | http://localhost:3001 | Attack analytics |

## Demo Attacks

### 1. SQL Injection (Login)
- Go to: `http://localhost:8000/login`
- **Username**: `admin' OR 1=1--`
- **Password**: `anything`
- **Result**: Blocked by honeypot ✅

### 2. SQL Injection (Search)
- Go to: `http://localhost:8000`
- **Search**: `iPhone' OR 1=1--`
- **Result**: Blocked by honeypot ✅

### 3. XSS (Reviews)
- Go to: `http://localhost:8000/product/1`
- **Comment**: `<script>alert('XSS')</script>`
- **Result**: Blocked by honeypot ✅

### 4. IDOR (Orders)
- Go to: `http://localhost:8000/profile`
- Change user_id to `2` or `3`
- **Result**: Logged and monitored ⚠️

## Side-by-Side Comparison

Try the same attacks on **both ports**:

**Port 3000 (Unprotected)**:
- ❌ All attacks succeed
- ❌ No protection
- ❌ No logging

**Port 8000 (Protected)**:
- ✅ Attacks blocked
- ✅ ML + Regex detection
- ✅ AI honeypot traps attackers
- ✅ All attacks logged

## Stopping the Demo

Press `Ctrl+C` in each PowerShell window to stop the services.

## Troubleshooting

**Port already in use?**
```powershell
# Kill processes on port 3000
Get-Process -Id (Get-NetTCPConnection -LocalPort 3000).OwningProcess | Stop-Process -Force

# Kill processes on port 8000
Get-Process -Id (Get-NetTCPConnection -LocalPort 8000).OwningProcess | Stop-Process -Force
```

**Database not seeded?**
```powershell
cd ../dvwa
node init-db.js
```
