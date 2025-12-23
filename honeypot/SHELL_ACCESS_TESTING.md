# Shell Access Restriction - Testing Guide

## Changes Made

### 1. Endpoint Renamed
- **Old:** `/terminal` and `/api/terminal`
- **New:** `/shell` and `/api/shell`

### 2. Access Control Added
The shell interface is now **only accessible when an IP is trapped**.

**Behavior:**
- **Not Trapped:** Returns 404 (endpoint appears to not exist)
- **Trapped:** Shows full shell interface with command execution

### 3. Main Gateway Routing
Updated `main.py` to properly route shell requests for trapped IPs:
- Detects `/shell` and `/api/shell` endpoints
- Serves actual shell interface instead of generating fake LLM responses
- Maintains trap tracking and logging

---

## Testing Instructions

### Test 1: Access Shell When NOT Trapped (Should Fail)

1. **Clear any existing traps:**
   - Visit: `http://localhost:8000/debug/clear-all-traps`

2. **Try to access shell:**
   - Visit: `http://localhost:8000/shell`
   - **Expected:** 404 Not Found page

3. **Verify in logs:**
   - Should show `[SAFE]` routing to upstream
   - Upstream returns 404 (shell doesn't exist on real app)

---

### Test 2: Access Shell When TRAPPED (Should Work)

1. **Trigger a trap by sending suspicious request:**
   ```bash
   curl "http://localhost:8000/products?id=1' OR '1'='1"
   ```

2. **Check trap status:**
   - Visit: `http://localhost:8000/debug/trap-status`
   - **Expected:** Shows "TRAPPED (Temporary)" status

3. **Access shell:**
   - Visit: `http://localhost:8000/shell`
   - **Expected:** Full shell interface loads

4. **Test shell commands:**
   ```bash
   pwd
   ls -la
   cat /etc/passwd
   whoami
   cd /var/www/techshop
   cat .env
   ```

5. **Verify logging:**
   - All commands should be logged to database
   - Session tracking should work
   - Command history should persist

---

### Test 3: Access Shell When PERMANENTLY BLOCKED (Should Work)

1. **Get permanently blocked:**
   - Send 5 malicious requests (confidence > 0.80)
   - Example:
     ```bash
     for i in {1..5}; do
       curl "http://localhost:8000/admin' OR '1'='1-- -"
     done
     ```

2. **Check block status:**
   - Visit: `http://localhost:8000/debug/trap-status`
   - **Expected:** Shows "PERMANENTLY BLOCKED" status

3. **Access shell:**
   - Visit: `http://localhost:8000/shell`
   - **Expected:** Full shell interface loads (blocked IPs can still use shell)

---

## Expected Flow

### For Non-Trapped IP:
```
User → /shell
  ↓
Main Gateway (main.py)
  ↓
ML Firewall: SAFE
  ↓
Forward to Upstream (real app)
  ↓
Upstream returns 404
  ↓
User sees: 404 Not Found
```

### For Trapped IP:
```
User → /shell
  ↓
Main Gateway (main.py)
  ↓
Check: is_trapped(IP) = True
  ↓
Special routing for /shell
  ↓
Forward to honeypot.shell_view()
  ↓
Check trap status (redundant but safe)
  ↓
Serve shell interface
  ↓
User sees: Full shell UI
```

### For Shell Commands (Trapped IP):
```
User → /api/shell (POST with command)
  ↓
Main Gateway (main.py)
  ↓
Check: is_trapped(IP) = True
  ↓
Special routing for /api/shell
  ↓
Forward to honeypot.api_shell()
  ↓
Check trap status
  ↓
Process command via shell_processor
  ↓
Return output + updated prompt
  ↓
User sees: Command output
```

---

## Security Considerations

### Why 404 for Non-Trapped IPs?
- Makes the shell endpoint "invisible" to normal users
- Prevents accidental discovery
- Only attackers who trigger traps can find it

### Why Allow Permanently Blocked IPs?
- Keeps them engaged in the honeypot
- Gathers more intelligence about their techniques
- Wastes their time and resources

### Session Isolation
- Each trapped IP gets isolated file system
- Commands don't affect other sessions
- Complete activity tracking per attacker

---

## Troubleshooting

### Shell Returns 404 Even When Trapped
- Check trap status: `/debug/trap-status`
- Verify IP is actually trapped
- Check logs for routing decisions

### Shell Commands Not Working
- Verify `/api/shell` endpoint is accessible
- Check browser console for errors
- Ensure session is properly created

### Commands Return Fake LLM Responses Instead of Shell Output
- This means the special routing in `main.py` isn't working
- Check that `path_name == "shell"` or `path_name == "api/shell"`
- Verify imports are correct

---

## Code Changes Summary

### Files Modified:
1. **routers/honeypot.py**
   - Renamed `/terminal` → `/shell`
   - Renamed `/api/terminal` → `/api/shell`
   - Added trap status checking
   - Returns 404 if not trapped

2. **main.py**
   - Added special routing for `/shell` and `/api/shell`
   - Forwards to honeypot router instead of generating fake responses
   - Maintains trap tracking and logging

### Key Functions:
- `shell_view()` - Serves shell UI (only if trapped)
- `api_shell()` - Handles shell commands (only if trapped)
- Gateway special routing - Detects shell endpoints and forwards properly
