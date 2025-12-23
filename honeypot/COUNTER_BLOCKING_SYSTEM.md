# Counter-Based Permanent Blocking System

## Overview

The honeypot now implements a sophisticated **counter-based permanent blocking system** that gives attackers a limited number of chances before permanently blocking their IP address.

## How It Works

### Three-Tier Security System

```
┌─────────────────────────────────────────────────────────────┐
│                    REQUEST PROCESSING FLOW                   │
└─────────────────────────────────────────────────────────────┘

1. Check if IP is PERMANENTLY BLOCKED
   ├─ YES → Return 403 "Permanently Blocked" (no further processing)
   └─ NO  → Continue to step 2

2. Check if IP is TRAPPED (temporary)
   ├─ YES → Route to honeypot (fake responses)
   └─ NO  → Continue to step 3

3. ML Firewall Analysis
   ├─ SAFE (confidence ≤ 0.30)
   │  └─ Forward to upstream application
   │
   ├─ SUSPICIOUS (confidence 0.30-0.80)
   │  ├─ Trap IP (temporary, 30 minutes)
   │  └─ Route to honeypot
   │
   └─ MALICIOUS (confidence > 0.80)
      ├─ Increment malicious counter
      ├─ If counter >= 5 → PERMANENTLY BLOCK
      └─ Return 403 with counter info
```

## Confidence-Based Routing

| Confidence | Verdict | Action | Counter | Trap | Block |
|------------|---------|--------|---------|------|-------|
| ≤ 0.30 | SAFE | Forward to upstream | No change | No | No |
| 0.30 - 0.80 | SUSPICIOUS | Route to honeypot | No change | Yes (30 min) | No |
| > 0.80 | MALICIOUS | Block with 403 | +1 | No | After 5 attempts |

## Malicious Counter System

### Counter Behavior

- **Increments**: Every MALICIOUS request (confidence > 0.80)
- **Threshold**: 5 MALICIOUS attempts
- **Persistence**: Stored in MongoDB, survives restarts
- **Reset**: Only via `/debug/unblock` endpoint

### Counter States

```
Attempt 1/5: ⚠️  Warning shown, 4 attempts remaining
Attempt 2/5: ⚠️  Warning shown, 3 attempts remaining
Attempt 3/5: ⚠️  Warning shown, 2 attempts remaining
Attempt 4/5: ⚠️  Warning shown, 1 attempt remaining
Attempt 5/5: 🚫 PERMANENTLY BLOCKED
```

## Response Examples

### First MALICIOUS Attempt (1/5)

**JSON Response:**
```json
{
  "success": false,
  "error": "Forbidden",
  "message": "Access denied. Your request has been blocked and logged.",
  "malicious_attempts": 1,
  "attempts_remaining": 4,
  "warning": "Warning: 4 more malicious attempt(s) before permanent block.",
  "request_id": "BLK-a1b2c3d4",
  "timestamp": "2025-12-23T10:30:00.000000Z"
}
```

**HTML Response:**
```html
403 Forbidden
Access Denied
Your request has been blocked and logged.

Malicious Attempts: 1/5
Warning: 4 more malicious attempt(s) before permanent block.
```

### Fifth MALICIOUS Attempt (5/5 - Permanent Block)

**JSON Response:**
```json
{
  "success": false,
  "error": "Forbidden",
  "message": "Access denied. Your request has been blocked and logged.",
  "malicious_attempts": 5,
  "attempts_remaining": 0,
  "warning": "Your IP has been permanently blocked.",
  "request_id": "BLK-e5f6g7h8",
  "timestamp": "2025-12-23T10:35:00.000000Z"
}
```

### Subsequent Requests After Permanent Block

**JSON Response:**
```json
{
  "success": false,
  "error": "Permanently Blocked",
  "message": "Your IP has been permanently blocked due to repeated malicious activity.",
  "blocked_at": "2025-12-23 10:35:00",
  "reason": "Exceeded malicious threshold (5 attempts)"
}
```

## Debug Endpoints

### `/debug/trap-status` - Security Status Dashboard

Shows comprehensive security status:

**Permanent Block Status:**
- 🚫 **PERMANENTLY BLOCKED** - Shows block info and unblock button
- ⚠️ **WARNING** - Shows counter (e.g., 3/5 attempts) and remaining attempts
- ✅ **NOT BLOCKED** - No malicious attempts detected

**Temporary Trap Status:**
- Shows if IP is trapped (SUSPICIOUS requests)
- Displays trap duration and expiration time

**All Blocked IPs:**
- Lists all permanently blocked IPs
- Shows malicious attempt count for each

**All Trapped IPs:**
- Lists all temporarily trapped IPs
- Shows trap reason and duration

### `/debug/unblock` - Unblock IP

**POST** request to remove IP from permanent block list.

**Actions:**
1. Removes IP from permanent block list
2. Resets malicious counter to 0
3. Allows IP to access the system again

**Response:**
```html
IP Unblocked!
Your IP (127.0.0.1) has been removed from the permanent block list.
Your malicious attempt counter has been reset to 0.
```

### `/debug/clear-trap` - Clear Temporary Trap

**POST** request to remove IP from temporary trap list (SUSPICIOUS requests).

### `/debug/clear-all-traps` - Clear All Traps

**POST** request to clear all temporary traps (localhost only).

## Database Collections

### `permanent_blocks` Collection

Stores permanent block records:

```javascript
{
  "ip": "192.168.1.100",
  "blocked_at": ISODate("2025-12-23T10:35:00Z"),
  "reason": "Exceeded malicious threshold (5 attempts)",
  "malicious_count": 5,
  "active": true,
  "unblocked_at": null  // Set when unblocked
}
```

### `traps` Collection

Stores temporary trap records:

```javascript
{
  "ip": "192.168.1.101",
  "trapped_at": ISODate("2025-12-23T10:30:00Z"),
  "reason": "SUSPICIOUS activity detected on /api/login (confidence: 0.65)",
  "attack_payload": "POST /api/login...",
  "request_count": 12,
  "active": true,
  "released_at": null  // Set when trap expires or cleared
}
```

## Testing the System

### Test 1: Submit 5 MALICIOUS Requests

```bash
# Attempt 1
curl -X POST http://localhost:8000/api/auth \
  -H "Content-Type: application/json" \
  -d '{"username": "admin'\'' OR 1=1--", "password": "test"}'
# Response: 403, malicious_attempts: 1, attempts_remaining: 4

# Attempt 2
curl -X POST http://localhost:8000/api/auth \
  -H "Content-Type: application/json" \
  -d '{"username": "admin'\'' OR 1=1--", "password": "test"}'
# Response: 403, malicious_attempts: 2, attempts_remaining: 3

# ... repeat 3 more times ...

# Attempt 5
curl -X POST http://localhost:8000/api/auth \
  -H "Content-Type: application/json" \
  -d '{"username": "admin'\'' OR 1=1--", "password": "test"}'
# Response: 403, malicious_attempts: 5, attempts_remaining: 0
# IP is now PERMANENTLY BLOCKED
```

### Test 2: Check Status

```bash
curl http://localhost:8000/debug/trap-status
# Shows: PERMANENTLY BLOCKED status with unblock button
```

### Test 3: Unblock IP

```bash
curl -X POST http://localhost:8000/debug/unblock
# Response: IP Unblocked! Counter reset to 0.
```

## Logs

### Console Output Examples

**First MALICIOUS attempt:**
```
INFO: [MALICIOUS COUNTER] IP 127.0.0.1 - Attempt #1/5
WARNING: [BLOCKED] 127.0.0.1 - MALICIOUS attack #1 on /api/auth (confidence: 0.95) - 4 attempts remaining before permanent block
```

**Fifth MALICIOUS attempt (permanent block):**
```
INFO: [MALICIOUS COUNTER] IP 127.0.0.1 - Attempt #5/5
ERROR: [PERMANENTLY BLOCKED] IP 127.0.0.1 - 5 MALICIOUS attempts
ERROR: [BLOCKED] 127.0.0.1 - MALICIOUS attack #5 on /api/auth (confidence: 0.95) - PERMANENTLY BLOCKED
```

**Subsequent request after permanent block:**
```
ERROR: [PERMANENTLY BLOCKED] 127.0.0.1 - Blocked 120s ago - 5 MALICIOUS attempts
```

## Key Benefits

1. **Progressive Deterrence**: Attackers get clear warnings before permanent block
2. **Reduced False Positives**: Legitimate users who trigger false positives aren't immediately blocked
3. **Persistent Tracking**: Counters survive server restarts via MongoDB
4. **Clear Feedback**: Attackers know exactly how many attempts they have left
5. **Easy Management**: Simple unblock endpoint for administrators
6. **Comprehensive Monitoring**: Debug dashboard shows all security states

## Security Considerations

### Why 5 Attempts?

- **Balance**: Enough to avoid false positives, few enough to stop persistent attackers
- **Deterrence**: Clear escalation discourages continued attacks
- **Flexibility**: Threshold can be adjusted in `trap_tracker.py` (`malicious_threshold`)

### Why Separate SUSPICIOUS and MALICIOUS?

- **SUSPICIOUS** (0.30-0.80): Possible attack, route to honeypot for intelligence gathering
- **MALICIOUS** (> 0.80): Confirmed attack, count towards permanent block

This allows the system to:
- Gather intelligence from low-confidence attacks
- Progressively block high-confidence attacks
- Minimize false positives while maximizing security

---

**Implementation Status:** ✅ Complete and ready for testing!
