# Manual Startup Guide

This guide explains how to start each component of the security system manually in separate terminals. This is useful for debugging and seeing the logs of each service clearly.

**Prerequisites:**
- You are in the root directory: `C:\Users\Dell\Desktop\dec25_intern_A_security`
- Virtual Environment is at: `C:\Users\Dell\Desktop\myenv` (or `..\myenv`)

---

## 1. Terminal 1: Vulnerable App (DVWA)
This is the protected application running on Port 3000.

```powershell
# Open a new terminal
cd dvwa
npm run dev
# Expected Output: Ready on http://localhost:3000
```

---

## 2. Terminal 2: Honeypot Service
This handles deception and analytics on Port 8001.

```powershell
# Open a new terminal
# Activate Virtual Environment
. ..\myenv\Scripts\Activate.ps1

cd honeypot
# Run on Port 8001
uvicorn main:app --host 0.0.0.0 --port 8001 --reload
# Expected Output: Uvicorn running on http://0.0.0.0:8001
```

---

## 3. Terminal 3: QuantumShield Gateway (WAF + ML)
This is the main firewall engine (Port 8000) that integrates ML classifiers and routes traffic.

```powershell
# Open a new terminal
# Activate Virtual Environment
. ..\myenv\Scripts\Activate.ps1

cd quantumshield
# Ensure python path includes the parent dir for imports
$env:PYTHONPATH='..'

# Run the engine
python full_run.py
# Expected Output: QuantumShield is running... API server started... Reverse Proxy starting...
```

---

## 4. Terminal 4: Frontend Dashboard (Optional)
This visualizes the attacks and traffic.

```powershell
# Open a new terminal
cd frontend
npm run dev
# Expected Output: Ready on http://localhost:3001 (or 3000 if DVWA is not running, usually 3001)
```

---

## Verification

Once all terminals are running:

1.  **Visit Gateway**: [http://localhost:8000/](http://localhost:8000/) → Should show DVWA.
2.  **Test Attack**: [http://localhost:8000/?q=' OR 1=1](http://localhost:8000/?q=' OR 1=1) → Should show Honeypot Page.
3.  **Visit Dashboard**: [http://localhost:3001](http://localhost:3001) → Should show live stats.
