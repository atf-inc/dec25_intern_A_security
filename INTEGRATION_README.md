# Security System Integration

## Overview
This project integrates three main components:
1.  **QuantumShield WAF** (Port 8000): The main gateway. It inspects all traffic.
2.  **DVWA** (Port 3000): The protected vulnerable application.
3.  **Honeypot** (Port 8001): A deception backend and analytics server.

## Architecture
- **Safe Traffic**: User -> QuantumShield (8000) -> DVWA (3000)
- **Attack Traffic**: User -> QuantumShield (8000) -> [Detected & Redirected] -> Honeypot (8001)

## How to Run
1.  Open PowerShell in the root directory.
2.  Run `.\start_all.ps1`.
3.  Three windows will open for the 3 services.

## Verification
- Access `http://localhost:8000/`. You should see the DVWA app.
- Try an attack (e.g. `http://localhost:8000/?test=<script>alert(1)</script>`). You should be silently redirected to the Honeypot (check the logs in Honeypot window).
