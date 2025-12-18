# Quick Start Script for DVWA Demo
# Simpler version without colors for compatibility

Write-Host "Starting DVWA + QuantumShield Demo..."
Write-Host ""

# Activate virtual environment
& ".\myenv\Scripts\Activate.ps1"

# Start DVWA on Port 3000
Write-Host "Starting DVWA on Port 3000..."
Start-Process powershell -ArgumentList "-NoExit", "-Command", "cd '../dvwa'; npm run dev"

Start-Sleep -Seconds 3

# Start Honeypot on Port 8000
Write-Host "Starting Honeypot on Port 8000..."
Start-Process powershell -ArgumentList "-NoExit", "-Command", "cd '$PWD'; & '.\myenv\Scripts\Activate.ps1'; uvicorn main:app --port 8000"

Start-Sleep -Seconds 2

Write-Host ""
Write-Host "Demo Started!"
Write-Host ""
Write-Host "PROTECTED:   http://localhost:8000 (Use this!)"
Write-Host "UNPROTECTED: http://localhost:3000 (For comparison)"
Write-Host "DASHBOARD:   http://localhost:3001"
Write-Host ""
Write-Host "Test SQLi: Username = admin' OR 1=1--"
Write-Host ""
