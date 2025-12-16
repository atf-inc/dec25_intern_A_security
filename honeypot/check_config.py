# Start Demo Script
# 1. Activate Environment
$VenvPath = ".\myenv\Scripts\Activate.ps1"
if (Test-Path $VenvPath) {
    Write-Host "Activating virtual environment..."
    & $VenvPath
} else {
    Write-Host "Virtual environment not found! Please run 'python -m venv myenv' and install requirements."
    exit
}

# 2. Start Vulnerable Server (Port 8001)
Write-Host "Starting Vulnerable Server on Port 8001..."
Start-Process powershell -ArgumentList "-NoExit", "-Command", "& '$VenvPath'; python vulnerable_server.py"

# 3. Start Firewall Proxy (Port 8000)
Write-Host "Starting Firewall Proxy on Port 8000..."
Start-Process powershell -ArgumentList "-NoExit", "-Command", "& '$VenvPath'; uvicorn main:app --host 0.0.0.0 --port 8000 --reload"

Write-Host "Demo started!"
Write-Host "Vulnerable App: http://localhost:8001"
Write-Host "Protected App: http://localhost:8000"
