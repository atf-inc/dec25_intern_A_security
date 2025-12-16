# Start Integrated Demo (Next.js App + Honeypot)

# 1. Activate Python Environment
$VenvPath = ".\myenv\Scripts\Activate.ps1"
if (Test-Path $VenvPath) {
    Write-Host "Activating virtual environment..."
    & $VenvPath
} else {
    Write-Host "Virtual environment not found! Please run 'python -m venv myenv' and install requirements."
    exit
}

# 2. Start Vulnerable Next.js App (Port 3000)
# We go up one level to vulnerable-app directory
Write-Host "Starting Vulnerable Next.js App on Port 3000..."
$NextJsPath = "..\vulnerable-app"

if (Test-Path $NextJsPath) {
    # Start Next.js in a new window
    # We explicitly set WAF_ENABLED=false just to be sure, though it defaults to false.
    Start-Process powershell -ArgumentList "-NoExit", "-Command", "cd '$NextJsPath'; $env:WAF_ENABLED='false'; npm run dev"
} else {
    Write-Host "Error: vulnerable-app directory not found at $NextJsPath"
    exit
}

# 3. Start Firewall Proxy (Port 8000)
Write-Host "Starting Firewall Proxy on Port 8000..."
# We run uvicorn in a new window as well
Start-Process powershell -ArgumentList "-NoExit", "-Command", "& '$VenvPath'; uvicorn main:app --host 0.0.0.0 --port 8000 --reload"

Write-Host "Integrated Demo started!"
Write-Host "Protected App Entry Point: http://localhost:8000"
Write-Host "Direct Next.js App (Unsafe): http://localhost:3000"
