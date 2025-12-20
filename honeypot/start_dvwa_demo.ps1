# QuantumShield + DVWA Demo Startup Script
# This script starts both the vulnerable DVWA app and the protective honeypot

Write-Host "🚀 Starting QuantumShield Protection Demo..." -ForegroundColor Cyan
Write-Host ""

# Activate Python virtual environment
Write-Host "Activating virtual environment..." -ForegroundColor Yellow
& ".\myenv\Scripts\Activate.ps1"

# Set environment variable to point honeypot to DVWA
Write-Host "Configuring honeypot to protect DVWA..." -ForegroundColor Yellow
$env:DVWA_MODE = "true"

# Start DVWA (Vulnerable App) on Port 3000
Write-Host "Starting DVWA (Vulnerable E-commerce) on Port 3000..." -ForegroundColor Green
Start-Process powershell -ArgumentList "-NoExit", "-Command", "cd '../dvwa'; Write-Host '🛒 DVWA E-commerce App' -ForegroundColor Magenta; Write-Host 'Port: 3000 (UNPROTECTED - Direct Access)' -ForegroundColor Red; Write-Host ''; npm run dev"

# Wait a bit for DVWA to start
Start-Sleep -Seconds 3

# Start Honeypot Firewall on Port 8000
Write-Host "Starting QuantumShield Firewall on Port 8000..." -ForegroundColor Green
Start-Process powershell -ArgumentList "-NoExit", "-Command", "cd '$PWD'; & '.\myenv\Scripts\Activate.ps1'; Write-Host '🛡️ QuantumShield Honeypot + Firewall' -ForegroundColor Cyan; Write-Host 'Port: 8000 (PROTECTED - Recommended)' -ForegroundColor Green; Write-Host ''; uvicorn main:app --port 8000"

# Wait for services to start
Start-Sleep -Seconds 2

Write-Host ""
Write-Host "✅ Demo Started Successfully!" -ForegroundColor Green
Write-Host ""
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan
Write-Host "📊 ACCESS POINTS:" -ForegroundColor Yellow
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan
Write-Host ""
Write-Host "  🛡️  PROTECTED (Recommended):" -ForegroundColor Green
Write-Host "      http://localhost:8000" -ForegroundColor White
Write-Host "      → Honeypot + ML Firewall Protection" -ForegroundColor Gray
Write-Host ""
Write-Host "  ⚠️  UNPROTECTED (For Comparison):" -ForegroundColor Red
Write-Host "      http://localhost:3000" -ForegroundColor White
Write-Host "      → Direct DVWA Access (Vulnerable!)" -ForegroundColor Gray
Write-Host ""
Write-Host "  📈 Analytics Dashboard:" -ForegroundColor Magenta
Write-Host "      http://localhost:3001" -ForegroundColor White
Write-Host "      → Live Attack Monitoring" -ForegroundColor Gray
Write-Host ""
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan
Write-Host "🎯 DEMO ATTACKS TO TRY:" -ForegroundColor Yellow
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan
Write-Host ""
Write-Host "  1. SQL Injection (Login):" -ForegroundColor White
Write-Host "     Username: admin' OR 1=1--" -ForegroundColor Yellow
Write-Host "     Password: anything" -ForegroundColor Yellow
Write-Host ""
Write-Host "  2. SQL Injection (Search):" -ForegroundColor White
Write-Host "     Search: iPhone' OR 1=1--" -ForegroundColor Yellow
Write-Host ""
Write-Host "  3. XSS (Product Review):" -ForegroundColor White
Write-Host "     Comment: <script>alert('XSS')</script>" -ForegroundColor Yellow
Write-Host ""
Write-Host "  4. IDOR (Orders):" -ForegroundColor White
Write-Host "     Change user_id to 2 or 3 in profile" -ForegroundColor Yellow
Write-Host ""
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan
Write-Host ""
Write-Host "💡 TIP: Try attacks on BOTH ports to see the difference!" -ForegroundColor Cyan
Write-Host "    Port 3000 = Vulnerable (attacks succeed)" -ForegroundColor Red
Write-Host "    Port 8000 = Protected (attacks blocked)" -ForegroundColor Green
Write-Host ""
Write-Host "Press Ctrl+C in each window to stop services" -ForegroundColor Gray
Write-Host ""
