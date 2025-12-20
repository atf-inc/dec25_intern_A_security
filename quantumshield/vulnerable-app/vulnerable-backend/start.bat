@echo off
REM Start the vulnerable backend server

echo Starting Vulnerable Backend API...
echo WAF_ENABLED=%WAF_ENABLED%

if "%WAF_ENABLED%"=="" set WAF_ENABLED=false

python app.py

pause

