#!/bin/bash
# Start the vulnerable backend server

echo "Starting Vulnerable Backend API..."
echo "WAF_ENABLED=${WAF_ENABLED:-false}"

export WAF_ENABLED=${WAF_ENABLED:-false}
python app.py

