import subprocess
import sys
import os
import time

try:
    from flask import Flask, request, Response
    import requests
except ImportError:
    print("Installing requirements (flask, requests)...")
    subprocess.check_call([sys.executable, "-m", "pip", "install", "flask", "requests", "flask-cors"])
    from flask import Flask, request, Response
    import requests

# Configuration
REMOTE_URL = "https://quantum-llm-waf-chatbot-1015557087390.us-central1.run.app"
PORT = 8080

app = Flask(__name__)
TOKEN = None
TOKEN_EXPIRY = 0

def get_token():
    """Retrieves a fresh identity token from gcloud."""
    global TOKEN, TOKEN_EXPIRY
    
    # Reuse token if it matches and is not close to expiry (tokens last 1 hour usually)
    if TOKEN and time.time() < TOKEN_EXPIRY:
        return TOKEN

    print("🔄 Refreshing authentication token...")
    try:
        # Use shell=True to handle Windows batch file resolution
        result = subprocess.run(
            "gcloud auth print-identity-token", 
            shell=True, 
            capture_output=True, 
            text=True, 
            check=True
        )
        token = result.stdout.strip()
        TOKEN = token
        TOKEN_EXPIRY = time.time() + 3000  # Cache for 50 minutes
        print("✅ Token refreshed successfully")
        return token
    except subprocess.CalledProcessError as e:
        print(f"❌ Error getting token: {e.stderr}")
        return None

@app.route('/', defaults={'path': ''}, methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH'])
@app.route('/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH'])
def proxy(path):
    token = get_token()
    if not token:
        return "Failed to authenticate with gcloud. Please run 'gcloud auth login' first.", 500

    target_url = f"{REMOTE_URL}/{path}"
    
    # Prepare headers: Forward browser headers but inject Authorization
    headers = {key: value for (key, value) in request.headers if key.lower() != 'host'}
    headers['Authorization'] = f"Bearer {token}"
    
    # Clean up some headers that might conflict
    for h in ['Content-Length', 'Transfer-Encoding']:
        if h in headers:
            del headers[h]

    try:
        # Forward request to Cloud Run
        resp = requests.request(
            method=request.method,
            url=target_url,
            headers=headers,
            data=request.get_data(),
            cookies=request.cookies,
            allow_redirects=False
        )
        
        # Prepare response headers
        excluded_headers = ['content-encoding', 'content-length', 'transfer-encoding', 'connection']
        response_headers = [
            (name, value) for (name, value) in resp.raw.headers.items()
            if name.lower() not in excluded_headers
        ]

        # Return proxied response
        return Response(resp.content, resp.status_code, response_headers)
    except Exception as e:
        print(f"Proxy Error: {e}")
        return f"Proxy Error: {e}", 500

if __name__ == '__main__':
    print("\n" + "="*60)
    print("🚀 QUANTUM LLM WAF - SECURE LOCAL PROXY")
    print("="*60)
    print("Since your user role (Editor) cannot enable public access,")
    print("this proxy will securely tunnel your local traffic to Cloud Run.")
    print("-" * 60)
    print("="*60)
    print("Since your user role (Editor) cannot enable public access,")
    print("this proxy will securely tunnel your local traffic to Cloud Run.")
    print("-" * 60)
    
    # Try ports 9090, 8080, 5000 in order
    for port in [9090, 8080, 5000]:
        try:
            print(f"Attempting to start on http://127.0.0.1:{port} ...")
            app.run(host="127.0.0.1", port=port, debug=False)
            break
        except OSError as e:
            print(f"⚠️  Port {port} failed: {e}")
            continue
