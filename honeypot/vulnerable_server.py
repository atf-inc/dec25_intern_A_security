import uvicorn
from fastapi import FastAPI, Request, Form
from fastapi.responses import HTMLResponse

app = FastAPI(title="Legacy Admin Panel (Vulnerable)")

# Mock Database with a flag
USERS_DB = {
    "admin": "complex_password_123"
}

@app.get("/", response_class=HTMLResponse)
async def login_page():
    return """
    <html>
        <head>
            <title>Legacy Admin Login</title>
            <style>
                body { font-family: sans-serif; display: flex; justify-content: center; align-items: center; height: 100vh; background: #f0f0f0; }
                .login-box { background: white; padding: 2rem; border-radius: 8px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); width: 300px; }
                h2 { color: #333; text-align: center; }
                input { width: 100%; padding: 8px; margin: 10px 0; border: 1px solid #ddd; border-radius: 4px; box-sizing: border-box; }
                button { width: 100%; padding: 10px; background: #007bff; color: white; border: none; border-radius: 4px; cursor: pointer; }
                button:hover { background: #0056b3; }
                .warning { color: red; font-size: 0.8em; text-align: center; margin-top: 10px; }
            </style>
        </head>
        <body>
            <div class="login-box">
                <h2>Legacy Admin Panel</h2>
                <form action="/login" method="post">
                    <input type="text" name="username" placeholder="Username" required>
                    <input type="password" name="password" placeholder="Password" required>
                    <button type="submit">Login</button>
                </form>
                <div class="warning">Authorized Personnel Only</div>
            </div>
        </body>
    </html>
    """

@app.post("/login", response_class=HTMLResponse)
async def login(username: str = Form(...), password: str = Form(...)):
    # VULNERABLE CODE: Simulating SQL Injection
    # A real vulnerable query might look like: f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
    
    # Simulate the vulnerability logic
    # Triggers if the input contains SQL injection patterns normally capable of bypassing auth
    is_sqli = "'" in username or " OR " in username.upper()
    
    if is_sqli:
        # Simulate successful hack via SQLi
        return f"""
        <html>
            <body style="background: #ffcccc; padding: 2rem; text-align: center; font-family: sans-serif;">
                <h1 style="color: #cc0000;">⚠️ SYSTEM COMPROMISED</h1>
                <p><strong>SQL Injection Successful!</strong></p>
                <p>Backend executed: <code>SELECT * FROM users WHERE username = '{username}'...</code></p>
                <p>Welcome, Admin. (Access granted via bypass)</p>
                <a href="/">Back</a>
            </body>
        </html>
        """
    
    # Normal Login Logic
    if username == "admin" and password == USERS_DB["admin"]:
        return """
        <html>
            <body style="background: #ccffcc; padding: 2rem; text-align: center; font-family: sans-serif;">
                <h1 style="color: #006600;">Login Successful</h1>
                <p>Welcome to the Dashboard, Admin.</p>
                <a href="/">Logout</a>
            </body>
        </html>
        """
    else:
        return """
        <html>
            <body style="background: #f0f0f0; padding: 2rem; text-align: center; font-family: sans-serif;">
                <h1 style="color: #666;">Login Failed</h1>
                <p>Invalid credentials.</p>
                <a href="/">Try Again</a>
            </body>
        </html>
        """

if __name__ == "__main__":
    print("Starting Vulnerable Server on http://localhost:8001")
    uvicorn.run(app, host="0.0.0.0", port=8001)
