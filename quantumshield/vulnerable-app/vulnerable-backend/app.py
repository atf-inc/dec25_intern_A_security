"""
Vulnerable Backend API for WAF Testing
Contains intentional security vulnerabilities for testing WAF protection
"""

from fastapi import FastAPI, Request, Form, File, UploadFile, Query, Cookie, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, HTMLResponse, FileResponse
from fastapi.staticfiles import StaticFiles
import sqlite3
import os
import subprocess
import json
import base64
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Optional, List
import uuid
from datetime import datetime

# Import WAF if enabled
WAF_ENABLED = os.getenv('WAF_ENABLED', 'false').lower() == 'true'
waf_engine = None

if WAF_ENABLED:
    try:
        import sys
        from pathlib import Path as PathLib
        
        # Add parent directory to path
        parent_dir = PathLib(__file__).parent.parent.absolute()
        sys.path.insert(0, str(parent_dir))
        
        from quantumshield.application_layer.waf.waf_engine import WAFEngine
        
        waf_engine = WAFEngine({
            'enabled': True,
            'rules_dir': str(parent_dir / 'quantumshield' / 'application_layer' / 'waf' / 'rules'),
            'data_files_dir': str(parent_dir / 'quantumshield' / 'application_layer' / 'waf' / 'data_files'),
            'block_on_violation': True
        })
        
        print("[WAF] WAF Engine initialized and enabled")
    except Exception as e:
        print(f"[WAF] Failed to initialize WAF: {e}")
        print("[WAF] Running without WAF protection")
else:
    print("[WAF] WAF is disabled - running in vulnerable mode")

app = FastAPI(title="Vulnerable E-Commerce API", description="Vulnerable backend for WAF testing")

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize database
db_path = "vulnerable.db"
conn = sqlite3.connect(db_path, check_same_thread=False)
cursor = conn.cursor()

# Create tables
cursor.execute("""
    CREATE TABLE IF NOT EXISTS products (
        id INTEGER PRIMARY KEY,
        name TEXT,
        description TEXT,
        price REAL,
        category TEXT,
        stock INTEGER
    )
""")

cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY,
        username TEXT UNIQUE,
        password TEXT,
        email TEXT,
        balance REAL,
        role TEXT
    )
""")

cursor.execute("""
    CREATE TABLE IF NOT EXISTS reviews (
        id INTEGER PRIMARY KEY,
        product_id INTEGER,
        author TEXT,
        rating INTEGER,
        comment TEXT,
        created_at TEXT
    )
""")

cursor.execute("""
    CREATE TABLE IF NOT EXISTS orders (
        id INTEGER PRIMARY KEY,
        user_id INTEGER,
        total REAL,
        status TEXT,
        created_at TEXT
    )
""")

# Insert sample data
try:
    cursor.execute("INSERT INTO products (name, description, price, category, stock) VALUES (?, ?, ?, ?, ?)",
                   ("Laptop Pro", "High-performance laptop", 1299.99, "Electronics", 50))
    cursor.execute("INSERT INTO products (name, description, price, category, stock) VALUES (?, ?, ?, ?, ?)",
                   ("Smartphone X", "Latest smartphone", 899.99, "Electronics", 100))
    cursor.execute("INSERT INTO products (name, description, price, category, stock) VALUES (?, ?, ?, ?, ?)",
                   ("Wireless Headphones", "Premium headphones", 199.99, "Audio", 75))
    conn.commit()
except:
    pass

try:
    cursor.execute("INSERT INTO users (username, password, email, balance, role) VALUES (?, ?, ?, ?, ?)",
                   ("admin", "admin123", "admin@example.com", 10000, "admin"))
    cursor.execute("INSERT INTO users (username, password, email, balance, role) VALUES (?, ?, ?, ?, ?)",
                   ("user1", "password123", "user1@example.com", 500, "user"))
    conn.commit()
except:
    pass

# WAF Middleware
@app.middleware("http")
async def waf_middleware(request: Request, call_next):
    if WAF_ENABLED and waf_engine:
        try:
            # Get request body
            body = b""
            async for chunk in request.stream():
                body += chunk
            
            # Extract request data
            request_data = {
                'method': request.method,
                'uri': str(request.url.path),
                'headers': dict(request.headers),
                'body': body.decode('utf-8', errors='ignore'),
                'query_params': dict(request.query_params),
                'body_params': {},
                'src_ip': request.client.host if request.client else '127.0.0.1',
                'timestamp': datetime.utcnow().isoformat()
            }
            
            # Process through WAF
            result = waf_engine.process_request(request_data)
            
            if not result.allowed:
                return JSONResponse(
                    status_code=403,
                    content={
                        'error': 'Request blocked by WAF',
                        'reason': result.reason,
                        'violations': [
                            {
                                'type': v.get('type'),
                                'severity': v.get('severity'),
                                'reason': v.get('reason')
                            } for v in result.violations
                        ]
                    }
                )
        except Exception as e:
            print(f"[WAF] Error: {e}")
    
    # Recreate request with body
    async def receive():
        return {'type': 'http.request', 'body': body}
    
    request._receive = receive
    response = await call_next(request)
    return response

# ==================== VULNERABLE ENDPOINTS ====================

@app.get("/")
async def root():
    return {
        "message": "Vulnerable E-Commerce API",
        "waf_enabled": WAF_ENABLED,
        "endpoints": {
            "products": "/api/products",
            "search": "/api/products/search?q=...",
            "reviews": "/api/reviews",
            "cart": "/api/cart",
            "checkout": "/api/checkout",
            "users": "/api/users/{id}",
            "orders": "/api/orders/track?url=...",
            "admin_upload": "/api/admin/upload",
            "admin_files": "/api/admin/files?file=...",
            "admin_import": "/api/admin/import"
        }
    }

# 1. SQL INJECTION - Product Search
@app.get("/api/products/search")
async def search_products(q: str = Query(..., description="Search query (VULNERABLE to SQL Injection)")):
    """VULNERABLE: SQL Injection in search"""
    try:
        # VULNERABLE: Direct SQL injection
        query = f"SELECT * FROM products WHERE name LIKE '%{q}%' OR description LIKE '%{q}%'"
        cursor.execute(query)
        results = cursor.fetchall()
        
        products = []
        for row in results:
            products.append({
                "id": row[0],
                "name": row[1],
                "description": row[2],
                "price": row[3],
                "category": row[4],
                "stock": row[5]
            })
        
        return {
            "query": query,
            "products": products,
            "warning": "VULNERABLE: SQL injection possible. Try: test' OR '1'='1"
        }
    except Exception as e:
        return {"error": str(e), "query": query if 'query' in locals() else "N/A"}

# 2. SQL INJECTION - Get Product by ID
@app.get("/api/products/{product_id}")
async def get_product(product_id: str):
    """VULNERABLE: SQL Injection in product ID"""
    try:
        # VULNERABLE: Direct SQL injection
        query = f"SELECT * FROM products WHERE id = {product_id}"
        cursor.execute(query)
        row = cursor.fetchone()
        
        if row:
            return {
                "id": row[0],
                "name": row[1],
                "description": row[2],
                "price": row[3],
                "category": row[4],
                "stock": row[5],
                "query": query,
                "warning": "VULNERABLE: SQL injection possible"
            }
        return {"error": "Product not found", "query": query}
    except Exception as e:
        return {"error": str(e), "query": query if 'query' in locals() else "N/A"}

# 3. XSS - Reflected XSS in Search
@app.get("/api/search")
async def search(q: str = Query(..., description="Search query (VULNERABLE to XSS)")):
    """VULNERABLE: Reflected XSS"""
    return {
        "query": q,
        "results": f"Search results for: {q}",
        "warning": "VULNERABLE: XSS possible. Try: <script>alert('XSS')</script>"
    }

# 4. XSS - Stored XSS in Reviews
@app.post("/api/reviews")
async def create_review(
    product_id: int = Form(...),
    author: str = Form(...),
    rating: int = Form(...),
    comment: str = Form(..., description="Review comment (VULNERABLE to Stored XSS)")
):
    """VULNERABLE: Stored XSS in reviews"""
    # VULNERABLE: No sanitization
    cursor.execute(
        "INSERT INTO reviews (product_id, author, rating, comment, created_at) VALUES (?, ?, ?, ?, ?)",
        (product_id, author, rating, comment, datetime.now().isoformat())
    )
    conn.commit()
    
    return {
        "success": True,
        "review": {
            "product_id": product_id,
            "author": author,
            "rating": rating,
            "comment": comment
        },
        "warning": "VULNERABLE: Stored XSS - comment not sanitized"
    }

@app.get("/api/reviews/{product_id}")
async def get_reviews(product_id: int):
    """Get reviews for a product"""
    cursor.execute("SELECT * FROM reviews WHERE product_id = ?", (product_id,))
    rows = cursor.fetchall()
    
    reviews = []
    for row in rows:
        reviews.append({
            "id": row[0],
            "product_id": row[1],
            "author": row[2],
            "rating": row[3],
            "comment": row[4],  # VULNERABLE: Will be rendered as HTML
            "created_at": row[5]
        })
    
    return {"reviews": reviews, "warning": "VULNERABLE: Comments contain unsanitized HTML"}

# 5. COMMAND INJECTION - File Processing
@app.post("/api/admin/process")
async def process_file(filename: str = Form(..., description="Filename (VULNERABLE to Command Injection)")):
    """VULNERABLE: Command Injection"""
    try:
        # VULNERABLE: Direct command execution
        command = f"file {filename}"
        result = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=5)
        
        return {
            "command": command,
            "output": result.stdout,
            "error": result.stderr,
            "warning": "VULNERABLE: Command injection possible. Try: test.txt; ls"
        }
    except Exception as e:
        return {"error": str(e), "warning": "VULNERABLE: Command execution failed"}

# 6. PATH TRAVERSAL - File Reading
@app.get("/api/admin/files")
async def read_file(file: str = Query(..., description="File path (VULNERABLE to Path Traversal)")):
    """VULNERABLE: Path Traversal"""
    try:
        # VULNERABLE: No path validation
        file_path = os.path.join("public", file)
        with open(file_path, 'r') as f:
            content = f.read()
        
        return {
            "file": file,
            "path": file_path,
            "content": content,
            "warning": "VULNERABLE: Path traversal possible. Try: ../../../etc/passwd"
        }
    except Exception as e:
        return {"error": str(e), "file": file}

# 7. FILE UPLOAD - No Validation
@app.post("/api/admin/upload")
async def upload_file(file: UploadFile = File(..., description="File to upload (VULNERABLE)")):
    """VULNERABLE: File upload without validation"""
    try:
        # VULNERABLE: No file type or content validation
        upload_dir = Path("uploads")
        upload_dir.mkdir(exist_ok=True)
        
        file_path = upload_dir / file.filename
        content = await file.read()
        
        with open(file_path, 'wb') as f:
            f.write(content)
        
        return {
            "success": True,
            "filename": file.filename,
            "size": len(content),
            "content_type": file.content_type,
            "path": str(file_path),
            "warning": "VULNERABLE: File uploaded without validation!"
        }
    except Exception as e:
        return {"error": str(e)}

# 8. AUTHENTICATION BYPASS - Login
@app.post("/api/login")
async def login(
    username: str = Form(...),
    password: str = Form(..., description="Password (VULNERABLE to SQL Injection)")
):
    """VULNERABLE: Authentication bypass"""
    try:
        # VULNERABLE: SQL injection in login
        query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
        cursor.execute(query)
        user = cursor.fetchone()
        
        if user:
            token = base64.b64encode(f"{username}:{password}".encode()).decode()
            return {
                "success": True,
                "token": token,
                "user": {
                    "id": user[0],
                    "username": user[1],
                    "email": user[3],
                    "role": user[5]
                },
                "query": query,
                "warning": "VULNERABLE: SQL injection in login. Try: admin' OR '1'='1"
            }
        
        return {
            "success": False,
            "message": "Invalid credentials",
            "query": query
        }
    except Exception as e:
        return {"error": str(e), "query": query if 'query' in locals() else "N/A"}

# 9. IDOR - User Profile
@app.get("/api/users/{user_id}")
async def get_user(user_id: int, token: Optional[str] = Cookie(None)):
    """VULNERABLE: IDOR - no authorization check"""
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    user = cursor.fetchone()
    
    if user:
        return {
            "id": user[0],
            "username": user[1],
            "email": user[3],
            "balance": user[4],
            "role": user[5],
            "warning": "VULNERABLE: IDOR - can access any user by changing ID"
        }
    
    return {"error": "User not found"}

@app.put("/api/users/{user_id}")
async def update_user(user_id: int, balance: float = Form(...)):
    """VULNERABLE: IDOR - can modify any user"""
    cursor.execute("UPDATE users SET balance = ? WHERE id = ?", (balance, user_id))
    conn.commit()
    
    return {
        "success": True,
        "user_id": user_id,
        "new_balance": balance,
        "warning": "VULNERABLE: IDOR - can modify any user without authorization!"
    }

# 10. SSRF - Order Tracking
@app.get("/api/orders/track")
async def track_order(url: str = Query(..., description="Tracking URL (VULNERABLE to SSRF)")):
    """VULNERABLE: SSRF"""
    try:
        # Try httpx first, fallback to requests
        try:
            import httpx as http_client
            response = http_client.get(url, timeout=5)
            content = response.text[:500]
            status_code = response.status_code
        except ImportError:
            import requests as http_client
            response = http_client.get(url, timeout=5)
            content = response.text[:500]
            status_code = response.status_code
        
        # VULNERABLE: No URL validation
        return {
            "url": url,
            "status_code": status_code,
            "content": content,
            "warning": "VULNERABLE: SSRF possible. Try: http://localhost:22 or file:///etc/passwd"
        }
    except Exception as e:
        return {"error": str(e), "url": url}

# 11. XXE - Product Import
@app.post("/api/admin/import")
async def import_products(request: Request):
    """VULNERABLE: XXE"""
    content_type = request.headers.get("content-type", "")
    body = await request.body()
    
    if "xml" in content_type.lower():
        try:
            # VULNERABLE: XXE - external entities enabled
            root = ET.fromstring(body)
            
            products = []
            for product in root.findall('product'):
                products.append({
                    "name": product.find('name').text if product.find('name') is not None else "",
                    "price": product.find('price').text if product.find('price') is not None else "",
                })
            
            return {
                "success": True,
                "products": products,
                "xml": body.decode('utf-8'),
                "warning": "VULNERABLE: XXE - external entities processed!"
            }
        except Exception as e:
            return {"error": str(e), "warning": "VULNERABLE: XXE parsing error"}
    
    return {"error": "Invalid content type"}

# 12. INSECURE DESERIALIZATION - JSON Import
@app.post("/api/admin/import-json")
async def import_json(request: Request):
    """VULNERABLE: Insecure Deserialization"""
    body = await request.body()
    
    try:
        # VULNERABLE: Using eval for deserialization (VERY DANGEROUS)
        data = eval(f"({body.decode('utf-8')})")
        
        return {
            "success": True,
            "deserialized": data,
            "warning": "VULNERABLE: Using eval() - can execute arbitrary code!"
        }
    except Exception as e:
        return {"error": str(e), "warning": "VULNERABLE: Deserialization error"}

# Get all products
@app.get("/api/products")
async def get_products():
    cursor.execute("SELECT * FROM products")
    rows = cursor.fetchall()
    
    products = []
    for row in rows:
        products.append({
            "id": row[0],
            "name": row[1],
            "description": row[2],
            "price": row[3],
            "category": row[4],
            "stock": row[5]
        })
    
    return {"products": products}

# Create uploads and public directories
os.makedirs("uploads", exist_ok=True)
os.makedirs("public", exist_ok=True)

# Create a test file
with open("public/test.txt", "w") as f:
    f.write("This is a test file for path traversal testing.")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)

