# Vulnerable Backend API - WAF Testing

Complete Python FastAPI backend with all application-layer vulnerabilities for testing WAF protection.

## Features

- ✅ 11 Different Vulnerability Types
- ✅ FastAPI REST API
- ✅ SQLite Database
- ✅ WAF Integration Ready
- ✅ CORS Enabled for Frontend
- ✅ Easy to Test

## Vulnerabilities Included

1. **SQL Injection** - Product search and product ID lookup
2. **XSS (Reflected)** - Search API
3. **XSS (Stored)** - Product reviews
4. **Command Injection** - Admin file processing
5. **Path Traversal** - Admin file reading
6. **File Upload** - No validation
7. **Authentication Bypass** - SQL injection in login
8. **IDOR** - User profile access and modification
9. **SSRF** - Order tracking
10. **XXE** - Product import (XML)
11. **Insecure Deserialization** - JSON import using eval()

## Installation

```bash
# Install dependencies
pip install -r requirements.txt

# Or install manually
pip install fastapi uvicorn python-multipart aiofiles httpx
```

## Running the Backend

### Without WAF (Vulnerable Mode)

```bash
# Windows
python app.py

# Linux/Mac
python3 app.py

# Or with uvicorn
uvicorn app:app --host 0.0.0.0 --port 8000
```

### With WAF (Protected Mode)

```bash
# Windows
set WAF_ENABLED=true
python app.py

# Linux/Mac
export WAF_ENABLED=true
python3 app.py
```

The API will be available at `http://localhost:8000`

## API Endpoints

### Base
- `GET /` - API information and status

### Products
- `GET /api/products` - Get all products
- `GET /api/products/{id}` - Get product by ID (SQL Injection)
- `GET /api/products/search?q=...` - Search products (SQL Injection)

### Search
- `GET /api/search?q=...` - Search (XSS Reflected)

### Reviews
- `POST /api/reviews` - Create review (Stored XSS)
- `GET /api/reviews/{product_id}` - Get reviews

### Authentication
- `POST /api/login` - Login (Auth Bypass)

### Users
- `GET /api/users/{id}` - Get user (IDOR)
- `PUT /api/users/{id}` - Update user (IDOR)

### Orders
- `GET /api/orders/track?url=...` - Track order (SSRF)

### Admin
- `POST /api/admin/upload` - Upload file (No validation)
- `GET /api/admin/files?file=...` - Read file (Path Traversal)
- `POST /api/admin/process` - Process file (Command Injection)
- `POST /api/admin/import` - Import products (XXE)
- `POST /api/admin/import-json` - Import JSON (Deserialization)

## Testing

### Using the Frontend

1. Start the backend: `python app.py`
2. Open `vulnerable-frontend/index.html` in a browser
3. Use the web interface to test each vulnerability

### Using curl

```bash
# SQL Injection
curl "http://localhost:8000/api/products/search?q=test' OR '1'='1"

# XSS
curl "http://localhost:8000/api/search?q=<script>alert('XSS')</script>"

# SSRF
curl "http://localhost:8000/api/orders/track?url=http://localhost:22"
```

### Using Python

See `test_attacks.py` for automated testing scripts.

## WAF Integration

The backend automatically integrates with QuantumShield WAF when `WAF_ENABLED=true`:

1. All requests are intercepted by WAF middleware
2. Request data is sent to WAF engine
3. If threat detected → 403 Forbidden response
4. If no threat → Request proceeds normally

## Database

SQLite database (`vulnerable.db`) is created automatically with:
- Products table
- Users table
- Reviews table
- Orders table

Sample data is inserted on first run.

## Security Notes

⚠️ **WARNING**: This backend contains intentional vulnerabilities. Do not:
- Deploy to production
- Expose to the internet
- Use real credentials
- Store sensitive data

## Troubleshooting

### WAF not working
- Check that `WAF_ENABLED=true` is set
- Verify QuantumShield WAF module is accessible
- Check console for WAF initialization messages

### Import errors
- Make sure all dependencies are installed
- Check Python version (3.8+)
- Verify database permissions

### Port already in use
- Change port in `app.py`: `uvicorn.run(app, host="0.0.0.0", port=8001)`

