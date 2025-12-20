# ShopVuln - Vulnerable E-Commerce Platform

⚠️ **WARNING**: This is a **vulnerable e-commerce application** designed for WAF (Web Application Firewall) testing. It contains **intentional security vulnerabilities** and should **NEVER** be deployed in a production environment.

## Overview

ShopVuln is a fully functional e-commerce website that looks and feels like a real online store (similar to Flipkart/Amazon), but contains comprehensive application-level vulnerabilities integrated into natural e-commerce features:

- **Product Search** → SQL Injection, Reflected XSS
- **Product Reviews** → Stored XSS
- **Shopping Cart** → IDOR
- **Wishlist** → IDOR
- **Product Comparison** → SQL Injection, Stored XSS
- **Recommendations** → SQL Injection, IDOR
- **Checkout** → Authentication Bypass, Weak Authentication
- **User Profiles** → IDOR
- **Order Tracking** → SSRF
- **Admin Panel** → File Upload, Command Injection, Path Traversal, Broken Access Control
- **Product Import** → XXE, Insecure Deserialization
- **Money Transfer** → CSRF, SQL Injection, IDOR
- **Configuration** → Security Misconfiguration, Path Traversal

## Features

### E-Commerce Features
- ✅ Product catalog with 15+ products across multiple categories
- ✅ Advanced product search and filtering
- ✅ Product detail pages with specifications
- ✅ Customer reviews and ratings system
- ✅ Shopping cart functionality
- ✅ Wishlist feature
- ✅ Product comparison tool
- ✅ Personalized product recommendations
- ✅ Checkout process with payment
- ✅ User authentication and profiles
- ✅ Order tracking system
- ✅ Admin panel for product and user management
- ✅ Money transfer between users
- ✅ Configuration management

### Vulnerabilities (All Integrated Naturally - OWASP Top 10 Coverage)

#### A01:2021 – Broken Access Control
- **IDOR** - User profiles, shopping carts, wishlists, recommendations
- **Broken Access Control** - Admin endpoints accessible without proper authorization

#### A02:2021 – Cryptographic Failures
- **Weak Authentication** - Plain text passwords, predictable tokens
- **Session Management** - Weak session tokens, no proper session handling

#### A03:2021 – Injection
- **SQL Injection** - Product search, filters, comparison, recommendations, login, admin
- **Command Injection** - Admin file processing
- **XXE** - Product import (XML)

#### A04:2021 – Insecure Design
- **CSRF** - Money transfer, configuration changes
- **Missing Security Controls** - No rate limiting, no input validation

#### A05:2021 – Security Misconfiguration
- **Exposed Configuration** - Config endpoint exposes sensitive files
- **Default Credentials** - Weak default passwords
- **Verbose Error Messages** - Detailed error information exposed

#### A06:2021 – Vulnerable and Outdated Components
- **Insecure Deserialization** - Using eval() for JSON deserialization
- **Outdated Practices** - Using deprecated/unsafe methods

#### A07:2021 – Identification and Authentication Failures
- **Authentication Bypass** - SQL injection in login
- **Weak Passwords** - No password complexity requirements
- **Session Fixation** - Predictable session tokens

#### A08:2021 – Software and Data Integrity Failures
- **Insecure Deserialization** - Code execution via deserialization
- **File Upload** - No file validation

#### A09:2021 – Security Logging and Monitoring Failures
- **Insufficient Logging** - No security event logging
- **No Monitoring** - No intrusion detection

#### A10:2021 – Server-Side Request Forgery (SSRF)
- **SSRF** - Order tracking makes arbitrary HTTP requests

## Installation

```bash
# 1. Install dependencies
npm install

# 2. Create uploads directory
mkdir -p public/uploads

# 3. Create environment file
cp .env.example .env.local

# 4. Configure WAF (optional)
# Edit .env.local and set WAF_ENABLED=true to enable WAF protection
# Or leave it false/unset to test vulnerabilities

# 5. Start the application
npm run dev
```

The application will be available at `http://localhost:3000`

## Usage

### Testing Without WAF (Vulnerable Mode)

1. Set `WAF_ENABLED=false` in `.env.local` (or leave unset)
2. Start the app: `npm run dev`
3. Navigate through the e-commerce site
4. Try the attack payloads - **they should succeed**

### Testing With WAF (Protected Mode)

1. Install WAF API service dependencies:
   ```bash
   pip install -r waf-api-requirements.txt
   ```

2. Start WAF API service (in separate terminal):
   ```bash
   python waf-api-service.py
   ```

3. Set `WAF_ENABLED=true` in `.env.local`
4. Restart the app: `npm run dev`
5. Try the same attacks - **they should be blocked**

See `WAF_SETUP.md` for detailed WAF integration instructions.

## Vulnerability Locations

| Vulnerability | Location | Test Path | API Endpoint |
|--------------|----------|-----------|--------------|
| SQL Injection | Search, Filters | `/search?q=test' OR '1'='1` | `/api/search` |
| SQL Injection | Product Comparison | `/api/compare?ids=1) OR 1=1--` | `/api/compare` |
| SQL Injection | Recommendations | `/api/recommendations?category=' OR 1=1--` | `/api/recommendations` |
| SQL Injection | Login | POST to `/api/auth/login` with `username=admin' OR '1'='1` | `/api/auth/login` |
| XSS (Reflected) | Search Results | `/search?q=<script>alert('XSS')</script>` | `/api/search` |
| XSS (Stored) | Product Reviews | POST review with `<img src=x onerror=alert('XSS')>` | `/api/reviews` |
| XSS (Stored) | Product Comparison | POST comparison name with `<script>alert('XSS')</script>` | `/api/compare` |
| IDOR | Shopping Cart | Change `user_id` cookie | `/api/cart` |
| IDOR | Wishlist | `/api/wishlist?userId=admin` | `/api/wishlist` |
| IDOR | User Profile | `/api/users/1` (change ID) | `/api/users/[id]` |
| IDOR | Recommendations | `/api/recommendations?userId=admin` | `/api/recommendations` |
| CSRF | Money Transfer | POST to `/api/csrf/transfer` from external site | `/api/csrf/transfer` |
| SSRF | Order Tracking | `/api/orders/track?url=http://localhost:22` | `/api/orders/track` |
| Command Injection | Admin File Processing | Upload file with name `test; ls` | `/api/admin/upload?action=process` |
| Path Traversal | Admin File Reading | `/api/admin/files?file=../../../package.json` | `/api/admin/files` |
| Path Traversal | Configuration | `/api/config?file=../.env` | `/api/config` |
| File Upload | Admin Panel | Upload any file type | `/api/admin/upload` |
| Authentication Bypass | Login | `username=admin' OR '1'='1` | `/api/auth/login` |
| Broken Access Control | Admin Users | Access `/api/admin/users` without admin role | `/api/admin/users` |
| XXE | Product Import | POST XML with external entity | `/api/admin/import` (XML) |
| Insecure Deserialization | Product Import | POST JSON with `__proto__` | `/api/admin/import` (JSON) |
| Security Misconfiguration | Config Exposure | `/api/config?file=../quantumshield/config/settings.json` | `/api/config` |

## Attack Examples

### SQL Injection
```
Search: test' OR '1'='1
Search: 1 UNION SELECT null, null, null, null
```

### XSS
```
Search: <script>alert('XSS')</script>
Review: <img src=x onerror=alert('XSS')>
URL: /search?q=<svg onload=alert('XSS')>
```

### Command Injection
```
File Processing: localhost; ls
File Processing: localhost && dir
```

### Path Traversal
```
File Path: ../../../package.json
File Path: ../../../etc/passwd
```

### Authentication Bypass
```
Username: admin' OR '1'='1
Password: anything
Or: admin/password123
```

### IDOR
```
Profile: /profile (change user ID input)
Cart: Change user_id cookie value
```

### SSRF
```
Tracking URL: http://localhost:22
Tracking URL: file:///etc/passwd
Tracking URL: http://169.254.169.254/latest/meta-data/
```

### XXE
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<products>
  <product>
    <name>&xxe;</name>
  </product>
</products>
```

### Deserialization
```json
{"name": "test", "__proto__": {"isAdmin": true}}
```

## Automated Testing

See `attack-scripts/` directory for automated attack scripts:

```bash
cd attack-scripts
pip install -r requirements.txt
python test_all_attacks.py
```

## Project Structure

```
vulnerable-app/
├── app/
│   ├── api/                    # API endpoints (vulnerable)
│   │   ├── products/          # SQL injection
│   │   ├── reviews/           # XSS
│   │   ├── cart/              # IDOR
│   │   ├── checkout/          # Auth bypass
│   │   ├── users/             # IDOR
│   │   ├── orders/            # SSRF
│   │   └── admin/             # Multiple vulnerabilities
│   ├── search/                # SQL injection, XSS
│   ├── products/              # Product pages
│   ├── cart/                  # Shopping cart
│   ├── checkout/              # Checkout
│   ├── profile/               # User profile (IDOR)
│   ├── orders/                # Order tracking (SSRF)
│   ├── admin/                 # Admin panel
│   └── vulnerabilities/       # Vulnerability reference
├── middleware.ts              # WAF integration
├── package.json
└── README.md
```

## WAF Integration

The WAF is integrated via Next.js middleware and a Python WAF API service. When `WAF_ENABLED=true`:

1. Requests to vulnerable endpoints are intercepted by Next.js middleware
2. Request data is sent to WAF API service (Python)
3. WAF API service processes request through QuantumShield WAF engine
4. If threat detected → 403 Forbidden response
5. If no threat → Request proceeds to application

### WAF API Service

The WAF API service (`waf-api-service.py`) provides an HTTP API that:
- Accepts HTTP requests from Next.js middleware
- Processes them through QuantumShield WAF engine
- Returns allow/block decisions with violation details

See `WAF_SETUP.md` for detailed setup instructions.

## Security Notes

⚠️ **CRITICAL WARNINGS**:

- This application is **intentionally vulnerable**
- **DO NOT** deploy to production
- **DO NOT** use real credentials or sensitive data
- Use only in **isolated testing environments**
- All vulnerabilities are documented for educational purposes

## License

This is a testing application. Use at your own risk.

## Support

For WAF testing and integration questions, refer to:
- `WAF_SETUP.md` - Detailed WAF integration setup
- `SETUP.md` - Detailed setup instructions
- `QUICK_START.md` - Quick start guide
- `../quantumshield/docs/WINDOWS_COMPATIBILITY.md` - WAF compatibility

## New Features Added

### E-Commerce Features
- **Wishlist** - Save products for later (vulnerable to IDOR)
- **Product Comparison** - Compare multiple products side-by-side (vulnerable to SQL Injection and XSS)
- **Recommendations** - Personalized product recommendations (vulnerable to SQL Injection and IDOR)
- **Enhanced Authentication** - Login system with multiple vulnerabilities
- **Money Transfer** - Transfer funds between users (vulnerable to CSRF, SQL Injection, IDOR)
- **Configuration Management** - Runtime configuration (vulnerable to Security Misconfiguration)

### Additional Vulnerabilities
- **CSRF** - Cross-Site Request Forgery in money transfer
- **Broken Access Control** - Admin endpoints accessible without proper authorization
- **Security Misconfiguration** - Exposed configuration files and settings
- **Enhanced SQL Injection** - Multiple endpoints with SQL injection
- **Enhanced XSS** - Reflected and stored XSS in multiple locations
