# Complete Vulnerability Reference

This document provides a comprehensive list of all vulnerabilities in ShopVuln e-commerce platform.

## OWASP Top 10 2021 Coverage

### A01:2021 – Broken Access Control

#### IDOR (Insecure Direct Object Reference)

1. **Shopping Cart** (`/api/cart`)
   - **Vulnerability**: Can access any user's cart by changing `user_id` cookie
   - **Test**: Change cookie `user_id=admin` to access admin's cart
   - **Impact**: View/modify other users' shopping carts

2. **Wishlist** (`/api/wishlist`)
   - **Vulnerability**: Can access/modify any user's wishlist via `userId` parameter
   - **Test**: `GET /api/wishlist?userId=admin`
   - **Impact**: View/modify other users' wishlists

3. **User Profiles** (`/api/users/[id]`)
   - **Vulnerability**: Can access any user's profile by changing ID
   - **Test**: `GET /api/users/1`, `GET /api/users/2`
   - **Impact**: View/modify any user's personal information

4. **Recommendations** (`/api/recommendations`)
   - **Vulnerability**: Can access recommendations for any user
   - **Test**: `GET /api/recommendations?userId=admin`
   - **Impact**: Privacy violation

#### Broken Access Control

5. **Admin Users Endpoint** (`/api/admin/users`)
   - **Vulnerability**: Role check can be bypassed by modifying `role` cookie
   - **Test**: Set cookie `role=admin` to access admin endpoints
   - **Impact**: Unauthorized access to admin functions

### A02:2021 – Cryptographic Failures

6. **Weak Authentication** (`/api/auth/login`)
   - **Vulnerability**: Plain text passwords, predictable tokens
   - **Test**: Login with `admin/password123` or `user1/password123`
   - **Impact**: Account compromise

7. **Session Management** (Multiple endpoints)
   - **Vulnerability**: Weak session tokens (base64 encoded username:password)
   - **Test**: Decode `auth_token` cookie to get credentials
   - **Impact**: Session hijacking

### A03:2021 – Injection

#### SQL Injection

8. **Product Search** (`/api/search`)
   - **Vulnerability**: SQL injection in search query, category, price filters
   - **Test**: `?q=test' OR '1'='1` or `?category=' OR 1=1--`
   - **Impact**: Database compromise, data exfiltration

9. **Product Comparison** (`/api/compare`)
   - **Vulnerability**: SQL injection in product IDs
   - **Test**: `?ids=1) OR 1=1--`
   - **Impact**: Database compromise

10. **Recommendations** (`/api/recommendations`)
    - **Vulnerability**: SQL injection in category and limit parameters
    - **Test**: `?category=' OR 1=1--`
    - **Impact**: Database compromise

11. **Login** (`/api/auth/login`)
    - **Vulnerability**: SQL injection in username/password
    - **Test**: `username=admin' OR '1'='1`
    - **Impact**: Authentication bypass

12. **Products** (`/api/products`)
    - **Vulnerability**: SQL injection in search, category, price filters
    - **Test**: `?search=test' OR '1'='1`
    - **Impact**: Database compromise

13. **Product Details** (`/api/products/[id]`)
    - **Vulnerability**: SQL injection in product ID
    - **Test**: `GET /api/products/1 OR 1=1--`
    - **Impact**: Database compromise

14. **CSRF Transfer** (`/api/csrf/transfer`)
    - **Vulnerability**: SQL injection in user IDs and amount
    - **Test**: `POST {"toUserId": "1 OR 1=1--", "amount": 100}`
    - **Impact**: Database compromise, financial fraud

15. **Admin Users** (`/api/admin/users`)
    - **Vulnerability**: SQL injection in search and sort parameters
    - **Test**: `?search=' OR 1=1--` or `?sortBy=id; DROP TABLE users--`
    - **Impact**: Database compromise, data loss

#### Command Injection

16. **Admin File Upload** (`/api/admin/upload`)
    - **Vulnerability**: Command injection in file processing
    - **Test**: Upload file with name `test; ls` or `test && cat /etc/passwd`
    - **Impact**: Remote code execution

### A04:2021 – Insecure Design

17. **CSRF** (`/api/csrf/transfer`)
    - **Vulnerability**: No CSRF protection on money transfer
    - **Test**: Create malicious page that POSTs to transfer endpoint
    - **Impact**: Unauthorized money transfers

18. **Missing Security Controls**
    - **Vulnerability**: No rate limiting, no input validation
    - **Impact**: Brute force attacks, DoS

### A05:2021 – Security Misconfiguration

19. **Configuration Exposure** (`/api/config`)
    - **Vulnerability**: Exposes sensitive configuration files
    - **Test**: `?file=../.env` or `?file=../quantumshield/config/settings.json`
    - **Impact**: Information disclosure

20. **Verbose Error Messages**
    - **Vulnerability**: Detailed error messages expose system information
    - **Test**: Trigger SQL errors to see database structure
    - **Impact**: Information disclosure

21. **Default Credentials**
    - **Vulnerability**: Weak default passwords
    - **Test**: `admin/password123`, `user1/password123`
    - **Impact**: Unauthorized access

### A06:2021 – Vulnerable and Outdated Components

22. **Insecure Deserialization** (`/api/admin/import`)
    - **Vulnerability**: Using `eval()` for JSON deserialization
    - **Test**: `POST {"__proto__": {"isAdmin": true}}`
    - **Impact**: Code execution, prototype pollution

### A07:2021 – Identification and Authentication Failures

23. **Authentication Bypass** (`/api/auth/login`)
    - **Vulnerability**: SQL injection allows bypassing authentication
    - **Test**: `username=admin' OR '1'='1`
    - **Impact**: Unauthorized access

24. **Weak Passwords**
    - **Vulnerability**: No password complexity requirements
    - **Impact**: Easy account compromise

### A08:2021 – Software and Data Integrity Failures

25. **File Upload** (`/api/admin/upload`)
    - **Vulnerability**: No file type validation
    - **Test**: Upload PHP shell, executable files
    - **Impact**: Remote code execution

26. **Insecure Deserialization** (see #22)

### A09:2021 – Security Logging and Monitoring Failures

27. **Insufficient Logging**
    - **Vulnerability**: No security event logging
    - **Impact**: No audit trail, difficult to detect attacks

### A10:2021 – Server-Side Request Forgery (SSRF)

28. **Order Tracking** (`/api/orders/track`)
    - **Vulnerability**: Makes arbitrary HTTP requests
    - **Test**: `?url=http://localhost:22` or `?url=file:///etc/passwd`
    - **Impact**: Internal network access, file reading

## Cross-Site Scripting (XSS)

### Reflected XSS

29. **Search** (`/api/search`)
    - **Vulnerability**: Search query reflected in response without sanitization
    - **Test**: `?q=<script>alert('XSS')</script>`
    - **Impact**: Session hijacking, phishing

### Stored XSS

30. **Product Reviews** (`/api/reviews`)
    - **Vulnerability**: Review comments stored and displayed without sanitization
    - **Test**: POST review with `<img src=x onerror=alert('XSS')>`
    - **Impact**: Persistent XSS attack

31. **Product Comparison** (`/api/compare`)
    - **Vulnerability**: Comparison name stored without sanitization
    - **Test**: POST with `{"comparisonName": "<script>alert('XSS')</script>"}`
    - **Impact**: Persistent XSS attack

## XML External Entity (XXE)

32. **Product Import** (`/api/admin/import`)
    - **Vulnerability**: XML parser processes external entities
    - **Test**: POST XML with `<!ENTITY xxe SYSTEM "file:///etc/passwd">`
    - **Impact**: File reading, SSRF

## Path Traversal

33. **Admin File Reading** (`/api/admin/files`)
    - **Vulnerability**: No path validation
    - **Test**: `?file=../../../package.json`
    - **Impact**: Arbitrary file reading

34. **Configuration** (`/api/config`)
    - **Vulnerability**: No path validation
    - **Test**: `?file=../.env`
    - **Impact**: Sensitive file reading

## Summary

- **Total Vulnerabilities**: 34+
- **OWASP Top 10 Coverage**: 10/10 categories
- **Critical Vulnerabilities**: 15+
- **High Severity**: 20+
- **Medium Severity**: 10+

All vulnerabilities are intentionally included for WAF testing purposes.
