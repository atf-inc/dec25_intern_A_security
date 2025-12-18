#!/usr/bin/env python3
"""
Automated attack scripts for testing WAF protection.
Run these scripts to test if attacks are blocked when WAF is enabled.
"""

import requests
import json
import sys
from typing import Dict, Any

BASE_URL = "http://localhost:3000"

def test_sql_injection() -> Dict[str, Any]:
    """Test SQL injection attacks."""
    print("\n" + "="*60)
    print("Testing SQL Injection")
    print("="*60)
    
    attacks = [
        ("1 OR 1=1", "Basic SQL injection"),
        ("1' OR '1'='1", "SQL injection with quotes"),
        ("1 UNION SELECT null, null, null, null", "UNION-based injection"),
        ("1'; DROP TABLE users; --", "SQL injection with DROP"),
    ]
    
    results = []
    for payload, description in attacks:
        try:
            response = requests.get(f"{BASE_URL}/api/vulnerable/sql-injection?id={payload}", timeout=5)
            results.append({
                "payload": payload,
                "description": description,
                "status_code": response.status_code,
                "blocked": response.status_code == 403,
                "response": response.json() if response.status_code != 403 else None
            })
            print(f"  {description}: {'BLOCKED ✓' if response.status_code == 403 else 'ALLOWED ✗'}")
        except Exception as e:
            results.append({
                "payload": payload,
                "description": description,
                "error": str(e)
            })
            print(f"  {description}: ERROR - {e}")
    
    return {"sql_injection": results}

def test_xss() -> Dict[str, Any]:
    """Test XSS attacks."""
    print("\n" + "="*60)
    print("Testing XSS (Cross-Site Scripting)")
    print("="*60)
    
    attacks = [
        ("<script>alert('XSS')</script>", "Basic XSS"),
        ("<img src=x onerror=alert('XSS')>", "XSS with img tag"),
        ("<svg onload=alert('XSS')>", "XSS with SVG"),
        ("javascript:alert('XSS')", "JavaScript protocol"),
    ]
    
    results = []
    for payload, description in attacks:
        try:
            response = requests.get(f"{BASE_URL}/api/vulnerable/xss?name={payload}", timeout=5)
            results.append({
                "payload": payload,
                "description": description,
                "status_code": response.status_code,
                "blocked": response.status_code == 403,
                "response": response.json() if response.status_code != 403 else None
            })
            print(f"  {description}: {'BLOCKED ✓' if response.status_code == 403 else 'ALLOWED ✗'}")
        except Exception as e:
            results.append({
                "payload": payload,
                "description": description,
                "error": str(e)
            })
            print(f"  {description}: ERROR - {e}")
    
    return {"xss": results}

def test_command_injection() -> Dict[str, Any]:
    """Test command injection attacks."""
    print("\n" + "="*60)
    print("Testing Command Injection")
    print("="*60)
    
    attacks = [
        ("localhost; ls", "Command chaining (Linux)"),
        ("localhost && dir", "Command chaining (Windows)"),
        ("localhost | cat /etc/passwd", "Pipe command"),
        ("localhost; rm -rf /", "Destructive command"),
    ]
    
    results = []
    for payload, description in attacks:
        try:
            response = requests.get(f"{BASE_URL}/api/vulnerable/command-injection?host={payload}", timeout=5)
            results.append({
                "payload": payload,
                "description": description,
                "status_code": response.status_code,
                "blocked": response.status_code == 403,
                "response": response.json() if response.status_code != 403 else None
            })
            print(f"  {description}: {'BLOCKED ✓' if response.status_code == 403 else 'ALLOWED ✗'}")
        except Exception as e:
            results.append({
                "payload": payload,
                "description": description,
                "error": str(e)
            })
            print(f"  {description}: ERROR - {e}")
    
    return {"command_injection": results}

def test_path_traversal() -> Dict[str, Any]:
    """Test path traversal attacks."""
    print("\n" + "="*60)
    print("Testing Path Traversal")
    print("="*60)
    
    attacks = [
        ("../../../etc/passwd", "Linux path traversal"),
        ("..\\..\\..\\windows\\system32\\config\\sam", "Windows path traversal"),
        ("../../package.json", "Relative path traversal"),
        ("....//....//etc/passwd", "Encoded path traversal"),
    ]
    
    results = []
    for payload, description in attacks:
        try:
            response = requests.get(f"{BASE_URL}/api/vulnerable/path-traversal?file={payload}", timeout=5)
            results.append({
                "payload": payload,
                "description": description,
                "status_code": response.status_code,
                "blocked": response.status_code == 403,
                "response": response.json() if response.status_code != 403 else None
            })
            print(f"  {description}: {'BLOCKED ✓' if response.status_code == 403 else 'ALLOWED ✗'}")
        except Exception as e:
            results.append({
                "payload": payload,
                "description": description,
                "error": str(e)
            })
            print(f"  {description}: ERROR - {e}")
    
    return {"path_traversal": results}

def test_ssrf() -> Dict[str, Any]:
    """Test SSRF attacks."""
    print("\n" + "="*60)
    print("Testing SSRF (Server-Side Request Forgery)")
    print("="*60)
    
    attacks = [
        ("http://localhost:22", "Internal service access"),
        ("file:///etc/passwd", "File protocol"),
        ("http://169.254.169.254/latest/meta-data/", "Cloud metadata service"),
        ("http://127.0.0.1:3306", "Database port scan"),
    ]
    
    results = []
    for payload, description in attacks:
        try:
            response = requests.get(f"{BASE_URL}/api/vulnerable/ssrf?url={payload}", timeout=5)
            results.append({
                "payload": payload,
                "description": description,
                "status_code": response.status_code,
                "blocked": response.status_code == 403,
                "response": response.json() if response.status_code != 403 else None
            })
            print(f"  {description}: {'BLOCKED ✓' if response.status_code == 403 else 'ALLOWED ✗'}")
        except Exception as e:
            results.append({
                "payload": payload,
                "description": description,
                "error": str(e)
            })
            print(f"  {description}: ERROR - {e}")
    
    return {"ssrf": results}

def test_auth_bypass() -> Dict[str, Any]:
    """Test authentication bypass."""
    print("\n" + "="*60)
    print("Testing Authentication Bypass")
    print("="*60)
    
    attacks = [
        ({"username": "admin' OR '1'='1", "password": "anything"}, "SQL injection in login"),
        ({"username": "admin", "password": "' OR '1'='1"}, "SQL injection in password"),
        ({"username": "admin", "password": "admin123"}, "Valid credentials (should work)"),
    ]
    
    results = []
    for payload, description in attacks:
        try:
            response = requests.post(
                f"{BASE_URL}/api/vulnerable/auth-bypass",
                json=payload,
                timeout=5
            )
            results.append({
                "payload": payload,
                "description": description,
                "status_code": response.status_code,
                "blocked": response.status_code == 403,
                "response": response.json() if response.status_code != 403 else None
            })
            print(f"  {description}: {'BLOCKED ✓' if response.status_code == 403 else 'ALLOWED ✗'}")
        except Exception as e:
            results.append({
                "payload": payload,
                "description": description,
                "error": str(e)
            })
            print(f"  {description}: ERROR - {e}")
    
    return {"auth_bypass": results}

def main():
    """Run all attack tests."""
    print("="*60)
    print("WAF Attack Test Suite")
    print("="*60)
    print(f"Target: {BASE_URL}")
    print("\nMake sure the vulnerable app is running!")
    print("Press Enter to continue or Ctrl+C to cancel...")
    
    try:
        input()
    except KeyboardInterrupt:
        print("\nCancelled.")
        sys.exit(0)
    
    all_results = {}
    
    # Run all tests
    all_results.update(test_sql_injection())
    all_results.update(test_xss())
    all_results.update(test_command_injection())
    all_results.update(test_path_traversal())
    all_results.update(test_ssrf())
    all_results.update(test_auth_bypass())
    
    # Summary
    print("\n" + "="*60)
    print("Test Summary")
    print("="*60)
    
    total_tests = 0
    blocked_tests = 0
    
    for category, tests in all_results.items():
        for test in tests:
            total_tests += 1
            if test.get("blocked"):
                blocked_tests += 1
    
    print(f"Total Tests: {total_tests}")
    print(f"Blocked by WAF: {blocked_tests}")
    print(f"Allowed: {total_tests - blocked_tests}")
    print(f"Protection Rate: {(blocked_tests/total_tests*100):.1f}%" if total_tests > 0 else "N/A")
    
    # Save results
    with open("attack_results.json", "w") as f:
        json.dump(all_results, f, indent=2)
    
    print("\nResults saved to attack_results.json")

if __name__ == "__main__":
    main()

