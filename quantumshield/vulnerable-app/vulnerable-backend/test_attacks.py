#!/usr/bin/env python3
"""
Automated attack testing script for vulnerable backend
Tests all vulnerabilities and reports which are blocked by WAF
"""

import requests
import json
import sys
from typing import Dict, Any

API_BASE = "http://localhost:8000"

def test_sql_injection() -> Dict[str, Any]:
    """Test SQL injection attacks"""
    print("\n" + "="*60)
    print("Testing SQL Injection")
    print("="*60)
    
    attacks = [
        ("test' OR '1'='1", "Basic SQL injection"),
        ("1' UNION SELECT null, null, null, null, null, null--", "UNION injection"),
        ("'; DROP TABLE products; --", "Destructive SQL"),
    ]
    
    results = []
    for payload, description in attacks:
        try:
            response = requests.get(f"{API_BASE}/api/products/search", params={"q": payload}, timeout=5)
            blocked = response.status_code == 403
            results.append({
                "payload": payload,
                "description": description,
                "status_code": response.status_code,
                "blocked": blocked
            })
            status = "BLOCKED ✓" if blocked else "ALLOWED ✗"
            print(f"  {description}: {status} (Status: {response.status_code})")
        except Exception as e:
            print(f"  {description}: ERROR - {e}")
            results.append({"payload": payload, "error": str(e)})
    
    return {"sql_injection": results}

def test_xss() -> Dict[str, Any]:
    """Test XSS attacks"""
    print("\n" + "="*60)
    print("Testing XSS (Reflected)")
    print("="*60)
    
    attacks = [
        ("<script>alert('XSS')</script>", "Basic XSS"),
        ("<img src=x onerror=alert('XSS')>", "XSS with img tag"),
        ("<svg onload=alert('XSS')>", "XSS with SVG"),
    ]
    
    results = []
    for payload, description in attacks:
        try:
            response = requests.get(f"{API_BASE}/api/search", params={"q": payload}, timeout=5)
            blocked = response.status_code == 403
            results.append({
                "payload": payload,
                "description": description,
                "status_code": response.status_code,
                "blocked": blocked
            })
            status = "BLOCKED ✓" if blocked else "ALLOWED ✗"
            print(f"  {description}: {status} (Status: {response.status_code})")
        except Exception as e:
            print(f"  {description}: ERROR - {e}")
            results.append({"payload": payload, "error": str(e)})
    
    return {"xss": results}

def test_command_injection() -> Dict[str, Any]:
    """Test command injection"""
    print("\n" + "="*60)
    print("Testing Command Injection")
    print("="*60)
    
    attacks = [
        ("test.txt; ls", "Command chaining (Linux)"),
        ("test.txt && dir", "Command chaining (Windows)"),
        ("test.txt | cat /etc/passwd", "Pipe command"),
    ]
    
    results = []
    for payload, description in attacks:
        try:
            response = requests.post(
                f"{API_BASE}/api/admin/process",
                data={"filename": payload},
                timeout=5
            )
            blocked = response.status_code == 403
            results.append({
                "payload": payload,
                "description": description,
                "status_code": response.status_code,
                "blocked": blocked
            })
            status = "BLOCKED ✓" if blocked else "ALLOWED ✗"
            print(f"  {description}: {status} (Status: {response.status_code})")
        except Exception as e:
            print(f"  {description}: ERROR - {e}")
            results.append({"payload": payload, "error": str(e)})
    
    return {"command_injection": results}

def test_path_traversal() -> Dict[str, Any]:
    """Test path traversal"""
    print("\n" + "="*60)
    print("Testing Path Traversal")
    print("="*60)
    
    attacks = [
        ("../../../etc/passwd", "Linux path traversal"),
        ("..\\..\\..\\windows\\system32\\config\\sam", "Windows path traversal"),
        ("../../package.json", "Relative path traversal"),
    ]
    
    results = []
    for payload, description in attacks:
        try:
            response = requests.get(f"{API_BASE}/api/admin/files", params={"file": payload}, timeout=5)
            blocked = response.status_code == 403
            results.append({
                "payload": payload,
                "description": description,
                "status_code": response.status_code,
                "blocked": blocked
            })
            status = "BLOCKED ✓" if blocked else "ALLOWED ✗"
            print(f"  {description}: {status} (Status: {response.status_code})")
        except Exception as e:
            print(f"  {description}: ERROR - {e}")
            results.append({"payload": payload, "error": str(e)})
    
    return {"path_traversal": results}

def test_auth_bypass() -> Dict[str, Any]:
    """Test authentication bypass"""
    print("\n" + "="*60)
    print("Testing Authentication Bypass")
    print("="*60)
    
    attacks = [
        ({"username": "admin' OR '1'='1", "password": "anything"}, "SQL injection in username"),
        ({"username": "admin", "password": "' OR '1'='1"}, "SQL injection in password"),
        ({"username": "admin", "password": "admin123"}, "Valid credentials"),
    ]
    
    results = []
    for payload, description in attacks:
        try:
            response = requests.post(
                f"{API_BASE}/api/login",
                data=payload,
                timeout=5
            )
            blocked = response.status_code == 403
            results.append({
                "payload": payload,
                "description": description,
                "status_code": response.status_code,
                "blocked": blocked
            })
            status = "BLOCKED ✓" if blocked else "ALLOWED ✗"
            print(f"  {description}: {status} (Status: {response.status_code})")
        except Exception as e:
            print(f"  {description}: ERROR - {e}")
            results.append({"payload": payload, "error": str(e)})
    
    return {"auth_bypass": results}

def test_ssrf() -> Dict[str, Any]:
    """Test SSRF"""
    print("\n" + "="*60)
    print("Testing SSRF")
    print("="*60)
    
    attacks = [
        ("http://localhost:22", "Internal service (SSH)"),
        ("file:///etc/passwd", "File protocol"),
        ("http://169.254.169.254/latest/meta-data/", "Cloud metadata"),
    ]
    
    results = []
    for payload, description in attacks:
        try:
            response = requests.get(f"{API_BASE}/api/orders/track", params={"url": payload}, timeout=5)
            blocked = response.status_code == 403
            results.append({
                "payload": payload,
                "description": description,
                "status_code": response.status_code,
                "blocked": blocked
            })
            status = "BLOCKED ✓" if blocked else "ALLOWED ✗"
            print(f"  {description}: {status} (Status: {response.status_code})")
        except Exception as e:
            print(f"  {description}: ERROR - {e}")
            results.append({"payload": payload, "error": str(e)})
    
    return {"ssrf": results}

def main():
    """Run all tests"""
    print("="*60)
    print("Vulnerable Backend - Attack Test Suite")
    print("="*60)
    print(f"Target: {API_BASE}")
    
    # Check if API is running
    try:
        response = requests.get(f"{API_BASE}/", timeout=2)
        data = response.json()
        print(f"\nAPI Status: Connected")
        print(f"WAF Enabled: {data.get('waf_enabled', False)}")
    except:
        print(f"\nERROR: Cannot connect to API at {API_BASE}")
        print("Make sure the backend is running: python app.py")
        sys.exit(1)
    
    print("\nPress Enter to start testing or Ctrl+C to cancel...")
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
    all_results.update(test_auth_bypass())
    all_results.update(test_ssrf())
    
    # Summary
    print("\n" + "="*60)
    print("Test Summary")
    print("="*60)
    
    total_tests = 0
    blocked_tests = 0
    
    for category, tests in all_results.items():
        for test in tests:
            if 'blocked' in test:
                total_tests += 1
                if test['blocked']:
                    blocked_tests += 1
    
    print(f"Total Tests: {total_tests}")
    print(f"Blocked by WAF: {blocked_tests}")
    print(f"Allowed: {total_tests - blocked_tests}")
    if total_tests > 0:
        print(f"Protection Rate: {(blocked_tests/total_tests*100):.1f}%")
    
    # Save results
    with open("attack_results.json", "w") as f:
        json.dump(all_results, f, indent=2)
    
    print("\nResults saved to attack_results.json")

if __name__ == "__main__":
    main()

