
import logging
import json
import re
from typing import Dict, Any, List, Optional
from .sql_injection_detector import SQLInjectionDetector
from .xss_detector import XSSDetector
from .command_injection_detector import CommandInjectionDetector
from .path_traversal_detector import PathTraversalDetector
from .xxe_detector import XXEDetector
from .ssrf_detector import SSRFDetector

# from .http_inspector import HTTPInspector # Assuming this exists or will be used

logger = logging.getLogger(__name__)

class WAFEngine:
    """
    Web Application Firewall (WAF) Engine.
    Orchestrates L7 protection modules.
    """
    
    # Whitelist of common benign patterns that should never be blocked
    BENIGN_WHITELIST = [
        # Common field names (as standalone values, not in attack context)
        re.compile(rb'^(username|password|user|email|name|id)$', re.I),
        # Simple numeric values
        re.compile(rb'^\d+$'),
        # Simple alphanumeric (short, no special chars)
        re.compile(rb'^[a-zA-Z0-9_]{1,50}$'),
        # Common JSON field names (quoted)
        re.compile(rb'^"?(username|password|user|email|name|id)"?:?\s*"?[a-zA-Z0-9_@.-]*"?$', re.I),
    ]
    
    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}
        self.sql_detector = SQLInjectionDetector()
        self.xss_detector = XSSDetector()
        self.cmd_detector = CommandInjectionDetector()
        self.path_detector = PathTraversalDetector()
        self.xxe_detector = XXEDetector()
        self.ssrf_detector = SSRFDetector()
        
        # self.http_inspector = HTTPInspector()
        logger.info("WAF Engine initialized")

    def analyze_request(self, method: str, path: str, headers: Dict[str, str], body: str = "", 
                       query_params: Dict[str, Any] = None, body_params: Dict[str, Any] = None,
                       all_params: Dict[str, Any] = None) -> bool:
        """
        Analyze HTTP request for malicious content.
        Returns True if malicious, False otherwise.
        """
        violations = self.process_request(method, path, headers, body, query_params, body_params, all_params)
        return len(violations) > 0
    
    def _is_whitelisted(self, payload_data: bytes) -> bool:
        """
        Check if payload matches whitelist patterns (definitely benign).
        """
        payload_lower = payload_data.lower()
        
        # Check literal whitelist patterns
        for pattern in self.BENIGN_WHITELIST:
            if isinstance(pattern, bytes):
                if pattern in payload_lower:
                    return True
            elif isinstance(pattern, re.Pattern):
                if pattern.match(payload_data):
                    return True
        
        return False
    
    def _check_payload(self, payload_data: bytes, param_name: str = "") -> List[Dict[str, str]]:
        """
        Check a payload for various attack signatures.
        Returns list of violations found.
        """
        violations = []
        
        # Skip if payload is whitelisted (definitely benign)
        if self._is_whitelisted(payload_data):
            logger.debug(f"Payload whitelisted (benign): {payload_data[:100]}")
            return violations
        
        payload_dict = {"payload": payload_data}
        
        # Helper to check a detector and append violation
        def check_detector(detector, type_name, reason_prefix):
            result = detector.detect(payload_dict)
            if result:
                location = f" in {param_name}" if param_name else ""
                violations.append({
                    "type": type_name,
                    "reason": f"{reason_prefix} pattern detected{location}",
                    "location": param_name or "request"
                })

        # 1. SQL Injection
        check_detector(self.sql_detector, "sql_injection", "SQL injection")
            
        # 2. XSS
        check_detector(self.xss_detector, "xss", "XSS (Cross-Site Scripting)")
        
        # 3. Command Injection
        check_detector(self.cmd_detector, "command_injection", "Command Injection")

        # 4. Path Traversal
        check_detector(self.path_detector, "path_traversal", "Path Traversal")

        # 5. XXE
        check_detector(self.xxe_detector, "xxe", "XXE")

        # 6. SSRF
        check_detector(self.ssrf_detector, "ssrf", "SSRF")
            
        return violations
    
    def _is_benign_value(self, value: Any) -> bool:
        """
        Check if a value looks like legitimate/benign data.
        Returns True if the value appears safe and doesn't need strict checking.
        """
        if value is None:
            return True
        
        value_str = str(value).strip()
        
        # Empty values are benign
        if not value_str:
            return True
        
        # Check if it's a simple number
        try:
            float(value_str)
            return True
        except (ValueError, TypeError):
            pass
        
        # Check if it's valid JSON (legitimate JSON data)
        if value_str.startswith('{') and value_str.endswith('}'):
            try:
                json.loads(value_str)
                # If it's valid JSON with simple values, it's likely benign
                parsed = json.loads(value_str)
                if isinstance(parsed, dict):
                    # Check if all values are simple (numbers, strings, bools)
                    for v in parsed.values():
                        if not isinstance(v, (str, int, float, bool, type(None))):
                            return False
                    # If it's simple JSON, allow it (but still check for obvious attacks)
                    return True
            except (json.JSONDecodeError, ValueError):
                pass
        
        # Simple alphanumeric strings (short, no special chars) are likely benign
        if value_str.isalnum() and len(value_str) < 50:
            return True
        
        # Common benign patterns
        benign_patterns = [
            r'^[a-zA-Z0-9_@.-]+$',  # Email-like, username-like
            r'^[a-zA-Z\s]+$',  # Plain text
        ]
        import re
        for pattern in benign_patterns:
            if re.match(pattern, value_str) and len(value_str) < 100:
                return True
        
        return False
    
    def _check_params(self, params: Dict[str, Any], param_type: str = "") -> List[Dict[str, str]]:
        """
        Check all parameter values for malicious content.
        """
        violations = []
        
        if not params:
            return violations
        
        # Common form field names that typically contain benign data
        BENIGN_FIELD_NAMES = {'username', 'user', 'password', 'email', 'name', 'id', 'firstname', 
                             'lastname', 'phone', 'address', 'city', 'zip', 'country'}
        
        for key, value in params.items():
            if value is None:
                continue
            
            value_str = str(value)
            value_bytes = value_str.encode('utf-8', errors='ignore')
            
            # Skip checking if:
            # 1. Field name is common benign field AND
            # 2. Value is simple (alphanumeric, short, no special SQL/command chars)
            key_lower = key.lower()
            if key_lower in BENIGN_FIELD_NAMES:
                # Check if value is simple and benign
                if self._is_simple_benign_value(value_str):
                    logger.debug(f"Skipping check for benign field '{key}' with simple value")
                    continue
            
            # Check this parameter value
            param_violations = self._check_payload(value_bytes, f"{param_type}.{key}")
            violations.extend(param_violations)
        
        return violations
    
    def _is_simple_benign_value(self, value_str: str) -> bool:
        """
        Check if a value is simple and definitely benign (no need to check).
        """
        if not value_str:
            return True
        
        # Simple numeric
        try:
            float(value_str)
            return True
        except (ValueError, TypeError):
            pass
        
        # Simple alphanumeric (short, no special chars that could be attacks)
        if len(value_str) <= 50:
            # Allow alphanumeric, underscore, dash, dot, @ (for emails)
            if re.match(r'^[a-zA-Z0-9_@.-]+$', value_str):
                # But exclude if it contains SQL/command injection patterns
                suspicious = ['union', 'select', 'drop', 'delete', 'insert', 'update', 
                             'script', 'javascript', 'onerror', 'onclick', 'cmd', 'exec',
                             'cat ', 'ls ', 'dir', 'whoami', ';', '|', '&&', '||']
                value_lower = value_str.lower()
                if not any(sus in value_lower for sus in suspicious):
                    return True
        
        return False
    
    def process_request(self, method: str, path: str, headers: Dict[str, str], body: str = "",
                       query_params: Dict[str, Any] = None, body_params: Dict[str, Any] = None,
                       all_params: Dict[str, Any] = None) -> list:
        """
        Process HTTP request and return detailed violations.
        Returns list of violation dictionaries with 'type' and 'reason' keys.
        
        Args:
            method: HTTP method (GET, POST, etc.)
            path: Request path/URI
            headers: Request headers
            body: Raw request body as string
            query_params: Query parameters as dict
            body_params: Body parameters as dict
            all_params: Combined parameters as dict
        """
        violations = []
        
        query_params = query_params or {}
        body_params = body_params or {}
        all_params = all_params or {}
        
        # 1. Check path
        path_bytes = path.encode('utf-8', errors='ignore')
        violations.extend(self._check_payload(path_bytes, "path"))
        
        # 2. Check raw body
        if body:
            if isinstance(body, str):
                # If body is valid JSON, parse it and check individual values instead
                # This reduces false positives from JSON structure characters
                try:
                    parsed_body = json.loads(body)
                    if isinstance(parsed_body, dict):
                        # Check individual JSON values instead of raw body
                        # This is already done in step 4 (body_params), so skip raw body check
                        pass
                    else:
                        # Not a dict, check as string
                        body_bytes = body.encode('utf-8', errors='ignore')
                        violations.extend(self._check_payload(body_bytes, "body"))
                except (json.JSONDecodeError, ValueError):
                    # Not JSON, check as string
                    body_bytes = body.encode('utf-8', errors='ignore')
                    violations.extend(self._check_payload(body_bytes, "body"))
            else:
                body_bytes = body
                violations.extend(self._check_payload(body_bytes, "body"))
        
        # 3. Check query parameters individually
        violations.extend(self._check_params(query_params, "query"))
        
        # 4. Check body parameters individually
        violations.extend(self._check_params(body_params, "body"))
        
        # 5. Check all_params (combined) - but avoid duplicates
        # Only check params that weren't already checked
        unchecked_params = {k: v for k, v in all_params.items() 
                           if k not in query_params and k not in body_params}
        violations.extend(self._check_params(unchecked_params, "param"))
        
        # 6. Check headers (especially User-Agent, Referer, etc.)
        suspicious_headers = ['user-agent', 'referer', 'x-forwarded-for', 'origin']
        for header_name in suspicious_headers:
            if header_name in headers:
                header_value = headers[header_name]
                if header_value:
                    header_bytes = str(header_value).encode('utf-8', errors='ignore')
                    violations.extend(self._check_payload(header_bytes, f"header.{header_name}"))
        
        # Remove duplicates (same type and location)
        seen = set()
        unique_violations = []
        for v in violations:
            key = (v.get('type'), v.get('location', ''))
            if key not in seen:
                seen.add(key)
                unique_violations.append(v)
        
        if unique_violations:
            logger.warning(f"WAF detected {len(unique_violations)} violation(s) in {method} {path}")
            for v in unique_violations:
                logger.warning(f"  - {v.get('type')}: {v.get('reason')} ({v.get('location', 'unknown')})")
            # Log request details for debugging false positives
            if query_params or body_params:
                logger.debug(f"  Request params: query={query_params}, body={body_params}")
        else:
            logger.debug(f"WAF allowed request: {method} {path}")
        
        return unique_violations
