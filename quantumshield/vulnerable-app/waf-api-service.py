"""
WAF API Service for ShopVuln
Provides HTTP API endpoint for Next.js middleware to integrate with QuantumShield WAF
"""

import os
import sys
import json
import logging
import re
from typing import Dict, Any, Optional, List
from pathlib import Path
from datetime import datetime

# Add QuantumShield to path
current_dir = Path(__file__).parent
quantumshield_path = current_dir.parent / "quantumshield"
sys.path.insert(0, str(quantumshield_path.parent))

try:
    from quantumshield.application_layer.waf.waf_engine import WAFEngine
except ImportError as e:
    print(f"Warning: Could not import QuantumShield WAF. Error: {e}")
    print("Make sure QuantumShield is properly installed and path is correct.")
    WAFEngine = None

# Try to use Flask or FastAPI if available
try:
    from flask import Flask, request, jsonify
    from flask_cors import CORS
    FLASK_AVAILABLE = True
except ImportError:
    FLASK_AVAILABLE = False
    print("Flask not available. Install with: pip install flask flask-cors")

try:
    from fastapi import FastAPI, Request, HTTPException
    from fastapi.middleware.cors import CORSMiddleware
    from fastapi.responses import JSONResponse
    FASTAPI_AVAILABLE = True
except ImportError:
    FASTAPI_AVAILABLE = False
    print("FastAPI not available. Install with: pip install fastapi uvicorn")

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,  # Changed to DEBUG for better visibility
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Initialize WAF Engine
waf_engine: Optional[WAFEngine] = None


def initialize_waf(config: Dict[str, Any]) -> bool:
    """Initialize WAF engine with configuration."""
    global waf_engine
    
    if WAFEngine is None:
        logger.error("WAFEngine not available. Cannot initialize WAF.")
        return False
    
    try:
        # Get paths from config or use defaults
        rules_dir = config.get('rules_dir')
        data_files_dir = config.get('data_files_dir')
        geoip_db_path = config.get('geoip_db_path')
        reports_dir = config.get('reports_dir', './waf-reports')
        
        # Build WAF config
        waf_config = {
            'enabled': config.get('enabled', True),
            'rules_dir': rules_dir,
            'data_files_dir': data_files_dir,
            'geoip_db_path': geoip_db_path,
            'reports_dir': reports_dir,
            'block_on_violation': config.get('block_on_violation', True),
            'capture_request_response': config.get('capture_request_response', False)
        }
        
        waf_engine = WAFEngine(config=waf_config)
        logger.info("WAF Engine initialized successfully")
        return True
    except Exception as e:
        logger.error(f"Failed to initialize WAF engine: {e}", exc_info=True)
        return False


def detect_sql_injection(text: str) -> List[Dict[str, Any]]:
    """Detect SQL injection patterns in text."""
    violations = []
    
    if not text:
        return violations
    
    # SQL Injection patterns
    sql_patterns = [
        (r"(\bOR\b|\bAND\b)\s*\d+\s*=\s*\d+", "SQL Injection: OR/AND condition"),
        (r"(\bOR\b|\bAND\b)\s*['\"]?\d+['\"]?\s*=\s*['\"]?\d+['\"]?", "SQL Injection: OR/AND condition with quotes"),
        (r"(\bUNION\b.*\bSELECT\b)", "SQL Injection: UNION SELECT"),
        (r"(\bSELECT\b.*\bFROM\b)", "SQL Injection: SELECT FROM"),
        (r"(\bINSERT\b.*\bINTO\b)", "SQL Injection: INSERT INTO"),
        (r"(\bUPDATE\b.*\bSET\b)", "SQL Injection: UPDATE SET"),
        (r"(\bDELETE\b.*\bFROM\b)", "SQL Injection: DELETE FROM"),
        (r"(\bDROP\b.*\bTABLE\b)", "SQL Injection: DROP TABLE"),
        (r"(\bEXEC\b|\bEXECUTE\b)", "SQL Injection: EXEC/EXECUTE"),
        (r"(\bEXEC\s*\(|\bEXECUTE\s*\()", "SQL Injection: EXEC/EXECUTE with parentheses"),
        (r"(\bWAITFOR\b.*\bDELAY\b)", "SQL Injection: WAITFOR DELAY"),
        (r"(\bSLEEP\s*\()", "SQL Injection: SLEEP function"),
        (r"('|\")\s*OR\s*('|\")\s*=\s*('|\")", "SQL Injection: OR with quotes"),
        (r"('|\")\s*AND\s*('|\")\s*=\s*('|\")", "SQL Injection: AND with quotes"),
        (r"(--|\#|\/\*|\*\/)", "SQL Injection: Comment markers"),
        (r"(\bOR\b\s*['\"]?\d+['\"]?\s*OR\b)", "SQL Injection: Multiple OR"),
        (r"(\b1\s*=\s*1\b|\b'1'\s*=\s*'1'\b)", "SQL Injection: 1=1 condition"),
        (r"(\b1\s*=\s*2\b|\b'1'\s*=\s*'2'\b)", "SQL Injection: 1=2 condition"),
        (r"(\bCHAR\s*\(|\bCHR\s*\()", "SQL Injection: CHAR/CHR function"),
        (r"(\bCONCAT\s*\()", "SQL Injection: CONCAT function"),
        (r"(\bSUBSTRING\s*\(|\bSUBSTR\s*\()", "SQL Injection: SUBSTRING function"),
    ]
    
    text_lower = text.lower()
    
    for pattern, description in sql_patterns:
        if re.search(pattern, text_lower, re.IGNORECASE):
            violations.append({
                'type': 'sql_injection',
                'severity': 'critical',
                'reason': description,
                'rule_id': 'SQL_INJECTION_DETECTED',
                'pattern': pattern
            })
    
    return violations


def detect_xss(text: str) -> List[Dict[str, Any]]:
    """Detect XSS patterns in text."""
    violations = []
    
    if not text:
        return violations
    
    # XSS patterns
    xss_patterns = [
        (r"<script[^>]*>.*?</script>", "XSS: Script tag"),
        (r"javascript:", "XSS: JavaScript protocol"),
        (r"onerror\s*=", "XSS: onerror handler"),
        (r"onload\s*=", "XSS: onload handler"),
        (r"onclick\s*=", "XSS: onclick handler"),
        (r"<img[^>]*src[^>]*=.*x.*onerror", "XSS: Image with onerror"),
        (r"<svg[^>]*onload", "XSS: SVG with onload"),
        (r"<iframe[^>]*src", "XSS: iframe tag"),
        (r"eval\s*\(", "XSS: eval function"),
        (r"alert\s*\(", "XSS: alert function"),
        (r"document\.cookie", "XSS: document.cookie"),
        (r"document\.write", "XSS: document.write"),
    ]
    
    text_lower = text.lower()
    
    for pattern, description in xss_patterns:
        if re.search(pattern, text_lower, re.IGNORECASE):
            violations.append({
                'type': 'xss',
                'severity': 'high',
                'reason': description,
                'rule_id': 'XSS_DETECTED',
                'pattern': pattern
            })
    
    return violations


def detect_command_injection(text: str) -> List[Dict[str, Any]]:
    """Detect command injection patterns."""
    violations = []
    
    if not text:
        return violations
    
    # Command injection patterns
    cmd_patterns = [
        (r"[;&|`]\s*(ls|dir|cat|type|rm|del|mkdir|cd)", "Command Injection: Shell command"),
        (r"(ls|dir|cat|type|rm|del|mkdir|cd)\s*[;&|`]", "Command Injection: Shell command"),
        (r"\|\s*(ls|dir|cat|type|rm|del)", "Command Injection: Pipe to command"),
        (r"&&\s*(ls|dir|cat|type|rm|del)", "Command Injection: AND command"),
        (r";\s*(ls|dir|cat|type|rm|del)", "Command Injection: Semicolon command"),
        (r"`.*(ls|dir|cat|type|rm|del)", "Command Injection: Backtick command"),
        (r"\$\s*\(.*\)", "Command Injection: Command substitution"),
    ]
    
    text_lower = text.lower()
    
    for pattern, description in cmd_patterns:
        if re.search(pattern, text_lower, re.IGNORECASE):
            violations.append({
                'type': 'command_injection',
                'severity': 'critical',
                'reason': description,
                'rule_id': 'COMMAND_INJECTION_DETECTED',
                'pattern': pattern
            })
    
    return violations


def process_waf_request(request_data: Dict[str, Any]) -> Dict[str, Any]:
    """Process request through WAF."""
    if waf_engine is None:
        # Fallback: Use basic pattern matching if WAF engine not available
        violations = []
        
        # Check body
        body = request_data.get('body', '')
        if body:
            violations.extend(detect_sql_injection(body))
            violations.extend(detect_xss(body))
            violations.extend(detect_command_injection(body))
        
        # Check query parameters
        query_params = request_data.get('query_params', {})
        query_str = json.dumps(query_params)
        if query_str:
            violations.extend(detect_sql_injection(query_str))
            violations.extend(detect_xss(query_str))
            violations.extend(detect_command_injection(query_str))
        
        # Check body parameters
        body_params = request_data.get('body_params', {})
        body_str = json.dumps(body_params)
        if body_str:
            violations.extend(detect_sql_injection(body_str))
            violations.extend(detect_xss(body_str))
            violations.extend(detect_command_injection(body_str))
        
        # Check URI
        uri = request_data.get('uri', '')
        if uri:
            violations.extend(detect_sql_injection(uri))
            violations.extend(detect_xss(uri))
        
        if violations:
            return {
                'allowed': False,
                'violations': violations,
                'action': 'block',
                'reason': f'{len(violations)} violation(s) detected'
            }
        
        return {
            'allowed': True,
            'violations': [],
            'action': 'allow',
            'reason': 'WAF engine not initialized - using basic pattern matching',
            'warning': 'WAF not fully available - running in basic mode'
        }
    
    try:
        result = waf_engine.process_request(request_data)
        
        # Add additional pattern matching if WAF didn't catch it
        if result.get('allowed', True):
            violations = []
            
            # Check body
            body = request_data.get('body', '')
            if body:
                violations.extend(detect_sql_injection(body))
                violations.extend(detect_xss(body))
                violations.extend(detect_command_injection(body))
            
            # Check query parameters
            query_params = request_data.get('query_params', {})
            query_str = json.dumps(query_params)
            if query_str:
                violations.extend(detect_sql_injection(query_str))
                violations.extend(detect_xss(query_str))
                violations.extend(detect_command_injection(query_str))
            
            # Check body parameters
            body_params = request_data.get('body_params', {})
            body_str = json.dumps(body_params)
            if body_str:
                violations.extend(detect_sql_injection(body_str))
                violations.extend(detect_xss(body_str))
                violations.extend(detect_command_injection(body_str))
            
            # Check all parameters (combined)
            all_params = request_data.get('all_params', {})
            all_params_str = json.dumps(all_params)
            if all_params_str:
                violations.extend(detect_sql_injection(all_params_str))
                violations.extend(detect_xss(all_params_str))
                violations.extend(detect_command_injection(all_params_str))
            
            # Also check individual parameter values
            for key, value in all_params.items():
                if isinstance(value, str) and value:
                    violations.extend(detect_sql_injection(value))
                    violations.extend(detect_xss(value))
                    violations.extend(detect_command_injection(value))
            
            # Check URI
            uri = request_data.get('uri', '')
            if uri:
                violations.extend(detect_sql_injection(uri))
                violations.extend(detect_xss(uri))
            
            if violations:
                result['allowed'] = False
                result['violations'] = violations
                result['action'] = 'block'
                result['reason'] = f'{len(violations)} violation(s) detected'
        
        return result
    except Exception as e:
        logger.error(f"Error processing WAF request: {e}", exc_info=True)
        # Fallback to basic pattern matching on error
        violations = []
        
        body = request_data.get('body', '')
        if body:
            violations.extend(detect_sql_injection(body))
            violations.extend(detect_xss(body))
            violations.extend(detect_command_injection(body))
        
        query_params = request_data.get('query_params', {})
        query_str = json.dumps(query_params)
        if query_str:
            violations.extend(detect_sql_injection(query_str))
            violations.extend(detect_xss(query_str))
        
        body_params = request_data.get('body_params', {})
        body_str = json.dumps(body_params)
        if body_str:
            violations.extend(detect_sql_injection(body_str))
            violations.extend(detect_xss(body_str))
        
        if violations:
            return {
                'allowed': False,
                'violations': violations,
                'action': 'block',
                'reason': f'{len(violations)} violation(s) detected (fallback mode)'
            }
        
        return {
            'allowed': True,
            'violations': [],
            'action': 'allow',
            'reason': f'WAF processing error: {str(e)}',
            'error': True
        }


# Initialize from environment variables
def load_config_from_env() -> Dict[str, Any]:
    """Load configuration from environment variables."""
    current_dir = Path(__file__).parent
    quantumshield_path = current_dir.parent / "quantumshield"
    
    config = {
        'enabled': os.getenv('WAF_ENABLED', 'false').lower() == 'true',
        'rules_dir': os.getenv('WAF_RULES_DIR', str(quantumshield_path / 'application_layer' / 'waf' / 'rules')),
        'data_files_dir': os.getenv('WAF_DATA_FILES_DIR', str(quantumshield_path / 'application_layer' / 'waf' / 'data_files')),
        'geoip_db_path': os.getenv('GEOIP_DB_PATH'),
        'reports_dir': os.getenv('WAF_REPORTS_DIR', './waf-reports'),
        'block_on_violation': os.getenv('WAF_BLOCK_ON_VIOLATION', 'true').lower() == 'true',
        'capture_request_response': os.getenv('WAF_CAPTURE_REQUEST_RESPONSE', 'false').lower() == 'true'
    }
    
    return config


# Initialize WAF
config = load_config_from_env()
if config['enabled']:
    initialize_waf(config)
else:
    logger.info("WAF is disabled in configuration")


# Create API application
if FASTAPI_AVAILABLE:
    app = FastAPI(title="ShopVuln WAF API Service", version="1.0.0")
    
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],  # In production, specify allowed origins
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    
    @app.post("/api/waf/process")
    async def process_request(request: Request):
        """Process HTTP request through WAF."""
        try:
            body = await request.json()
            
            # Extract source IP from headers
            src_ip = (
                request.headers.get('x-forwarded-for', '').split(',')[0].strip() or
                request.headers.get('x-real-ip') or
                request.client.host if hasattr(request.client, 'host') else '127.0.0.1'
            )
            
            # Build request data
            request_data = {
                'method': body.get('method', 'GET'),
                'uri': body.get('uri', ''),
                'headers': body.get('headers', {}),
                'body': body.get('body', ''),
                'query_params': body.get('query_params', {}),
                'body_params': body.get('body_params', {}),
                'src_ip': src_ip,
                'timestamp': datetime.utcnow().isoformat()
            }
            
            # Log request for debugging
            logger.info(f"Processing WAF request: {request_data.get('method')} {request_data.get('uri')}")
            logger.debug(f"Request data: {json.dumps(request_data, indent=2)}")
            
            # Process through WAF
            result = process_waf_request(request_data)
            
            # Log result
            if not result.get('allowed', True):
                logger.warning(f"Request blocked: {result.get('reason')} - Violations: {len(result.get('violations', []))}")
                for violation in result.get('violations', []):
                    logger.warning(f"  - {violation.get('type')}: {violation.get('reason')}")
            else:
                logger.debug(f"Request allowed: {result.get('reason')}")
            
            return JSONResponse(content=result)
            
        except Exception as e:
            logger.error(f"Error in process_request endpoint: {e}", exc_info=True)
            raise HTTPException(status_code=500, detail=str(e))
    
    @app.get("/health")
    async def health_check():
        """Health check endpoint."""
        return {
            'status': 'healthy',
            'waf_enabled': waf_engine is not None,
            'timestamp': datetime.utcnow().isoformat()
        }
    
    @app.get("/")
    async def root():
        """Root endpoint."""
        return {
            'service': 'ShopVuln WAF API Service',
            'version': '1.0.0',
            'waf_status': 'enabled' if waf_engine else 'disabled'
        }

elif FLASK_AVAILABLE:
    app = Flask(__name__)
    CORS(app)
    
    @app.route('/api/waf/process', methods=['POST'])
    def process_request():
        """Process HTTP request through WAF."""
        try:
            body = request.json
            
            # Extract source IP
            src_ip = (
                request.headers.get('X-Forwarded-For', '').split(',')[0].strip() or
                request.headers.get('X-Real-IP') or
                request.remote_addr or '127.0.0.1'
            )
            
            # Build request data
            request_data = {
                'method': body.get('method', 'GET'),
                'uri': body.get('uri', ''),
                'headers': body.get('headers', {}),
                'body': body.get('body', ''),
                'query_params': body.get('query_params', {}),
                'body_params': body.get('body_params', {}),
                'src_ip': src_ip,
                'timestamp': datetime.utcnow().isoformat()
            }
            
            # Process through WAF
            result = process_waf_request(request_data)
            
            return jsonify(result)
            
        except Exception as e:
            logger.error(f"Error in process_request endpoint: {e}", exc_info=True)
            return jsonify({'error': str(e)}), 500
    
    @app.route('/health', methods=['GET'])
    def health_check():
        """Health check endpoint."""
        return jsonify({
            'status': 'healthy',
            'waf_enabled': waf_engine is not None,
            'timestamp': datetime.utcnow().isoformat()
        })
    
    @app.route('/', methods=['GET'])
    def root():
        """Root endpoint."""
        return jsonify({
            'service': 'ShopVuln WAF API Service',
            'version': '1.0.0',
            'waf_status': 'enabled' if waf_engine else 'disabled'
        })

else:
    # Fallback: Simple HTTP server
    from http.server import HTTPServer, BaseHTTPRequestHandler
    import urllib.parse
    
    class WAFHandler(BaseHTTPRequestHandler):
        def do_POST(self):
            if self.path == '/api/waf/process':
                content_length = int(self.headers['Content-Length'])
                body = self.rfile.read(content_length)
                request_data = json.loads(body.decode('utf-8'))
                
                # Extract source IP
                src_ip = (
                    self.headers.get('X-Forwarded-For', '').split(',')[0].strip() or
                    self.headers.get('X-Real-IP') or
                    self.client_address[0] if self.client_address else '127.0.0.1'
                )
                
                # Build request data
                waf_request = {
                    'method': request_data.get('method', 'GET'),
                    'uri': request_data.get('uri', ''),
                    'headers': request_data.get('headers', {}),
                    'body': request_data.get('body', ''),
                    'query_params': request_data.get('query_params', {}),
                    'body_params': request_data.get('body_params', {}),
                    'src_ip': src_ip,
                    'timestamp': datetime.utcnow().isoformat()
                }
                
                result = process_waf_request(waf_request)
                
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Access-Control-Allow-Origin', '*')
                self.end_headers()
                self.wfile.write(json.dumps(result).encode('utf-8'))
            else:
                self.send_response(404)
                self.end_headers()
        
        def do_GET(self):
            if self.path == '/health':
                response = {
                    'status': 'healthy',
                    'waf_enabled': waf_engine is not None,
                    'timestamp': datetime.utcnow().isoformat()
                }
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps(response).encode('utf-8'))
            else:
                self.send_response(404)
                self.end_headers()
        
        def log_message(self, format, *args):
            logger.info(f"{self.address_string()} - {format % args}")
    
    app = None  # Not a WSGI app, will use HTTPServer


if __name__ == '__main__':
    import argparse
    
    parser = argparse.ArgumentParser(description='ShopVuln WAF API Service')
    parser.add_argument('--host', default='127.0.0.1', help='Host to bind to')
    parser.add_argument('--port', type=int, default=8000, help='Port to bind to')
    parser.add_argument('--reload', action='store_true', help='Enable auto-reload (FastAPI only)')
    args = parser.parse_args()
    
    if FASTAPI_AVAILABLE:
        import uvicorn
        uvicorn.run(app, host=args.host, port=args.port, reload=args.reload)
    elif FLASK_AVAILABLE:
        app.run(host=args.host, port=args.port, debug=True)
    else:
        server = HTTPServer((args.host, args.port), WAFHandler)
        logger.info(f"Starting WAF API Service on http://{args.host}:{args.port}")
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            logger.info("Shutting down WAF API Service")
            server.shutdown()
