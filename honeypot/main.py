from fastapi import FastAPI, Request, BackgroundTasks, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse, Response, StreamingResponse
from contextlib import asynccontextmanager
import httpx
import json
from core.database import db
from core.firewall import firewall_model
from core.email_notifier import email_notifier
from core.slack_notifier import slack_notifier
from core.trap_tracker import trap_tracker
from routers import analytics, honeypot, chat
from config import settings
import logging
import os

# Configure Logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("proxy")

UPSTREAM_URL = os.getenv("UPSTREAM_URL", "http://127.0.0.1:3000")

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    await db.connect()
    # Ensure model is trained
    if not firewall_model.is_trained:
        firewall_model._train_model()
    yield
    # Shutdown
    await db.close()

app = FastAPI(title="QuantumShield Firewall Proxy", lifespan=lifespan)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://localhost:3001"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include Analytics Router (So Dashboard still works)
app.include_router(analytics.router)

# Include Chat Router for NLP-powered queries
app.include_router(chat.router)


# ============================================================================
# DEBUG ENDPOINTS - For testing trap functionality
# These are defined BEFORE the catch-all route so they get matched first
# ============================================================================

@app.get("/debug/trap-status", response_class=HTMLResponse)
async def debug_trap_status(request: Request):
    """Show trap status for the current IP and provide controls."""
    client_ip = request.client.host
    trap_info = trap_tracker.get_trap_info(client_ip)
    all_traps = trap_tracker.get_all_traps()
    
    if trap_info:
        status_html = f"""
        <div style="background: #ffcccc; padding: 15px; border-radius: 8px; margin-bottom: 20px;">
            <h3 style="color: #cc0000; margin: 0;">TRAPPED</h3>
            <p><strong>Since:</strong> {trap_info['trapped_at_human']}</p>
            <p><strong>Duration:</strong> {trap_info['elapsed_seconds']} seconds</p>
            <p><strong>Expires in:</strong> {trap_info['remaining_seconds']} seconds</p>
            <p><strong>Reason:</strong> {trap_info['reason']}</p>
            <p><strong>Requests while trapped:</strong> {trap_info['request_count']}</p>
            <p><strong>Original payload:</strong> <code>{trap_info['attack_payload'][:100]}...</code></p>
        </div>
        """
    else:
        status_html = """
        <div style="background: #ccffcc; padding: 15px; border-radius: 8px; margin-bottom: 20px;">
            <h3 style="color: #00cc00; margin: 0;">NOT TRAPPED</h3>
            <p>Your IP is not currently in the trap list.</p>
        </div>
        """
    
    # List all trapped IPs
    traps_list = ""
    if all_traps:
        traps_list = "<ul>"
        for ip, info in all_traps.items():
            traps_list += f"<li><strong>{ip}</strong> - {info['reason']} ({info['elapsed_seconds']}s ago)</li>"
        traps_list += "</ul>"
    else:
        traps_list = "<p><em>No IPs currently trapped.</em></p>"
    
    return f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Trap Status - Debug</title>
        <style>
            body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; 
                   max-width: 800px; margin: 50px auto; padding: 20px; background: #1a1a2e; color: #eee; }}
            h1 {{ color: #00d4ff; }}
            h2 {{ color: #ff6b6b; border-bottom: 1px solid #333; padding-bottom: 10px; }}
            code {{ background: #333; padding: 2px 6px; border-radius: 4px; }}
            button {{ background: #ff6b6b; color: white; border: none; padding: 10px 20px; 
                     border-radius: 5px; cursor: pointer; font-size: 16px; margin: 5px; }}
            button:hover {{ background: #ff4757; }}
            .clear-btn {{ background: #ffa502; }}
            .clear-btn:hover {{ background: #ff7f00; }}
        </style>
    </head>
    <body>
        <h1>Trap Status Debug Panel</h1>
        
        <h2>Your IP: {client_ip}</h2>
        {status_html}
        
        <form action="/debug/clear-trap" method="post" style="display: inline;">
            <button type="submit">Clear My Trap</button>
        </form>
        <form action="/debug/clear-all-traps" method="post" style="display: inline;">
            <button type="submit" class="clear-btn">Clear All Traps</button>
        </form>
        
        <h2>All Trapped IPs ({len(all_traps)})</h2>
        {traps_list}
        
        <hr style="border-color: #333; margin: 30px 0;">
        <p style="color: #888;">
            <strong>How it works:</strong> When the ML firewall detects an attack, 
            the attacker's IP is added to the trap list. All subsequent requests from 
            that IP go directly to the honeypot, regardless of content.
        </p>
        <p style="color: #888;">
            <a href="/" style="color: #00d4ff;">Back to main site</a>
        </p>
    </body>
    </html>
    """


@app.post("/debug/clear-trap")
async def debug_clear_trap(request: Request):
    """Clear trap for the current IP."""
    client_ip = request.client.host
    cleared = trap_tracker.clear_trap(client_ip)
    
    if cleared:
        return HTMLResponse(f"""
        <html><body style="font-family: sans-serif; text-align: center; padding: 50px; background: #1a1a2e; color: #eee;">
            <h1 style="color: #00ff00;">Trap Cleared!</h1>
            <p>Your IP ({client_ip}) has been removed from the trap list.</p>
            <a href="/debug/trap-status" style="color: #00d4ff;">Back to status</a>
        </body></html>
        """)
    else:
        return HTMLResponse(f"""
        <html><body style="font-family: sans-serif; text-align: center; padding: 50px; background: #1a1a2e; color: #eee;">
            <h1 style="color: #ffcc00;">Not Trapped</h1>
            <p>Your IP ({client_ip}) was not in the trap list.</p>
            <a href="/debug/trap-status" style="color: #00d4ff;">Back to status</a>
        </body></html>
        """)


@app.post("/debug/clear-all-traps")
async def debug_clear_all_traps(request: Request):
    """Clear all trapped IPs."""
    # Security: Only allow from localhost
    client_ip = request.client.host
    if client_ip not in ["127.0.0.1", "::1", "localhost"]:
        raise HTTPException(status_code=403, detail="Only allowed from localhost")
    
    count = trap_tracker.clear_all_traps()
    
    return HTMLResponse(f"""
    <html><body style="font-family: sans-serif; text-align: center; padding: 50px; background: #1a1a2e; color: #eee;">
        <h1 style="color: #00ff00;">All Traps Cleared!</h1>
        <p>Cleared {count} trapped IP(s).</p>
        <a href="/debug/trap-status" style="color: #00d4ff;">Back to status</a>
    </body></html>
    """)


# ============================================================================
# MAIN GATEWAY - Catches all other requests
# ============================================================================

@app.api_route("/{path_name:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"])
async def gateway_proxy(request: Request, path_name: str, background_tasks: BackgroundTasks):
    """
    Main Gateway Logic:
    1. Check if IP is already trapped (session-based trapping)
    2. Extract Request Data and check ML Firewall with confidence scoring
    3. Route to Honeypot (trapped/malicious) or Upstream (safe)
    4. Send email and Slack alerts for MALICIOUS attacks
    """
    client_ip = request.client.host
    
    # 1. Extract Data for Analysis
    method = request.method
    query_params = str(request.query_params)
    
    # Read body (keep available for forwarding)
    body_bytes = await request.body()
    body_str = body_bytes.decode('utf-8', errors='replace')
    
    # Combine inputs for analysis
    analysis_text = f"{method} /{path_name}?{query_params}\n{body_str}"
    
    # Extract request metadata for logging
    request_metadata = {
        "http_method": method,
        "path": f"/{path_name}",
        "query_params": dict(request.query_params),
        "headers": {
            "user_agent": request.headers.get("user-agent", ""),
            "referer": request.headers.get("referer", ""),
            "content_type": request.headers.get("content-type", ""),
            "origin": request.headers.get("origin", ""),
            "x_forwarded_for": request.headers.get("x-forwarded-for", ""),
        },
        "body_size": len(body_bytes),
    }
    
    # Helper to patch request body for honeypot handler
    async def patch_request_body():
        async def receive():
            return {"type": "http.request", "body": body_bytes}
        request._receive = receive
    
    # ========================================================================
    # 2. CHECK IF ALREADY TRAPPED (Session-based trapping)
    # ========================================================================
    if trap_tracker.is_trapped(client_ip):
        trap_info = trap_tracker.get_trap_info(client_ip)
        logger.warning(f"[TRAPPED SESSION] {client_ip} - Request #{trap_info['request_count']} while trapped")
        
        await patch_request_body()
        response_content = await honeypot.handle_honeypot_request(
            request, 
            background_tasks,
            **request_metadata
        )
        return _format_honeypot_response(response_content, path_name, request)
    
    # ========================================================================
    # 3. FIREWALL CHECK (ML + Heuristics with confidence scoring)
    # ========================================================================
    ml_result = firewall_model.predict_with_confidence(analysis_text)
    ml_verdict = ml_result["verdict"]
    ml_confidence = ml_result["confidence"]
    
    # ========================================================================
    # 3a. MALICIOUS - Block immediately (high confidence attacks)
    # ========================================================================
    if ml_verdict == "MALICIOUS":
        logger.warning(f"[BLOCKED] {client_ip} - MALICIOUS attack on /{path_name} (confidence: {ml_confidence:.2f})")
        
        # Send email and Slack alerts for MALICIOUS attacks
        background_tasks.add_task(
            email_notifier.send_attack_alert,
            ip=client_ip,
            method=method,
            path=path_name,
            ml_verdict=ml_verdict,
            ml_confidence=ml_confidence,
            payload=body_str[:500]
        )
        background_tasks.add_task(
            slack_notifier.send_attack_alert,
            ip=client_ip,
            method=method,
            path=path_name,
            ml_verdict=ml_verdict,
            ml_confidence=ml_confidence,
            payload=body_str[:500]
        )
        
        return _block_malicious_request(request, client_ip, path_name, ml_confidence)
    
    # ========================================================================
    # 3b. SUSPICIOUS - Route to honeypot for deception and intelligence
    # ========================================================================
    if ml_verdict == "SUSPICIOUS":
        # TRAP THIS IP for future requests
        trap_tracker.trap_session(
            ip=client_ip,
            reason=f"SUSPICIOUS activity detected on /{path_name} (confidence: {ml_confidence:.2f})",
            attack_payload=analysis_text
        )
        
        logger.warning(f"[HONEYPOT] {client_ip} trapped - SUSPICIOUS on /{path_name} (confidence: {ml_confidence:.2f})")
        
        await patch_request_body()
        response_content = await honeypot.handle_honeypot_request(
            request, 
            background_tasks,
            ml_verdict=ml_verdict,
            ml_confidence=ml_confidence,
            **request_metadata
        )
        return _format_honeypot_response(response_content, path_name, request)
    
    # ========================================================================
    # 4. SAFE - Forward to Upstream
    # ========================================================================
    logger.info(f"[SAFE] Forwarding to {UPSTREAM_URL}/{path_name}")
    
    client = httpx.AsyncClient(base_url=UPSTREAM_URL)
    try:
        upstream_req = client.build_request(
            method,
            f"/{path_name}",
            content=body_bytes,
            params=request.query_params,
            headers=request.headers.raw,
            timeout=10.0
        )
        
        upstream_response = await client.send(upstream_req)
        content = upstream_response.content
        
        # Remove compression headers
        headers = dict(upstream_response.headers)
        headers.pop("content-encoding", None)
        headers.pop("content-length", None)
        headers.pop("transfer-encoding", None)
        
        return Response(
            content=content,
            status_code=upstream_response.status_code,
            headers=headers,
            media_type=upstream_response.headers.get("content-type")
        )
    except Exception as e:
        logger.error(f"Upstream error: {str(e)}")
        return JSONResponse({"error": "Upstream unavailable"}, status_code=503)
    finally:
        await client.aclose()


def _block_malicious_request(request: Request, client_ip: str, path_name: str, confidence: float) -> Response:
    """
    Block a malicious request with a 403 Forbidden response.
    
    MALICIOUS attacks (high confidence) are blocked immediately without deception.
    This saves resources and clearly denies access to confirmed attackers.
    """
    import uuid
    import datetime
    
    # Check what format the client expects
    wants_json = _wants_json(request)
    
    if wants_json:
        return JSONResponse(
            content={
                "success": False,
                "error": "Forbidden",
                "message": "Access denied. Your request has been blocked and logged.",
                "request_id": f"BLK-{uuid.uuid4().hex[:8]}",
                "timestamp": datetime.datetime.utcnow().isoformat() + "Z"
            },
            status_code=403,
            headers={"X-Request-ID": str(uuid.uuid4())[:8]}
        )
    
    # HTML response for browsers
    return HTMLResponse(
        content=f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>403 Forbidden</title>
            <style>
                body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
                       background: #1a1a2e; color: #eee; text-align: center; padding: 50px; }}
                h1 {{ color: #ff6b6b; font-size: 48px; margin-bottom: 10px; }}
                p {{ color: #888; font-size: 18px; }}
                .code {{ font-family: monospace; background: #333; padding: 2px 8px; border-radius: 4px; }}
            </style>
        </head>
        <body>
            <h1>403</h1>
            <p>Access Denied</p>
            <p>Your request has been blocked and logged.</p>
            <p class="code">Request ID: BLK-{uuid.uuid4().hex[:8]}</p>
        </body>
        </html>
        """,
        status_code=403,
        headers={"X-Request-ID": str(uuid.uuid4())[:8]}
    )


def _wants_json(request: Request) -> bool:
    """
    Check if the client expects JSON response.
    This makes honeypot responses format-aware for more realistic deception.
    """
    accept = request.headers.get("accept", "")
    content_type = request.headers.get("content-type", "")
    user_agent = request.headers.get("user-agent", "").lower()
    
    # Explicit JSON preference
    if "application/json" in accept:
        return True
    
    # Sending JSON body usually expects JSON response
    if "application/json" in content_type:
        return True
    
    # Common API testing tools
    api_tools = ["postman", "insomnia", "httpie", "curl", "python-requests", "axios"]
    if any(tool in user_agent for tool in api_tools):
        return True
    
    return False


def _format_honeypot_response(response_content: str, path_name: str, request: Request) -> Response:
    """
    Format the honeypot response based on what the client expects.
    
    - API tools (Postman, curl) → JSON response
    - Browsers → HTML response
    
    This makes the honeypot more realistic and harder to detect.
    """
    import uuid
    
    if not response_content:
        return Response(content="", media_type="text/plain")
    
    # Check what format the client expects
    wants_json = _wants_json(request)
    is_api_path = path_name.startswith("api/") or "/api/" in path_name
    is_html = "<html" in response_content.lower() or "<!doctype" in response_content.lower()
    
    # API tools expect JSON - give them realistic API error response
    if wants_json or (is_api_path and not is_html):
        # Try to parse existing JSON response
        try:
            parsed = json.loads(response_content)
            return JSONResponse(
                content=parsed, 
                headers={"X-Request-ID": str(uuid.uuid4())[:8]}
            )
        except (json.JSONDecodeError, TypeError):
            pass
        
        # Generate realistic API error response
        return JSONResponse(
            content={
                "success": False,
                "error": "Forbidden",
                "message": "Access denied. Your request has been logged.",
                "request_id": f"TK-{uuid.uuid4().hex[:8]}",
                "timestamp": __import__('datetime').datetime.utcnow().isoformat() + "Z"
            },
            status_code=403,
            headers={"X-Request-ID": str(uuid.uuid4())[:8]}
        )
    
    # Browsers get HTML for visual deception
    if is_html:
        return Response(
            content=response_content,
            media_type="text/html",
            headers={"X-Request-ID": str(uuid.uuid4())[:8]}
        )
    
    # Fallback to plain text
    return Response(
        content=response_content,
        media_type="text/plain",
        headers={"X-Request-ID": str(uuid.uuid4())[:8]}
    )


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
