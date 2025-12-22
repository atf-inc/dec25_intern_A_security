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

# NOTE: Original Gateway Proxy Logic removed as QuantumShield now handles this.
# This service now acts purely as:
# 1. Deception Backend (Honeypot) - Receives redirected attacks
# 2. Analytics Backend - Serves dashboard data

@app.api_route("/{path_name:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"])
async def catch_all_honeypot(request: Request, path_name: str, background_tasks: BackgroundTasks):
    """
    Catch-all route for the Honeypot Service.
    
    If a request reaches here, it has likely been:
    1. Redirected by QuantumShield (Attack)
    2. Directly accessed (Checking honeypot)
    3. Analytics API call (handled by included router above)
    """
    client_ip = request.client.host
    method = request.method
    
    # Extract WAF Verdict from headers if available (added by QuantumShield)
    waf_verdict = request.headers.get("X-WAF-Verdict", "SUSPICIOUS")
    waf_confidence = float(request.headers.get("X-WAF-Confidence", "0.5"))
    original_client_ip = request.headers.get("X-Attacker-IP", client_ip)
    
    logger.info(f"[HONEYPOT] Processing request to /{path_name} from {original_client_ip} (Verdict: {waf_verdict})")
    
    # Helper to patch request body for honeypot handler if needed
    body_bytes = await request.body()
    async def receive():
        return {"type": "http.request", "body": body_bytes}
    request._receive = receive
    
    # Delegate to Honeypot Router logic
    response_content = await honeypot.handle_honeypot_request(
        request, 
        background_tasks,
        ml_verdict=waf_verdict,
        ml_confidence=waf_confidence
    )
    
    return honeypot._format_honeypot_response(response_content, path_name, request)


if __name__ == "__main__":
    import uvicorn
    # Changed port to 8001 to avoid conflict with QuantumShield (8000)
    uvicorn.run("main:app", host="0.0.0.0", port=8001, reload=True)
