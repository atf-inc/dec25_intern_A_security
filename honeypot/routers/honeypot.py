"""
Honeypot Router - Handles trapped attacker requests

All requests routed here are from detected attackers.
Responses are generated using LLM + TechShop templates for convincing deception.
"""

from fastapi import APIRouter, Request, BackgroundTasks, Response
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse
from core.session import session_manager
from core.deception import deception_engine
from core.logger import logger
import logging
import time
from typing import Optional, Dict, Any

log = logging.getLogger("honeypot_router")

router = APIRouter()


async def handle_honeypot_request(
    request: Request, 
    background_tasks: BackgroundTasks, 
    command: str = None,
    ml_verdict: str = None,
    ml_confidence: float = None,
    # New metadata parameters
    http_method: Optional[str] = None,
    path: Optional[str] = None,
    query_params: Optional[Dict[str, Any]] = None,
    headers: Optional[Dict[str, str]] = None,
    body_size: Optional[int] = None
):
    """
    Handle a request from a trapped attacker.
    
    Generates a deceptive response using LLM + TechShop templates.
    """
    client_ip = request.client.host
    user_agent = request.headers.get("user-agent", "unknown")
    
    # Get or create session
    session = await session_manager.get_or_create_session(client_ip, user_agent)
    session_id = session["session_id"]
    context = session["context"]
    
    # Add session_id to context for use in responses
    context["session_id"] = session_id

    # Build user input from request
    if command:
        user_input = command
    else:
        # Include method, path, query params, and body
        req_path = str(request.url.path)
        query = str(request.query_params) if request.query_params else ""
        
        user_input = f"{request.method} {req_path}"
        if query:
            user_input += f"?{query}"
        
        body = await request.body()
        if body:
            user_input += f"\nBody: {body.decode('utf-8', errors='replace')}"

    log.info(f"[HONEYPOT] Processing request from {client_ip}: {user_input[:80]}...")

    # Track response time for LLM generation
    start_time = time.time()
    
    # Generate deceptive response (now uses templates!)
    response_text = await deception_engine.process_input(context, user_input)
    
    # Calculate response time in milliseconds
    response_time_ms = (time.time() - start_time) * 1000

    # Log interaction with ML data and metadata in background
    background_tasks.add_task(
        logger.log_interaction, 
        session_id, 
        client_ip, 
        "http_request" if not command else "command", 
        user_input, 
        response_text[:500],  # Truncate for logging
        ml_verdict,
        ml_confidence,
        # New metadata fields
        http_method=http_method,
        path=path,
        query_params=query_params,
        headers=headers,
        body_size=body_size,
        response_time_ms=response_time_ms
    )
    
    # Update session history
    await session_manager.add_history(session_id, user_input, response_text[:200])

    return response_text

@router.get("/admin/login", response_class=HTMLResponse)
async def admin_login(request: Request, background_tasks: BackgroundTasks):
    # We can pre-seed a fake login page or ask LLM to generate one
    # For now, let's ask the LLM to generate a login page
    return await handle_honeypot_request(request, background_tasks, command="Show me the admin login page HTML")

@router.post("/admin/login", response_class=HTMLResponse)
async def admin_login_post(request: Request, background_tasks: BackgroundTasks):
    return await handle_honeypot_request(request, background_tasks)

@router.get("/terminal", response_class=HTMLResponse)
async def terminal_view(request: Request):
    # A simple web terminal UI that sends commands to /api/terminal
    return """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Terminal</title>
        <style>
            body { background-color: #000; color: #0f0; font-family: monospace; }
            #output { white-space: pre-wrap; }
            input { background: transparent; border: none; color: #0f0; outline: none; width: 80%; }
        </style>
    </head>
    <body>
        <div id="output">Welcome to Ubuntu 22.04 LTS (GNU/Linux 5.15.0-91-generic x86_64)<br></div>
        <span>$ </span><input type="text" id="cmd" autofocus>
        <script>
            const cmdInput = document.getElementById('cmd');
            const outputDiv = document.getElementById('output');
            
            cmdInput.addEventListener('keypress', async function (e) {
                if (e.key === 'Enter') {
                    const command = cmdInput.value;
                    outputDiv.innerHTML += '$ ' + command + '<br>';
                    cmdInput.value = '';
                    
                    const response = await fetch('/api/terminal', {
                        method: 'POST',
                        headers: {'Content-Type': 'application/json'},
                        body: JSON.stringify({command: command})
                    });
                    const data = await response.json();
                    outputDiv.innerHTML += data.output + '<br>';
                    window.scrollTo(0, document.body.scrollHeight);
                }
            });
        </script>
    </body>
    </html>
    """

@router.post("/api/terminal")
async def api_terminal(request: Request, background_tasks: BackgroundTasks):
    data = await request.json()
    command = data.get("command")
    response = await handle_honeypot_request(request, background_tasks, command=command)
    return {"output": response}

# Catch-all for other paths to simulate a full web server
@router.api_route("/{path_name:path}", methods=["GET", "POST", "PUT", "DELETE"])

# Share the formatting logic (or move it to a util, but for now we keep it simple)
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
    """
    import uuid
    import json
    
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
