"""
Honeypot Router - Handles trapped attacker requests

All requests routed here are from detected attackers.
Responses are generated using LLM + TechShop templates for convincing deception.
"""

from fastapi import APIRouter, Request, BackgroundTasks
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse
from core.session import session_manager
from core.deception import deception_engine
from core.logger import logger
import logging

log = logging.getLogger("honeypot_router")

router = APIRouter()


async def handle_honeypot_request(request: Request, background_tasks: BackgroundTasks, command: str = None):
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
        path = str(request.url.path)
        query = str(request.query_params) if request.query_params else ""
        
        user_input = f"{request.method} {path}"
        if query:
            user_input += f"?{query}"
        
        body = await request.body()
        if body:
            user_input += f"\nBody: {body.decode('utf-8', errors='replace')}"

    log.info(f"[HONEYPOT] Processing request from {client_ip}: {user_input[:80]}...")

    # Generate deceptive response (now uses templates!)
    response_text = await deception_engine.process_input(context, user_input)

    # Log interaction in background
    background_tasks.add_task(
        logger.log_interaction, 
        session_id, 
        client_ip, 
        "http_request" if not command else "command", 
        user_input, 
        response_text[:500]  # Truncate for logging
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
async def catch_all(request: Request, path_name: str, background_tasks: BackgroundTasks):
    return await handle_honeypot_request(request, background_tasks)
