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

@router.get("/shell", response_class=HTMLResponse)
async def shell_view(request: Request):
    """Enhanced shell interface - only accessible when IP is trapped"""
    from core.trap_tracker import trap_tracker
    
    client_ip = request.client.host
    
    # Check if IP is trapped
    if not trap_tracker.is_trapped(client_ip) and not trap_tracker.is_permanently_blocked(client_ip):
        # Not trapped - return 404 to appear as if endpoint doesn't exist
        return HTMLResponse(
            content="""
            <!DOCTYPE html>
            <html>
            <head><title>404 Not Found</title></head>
            <body>
                <h1>404 Not Found</h1>
                <p>The requested URL was not found on this server.</p>
            </body>
            </html>
            """,
            status_code=404
        )
    
    # IP is trapped - show shell interface
    return HTMLResponse(content="""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Shell - TechShop Server</title>
        <style>
            * {
                margin: 0;
                padding: 0;
                box-sizing: border-box;
            }
            
            body {
                background-color: #0c0c0c;
                color: #00ff00;
                font-family: 'Courier New', 'Consolas', monospace;
                font-size: 14px;
                line-height: 1.5;
                overflow: hidden;
            }
            
            #terminal-container {
                width: 100vw;
                height: 100vh;
                padding: 20px;
                overflow-y: auto;
            }
            
            #output {
                white-space: pre-wrap;
                word-wrap: break-word;
                margin-bottom: 10px;
            }
            
            .prompt-line {
                display: flex;
                align-items: center;
            }
            
            .prompt {
                color: #00ff00;
                margin-right: 5px;
                user-select: none;
            }
            
            #cmd {
                background: transparent;
                border: none;
                color: #00ff00;
                outline: none;
                flex: 1;
                font-family: inherit;
                font-size: inherit;
                caret-color: #00ff00;
            }
            
            .error {
                color: #ff5555;
            }
            
            .success {
                color: #50fa7b;
            }
            
            .info {
                color: #8be9fd;
            }
            
            /* Scrollbar styling */
            ::-webkit-scrollbar {
                width: 10px;
            }
            
            ::-webkit-scrollbar-track {
                background: #1a1a1a;
            }
            
            ::-webkit-scrollbar-thumb {
                background: #333;
                border-radius: 5px;
            }
            
            ::-webkit-scrollbar-thumb:hover {
                background: #555;
            }
        </style>
    </head>
    <body>
        <div id="terminal-container">
            <div id="output"></div>
            <div class="prompt-line">
                <span class="prompt" id="prompt">www-data@techshop-prod-01:~$ </span>
                <input type="text" id="cmd" autofocus autocomplete="off">
            </div>
        </div>
        
        <script>
            const cmdInput = document.getElementById('cmd');
            const outputDiv = document.getElementById('output');
            const promptSpan = document.getElementById('prompt');
            
            let commandHistory = [];
            let historyIndex = -1;
            let currentCommand = '';
            
            // Display welcome message
            outputDiv.innerHTML = `<span class="success">Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-91-generic x86_64)</span>

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

Last login: ${new Date().toLocaleString()} from 192.168.1.100

`;
            
            // Focus input when clicking anywhere
            document.addEventListener('click', () => cmdInput.focus());
            
            cmdInput.addEventListener('keydown', async function (e) {
                // Handle up/down arrow keys for command history
                if (e.key === 'ArrowUp') {
                    e.preventDefault();
                    if (commandHistory.length > 0) {
                        if (historyIndex === -1) {
                            currentCommand = cmdInput.value;
                            historyIndex = commandHistory.length - 1;
                        } else if (historyIndex > 0) {
                            historyIndex--;
                        }
                        cmdInput.value = commandHistory[historyIndex];
                    }
                    return;
                }
                
                if (e.key === 'ArrowDown') {
                    e.preventDefault();
                    if (historyIndex !== -1) {
                        if (historyIndex < commandHistory.length - 1) {
                            historyIndex++;
                            cmdInput.value = commandHistory[historyIndex];
                        } else {
                            historyIndex = -1;
                            cmdInput.value = currentCommand;
                        }
                    }
                    return;
                }
                
                // Handle Enter key
                if (e.key === 'Enter') {
                    const command = cmdInput.value.trim();
                    
                    // Display command with prompt
                    outputDiv.innerHTML += promptSpan.textContent + command + '\\n';
                    
                    if (command) {
                        // Add to history
                        commandHistory.push(command);
                        historyIndex = -1;
                        currentCommand = '';
                        
                        cmdInput.value = '';
                        
                        // Handle clear command locally
                        if (command === 'clear') {
                            outputDiv.innerHTML = '';
                            window.scrollTo(0, document.body.scrollHeight);
                            return;
                        }
                        
                        try {
                            // Send command to server
                            const response = await fetch('/api/shell', {
                                method: 'POST',
                                headers: {'Content-Type': 'application/json'},
                                body: JSON.stringify({command: command})
                            });
                            
                            const data = await response.json();
                            
                            // Display output
                            if (data.output) {
                                outputDiv.innerHTML += data.output + '\\n';
                            }
                            
                            // Update prompt if provided
                            if (data.prompt) {
                                promptSpan.textContent = data.prompt;
                            }
                        } catch (error) {
                            outputDiv.innerHTML += '<span class="error">Error: Connection failed</span>\\n';
                        }
                    } else {
                        cmdInput.value = '';
                    }
                    
                    // Scroll to bottom
                    window.scrollTo(0, document.body.scrollHeight);
                }
                
                // Handle Ctrl+C
                if (e.ctrlKey && e.key === 'c') {
                    e.preventDefault();
                    outputDiv.innerHTML += '^C\\n';
                    cmdInput.value = '';
                }
                
                // Handle Ctrl+L (clear)
                if (e.ctrlKey && e.key === 'l') {
                    e.preventDefault();
                    outputDiv.innerHTML = '';
                }
            });
            
            // Auto-focus on load
            cmdInput.focus();
        </script>
    </body>
    </html>
    """)

@router.post("/api/shell")
async def api_shell(request: Request, background_tasks: BackgroundTasks):
    """API endpoint for shell commands - only accessible when IP is trapped"""
    from core.fake_filesystem import get_filesystem
    from core.shell_processor import shell_processor
    from core.trap_tracker import trap_tracker
    import traceback
    
    client_ip = request.client.host
    
    try:
        # Check if IP is trapped
        if not trap_tracker.is_trapped(client_ip) and not trap_tracker.is_permanently_blocked(client_ip):
            return JSONResponse(
                content={"error": "Not found"},
                status_code=404
            )
        
        data = await request.json()
        command = data.get("command")
        
        # Get session info
        user_agent = request.headers.get("user-agent", "unknown")
        session = await session_manager.get_or_create_session(client_ip, user_agent)
        session_id = session["session_id"]
        
        # Process command through honeypot handler
        response = await handle_honeypot_request(request, background_tasks, command=command)
        
        # Get updated prompt
        fs = get_filesystem(session_id)
        prompt = shell_processor.get_prompt(fs)
        
        return {"output": response, "prompt": prompt}
    
    except Exception as e:
        log.error(f"Error in api_shell: {str(e)}")
        log.error(traceback.format_exc())
        return JSONResponse(
            content={"error": "Internal server error", "output": f"Error: {str(e)}"},
            status_code=500
        )

# Catch-all for other paths to simulate a full web server
@router.api_route("/{path_name:path}", methods=["GET", "POST", "PUT", "DELETE"])
async def catch_all(request: Request, path_name: str, background_tasks: BackgroundTasks):
    return await handle_honeypot_request(request, background_tasks)
