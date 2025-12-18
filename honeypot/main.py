from fastapi import FastAPI, Request, BackgroundTasks, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse, Response, StreamingResponse
from contextlib import asynccontextmanager
import httpx
from core.database import db
from core.firewall import firewall_model
from core.email_notifier import email_notifier
from routers import analytics, honeypot
import logging

# Configure Logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("proxy")

UPSTREAM_URL = "http://127.0.0.1:8001"

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
# Note: We do NOT include honeypot.router directly as a global router anymore.
# We will invoke its handler manually for trapped requests.

@app.api_route("/{path_name:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"])
async def gateway_proxy(request: Request, path_name: str, background_tasks: BackgroundTasks):
    """
    Main Gateway Logic:
    1. Extract Request Data.
    2. Check ML Firewall with confidence scoring.
    3. Route to Upstream (Safe) or Honeypot (Malicious/Suspicious).
    """
    
    # 1. Extract Data for Analysis
    method = request.method
    query_params = str(request.query_params)
    
    # We need to read the body, but also keep it available for forwarding
    # Starlette/FastAPI request body can be consumed only once.
    # We read it into memory.
    body_bytes = await request.body()
    body_str = body_bytes.decode('utf-8', errors='replace')
    
    # Combine inputs for analysis
    # "POST /login body=..."
    analysis_text = f"{method} /{path_name} {query_params}\n{body_str}"
    
    # 2. Firewall Check with confidence
    ml_result = firewall_model.predict_with_confidence(analysis_text)
    is_malicious = ml_result["is_malicious"]
    ml_verdict = ml_result["verdict"]
    ml_confidence = ml_result["confidence"]
    
    if is_malicious or ml_verdict == "SUSPICIOUS":
        # TRAP: Route to Honeypot for malicious or suspicious traffic
        logger.warning(f"[BLOCKED] {ml_verdict} traffic detected from {request.client.host} (confidence: {ml_confidence:.2f})")
        
        # Send email alert for MALICIOUS attacks (not SUSPICIOUS)
        if ml_verdict == "MALICIOUS":
            background_tasks.add_task(
                email_notifier.send_attack_alert,
                ip=request.client.host,
                method=method,
                path=path_name,
                ml_verdict=ml_verdict,
                ml_confidence=ml_confidence,
                payload=body_str[:500]
            )
        
        # We construct a new request or just pass existing one?
        # handle_honeypot_request expects the request object.
        # Since we consumed the body, we might need to patch it?
        # Actually, handle_honeypot_request calls `await request.body()`.
        # Since we already consumed it, we define a receive override.
        
        async def receive():
            return {"type": "http.request", "body": body_bytes}
        request._receive = receive
        
        # Call Honeypot Handler with ML data for logging
        response_content = await honeypot.handle_honeypot_request(
            request, 
            background_tasks,
            ml_verdict=ml_verdict,
            ml_confidence=ml_confidence
        )
        
        # Return the honeypot's response (HTML or JSON)
        # The honeypot router returns a string (HTML/JSON content) usually.
        # But handle_honeypot_request returns `response_text` (str).
        # We need to wrap it in a proper Response object.
        
        # Determine content type based on response look
        media_type = "text/html" if "<html" in response_content.lower() else "application/json"
        
        return Response(
            content=response_content, 
            media_type=media_type,
            headers={"X-QuantumShield-Trap": "Active - You are in a Honeypot"}
        )
        
    else:
        # SAFE: Forward to Upstream (Vulnerable Server)
        logger.info(f"[SAFE] Forwarding to {UPSTREAM_URL}/{path_name}")
        
        client = httpx.AsyncClient(base_url=UPSTREAM_URL)
        try:
            upstream_req = client.build_request(
                method,
                f"/{path_name}",
                content=body_bytes, # Pass original body
                params=request.query_params,
                headers=request.headers.raw, # Pass headers
                timeout=10.0
            )
            
            # Load full content to avoid streaming issues in demo
            upstream_response = await client.send(upstream_req)
            content = upstream_response.content
            
            return Response(
                content=content,
                status_code=upstream_response.status_code,
                headers=dict(upstream_response.headers),
                media_type=upstream_response.headers.get("content-type")
            )
        except Exception as e:
            logger.error(f"Upstream error: {str(e)}")
            return JSONResponse({"error": "Upstream unavailable"}, status_code=503)
        finally:
            await client.aclose()

if __name__ == "__main__":
    import uvicorn
    # Run slightly differently because we are a proxy now
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
