"""
Minimal FastAPI application for QuantumShield.

This provides a small REST API that can be expanded later. For now it
exposes health and (optional) statistics endpoints.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional
from pydantic import BaseModel

from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse

app = FastAPI(title="QuantumShield API", version="0.1.0")

from fastapi.middleware.cors import CORSMiddleware

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allow all for local dev, or specify ["http://localhost:3000", "http://localhost:3001"]
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Global engine reference (set by full_run.py)
_global_engine = None

def set_engine(engine):
    """Set the global engine reference."""
    global _global_engine
    _global_engine = engine


class WAFRequest(BaseModel):
    method: str
    uri: str
    headers: Dict[str, str] = {}
    body: str = ""
    query_params: Dict[str, str] = {}
    body_params: Dict[str, Any] = {}
    src_ip: str = "127.0.0.1"
    timestamp: Optional[str] = None
    all_params: Dict[str, Any] = {}


@app.get("/health", tags=["system"])
async def health() -> Dict[str, Any]:
    """Simple health check endpoint."""
    return {"status": "ok"}


@app.post("/api/waf/process", tags=["waf"])
async def process_waf_request(request: Request, waf_req: WAFRequest):
    """Process a request through the WAF engine."""
    import logging
    logger = logging.getLogger(__name__)
    
    logger.info(f"[WAF API] Processing request: {waf_req.method} {waf_req.uri}")
    if waf_req.query_params:
        logger.debug(f"[WAF API] Query params: {waf_req.query_params}")
    if waf_req.body_params:
        logger.debug(f"[WAF API] Body params: {waf_req.body_params}")
    
    # Try to get engine from app.state first, then fallback to global
    engine = None
    if hasattr(request.app.state, "engine"):
        engine = request.app.state.engine
    elif _global_engine:
        engine = _global_engine
    
    if not engine:
        logger.error("[WAF API] Engine not initialized")
        raise HTTPException(status_code=503, detail="Engine not initialized")
    
    if not engine.waf_engine:
        # Fallback if WAF is not enabled
        logger.warning("[WAF API] WAF engine disabled - allowing request")
        return {
            "allowed": True,
            "violations": [],
            "action": "allow",
            "reason": "WAF engine disabled",
            "warning": True
        }

    # Use WAF engine to analyze and get detailed violations
    # Pass all parameters to WAF for comprehensive checking
    violations = engine.waf_engine.process_request(
        waf_req.method,
        waf_req.uri,
        waf_req.headers,
        waf_req.body,
        query_params=waf_req.query_params,
        body_params=waf_req.body_params,
        all_params=waf_req.all_params
    )
    
    if violations:
        logger.warning(f"[WAF API] BLOCKED: {len(violations)} violation(s) detected")
        for v in violations:
            logger.warning(f"[WAF API]   - {v.get('type')}: {v.get('reason')}")
        return {
            "allowed": False,
            "violations": violations,
            "action": "block",
            "reason": "Malicious content detected"
        }
    
    logger.info(f"[WAF API] ALLOWED: {waf_req.method} {waf_req.uri}")
    return {
        "allowed": True,
        "violations": [],
        "action": "allow",
        "reason": "Clean"
    }
