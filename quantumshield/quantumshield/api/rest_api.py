"""REST API using FastAPI."""

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from typing import Dict, Any
import structlog
from ..config.settings import get_settings
from ..config.logging_config import get_logger

logger = get_logger(__name__)

app = FastAPI(title="QuantumShield API", version="1.0.0")

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/")
async def root():
    """Root endpoint."""
    return {"message": "QuantumShield API", "version": "1.0.0"}


@app.get("/status")
async def get_status():
    """Get system status."""
    return {"status": "running"}


@app.get("/alerts")
async def get_alerts():
    """Get security alerts."""
    return {"alerts": []}


@app.post("/rules")
async def create_rule(rule: Dict[str, Any]):
    """Create firewall rule."""
    return {"message": "Rule created", "rule": rule}


@app.delete("/rules/{rule_id}")
async def delete_rule(rule_id: str):
    """Delete firewall rule."""
    return {"message": "Rule deleted", "rule_id": rule_id}

