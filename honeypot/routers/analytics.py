from fastapi import APIRouter, Query
from fastapi.responses import JSONResponse
from core.database import db
from core.cache import response_cache
from core.llm_client import llm_client
from datetime import datetime, timedelta
from typing import Optional

router = APIRouter(prefix="/api/analytics", tags=["analytics"])

@router.get("/stats")
async def get_stats():
    """Get overall honeypot statistics"""
    logs_collection = db.get_collection("logs")
    sessions_collection = db.get_collection("sessions")
    
    # Count total interactions
    total_logs = await logs_collection.count_documents({})
    
    # Count active sessions
    active_sessions = await sessions_collection.count_documents({"active": True})
    
    # Count total sessions
    total_sessions = await sessions_collection.count_documents({})
    
    # Get cache stats
    cache_stats = response_cache.get_stats()
    
    # Get LLM stats
    llm_stats = llm_client.get_stats()
    
    # Get recent activity (last 24 hours)
    yesterday = datetime.utcnow() - timedelta(days=1)
    recent_logs = await logs_collection.count_documents({
        "timestamp": {"$gte": yesterday}
    })
    
    return {
        "total_interactions": total_logs,
        "active_sessions": active_sessions,
        "total_sessions": total_sessions,
        "recent_activity_24h": recent_logs,
        "cache": cache_stats,
        "llm": llm_stats,
        "uptime": "Live"
    }

@router.get("/sessions")
async def get_sessions(
    active_only: bool = Query(False, description="Return only active sessions"),
    limit: int = Query(50, description="Maximum number of sessions to return")
):
    """Get session information"""
    sessions_collection = db.get_collection("sessions")
    
    query = {}
    if active_only:
        query["active"] = True
    
    sessions = await sessions_collection.find(query).sort("start_time", -1).limit(limit).to_list(length=limit)
    
    # Convert ObjectId to string and format dates
    for session in sessions:
        session["_id"] = str(session["_id"])
        session["start_time"] = session["start_time"].isoformat() if isinstance(session["start_time"], datetime) else str(session["start_time"])
    
    return {
        "count": len(sessions),
        "sessions": sessions
    }

@router.get("/logs")
async def get_logs(
    session_id: Optional[str] = Query(None, description="Filter by session ID"),
    limit: int = Query(100, description="Maximum number of logs to return"),
    skip: int = Query(0, description="Number of logs to skip (for pagination)")
):
    """Get interaction logs with pagination"""
    logs_collection = db.get_collection("logs")
    
    query = {}
    if session_id:
        query["session_id"] = session_id
    
    logs = await logs_collection.find(query).sort("timestamp", -1).skip(skip).limit(limit).to_list(length=limit)
    
    # Convert ObjectId to string and format dates
    for log in logs:
        log["_id"] = str(log["_id"])
        log["timestamp"] = log["timestamp"].isoformat() if isinstance(log["timestamp"], datetime) else str(log["timestamp"])
    
    total = await logs_collection.count_documents(query)
    
    return {
        "count": len(logs),
        "total": total,
        "skip": skip,
        "limit": limit,
        "logs": logs
    }

@router.get("/patterns")
async def get_attack_patterns():
    """Get common attack patterns and frequencies"""
    logs_collection = db.get_collection("logs")
    
    # Aggregate attack types
    pipeline = [
        {
            "$group": {
                "_id": "$type",
                "count": {"$sum": 1}
            }
        },
        {
            "$sort": {"count": -1}
        }
    ]
    
    attack_types = await logs_collection.aggregate(pipeline).to_list(length=None)
    
    # Get top attacking IPs
    ip_pipeline = [
        {
            "$group": {
                "_id": "$ip",
                "count": {"$sum": 1}
            }
        },
        {
            "$sort": {"count": -1}
        },
        {
            "$limit": 10
        }
    ]
    
    top_ips = await logs_collection.aggregate(ip_pipeline).to_list(length=10)
    
    return {
        "attack_types": attack_types,
        "top_ips": top_ips
    }

@router.get("/timeline")
async def get_timeline(hours: int = Query(24, description="Number of hours to analyze")):
    """Get attack timeline data"""
    logs_collection = db.get_collection("logs")
    
    start_time = datetime.utcnow() - timedelta(hours=hours)
    
    # Aggregate by hour
    pipeline = [
        {
            "$match": {
                "timestamp": {"$gte": start_time}
            }
        },
        {
            "$group": {
                "_id": {
                    "$dateToString": {
                        "format": "%Y-%m-%d %H:00",
                        "date": "$timestamp"
                    }
                },
                "count": {"$sum": 1}
            }
        },
        {
            "$sort": {"_id": 1}
        }
    ]
    
    timeline = await logs_collection.aggregate(pipeline).to_list(length=None)
    
    return {
        "hours": hours,
        "data": timeline
    }
