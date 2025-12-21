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
    
    # Aggregate by attack_type (sqli, xss, command_injection, etc.)
    pipeline = [
        {
            "$group": {
                "_id": "$attack_type",
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
    
    # Aggregate by severity
    severity_pipeline = [
        {
            "$match": {
                "severity": {"$exists": True, "$ne": None}
            }
        },
        {
            "$group": {
                "_id": "$severity",
                "count": {"$sum": 1}
            }
        },
        {
            "$sort": {"count": -1}
        }
    ]
    
    severity_counts = await logs_collection.aggregate(severity_pipeline).to_list(length=None)
    
    return {
        "attack_types": attack_types,
        "top_ips": top_ips,
        "severity_distribution": severity_counts
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


@router.get("/ml-stats")
async def get_ml_stats():
    """Get ML model statistics and confidence distribution"""
    logs_collection = db.get_collection("logs")
    
    # Count verdicts
    verdict_pipeline = [
        {
            "$match": {
                "ml_verdict": {"$exists": True, "$ne": None}
            }
        },
        {
            "$group": {
                "_id": "$ml_verdict",
                "count": {"$sum": 1}
            }
        }
    ]
    
    verdict_results = await logs_collection.aggregate(verdict_pipeline).to_list(length=None)
    
    # Build verdict counts
    verdict_counts = {"safe": 0, "suspicious": 0, "malicious": 0}
    for item in verdict_results:
        verdict = item["_id"].lower() if item["_id"] else "safe"
        if verdict in verdict_counts:
            verdict_counts[verdict] = item["count"]
    
    # Get confidence distribution (bucket by 10%)
    confidence_pipeline = [
        {
            "$match": {
                "ml_confidence": {"$exists": True, "$ne": None}
            }
        },
        {
            "$bucket": {
                "groupBy": {"$multiply": [{"$floor": {"$multiply": ["$ml_confidence", 10]}}, 10]},
                "boundaries": [0, 10, 20, 30, 40, 50, 60, 70, 80, 90, 100],
                "default": "other",
                "output": {
                    "count": {"$sum": 1}
                }
            }
        }
    ]
    
    try:
        confidence_results = await logs_collection.aggregate(confidence_pipeline).to_list(length=None)
        confidence_distribution = [
            {"range": f"{int(item['_id'])}-{int(item['_id'])+10}", "count": item["count"]}
            for item in confidence_results if item["_id"] != "other"
        ]
    except Exception:
        # Fallback if $bucket not supported
        confidence_distribution = []
    
    # Calculate average confidence
    avg_pipeline = [
        {
            "$match": {
                "ml_confidence": {"$exists": True, "$ne": None}
            }
        },
        {
            "$group": {
                "_id": None,
                "avg_confidence": {"$avg": "$ml_confidence"},
                "total": {"$sum": 1}
            }
        }
    ]
    
    avg_results = await logs_collection.aggregate(avg_pipeline).to_list(length=1)
    avg_confidence = avg_results[0]["avg_confidence"] if avg_results else 0
    total_predictions = avg_results[0]["total"] if avg_results else 0
    
    return {
        "total_predictions": total_predictions,
        "verdict_counts": verdict_counts,
        "confidence_distribution": confidence_distribution,
        "average_confidence": avg_confidence * 100 if avg_confidence else 0
    }


@router.get("/summary/{session_id}")
async def get_threat_summary(session_id: str):
    """Generate AI-powered threat summary for a session"""
    from analysis import threat_summarizer
    
    summary = await threat_summarizer.generate_summary(session_id)
    return summary


@router.get("/playback/{session_id}")
async def get_attack_playback(session_id: str):
    """Get step-by-step playback data for an attack session"""
    logs_collection = db.get_collection("logs")
    sessions_collection = db.get_collection("sessions")
    
    # Get session info
    session = await sessions_collection.find_one({"session_id": session_id})
    if not session:
        return JSONResponse(
            status_code=404,
            content={"error": "Session not found"}
        )
    
    # Get all logs for this session, ordered by time
    logs = await logs_collection.find({"session_id": session_id}).sort("timestamp", 1).to_list(length=None)
    
    # Format for playback
    playback_steps = []
    for i, log in enumerate(logs):
        playback_steps.append({
            "step": i + 1,
            "timestamp": log["timestamp"].isoformat() if isinstance(log["timestamp"], datetime) else str(log["timestamp"]),
            "attack_type": log.get("attack_type", "unknown"),
            "request_type": log.get("type", "unknown"),
            "payload": log.get("payload", ""),
            "response": log.get("response", ""),
            "ip": log.get("ip", "")
        })
    
    return {
        "session_id": session_id,
        "ip_address": session.get("ip_address"),
        "user_agent": session.get("user_agent"),
        "start_time": session.get("start_time").isoformat() if isinstance(session.get("start_time"), datetime) else str(session.get("start_time")),
        "total_steps": len(playback_steps),
        "steps": playback_steps
    }


