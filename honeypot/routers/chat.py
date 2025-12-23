"""
NLP-Powered Chat Router
Translates natural language questions into MongoDB aggregation pipelines
and provides forensic analysis of attacker sessions.
"""
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field
from typing import Optional, List, Any, Literal
from core.database import db
from core.llm_client import llm_client
from datetime import datetime, timedelta
import json
import re

router = APIRouter(prefix="/api/chat", tags=["chat"])


# Request/Response Models
class ChatQueryRequest(BaseModel):
    message: str = Field(..., description="Natural language question from the user")


class ChatQueryResponse(BaseModel):
    content: str = Field(..., description="Text response to display")
    render_type: Literal["text", "table", "bar_chart", "pie_chart", "line_chart", "forensics"] = "text"
    data: Optional[Any] = Field(None, description="Structured data for charts/tables")
    query_executed: Optional[str] = Field(None, description="The MongoDB query that was executed")


class ForensicsResponse(BaseModel):
    session_id: str
    ip_address: Optional[str]
    command_history: List[dict]
    analysis: str
    intent: str
    threat_level: str
    blocked_actions: List[str]


# MongoDB Schema Reference for LLM
SCHEMA_REFERENCE = """
MongoDB Collections Schema:

1. **logs** collection:
   - _id: ObjectId
   - timestamp: DateTime
   - session_id: string
   - ip: string (IP address of attacker)
   - type: string (e.g., "http", "ssh", "command")
   - attack_type: string (e.g., "sql_injection", "xss", "rce", "path_traversal", "command_injection")
   - payload: string (the malicious input)
   - response: string (honeypot's response)
   - ml_verdict: string ("SAFE", "SUSPICIOUS", "MALICIOUS") - ML model's classification
   - ml_confidence: float (0.0 to 1.0) - ML model's confidence score
   - severity: string (e.g., "low", "medium", "high", "critical") - Attack severity level

2. **sessions** collection:
   - _id: ObjectId
   - session_id: string
   - ip_address: string
   - user_agent: string
   - start_time: DateTime
   - active: boolean
   - context: {
       current_directory: string,
       user: string,
       history: [{ cmd: string, res: string }]  // Command history
     }

Analytics Notes:
- Use $group to aggregate by IP, attack_type, ml_verdict, or severity
- Use $match with ml_confidence thresholds to filter by confidence levels
- Combine multiple $group stages to find patterns (e.g., which IP uses which attack type most)
"""

QUERY_EXAMPLES = """
Example natural language queries and their MongoDB pipelines:

1. "Show me all SQL injection attempts in the last hour"
   Collection: logs
   Pipeline: [
     {"$match": {"attack_type": "sql_injection", "timestamp": {"$gte": <1 hour ago>}}},
     {"$sort": {"timestamp": -1}},
     {"$limit": 50}
   ]
   render_type: table

2. "What are the top 10 attacking IPs?"
   Collection: logs
   Pipeline: [
     {"$group": {"_id": "$ip", "count": {"$sum": 1}}},
     {"$sort": {"count": -1}},
     {"$limit": 10}
   ]
   render_type: bar_chart

3. "Show attack distribution by type"
   Collection: logs
   Pipeline: [
     {"$group": {"_id": "$attack_type", "count": {"$sum": 1}}},
     {"$sort": {"count": -1}}
   ]
   render_type: pie_chart

4. "How many attacks happened each hour today?"
   Collection: logs
   Pipeline: [
     {"$match": {"timestamp": {"$gte": <24 hours ago>}}},
     {"$group": {"_id": {"$dateToString": {"format": "%Y-%m-%d %H:00", "date": "$timestamp"}}, "count": {"$sum": 1}}},
     {"$sort": {"_id": 1}}
   ]
   render_type: line_chart

5. "Show active sessions"
   Collection: sessions
   Pipeline: [
     {"$match": {"active": true}},
     {"$sort": {"start_time": -1}}
   ]
   render_type: table

6. "Find attacks with high confidence malicious verdict"
   Collection: logs
   Pipeline: [
     {"$match": {"ml_verdict": "MALICIOUS", "ml_confidence": {"$gte": 0.8}}},
     {"$sort": {"timestamp": -1}},
     {"$limit": 20}
   ]
   render_type: table

7. "Show ML verdict distribution"
   Collection: logs
   Pipeline: [
     {"$match": {"ml_verdict": {"$exists": true, "$ne": null}}},
     {"$group": {"_id": "$ml_verdict", "count": {"$sum": 1}}},
     {"$sort": {"count": -1}}
   ]
   render_type: pie_chart

8. "What's the average ML confidence score?"
   Collection: logs
   Pipeline: [
     {"$match": {"ml_confidence": {"$exists": true, "$ne": null}}},
     {"$group": {"_id": null, "avg_confidence": {"$avg": "$ml_confidence"}, "total": {"$sum": 1}}}
   ]
   render_type: text

9. "Which IP is the riskiest?" or "What is the most dangerous IP?"
   Collection: logs
   Pipeline: [
     {"$match": {"ml_verdict": "MALICIOUS"}},
     {"$group": {"_id": "$ip", "malicious_count": {"$sum": 1}, "avg_confidence": {"$avg": "$ml_confidence"}}},
     {"$sort": {"malicious_count": -1, "avg_confidence": -1}},
     {"$limit": 10}
   ]
   render_type: table

10. "What type of attack does IP X.X.X.X use most?" or "Show attack types for a specific IP"
    Collection: logs
    Pipeline: [
      {"$match": {"ip": "X.X.X.X"}},
      {"$group": {"_id": "$attack_type", "count": {"$sum": 1}}},
      {"$sort": {"count": -1}}
    ]
    render_type: bar_chart

11. "Which is the most common attack type?" or "Most used attack type"
    Collection: logs
    Pipeline: [
      {"$group": {"_id": "$attack_type", "count": {"$sum": 1}}},
      {"$sort": {"count": -1}},
      {"$limit": 1}
    ]
    render_type: text

12. "Show attacks by severity level"
    Collection: logs
    Pipeline: [
      {"$match": {"severity": {"$exists": true, "$ne": null}}},
      {"$group": {"_id": "$severity", "count": {"$sum": 1}}},
      {"$sort": {"count": -1}}
    ]
    render_type: pie_chart

13. "Show ML confidence distribution"
    Collection: logs
    Pipeline: [
      {"$match": {"ml_confidence": {"$exists": true, "$ne": null}}},
      {"$bucket": {
        "groupBy": {"$multiply": [{"$floor": {"$multiply": ["$ml_confidence", 10]}}, 10]},
        "boundaries": [0, 10, 20, 30, 40, 50, 60, 70, 80, 90, 100],
        "default": "other",
        "output": {"count": {"$sum": 1}}
      }}
    ]
    render_type: bar_chart
"""


def build_nlp_prompt(user_message: str) -> str:
    """Build the prompt for NL-to-MongoDB translation."""
    now = datetime.utcnow()
    
    return f"""You are a MongoDB query translator for a cybersecurity honeypot system.
Convert the user's natural language question into a MongoDB aggregation pipeline.

{SCHEMA_REFERENCE}

{QUERY_EXAMPLES}

Current UTC time: {now.isoformat()}

IMPORTANT RULES:
1. Always return valid JSON with this exact structure:
{{
  "collection": "logs" or "sessions",
  "pipeline": [...],  // Valid MongoDB aggregation pipeline
  "render_type": "text" | "table" | "bar_chart" | "pie_chart" | "line_chart",
  "explanation": "Brief explanation of what the query does"
}}

2. For time-based queries, use proper ISODate format strings like "{(now - timedelta(hours=1)).isoformat()}Z"
3. Choose render_type based on the data:
   - table: for listing individual records
   - bar_chart: for comparing counts across categories
   - pie_chart: for showing distribution/percentages
   - line_chart: for time-series data
   - text: for simple counts or when no visualization fits

4. If the question cannot be answered with the available data, return:
{{
  "collection": null,
  "pipeline": null,
  "render_type": "text",
  "explanation": "Explain what information is not available"
}}

User question: {user_message}

Respond ONLY with the JSON object, no additional text."""


@router.post("/query", response_model=ChatQueryResponse)
async def chat_query(request: ChatQueryRequest):
    """
    Process natural language query and return results with visualization hints.
    """
    user_message = request.message.strip()
    
    if not user_message:
        raise HTTPException(status_code=400, detail="Message cannot be empty")
    
    # Build prompt and get LLM response
    prompt = build_nlp_prompt(user_message)
    
    try:
        llm_response = await llm_client.generate_response(
            system_prompt="You are a precise MongoDB query generator. Output only valid JSON.",
            user_input=prompt
        )
        
        # Parse LLM response
        # Clean up response - remove markdown code blocks if present
        cleaned_response = llm_response.strip()
        if cleaned_response.startswith("```"):
            cleaned_response = re.sub(r'^```(?:json)?\n?', '', cleaned_response)
            cleaned_response = re.sub(r'\n?```$', '', cleaned_response)
        
        query_spec = json.loads(cleaned_response)
        
        # Check if query is not possible
        if query_spec.get("collection") is None:
            return ChatQueryResponse(
                content=query_spec.get("explanation", "I couldn't understand that query. Please try rephrasing."),
                render_type="text",
                data=None
            )
        
        collection_name = query_spec["collection"]
        pipeline = query_spec["pipeline"]
        render_type = query_spec.get("render_type", "table")
        explanation = query_spec.get("explanation", "")
        
        # Execute the pipeline
        collection = db.get_collection(collection_name)
        
        # Parse date strings in pipeline to datetime objects
        pipeline = parse_dates_in_pipeline(pipeline)
        
        results = await collection.aggregate(pipeline).to_list(length=100)
        
        # Format results
        formatted_results = format_results(results, render_type)
        
        # Build response content with actual result details
        if len(results) == 0:
            content = f"No results found. {explanation}"
        else:
            # Try to make the response more informative by showing key results
            content_parts = [f"Found {len(results)} result(s)."]
            
            # Add specific details based on the query type
            if len(formatted_results) > 0:
                first_result = formatted_results[0]
                
                # For single result queries (like "most common attack type")
                if len(results) == 1:
                    if "name" in first_result:
                        content_parts.append(f"**{first_result['name']}**")
                        if "count" in first_result:
                            content_parts.append(f"({first_result['count']} occurrences)")
                    elif "ip" in first_result:
                        content_parts.append(f"**{first_result['ip']}**")
                        if "malicious_count" in first_result:
                            content_parts.append(f"({first_result['malicious_count']} malicious attacks)")
                    elif "avg_confidence" in first_result:
                        avg_conf = first_result.get("avg_confidence", 0)
                        if isinstance(avg_conf, (int, float)):
                            content_parts.append(f"(Average confidence: {avg_conf:.1%})")
                
                # For top N queries
                elif len(results) <= 10 and "name" in first_result:
                    top_items = [r.get("name", "Unknown") for r in formatted_results[:3]]
                    content_parts.append(f"Top results: **{', '.join(top_items)}**")
                elif len(results) <= 10 and "ip" in first_result:
                    top_ips = [r.get("ip", "Unknown") for r in formatted_results[:3]]
                    content_parts.append(f"Top IPs: **{', '.join(top_ips)}**")
            
            if explanation:
                content_parts.append(explanation)
            
            content = " ".join(content_parts)
        
        return ChatQueryResponse(
            content=content,
            render_type=render_type,
            data=formatted_results,
            query_executed=json.dumps({"collection": collection_name, "pipeline": query_spec["pipeline"]})
        )
        
    except json.JSONDecodeError as e:
        print(f"[CHAT] JSON parse error: {e}")
        print(f"[CHAT] LLM response was: {llm_response}")
        return ChatQueryResponse(
            content="I had trouble understanding that query. Could you rephrase it?",
            render_type="text",
            data=None
        )
    except Exception as e:
        print(f"[CHAT] Error processing query: {e}")
        return ChatQueryResponse(
            content=f"An error occurred while processing your query: {str(e)}",
            render_type="text",
            data=None
        )


@router.post("/forensics/{session_id}", response_model=ForensicsResponse)
async def analyze_session_forensics(session_id: str):
    """
    Analyze attacker behavior from session command history.
    Explains what the attacker was trying to do and their intent.
    """
    sessions_collection = db.get_collection("sessions")
    logs_collection = db.get_collection("logs")
    
    # Fetch session
    session = await sessions_collection.find_one({"session_id": session_id})
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    
    # Get command history from session context
    context = session.get("context", {})
    history = context.get("history", [])
    
    # Also get related logs
    logs = await logs_collection.find({"session_id": session_id}).sort("timestamp", 1).to_list(length=50)
    
    # Build analysis prompt
    history_text = "\n".join([
        f"Command: {h.get('cmd', 'N/A')}\nResponse: {h.get('res', 'N/A')[:200]}"
        for h in history[-20:]  # Last 20 commands
    ])
    
    logs_text = "\n".join([
        f"[{log.get('type', 'unknown')}] {log.get('payload', '')[:150]}"
        for log in logs[-10:]  # Last 10 logs
    ])
    
    analysis_prompt = f"""Analyze this attacker's session and explain their behavior.

Session Info:
- IP Address: {session.get('ip_address', 'Unknown')}
- User Agent: {session.get('user_agent', 'Unknown')}
- Started: {session.get('start_time', 'Unknown')}

Command History (what the attacker typed):
{history_text if history_text else "No command history available"}

Attack Logs:
{logs_text if logs_text else "No attack logs available"}

Provide your analysis in this JSON format:
{{
  "analysis": "Detailed explanation of what the attacker did step by step",
  "intent": "Brief statement of the attacker's likely goal (e.g., 'Data exfiltration', 'Cryptocurrency mining', 'Lateral movement')",
  "threat_level": "Low" | "Medium" | "High" | "Critical",
  "blocked_actions": ["List of actions that were blocked or failed due to honeypot restrictions"]
}}

Be specific about attack techniques (reference MITRE ATT&CK if applicable).
Explain what would have happened if this were a real system vs what the honeypot allowed."""

    try:
        llm_response = await llm_client.generate_response(
            system_prompt="You are an expert cybersecurity forensics analyst. Analyze attacker behavior and provide clear, actionable intelligence.",
            user_input=analysis_prompt
        )
        
        # Parse response
        cleaned_response = llm_response.strip()
        if cleaned_response.startswith("```"):
            cleaned_response = re.sub(r'^```(?:json)?\n?', '', cleaned_response)
            cleaned_response = re.sub(r'\n?```$', '', cleaned_response)
        
        analysis_data = json.loads(cleaned_response)
        
        return ForensicsResponse(
            session_id=session_id,
            ip_address=session.get("ip_address"),
            command_history=history,
            analysis=analysis_data.get("analysis", "Analysis not available"),
            intent=analysis_data.get("intent", "Unknown"),
            threat_level=analysis_data.get("threat_level", "Medium"),
            blocked_actions=analysis_data.get("blocked_actions", [])
        )
        
    except Exception as e:
        print(f"[FORENSICS] Error analyzing session: {e}")
        return ForensicsResponse(
            session_id=session_id,
            ip_address=session.get("ip_address"),
            command_history=history,
            analysis=f"Error generating analysis: {str(e)}",
            intent="Unknown",
            threat_level="Medium",
            blocked_actions=[]
        )


def parse_dates_in_pipeline(pipeline: list) -> list:
    """
    Recursively parse ISO date strings in pipeline to datetime objects.
    """
    def parse_value(value):
        if isinstance(value, str):
            # Check if it looks like an ISO date
            if re.match(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}', value):
                try:
                    # Remove trailing Z if present
                    clean_value = value.rstrip('Z')
                    return datetime.fromisoformat(clean_value)
                except ValueError:
                    return value
            return value
        elif isinstance(value, dict):
            return {k: parse_value(v) for k, v in value.items()}
        elif isinstance(value, list):
            return [parse_value(item) for item in value]
        return value
    
    return parse_value(pipeline)


def format_results(results: list, render_type: str) -> Any:
    """
    Format MongoDB results for frontend consumption.
    """
    if not results:
        return []
    
    formatted = []
    for doc in results:
        formatted_doc = {}
        for key, value in doc.items():
            if key == "_id":
                if isinstance(value, dict):
                    # For grouped results, flatten the _id
                    formatted_doc.update({k: str(v) for k, v in value.items()})
                elif value is None:
                    # Skip null _id (from $group with _id: null)
                    continue
                else:
                    # For simple _id values (IP, attack_type, etc.), use a meaningful name
                    # Try to infer what the _id represents based on other fields
                    if "malicious_count" in doc or "avg_confidence" in doc:
                        formatted_doc["ip"] = str(value)
                    elif "count" in doc:
                        # Could be attack_type, severity, ml_verdict, etc.
                        # Use generic "name" for charts, but preserve original for tables
                        formatted_doc["name"] = str(value)
                    else:
                        formatted_doc["value"] = str(value)
            elif isinstance(value, datetime):
                formatted_doc[key] = value.isoformat()
            elif hasattr(value, '__str__'):
                formatted_doc[key] = str(value) if not isinstance(value, (int, float, bool, list, dict)) else value
            else:
                formatted_doc[key] = value
        formatted.append(formatted_doc)
    
    # For charts, ensure we have the right structure
    if render_type in ["bar_chart", "pie_chart", "line_chart"]:
        # Try to normalize to {name, value} format for Recharts
        chart_data = []
        for item in formatted:
            if "count" in item and "name" in item:
                chart_data.append({"name": str(item["name"]), "value": item["count"]})
            elif "value" in item and "name" in item:
                chart_data.append({"name": str(item["name"]), "value": item["value"]})
            elif "count" in item:
                # Fallback: try to find any string field for name
                name = item.get("ip") or item.get("name") or "Unknown"
                chart_data.append({"name": str(name), "value": item["count"]})
            else:
                # Keep as-is if we can't normalize
                chart_data.append(item)
        return chart_data if chart_data else formatted
    
    return formatted


@router.get("/suggestions")
async def get_query_suggestions():
    """
    Return suggested queries for the chat interface.
    """
    return {
        "suggestions": [
            "Show me all attacks in the last hour",
            "What are the top 10 attacking IPs?",
            "Which IP is the riskiest?",
            "What is the most common attack type?",
            "Show attack distribution by type",
            "Show ML verdict distribution",
            "What's the average ML confidence score?",
            "Find high-confidence malicious attacks",
            "Show attacks by severity level",
            "How many attacks happened each hour today?",
            "Show all active sessions",
            "What SQL injection attempts were detected?"
        ]
    }

