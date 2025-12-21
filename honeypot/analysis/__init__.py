"""
AI-Powered Threat Summarizer
Generates human-readable threat analysis from attack data using LLM with structured outputs
"""
from core.llm_client import llm_client
from core.database import db
from datetime import datetime
from pydantic import BaseModel, Field, ConfigDict
from typing import Literal, List
import json

# Pydantic models for structured output
class AttackTechnique(BaseModel):
    model_config = ConfigDict(extra='forbid')
    name: str = Field(description="Name of the attack technique")
    description: str = Field(description="Brief description of what the attacker attempted")
    severity: Literal["Low", "Medium", "High", "Critical"] = Field(description="Severity level of this technique")

class ThreatTimeline(BaseModel):
    model_config = ConfigDict(extra='forbid')
    phase: str = Field(description="Attack phase (e.g., Reconnaissance, Initial Access, Exploitation)")
    timestamp: str = Field(description="When this phase occurred")
    actions: List[str] = Field(description="List of actions taken in this phase")

class ThreatSummary(BaseModel):
    model_config = ConfigDict(extra='forbid')
    threat_level: Literal["Low", "Medium", "High", "Critical"] = Field(description="Overall threat level assessment")
    risk_score: int = Field(description="Numerical risk score from 0-100", ge=0, le=100)
    executive_summary: str = Field(description="2-3 sentence high-level summary for executives")
    attacker_profile: str = Field(description="Assessment of attacker sophistication and likely intent")
    attack_techniques: List[AttackTechnique] = Field(description="Specific attack techniques identified")
    timeline: List[ThreatTimeline] = Field(description="Chronological breakdown of the attack")
    indicators_of_compromise: List[str] = Field(description="Key IOCs like payloads, patterns, signatures")
    recommended_actions: List[str] = Field(description="3-5 specific, actionable security recommendations")
    mitre_tactics: List[str] = Field(description="Relevant MITRE ATT&CK tactics if applicable")

class ThreatSummarizer:
    def __init__(self):
        self.cache = {}  # Simple in-memory cache for summaries
        
    async def generate_summary(self, session_id: str) -> dict:
        """Generate AI threat summary for a session with structured output"""
        
        # Check cache
        if session_id in self.cache:
            return self.cache[session_id]
        
        # Fetch session and logs
        sessions_collection = db.get_collection("sessions")
        logs_collection = db.get_collection("logs")
        
        session = await sessions_collection.find_one({"session_id": session_id})
        if not session:
            return {"error": "Session not found"}
            
        logs = await logs_collection.find({"session_id": session_id}).sort("timestamp", 1).to_list(length=100)
        
        if not logs:
            return {"error": "No attack data found for this session"}
        
        # Build analysis context
        attack_types = {}
        payloads = []
        timestamps = []
        
        for log in logs:
            attack_type = log.get("attack_type", "unknown")
            attack_types[attack_type] = attack_types.get(attack_type, 0) + 1
            payload = log.get("payload", "")
            if payload:
                payloads.append(payload[:300])  # First 300 chars
            timestamps.append(log.get("timestamp", datetime.utcnow()).isoformat())
        
        # Build enhanced LLM prompt
        prompt = f"""Analyze this cybersecurity attack session and provide a comprehensive threat assessment.

Session Information:
- IP Address: {session.get('ip_address')}
- User Agent: {session.get('user_agent')}
- Session Duration: {timestamps[0] if timestamps else 'Unknown'} to {timestamps[-1] if timestamps else 'Unknown'}
- Total Interactions: {len(logs)}
- Attack Types Detected: {', '.join([f"{k.upper()}: {v}" for k, v in attack_types.items()])}

Sample Attack Payloads (chronological):
{chr(10).join(['- ' + p for p in payloads[:10]])}

Provide a detailed threat analysis focusing on:
1. What the attacker was trying to achieve
2. Their level of sophistication
3. Specific techniques used (reference MITRE ATT&CK if applicable)
4. Timeline of attack progression
5. Actionable security recommendations

Be specific and technical where appropriate, but keep the executive summary accessible to non-technical stakeholders."""

        try:
            # Generate summary using LLM with structured output
            from groq import AsyncGroq
            groq_client = AsyncGroq(api_key=llm_client.client.api_key)
            
            response = await groq_client.chat.completions.create(
                model="openai/gpt-oss-20b",  # Use a model that supports structured outputs
                messages=[
                    {
                        "role": "system",
                        "content": "You are an expert cybersecurity threat analyst. Analyze attack sessions and provide detailed, actionable threat intelligence reports."
                    },
                    {
                        "role": "user",
                        "content": prompt
                    }
                ],
                response_format={
                    "type": "json_schema",
                    "json_schema": {
                        "name": "threat_summary",
                        "schema": ThreatSummary.model_json_schema(),
                        "strict": True
                    }
                },
                temperature=0.3  # Lower temperature for more consistent analysis
            )
            
            # Parse and validate the structured response
            summary_data = ThreatSummary.model_validate(json.loads(response.choices[0].message.content))
            
            result = {
                "session_id": session_id,
                "ip_address": session.get("ip_address"),
                "user_agent": session.get("user_agent"),
                "total_attacks": len(logs),
                "attack_types": attack_types,
                "analysis": summary_data.model_dump(),
                "generated_at": datetime.utcnow().isoformat(),
                "model_used": "openai/gpt-oss-20b"
            }
            
            # Cache the result
            self.cache[session_id] = result
            
            print(f"[THREAT_SUMMARY] Generated structured summary for session {session_id}")
            print(f"[THREAT_SUMMARY] Threat Level: {summary_data.threat_level}, Risk Score: {summary_data.risk_score}")
            
            return result
            
        except Exception as e:
            print(f"[THREAT_SUMMARY] Error generating summary: {str(e)}")
            # Fallback to basic summary if structured output fails
            return {
                "error": f"Failed to generate structured summary: {str(e)}",
                "session_id": session_id,
                "ip_address": session.get("ip_address"),
                "total_attacks": len(logs),
                "attack_types": attack_types,
                "fallback_summary": f"Detected {len(logs)} attack attempts from {session.get('ip_address')}. Attack types: {', '.join(attack_types.keys())}. Manual analysis recommended."
            }

# Singleton instance
threat_summarizer = ThreatSummarizer()

