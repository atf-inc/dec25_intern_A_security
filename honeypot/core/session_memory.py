"""
Simple in-memory session manager (no MongoDB required)
Use this for demos when MongoDB is not available
"""
import uuid
from datetime import datetime

class InMemorySessionManager:
    def __init__(self):
        self.sessions = {}
    
    async def get_or_create_session(self, ip_address: str, user_agent: str):
        """Get existing session or create new one"""
        session_key = f"{ip_address}_{user_agent}"
        
        if session_key in self.sessions:
            return self.sessions[session_key]
        
        # Create new session
        session_id = str(uuid.uuid4())
        session = {
            "session_id": session_id,
            "ip_address": ip_address,
            "user_agent": user_agent,
            "context": {
                "user": "www-data",
                "current_directory": "/var/www/html",
                "system_type": "Ubuntu 22.04 LTS",
                "history": []
            },
            "created_at": datetime.utcnow(),
            "active": True
        }
        
        self.sessions[session_key] = session
        print(f"[OK] Created session: {session_id} for {ip_address}")
        return session
    
    async def add_history(self, session_id: str, command: str, response: str):
        """Add interaction to session history"""
        for session in self.sessions.values():
            if session["session_id"] == session_id:
                session["context"]["history"].append({
                    "cmd": command,
                    "res": response,
                    "timestamp": datetime.utcnow()
                })
                # Keep only last 10 interactions
                if len(session["context"]["history"]) > 10:
                    session["context"]["history"] = session["context"]["history"][-10:]
                break

# Create singleton instance
session_manager = InMemorySessionManager()
