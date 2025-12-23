import uuid
from datetime import datetime, timezone
from typing import Optional
from core.database import db

class SessionManager:
    def __init__(self):
        self.collection_name = "sessions"

    async def get_or_create_session(self, ip_address: str, user_agent: str):
        collection = db.get_collection(self.collection_name)
        session = await collection.find_one({"ip_address": ip_address, "active": True})
        
        if not session:
            session_id = str(uuid.uuid4())
            session = {
                "session_id": session_id,
                "ip_address": ip_address,
                "user_agent": user_agent,
                "start_time": datetime.now(timezone.utc),
                "active": True,
                "end_time": None,
                "duration_seconds": None,
                "context": {
                    "current_directory": "/var/www",
                    "user": "www-data",
                    "hostname": "techshop-prod-01",
                    "history": []
                }
            }
            await collection.insert_one(session)
        
        return session

    async def update_context(self, session_id: str, new_context: dict):
        collection = db.get_collection(self.collection_name)
        await collection.update_one(
            {"session_id": session_id},
            {"$set": {"context": new_context}}
        )

    async def add_history(self, session_id: str, command: str, response: str):
        collection = db.get_collection(self.collection_name)
        # We might want to limit history size to avoid huge prompts
        await collection.update_one(
            {"session_id": session_id},
            {"$push": {"context.history": {"cmd": command, "res": response}}}
        )

    async def end_session(self, session_id: str) -> Optional[dict]:
        """
        End a session and calculate its duration.
        
        Args:
            session_id: The session ID to end
            
        Returns:
            Updated session dict or None if not found
        """
        collection = db.get_collection(self.collection_name)
        
        # Get the session to calculate duration
        session = await collection.find_one({"session_id": session_id})
        if not session:
            return None
        
        end_time = datetime.now(timezone.utc)
        start_time = session.get("start_time")
        
        # Calculate duration in seconds
        duration_seconds = None
        if start_time:
            if isinstance(start_time, datetime):
                duration_seconds = (end_time - start_time).total_seconds()
            else:
                # Handle string format if needed
                try:
                    start_dt = datetime.fromisoformat(str(start_time).replace('Z', '+00:00'))
                    duration_seconds = (end_time - start_dt).total_seconds()
                except:
                    duration_seconds = None
        
        # Update session with end time and duration
        await collection.update_one(
            {"session_id": session_id},
            {
                "$set": {
                    "active": False,
                    "end_time": end_time,
                    "duration_seconds": duration_seconds
                }
            }
        )
        
        # Return updated session
        return await collection.find_one({"session_id": session_id})

    async def get_session(self, session_id: str) -> Optional[dict]:
        """Get a session by ID."""
        collection = db.get_collection(self.collection_name)
        return await collection.find_one({"session_id": session_id})

    async def update_session_duration(self, session_id: str) -> None:
        """
        Update the duration of an active session without ending it.
        Useful for real-time duration display.
        """
        collection = db.get_collection(self.collection_name)
        session = await collection.find_one({"session_id": session_id, "active": True})
        
        if session and session.get("start_time"):
            start_time = session["start_time"]
            now = datetime.now(timezone.utc)
            
            if isinstance(start_time, datetime):
                duration_seconds = (now - start_time).total_seconds()
            else:
                try:
                    start_dt = datetime.fromisoformat(str(start_time).replace('Z', '+00:00'))
                    duration_seconds = (now - start_dt).total_seconds()
                except:
                    return
            
            await collection.update_one(
                {"session_id": session_id},
                {"$set": {"duration_seconds": duration_seconds}}
            )

session_manager = SessionManager()
