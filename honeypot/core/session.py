import uuid
from datetime import datetime, timezone
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
                "context": {
                    "current_directory": "/home/admin",
                    "user": "admin",
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

session_manager = SessionManager()
