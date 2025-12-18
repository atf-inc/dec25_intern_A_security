from datetime import datetime, timezone
from core.database import db

class Logger:
    def __init__(self):
        self.collection_name = "logs"

    async def log_interaction(self, session_id: str, ip: str, request_type: str, payload: str, response: str):
        collection = db.get_collection(self.collection_name)
        log_entry = {
            "timestamp": datetime.now(timezone.utc),
            "session_id": session_id,
            "ip": ip,
            "type": request_type, # e.g., "command", "http_get", "login_attempt"
            "payload": payload,
            "response": response
        }
        await collection.insert_one(log_entry)

logger = Logger()
