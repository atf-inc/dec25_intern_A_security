"""
Migrate existing logs to use new request type classification.

This script updates old logs that have type='http_request' or type='command'
to use the new classification:
- trap_trigger: First request in a session
- trapped_interaction: Subsequent requests in a session
- blocked_request: Already correct
"""

import asyncio
from core.database import db

async def migrate_logs():
    await db.connect()
    logs_collection = db.get_collection('logs')
    
    print("=" * 60)
    print("Migrating Logs to New Request Type Classification")
    print("=" * 60)
    
    # Get all sessions
    sessions = await logs_collection.distinct("session_id")
    print(f"\n[INFO] Found {len(sessions)} unique sessions")
    
    updated_count = 0
    
    for session_id in sessions:
        # Skip blocked requests
        if session_id == "BLOCKED":
            continue
        
        # Get all logs for this session, sorted by timestamp
        session_logs = await logs_collection.find(
            {"session_id": session_id}
        ).sort("timestamp", 1).to_list(length=None)
        
        if not session_logs:
            continue
        
        # First log should be trap_trigger
        first_log = session_logs[0]
        if first_log.get('type') not in ['trap_trigger', 'blocked_request']:
            await logs_collection.update_one(
                {"_id": first_log["_id"]},
                {
                    "$set": {
                        "type": "trap_trigger",
                        "is_trap_trigger": True
                    }
                }
            )
            updated_count += 1
            print(f"  [OK] Updated session {session_id[:8]}... first log to trap_trigger")
        
        # Subsequent logs should be trapped_interaction
        for log in session_logs[1:]:
            if log.get('type') not in ['trapped_interaction', 'blocked_request']:
                await logs_collection.update_one(
                    {"_id": log["_id"]},
                    {
                        "$set": {
                            "type": "trapped_interaction",
                            "is_trap_trigger": False
                        }
                    }
                )
                updated_count += 1
    
    print(f"\n[SUCCESS] Updated {updated_count} logs")
    
    # Show summary
    print("\n[SUMMARY] Request type distribution:")
    pipeline = [
        {"$group": {"_id": "$type", "count": {"$sum": 1}}},
        {"$sort": {"count": -1}}
    ]
    types = await logs_collection.aggregate(pipeline).to_list(length=None)
    for t in types:
        print(f"  - {t['_id']}: {t['count']}")
    
    # Show trap triggers
    trap_count = await logs_collection.count_documents({"type": "trap_trigger"})
    print(f"\n[RESULT] Trap triggers now available: {trap_count}")
    
    await db.close()
    print("\n" + "=" * 60)
    print("Migration Complete!")
    print("=" * 60)

if __name__ == "__main__":
    asyncio.run(migrate_logs())
