import asyncio
from core.database import db

async def check_trap_triggers():
    await db.connect()
    logs_collection = db.get_collection('logs')
    
    # Check for trap triggers
    trap_triggers = await logs_collection.find({'type': 'trap_trigger'}).limit(10).to_list(length=10)
    print(f"\n[TRAP TRIGGERS] Found: {len(trap_triggers)}")
    for log in trap_triggers:
        print(f"  - IP: {log.get('ip')}, Session: {log.get('session_id')}, Time: {log.get('timestamp')}")
    
    # Check for all request types
    print("\n[ALL REQUEST TYPES]")
    pipeline = [
        {"$group": {"_id": "$type", "count": {"$sum": 1}}},
        {"$sort": {"count": -1}}
    ]
    types = await logs_collection.aggregate(pipeline).to_list(length=None)
    for t in types:
        print(f"  - {t['_id']}: {t['count']}")
    
    # Check recent logs
    print("\n[RECENT LOGS]")
    recent = await logs_collection.find().sort("timestamp", -1).limit(5).to_list(length=5)
    for log in recent:
        print(f"  - Type: {log.get('type')}, IP: {log.get('ip')}, Session: {log.get('session_id')}")
    
    await db.close()

if __name__ == "__main__":
    asyncio.run(check_trap_triggers())
