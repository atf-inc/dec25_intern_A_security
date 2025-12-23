from motor.motor_asyncio import AsyncIOMotorClient
from config import settings
import certifi
import ssl

class Database:
    client: AsyncIOMotorClient = None
    db = None

    async def connect(self):
        # Use certifi for proper SSL certificate handling (required for MongoDB Atlas)
        self.client = AsyncIOMotorClient(
            settings.MONGO_URI,
            tlsCAFile=certifi.where(),
            tls=True,
            tlsAllowInvalidCertificates=False
        )
        self.db = self.client[settings.DB_NAME]
        print(f"Connected to MongoDB: {settings.DB_NAME}")

    async def close(self):
        if self.client:
            self.client.close()
            print("Closed MongoDB connection")

    def get_collection(self, collection_name: str):
        return self.db[collection_name]

db = Database()
