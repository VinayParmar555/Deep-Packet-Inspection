import os
import redis.asyncio as redis
from typing import Optional

class RedisClient:
    """
    Async Redis client with connection pooling.
    Designed for FastAPI production usage.
    """

    def __init__(self):
        self._redis: Optional[redis.Redis] = None

    async def connect(self):
        redis_url = os.getenv("REDIS_URL", "redis://localhost:6379")

        self._redis = redis.from_url(
            redis_url,
            encoding="utf-8",
            decode_responses=True,  # important for string handling
            max_connections=20
        )

        # Test connection
        await self._redis.ping()

    async def disconnect(self):
        if self._redis:
            await self._redis.close()

    def get_client(self) -> redis.Redis:
        if not self._redis:
            raise RuntimeError("Redis not initialized")
        return self._redis

# Singleton instance
redis_manager = RedisClient()

# Shortcut for importing everywhere
def redis_client():
    return redis_manager.get_client()