import asyncio
from datetime import datetime, timedelta, timezone
from typing import Dict, Callable, List

from app.schema.connection_schema import (
    FiveTupleSchema,
    ConnectionSchema,
    ConnectionState,
    AppType,
)

class ConnectionTracker:

    def __init__(self, fp_id: int, max_connections: int = 100000):
        self.fp_id = fp_id
        self.max_connections = max_connections

        self._connections: Dict[str, ConnectionSchema] = {}
        self._lock = asyncio.Lock()

        self.total_seen = 0
        self.classified_count = 0
        self.blocked_count = 0

    # -------------------------------------------------
    # Internal Helpers
    # -------------------------------------------------

    def _key(self, tuple: FiveTupleSchema) -> str:
        return f"{tuple.src_ip}:{tuple.src_port}-" \
               f"{tuple.dst_ip}:{tuple.dst_port}-" \
               f"{tuple.protocol}"

    # -------------------------------------------------
    # Core API
    # -------------------------------------------------

    async def get_or_create(self, tuple: FiveTupleSchema) -> ConnectionSchema:
        key = self._key(tuple)

        async with self._lock:
            conn = self._connections.get(key)

            if conn:
                return conn

            if len(self._connections) >= self.max_connections:
                self._evict_oldest()

            now = datetime.now(timezone.utc)

            conn = ConnectionSchema(
                tuple=tuple,
                state=ConnectionState.NEW,
                first_seen=now,
                last_seen=now,
            )

            self._connections[key] = conn
            self.total_seen += 1

            return conn

    async def update(self, conn: ConnectionSchema, size: int, outbound: bool):
        async with self._lock:
            conn.last_seen = datetime.now(timezone.utc)

            if outbound:
                conn.packets_out += 1
                conn.bytes_out += size
            else:
                conn.packets_in += 1
                conn.bytes_in += size

    async def classify(self, conn: ConnectionSchema, app: AppType, sni: str | None):
        async with self._lock:
            if conn.state != ConnectionState.CLASSIFIED:
                self.classified_count += 1

            conn.state = ConnectionState.CLASSIFIED
            conn.app_type = app
            conn.sni = sni

    async def block(self, conn: ConnectionSchema):
        async with self._lock:
            if conn.state != ConnectionState.BLOCKED:
                self.blocked_count += 1

            conn.state = ConnectionState.BLOCKED

    async def close(self, tuple: FiveTupleSchema):
        key = self._key(tuple)

        async with self._lock:
            if key in self._connections:
                self._connections[key].state = ConnectionState.CLOSED
                del self._connections[key]

    # -------------------------------------------------
    # Cleanup
    # -------------------------------------------------

    async def cleanup_stale(self, timeout_seconds: int = 300) -> int:
        cutoff = datetime.now(timezone.utc) - timedelta(seconds=timeout_seconds)

        async with self._lock:
            to_remove = [
                key for key, conn in self._connections.items()
                if conn.last_seen < cutoff
            ]

            for key in to_remove:
                del self._connections[key]

            return len(to_remove)

    def _evict_oldest(self):
        if not self._connections:
            return

        oldest_key = min(
            self._connections,
            key=lambda k: self._connections[k].last_seen
        )

        del self._connections[oldest_key]

    # -------------------------------------------------
    # Stats
    # -------------------------------------------------

    async def get_active_count(self) -> int:
        async with self._lock:
            return len(self._connections)

    async def get_stats(self):
        async with self._lock:
            return {
                "active_connections": len(self._connections),
                "total_connections_seen": self.total_seen,
                "classified_connections": self.classified_count,
                "blocked_connections": self.blocked_count,
            }

    async def get_all(self) -> List[ConnectionSchema]:
        async with self._lock:
            return list(self._connections.values())

    async def for_each(self, callback: Callable[[ConnectionSchema], None]):
        async with self._lock:
            for conn in self._connections.values():
                callback(conn)

    async def clear(self):
        async with self._lock:
            self._connections.clear()