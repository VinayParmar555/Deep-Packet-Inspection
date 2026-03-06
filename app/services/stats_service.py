import asyncio
from collections import defaultdict


class StatsService:
    """
    Centralized statistics service for the DPI engine.
    Tracks packet counts, byte totals, protocol distribution,
    and per-application traffic breakdown.
    """

    def __init__(self):
        self._lock = asyncio.Lock()
        self.total_packets = 0
        self.total_bytes = 0
        self.forwarded = 0
        self.dropped = 0
        self.protocol_counts: dict[str, int] = defaultdict(int)
        self.app_counts: dict[str, int] = defaultdict(int)

    async def record_packet(self, size: int):
        async with self._lock:
            self.total_packets += 1
            self.total_bytes += size

    async def record_protocol(self, protocol: str):
        async with self._lock:
            self.protocol_counts[protocol] += 1

    async def record_app(self, app_type: str):
        async with self._lock:
            self.app_counts[app_type] += 1

    async def record_forward(self):
        async with self._lock:
            self.forwarded += 1

    async def record_drop(self):
        async with self._lock:
            self.dropped += 1

    async def snapshot(self) -> dict:
        async with self._lock:
            return {
                "total_packets": self.total_packets,
                "total_bytes": self.total_bytes,
                "tcp_packets": self.protocol_counts.get("TCP", 0),
                "udp_packets": self.protocol_counts.get("UDP", 0),
                "forwarded_packets": self.forwarded,
                "dropped_packets": self.dropped,
            }

    async def get_app_stats(self) -> dict:
        async with self._lock:
            return dict(self.app_counts)
