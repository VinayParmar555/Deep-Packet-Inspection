import asyncio
from collections import defaultdict, deque
from datetime import datetime, timezone


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
        self.start_time: datetime = datetime.now(timezone.utc)
        self.packet_timestamps = deque()
        self.byte_timestamps = deque()

    async def record_packet(self, size: int):
        now = datetime.now(timezone.utc)

        async with self._lock:
            self.total_packets += 1
            self.total_bytes += size
            self.packet_timestamps.append(now)
            self.byte_timestamps.append((now, size))

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

    async def get_rate_metrics(self) -> dict:
        async with self._lock:
            now = datetime.now(timezone.utc)
            window = 5  # seconds

            # Efficient eviction (O(1))
            while self.packet_timestamps and (
                now - self.packet_timestamps[0]
            ).total_seconds() > window:
                self.packet_timestamps.popleft()

            while self.byte_timestamps and (
                now - self.byte_timestamps[0][0]
            ).total_seconds() > window:
                self.byte_timestamps.popleft()

            packet_count = len(self.packet_timestamps)
            total_bytes = sum(b for (_, b) in self.byte_timestamps)

            pps = packet_count / window
            bps = total_bytes / window
            mbps = (total_bytes * 8) / (1_000_000 * window)

            return {
                "packets_per_sec": round(pps, 2),
                "bytes_per_sec": round(bps, 2),
                "throughput_mbps": round(mbps, 4),
                "window_seconds": window,
            }

    async def reset(self):
        """Reset all counters and start time."""
        async with self._lock:
            self.total_packets = 0
            self.total_bytes = 0
            self.forwarded = 0
            self.dropped = 0
            self.protocol_counts.clear()
            self.app_counts.clear()
            self.start_time = datetime.now(timezone.utc)

            # Reset sliding window
            self.packet_timestamps.clear()
            self.byte_timestamps.clear()