import pytest
from app.services.stats_service import StatsService


class TestStatsService:
    async def test_initial_snapshot_is_zero(self):
        svc = StatsService()
        snap = await svc.snapshot()
        assert snap["total_packets"] == 0
        assert snap["total_bytes"] == 0
        assert snap["forwarded_packets"] == 0
        assert snap["dropped_packets"] == 0

    async def test_record_packet_increments_counts(self):
        svc = StatsService()
        await svc.record_packet(1500)
        snap = await svc.snapshot()
        assert snap["total_packets"] == 1
        assert snap["total_bytes"] == 1500

    async def test_record_multiple_packets(self):
        svc = StatsService()
        for size in [100, 200, 300]:
            await svc.record_packet(size)
        snap = await svc.snapshot()
        assert snap["total_packets"] == 3
        assert snap["total_bytes"] == 600

    async def test_record_forward(self):
        svc = StatsService()
        await svc.record_packet(100)
        await svc.record_forward()
        snap = await svc.snapshot()
        assert snap["forwarded_packets"] == 1

    async def test_record_drop(self):
        svc = StatsService()
        await svc.record_packet(100)
        await svc.record_drop()
        snap = await svc.snapshot()
        assert snap["dropped_packets"] == 1

    async def test_record_protocol_tcp(self):
        svc = StatsService()
        await svc.record_protocol("TCP")
        snap = await svc.snapshot()
        assert snap["tcp_packets"] == 1
        assert snap["udp_packets"] == 0

    async def test_record_protocol_udp(self):
        svc = StatsService()
        await svc.record_protocol("UDP")
        snap = await svc.snapshot()
        assert snap["udp_packets"] == 1

    async def test_record_app(self):
        svc = StatsService()
        await svc.record_app("NETFLIX")
        await svc.record_app("NETFLIX")
        await svc.record_app("YOUTUBE")
        app_stats = await svc.get_app_stats()
        assert app_stats["NETFLIX"] == 2
        assert app_stats["YOUTUBE"] == 1

    async def test_snapshot_isolation(self):
        """Two independent instances must not share state."""
        a = StatsService()
        b = StatsService()
        await a.record_packet(500)
        snap_b = await b.snapshot()
        assert snap_b["total_packets"] == 0
