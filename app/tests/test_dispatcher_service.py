import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from app.services.dispatcher_service import DispatcherService
from app.schema.connection_schema import Protocol


def make_mock_packet(src_ip="1.2.3.4", dst_ip="5.6.7.8",
                     src_port=1234, dst_port=80, protocol=Protocol.TCP):
    packet = MagicMock()
    packet.tuple.src_ip   = src_ip
    packet.tuple.dst_ip   = dst_ip
    packet.tuple.src_port = src_port
    packet.tuple.dst_port = dst_port
    packet.tuple.protocol = protocol
    return packet


def make_dispatcher(num=2):
    callback = AsyncMock()
    with patch("app.services.dispatcher_service.RuleService"):
        dispatcher = DispatcherService(
            num_processors=num,
            output_callback=callback,
            queue_size=100,
        )
    return dispatcher, callback


class TestDispatcherService:

    # ── Init ──────────────────────────────

    def test_creates_correct_number_of_processors(self):
        dispatcher, _ = make_dispatcher(num=4)
        assert len(dispatcher.processors) == 4

    def test_dispatch_counts_initialized(self):
        dispatcher, _ = make_dispatcher(num=3)
        assert dispatcher.dispatch_counts == [0, 0, 0]

    def test_dropped_count_initialized(self):
        dispatcher, _ = make_dispatcher()
        assert dispatcher.dropped_count == 0

    # ── _select_processor ─────────────────

    def test_select_processor_in_range(self):
        dispatcher, _ = make_dispatcher(num=4)
        packet = make_mock_packet()
        index = dispatcher._select_processor(packet)
        assert 0 <= index < 4

    def test_select_processor_consistent(self):
        dispatcher, _ = make_dispatcher(num=4)
        packet = make_mock_packet()
        index1 = dispatcher._select_processor(packet)
        index2 = dispatcher._select_processor(packet)
        assert index1 == index2  # same packet → same worker

    def test_select_processor_different_packets(self):
        dispatcher, _ = make_dispatcher(num=8)
        p1 = make_mock_packet(src_port=1111)
        p2 = make_mock_packet(src_port=2222)
        # different packets may go to different workers (not guaranteed but test passes)
        i1 = dispatcher._select_processor(p1)
        i2 = dispatcher._select_processor(p2)
        assert 0 <= i1 < 8
        assert 0 <= i2 < 8

    # ── dispatch ──────────────────────────

    @pytest.mark.asyncio
    async def test_dispatch_allow(self):
        dispatcher, _ = make_dispatcher(num=2)
        packet = make_mock_packet()
        result = await dispatcher.dispatch(packet)
        assert result == "ALLOW"

    @pytest.mark.asyncio
    async def test_dispatch_increments_count(self):
        dispatcher, _ = make_dispatcher(num=2)
        packet = make_mock_packet()
        await dispatcher.dispatch(packet)
        assert sum(dispatcher.dispatch_counts) == 1

    @pytest.mark.asyncio
    async def test_dispatch_dropped_when_all_full(self):
        dispatcher, _ = make_dispatcher(num=2)

        # Fill all queues
        for proc in dispatcher.processors:
            proc.input_queue._shutdown = False
            # Fill the internal asyncio queue
            while True:
                ok = proc.input_queue.try_push(make_mock_packet())
                if not ok:
                    break

        packet = make_mock_packet()
        result = await dispatcher.dispatch(packet)
        assert result == "DROPPED"
        assert dispatcher.dropped_count == 1

    @pytest.mark.asyncio
    async def test_dispatch_fallback_to_other_worker(self):
        dispatcher, _ = make_dispatcher(num=2)
        packet = make_mock_packet()

        # Fill primary worker
        primary = dispatcher._select_processor(packet)
        while dispatcher.processors[primary].input_queue.try_push(make_mock_packet()):
            pass

        result = await dispatcher.dispatch(packet)
        # Should fall back to other worker
        assert result == "ALLOW"

    # ── get_dispatch_stats ────────────────

    @pytest.mark.asyncio
    async def test_get_dispatch_stats_structure(self):
        dispatcher, _ = make_dispatcher(num=2)
        await dispatcher.dispatch(make_mock_packet())

        stats = dispatcher.get_dispatch_stats()
        assert "total_dispatched" in stats
        assert "total_dropped_backpressure" in stats
        assert "workers" in stats
        assert len(stats["workers"]) == 2

    @pytest.mark.asyncio
    async def test_get_dispatch_stats_total(self):
        dispatcher, _ = make_dispatcher(num=2)
        for _ in range(3):
            await dispatcher.dispatch(make_mock_packet())

        stats = dispatcher.get_dispatch_stats()
        assert stats["total_dispatched"] == 3

    def test_get_dispatch_stats_worker_fields(self):
        dispatcher, _ = make_dispatcher(num=1)
        stats = dispatcher.get_dispatch_stats()
        worker = stats["workers"][0]
        assert "worker_id" in worker
        assert "dispatched" in worker
        assert "queue_size" in worker
        assert "processed" in worker
        assert "forwarded" in worker
        assert "dropped" in worker

    # ── Lifecycle ─────────────────────────

    @pytest.mark.asyncio
    async def test_start_and_stop(self):
        dispatcher, _ = make_dispatcher(num=2)
        await dispatcher.start()
        for proc in dispatcher.processors:
            assert proc.task is not None
        await dispatcher.stop()
        for proc in dispatcher.processors:
            assert proc.task is None
