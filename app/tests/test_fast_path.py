import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from app.services.fast_path import FastPathProcessor
from app.schema.connection_schema import ConnectionState, AppType, Protocol, FiveTupleSchema


def make_mock_packet(
    src_ip="192.168.1.1",
    dst_ip="8.8.8.8",
    src_port=1234,
    dst_port=80,
    protocol=Protocol.TCP,
    size=100,
    outbound=True,
    tcp_flags=0,
    domain=None,
    app_type=AppType.UNKNOWN,
):
    packet = MagicMock()
    packet.tuple = FiveTupleSchema(
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        protocol=protocol,
    )
    packet.size           = size
    packet.outbound       = outbound
    packet.tcp_flags      = tcp_flags
    packet.domain         = domain
    packet.app_type       = app_type
    return packet


def make_processor():
    rule_service    = AsyncMock()
    output_callback = AsyncMock()
    processor = FastPathProcessor(
        fp_id=0,
        rule_service=rule_service,
        output_callback=output_callback,
        queue_size=100,
    )
    return processor, rule_service, output_callback


# ─────────────────────────────────────────
# process_packet tests
# ─────────────────────────────────────────

class TestFastPathProcessor:

    @pytest.mark.asyncio
    async def test_process_packet_allow(self):
        processor, rule_service, _ = make_processor()
        rule_service.should_block.return_value = None  # not blocked

        packet = make_mock_packet()
        action = await processor.process_packet(packet)

        assert action == "ALLOW"
        assert processor.stats["forwarded"] == 1
        assert processor.stats["processed"] == 1

    @pytest.mark.asyncio
    async def test_process_packet_drop_rule(self):
        processor, rule_service, _ = make_processor()
        rule_service.should_block.return_value = MagicMock()  # blocked!

        packet = make_mock_packet()
        action = await processor.process_packet(packet)

        assert action == "DROP"
        assert processor.stats["dropped"] == 1

    @pytest.mark.asyncio
    async def test_process_packet_already_blocked(self):
        processor, rule_service, _ = make_processor()
        rule_service.should_block.return_value = None

        packet = make_mock_packet()

        # First packet — block it
        rule_service.should_block.return_value = MagicMock()
        await processor.process_packet(packet)

        # Second packet — same connection, should early-exit as BLOCKED
        rule_service.should_block.return_value = None
        action = await processor.process_packet(packet)

        assert action == "DROP"

    @pytest.mark.asyncio
    async def test_stats_processed_increments(self):
        processor, rule_service, _ = make_processor()
        rule_service.should_block.return_value = None

        for _ in range(5):
            await processor.process_packet(make_mock_packet())

        assert processor.stats["processed"] == 5

    @pytest.mark.asyncio
    async def test_classification_hit(self):
        processor, rule_service, _ = make_processor()
        rule_service.should_block.return_value = None

        packet = make_mock_packet(domain="youtube.com", app_type=AppType.YOUTUBE)
        await processor.process_packet(packet)

        assert processor.stats["classification_hits"] == 1

    @pytest.mark.asyncio
    async def test_no_classification_without_domain(self):
        processor, rule_service, _ = make_processor()
        rule_service.should_block.return_value = None

        packet = make_mock_packet(domain=None)
        await processor.process_packet(packet)

        assert processor.stats["classification_hits"] == 0

    # ── TCP state machine ─────────────────

    @pytest.mark.asyncio
    async def test_tcp_syn_state(self):
        processor, rule_service, _ = make_processor()
        rule_service.should_block.return_value = None

        packet = make_mock_packet(protocol=Protocol.TCP, tcp_flags=0x02)  # SYN
        await processor.process_packet(packet)

        conn = list(processor.conn_tracker._connections.values())[0]
        assert conn.tcp_state == "SYN_SENT"

    @pytest.mark.asyncio
    async def test_tcp_rst_state(self):
        processor, rule_service, _ = make_processor()
        rule_service.should_block.return_value = None

        packet = make_mock_packet(protocol=Protocol.TCP, tcp_flags=0x04)  # RST
        await processor.process_packet(packet)

        conn = list(processor.conn_tracker._connections.values())[0]
        assert conn.tcp_state == "CLOSED"

    @pytest.mark.asyncio
    async def test_tcp_fin_state(self):
        processor, rule_service, _ = make_processor()
        rule_service.should_block.return_value = None

        packet = make_mock_packet(protocol=Protocol.TCP, tcp_flags=0x01)  # FIN
        await processor.process_packet(packet)

        conn = list(processor.conn_tracker._connections.values())[0]
        assert conn.tcp_state == "CLOSED"

    @pytest.mark.asyncio
    async def test_udp_no_tcp_state(self):
        processor, rule_service, _ = make_processor()
        rule_service.should_block.return_value = None

        packet = make_mock_packet(protocol=Protocol.UDP, tcp_flags=0)
        await processor.process_packet(packet)

        conn = list(processor.conn_tracker._connections.values())[0]
        assert conn.tcp_state is None

    # ── Lifecycle ─────────────────────────

    @pytest.mark.asyncio
    async def test_start_creates_task(self):
        processor, _, _ = make_processor()
        await processor.start()
        assert processor.task is not None
        await processor.stop()

    @pytest.mark.asyncio
    async def test_stop_clears_task(self):
        processor, _, _ = make_processor()
        await processor.start()
        await processor.stop()
        assert processor.task is None

    @pytest.mark.asyncio
    async def test_start_idempotent(self):
        processor, _, _ = make_processor()
        await processor.start()
        task1 = processor.task
        await processor.start()   # already running — should not create new task
        assert processor.task is task1
        await processor.stop()

    # ── try_push ──────────────────────────

    def test_try_push_success(self):
        processor, _, _ = make_processor()
        packet = make_mock_packet()
        result = processor.input_queue.try_push(packet)
        assert result is True

    def test_try_push_full_queue(self):
        processor, rule_service, output_callback = make_processor()
        # Make a tiny queue
        processor.input_queue._queue._maxsize = 1
        processor.input_queue.try_push(make_mock_packet())  # fill it
        result = processor.input_queue.try_push(make_mock_packet())
        assert result is False
