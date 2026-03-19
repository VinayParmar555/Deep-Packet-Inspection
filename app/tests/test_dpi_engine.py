import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from app.services.dpi_engine import DPIEngine
from app.schema.dpi_config_schema import DPIConfig
from app.schema.connection_schema import AppType, FiveTupleSchema, Protocol


def make_config():
    return DPIConfig(num_workers=1, queue_size=100)


def make_mock_packet(
    src_ip="192.168.1.1", dst_ip="8.8.8.8",
    src_port=1234, dst_port=80,
    protocol=Protocol.TCP,
    size=100, outbound=True,
    domain=None, app_type=AppType.UNKNOWN,
):
    packet = MagicMock()
    packet.tuple = FiveTupleSchema(
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        protocol=protocol,
    )
    packet.size      = size
    packet.outbound  = outbound
    packet.domain    = domain
    packet.app_type  = app_type
    return packet


def make_engine():
    config = make_config()
    with patch("app.services.dpi_engine.DispatcherService") as MockDispatcher, \
         patch("app.services.dpi_engine.RuleService") as MockRule, \
         patch("app.services.dpi_engine.StatsService") as MockStats:

        mock_dispatcher = AsyncMock()
        mock_rule       = AsyncMock()
        mock_stats      = AsyncMock()

        MockDispatcher.return_value = mock_dispatcher
        MockRule.return_value       = mock_rule
        MockStats.return_value      = mock_stats

        engine = DPIEngine(config)
        engine.dispatcher   = mock_dispatcher
        engine.rule_service = mock_rule
        engine.stats_service = mock_stats

    return engine, mock_dispatcher, mock_rule, mock_stats


class TestDPIEngine:

    # ── Lifecycle ─────────────────────────

    @pytest.mark.asyncio
    async def test_start(self):
        engine, dispatcher, _, _ = make_engine()
        await engine.start()
        assert engine.is_running() is True
        dispatcher.start.assert_called_once()

    @pytest.mark.asyncio
    async def test_stop(self):
        engine, dispatcher, _, _ = make_engine()
        await engine.start()
        await engine.stop()
        assert engine.is_running() is False
        dispatcher.stop.assert_called_once()

    def test_is_running_default_false(self):
        engine, _, _, _ = make_engine()
        assert engine.is_running() is False

    # ── ingest_packet — forwarded ─────────

    @pytest.mark.asyncio
    async def test_ingest_packet_forwarded(self):
        engine, dispatcher, rule, stats = make_engine()
        dispatcher.dispatch.return_value = "ALLOW"
        rule.should_block.return_value   = None

        packet = make_mock_packet()
        response = await engine.ingest_packet(packet)

        assert response.status == "forwarded"

    @pytest.mark.asyncio
    async def test_ingest_packet_dropped_queue_full(self):
        engine, dispatcher, rule, stats = make_engine()
        dispatcher.dispatch.return_value = "DROPPED"

        packet = make_mock_packet()
        response = await engine.ingest_packet(packet)

        assert response.status == "dropped"
        stats.record_drop.assert_called()

    @pytest.mark.asyncio
    async def test_ingest_packet_blocked_by_rule(self):
        engine, dispatcher, rule, stats = make_engine()
        dispatcher.dispatch.return_value = "ALLOW"
        rule.should_block.return_value   = MagicMock()  # blocked!

        packet = make_mock_packet()
        response = await engine.ingest_packet(packet)

        assert response.status == "dropped"

    @pytest.mark.asyncio
    async def test_ingest_packet_records_stats(self):
        engine, dispatcher, rule, stats = make_engine()
        dispatcher.dispatch.return_value = "ALLOW"
        rule.should_block.return_value   = None

        packet = make_mock_packet(size=500)
        await engine.ingest_packet(packet)

        stats.record_packet.assert_called_once_with(500)

    # ── Rule management ───────────────────

    @pytest.mark.asyncio
    async def test_block_ip(self):
        engine, _, rule, _ = make_engine()
        await engine.block_ip("1.2.3.4")
        rule.block_ip.assert_called_once_with("1.2.3.4")

    @pytest.mark.asyncio
    async def test_unblock_ip(self):
        engine, _, rule, _ = make_engine()
        await engine.unblock_ip("1.2.3.4")
        rule.unblock_ip.assert_called_once_with("1.2.3.4")

    @pytest.mark.asyncio
    async def test_block_domain(self):
        engine, _, rule, _ = make_engine()
        await engine.block_domain("youtube.com")
        rule.block_domain.assert_called_once_with("youtube.com")

    @pytest.mark.asyncio
    async def test_unblock_domain(self):
        engine, _, rule, _ = make_engine()
        await engine.unblock_domain("youtube.com")
        rule.unblock_domain.assert_called_once_with("youtube.com")

    @pytest.mark.asyncio
    async def test_block_app(self):
        engine, _, rule, _ = make_engine()
        await engine.block_app("YOUTUBE")
        rule.block_app.assert_called_once_with("YOUTUBE")

    @pytest.mark.asyncio
    async def test_unblock_app(self):
        engine, _, rule, _ = make_engine()
        await engine.unblock_app("YOUTUBE")
        rule.unblock_app.assert_called_once_with("YOUTUBE")

    # ── Reporting ─────────────────────────

    @pytest.mark.asyncio
    async def test_get_stats(self):
        engine, _, _, stats = make_engine()
        stats.snapshot.return_value = {
            "total_packets": 100,
            "total_bytes": 5000,
            "tcp_packets": 80,
            "udp_packets": 20,
            "forwarded_packets": 90,
            "dropped_packets": 10,
        }
        result = await engine.get_stats()
        assert result.total_packets == 100

    @pytest.mark.asyncio
    async def test_get_dispatch_stats(self):
        engine, dispatcher, _, _ = make_engine()
        dispatcher.get_dispatch_stats.return_value = {"total_dispatched": 5}
        result = await engine.get_dispatch_stats()
        assert result["total_dispatched"] == 5

    @pytest.mark.asyncio
    async def test_get_blocked_ips(self):
        engine, _, rule, _ = make_engine()
        rule.get_blocked_ips.return_value = ["1.2.3.4"]
        result = await engine.get_blocked_ips()
        assert "1.2.3.4" in result

    @pytest.mark.asyncio
    async def test_get_blocked_domains(self):
        engine, _, rule, _ = make_engine()
        rule.get_blocked_domains.return_value = ["youtube.com"]
        result = await engine.get_blocked_domains()
        assert "youtube.com" in result

    @pytest.mark.asyncio
    async def test_get_blocked_apps(self):
        engine, _, rule, _ = make_engine()
        rule.get_blocked_apps.return_value = ["YOUTUBE"]
        result = await engine.get_blocked_apps()
        assert "YOUTUBE" in result

    # ── handle_output ─────────────────────

    @pytest.mark.asyncio
    async def test_handle_output_allow(self):
        engine, _, _, stats = make_engine()
        packet = make_mock_packet()
        await engine.handle_output(packet, "ALLOW")
        stats.record_forward.assert_called_once()

    @pytest.mark.asyncio
    async def test_handle_output_drop(self):
        engine, _, _, stats = make_engine()
        packet = make_mock_packet()
        await engine.handle_output(packet, "DROP")
        stats.record_drop.assert_called_once()

    @pytest.mark.asyncio
    async def test_handle_output_unknown_action(self):
        engine, _, _, stats = make_engine()
        packet = make_mock_packet()
        await engine.handle_output(packet, "UNKNOWN")
        stats.record_forward.assert_not_called()
        stats.record_drop.assert_not_called()

    # ── get_app_stats ─────────────────────

    @pytest.mark.asyncio
    async def test_get_app_stats(self):
        engine, _, _, stats = make_engine()
        stats.get_app_stats.return_value = {"YOUTUBE": 50}
        result = await engine.get_app_stats()
        assert "app_distribution" in result
        assert "unique_domains" in result
        assert "active_connections" in result
