from app.schema.dpi_config_schema import DPIConfig
from app.schema.packet_schema import PacketSchema
from app.schema.common_schema import IngestResponse
from app.schema.stats_schema import StatsResponse
from app.schema.connection_schema import ConnectionState
from app.services.dispatcher_service import DispatcherService
from app.services.connection import ConnectionTracker
from app.services.rule_service import RuleService
from app.services.stats_service import StatsService


class DPIEngine:
    """
    Orchestrates dispatcher, connection tracking,
    rule evaluation and statistics.
    """

    def __init__(self, config: DPIConfig):
        self.config = config

        # Core Components
        self.dispatcher = DispatcherService(
            config.num_workers,
            output_callback=self.handle_output,
            queue_size=config.queue_size,
        )
        self.connection_tracker = ConnectionTracker(fp_id=0)
        self.rule_service = RuleService()
        self.stats_service = StatsService()

        # Control
        self._running = False

    # ==========================================================
    # Engine Lifecycle
    # ==========================================================

    async def start(self):
        self._running = True
        await self.dispatcher.start()

    async def stop(self):
        self._running = False
        await self.dispatcher.stop()

    def is_running(self) -> bool:
        return self._running

    # ==========================================================
    # Packet Processing
    # ==========================================================

    async def ingest_packet(self, packet: PacketSchema) -> IngestResponse:

        t = packet.tuple

        # ---- Get or create connection ----
        conn = await self.connection_tracker.get_or_create(t)

        # ---- Update connection stats ----
        await self.connection_tracker.update(
            conn,
            size=packet.size,
            outbound=packet.outbound,
        )

        # ---- Update global stats ----
        await self.stats_service.record_packet(packet.size)
        await self.stats_service.record_protocol(t.protocol.value)

        # ---- Dispatch ----
        action = await self.dispatcher.dispatch(packet)

        # ---- Rule Check ----
        block_reason = await self.rule_service.should_block(
            src_ip=t.src_ip,
            dst_port=t.dst_port,
            app=packet.app_type.value if packet.app_type else "UNKNOWN",
            domain=packet.domain,
        )

        if block_reason or action == "DROPPED":
            await self.connection_tracker.block(conn)
            await self.stats_service.record_drop()
            return IngestResponse(status="dropped")

        # ---- Classify if needed ----
        if conn.state != ConnectionState.CLASSIFIED:
            await self.connection_tracker.classify(
                conn,
                app=packet.app_type,
                sni=packet.domain,
            )

        app_label = packet.app_type.value if packet.app_type else "UNKNOWN"
        await self.stats_service.record_app(app_label)
        await self.stats_service.record_forward()

        return IngestResponse(status="forwarded")

    # ==========================================================
    # Rule Management APIs
    # ==========================================================

    async def block_ip(self, ip: str):
        await self.rule_service.block_ip(ip)

    async def unblock_ip(self, ip: str):
        await self.rule_service.unblock_ip(ip)

    async def block_domain(self, domain: str):
        await self.rule_service.block_domain(domain)

    async def unblock_domain(self, domain: str):
        await self.rule_service.unblock_domain(domain)

    async def block_app(self, app: str):
        await self.rule_service.block_app(app)

    async def unblock_app(self, app: str):
        await self.rule_service.unblock_app(app)

    # ==========================================================
    # Reporting
    # ==========================================================

    async def get_stats(self) -> StatsResponse:
        snap = await self.stats_service.snapshot()
        return StatsResponse(**snap)

    async def get_app_stats(self) -> dict:
        app_distribution = await self.stats_service.get_app_stats()
        connections = await self.connection_tracker.get_all()
        unique_domains = list({
            conn.sni for conn in connections
            if conn.sni
        })
        return {
            "app_distribution": app_distribution,
            "unique_domains": unique_domains,
            "active_connections": len(connections),
        }

    async def get_dispatch_stats(self) -> dict:
        return self.dispatcher.get_dispatch_stats()

    async def get_blocked_domains(self):
        return await self.rule_service.get_blocked_domains()

    async def get_blocked_ips(self):
        return await self.rule_service.get_blocked_ips()

    async def get_blocked_apps(self):
        return await self.rule_service.get_blocked_apps()

    async def get_blocked_ports(self):
        return await self.rule_service.get_blocked_ports()

    # ==========================================================
    # Connection Info
    # ==========================================================

    async def get_active_connections(self):
        return await self.connection_tracker.get_all()

    async def get_connection_stats(self):
        return await self.connection_tracker.get_stats()

    # ==========================================================
    # Worker Output Callback
    # ==========================================================

    async def handle_output(self, packet: PacketSchema, action: str):
        if action == "DROP":
            await self.stats_service.record_drop()
