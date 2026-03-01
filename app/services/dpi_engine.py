import asyncio
from typing import Dict
from app.schema.dpi_config_schema import DPIConfig
from app.schema.packet_schema import PacketSchema
from app.schema.common_schema import IngestResponse
from app.schema.stats_schema import StatsResponse
from app.services.dispatcher_service import DispatcherService
from app.services.connection import ConnectionTracker
from app.services.rule_service import RuleService

class DPIEngine:
    """
    Orchestrates dispatcher, connection tracking,
    rule evaluation and statistics.
    """

    def __init__(self, config: DPIConfig):
        self.config = config

        # Core Components
        self.dispatcher = DispatcherService(config.num_workers, output_callback=self.handle_output)
        self.connection_tracker = ConnectionTracker(fp_id=0)
        self.rule_service = RuleService()

        # Control
        self._lock = asyncio.Lock()
        self._running = False

        # Statistics
        self.stats: Dict[str, int] = {
            "total_packets": 0,
            "total_bytes": 0,
            "tcp_packets": 0,
            "udp_packets": 0,
            "forwarded_packets": 0,
            "dropped_packets": 0,
        }

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
        async with self._lock:
            self.stats["total_packets"] += 1
            self.stats["total_bytes"] += packet.size

            if t.protocol == "TCP":
                self.stats["tcp_packets"] += 1
            elif t.protocol == "UDP":
                self.stats["udp_packets"] += 1

        # ---- Dispatch ----
        action = await self.dispatcher.dispatch(packet)

        # ---- Rule Check ----
        block_reason = await self.rule_service.should_block(
            src_ip=t.src_ip,

            dst_port=t.dst_port,
            app=packet.app_type,
            domain=packet.domain,
        )

        if block_reason or action == "DROP":
            await self.connection_tracker.block(conn)

            async with self._lock:
                self.stats["dropped_packets"] += 1

            return IngestResponse(status="dropped")

        # ---- Classify if needed ----
        await self.connection_tracker.classify(
            conn,
            app=packet.app_type,
            sni=packet.domain,
        )

        async with self._lock:
            self.stats["forwarded_packets"] += 1

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
        async with self._lock:
            return StatsResponse(**self.stats)
        
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

    async def handle_output(self, result):
        # Future use: update stats / log / async pipeline
        # For now just ignore
        pass